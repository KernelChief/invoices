import base64
import getpass
import hashlib
import hmac
import io
import json
import os
import re
import secrets
import smtplib
import sqlite3
import ssl
import sys
import time
from datetime import date, timedelta
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation
from email.message import EmailMessage
from xml.sax.saxutils import escape

from flask import (Flask, Response, abort, g, jsonify, redirect,
                   render_template_string, request, session, url_for)
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.units import inch
from reportlab.lib.utils import ImageReader
from reportlab.platypus import HRFlowable
from reportlab.platypus import Image as RLImage
from reportlab.platypus import Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle
from werkzeug.middleware.proxy_fix import ProxyFix
from werkzeug.security import check_password_hash, generate_password_hash

DB = os.environ.get("DB_PATH", "/var/lib/invoices/invoices.db")
PORT = int(os.environ.get("PORT", "8080"))
MIN_PW = 8
MAX_FAILS = 5
FAIL_WINDOW = 600
RESET_TTL = 600      # an emailed reset code works for this many seconds...
RESET_TRIES = 5      # ...and for this many guesses

app = Flask(__name__)
app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)
app.config.update(
    SESSION_COOKIE_NAME="invoices_session",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_SECURE=os.environ.get("COOKIE_SECURE") == "1",
    PERMANENT_SESSION_LIFETIME=timedelta(days=90),
    MAX_CONTENT_LENGTH=4 * 1024 * 1024,
)
FAILS = {}


# ======================================================================
# database
# ======================================================================

SCHEMA = """
CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    email TEXT NOT NULL DEFAULT '',
    pw_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    disabled INTEGER NOT NULL DEFAULT 0,
    epoch TEXT NOT NULL);
CREATE TABLE IF NOT EXISTS reset_codes (
    user_id INTEGER PRIMARY KEY REFERENCES users(id),
    code_hash TEXT NOT NULL,
    created INTEGER NOT NULL,
    tries INTEGER NOT NULL DEFAULT 0);
CREATE TABLE IF NOT EXISTS clients (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    address TEXT NOT NULL DEFAULT '',
    lang TEXT NOT NULL DEFAULT 'en',
    rate TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS services (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    name TEXT NOT NULL UNIQUE COLLATE NOCASE,
    desc_en TEXT NOT NULL DEFAULT '',
    desc_fr TEXT NOT NULL DEFAULT '',
    rate TEXT NOT NULL DEFAULT '');
CREATE TABLE IF NOT EXISTS invoices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    number TEXT NOT NULL UNIQUE,
    client_id INTEGER REFERENCES clients(id),
    issue_date TEXT NOT NULL,
    due_date TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'unpaid',
    paid_date TEXT,
    total_cents INTEGER NOT NULL,
    data TEXT NOT NULL);
"""


def get_setting(conn, key):
    row = conn.execute("SELECT value FROM settings WHERE key = ?", (key,)).fetchone()
    return row[0] if row else None


def set_setting(conn, key, value):
    conn.execute(
        "INSERT INTO settings (key, value) VALUES (?, ?) "
        "ON CONFLICT(key) DO UPDATE SET value = excluded.value",
        (key, value),
    )
    conn.commit()


def init_db():
    os.makedirs(os.path.dirname(DB), exist_ok=True)
    conn = sqlite3.connect(DB)
    conn.executescript(SCHEMA)
    old_hash = get_setting(conn, "pw_hash")
    if old_hash and not conn.execute("SELECT 1 FROM users").fetchone():
        # the single password from before accounts existed becomes the first admin
        conn.execute(
            "INSERT INTO users (username, pw_hash, is_admin, epoch) VALUES ('admin', ?, 1, ?)",
            (old_hash, get_setting(conn, "pw_epoch") or secrets.token_hex(8)),
        )
        conn.execute("DELETE FROM settings WHERE key IN ('pw_hash', 'pw_epoch')")
        conn.commit()
    if not get_setting(conn, "secret_key"):
        set_setting(conn, "secret_key", secrets.token_hex(32))
    key = get_setting(conn, "secret_key")
    conn.close()
    try:
        os.chmod(DB, 0o600)
    except OSError:
        pass
    return key


app.secret_key = init_db()


def db():
    if "db" not in g:
        g.db = sqlite3.connect(DB)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_):
    conn = g.pop("db", None)
    if conn:
        conn.close()


@app.before_request
def _nonce():
    g.csp_nonce = secrets.token_urlsafe(16)


@app.after_request
def headers(resp):
    nonce = g.get("csp_nonce", "")
    resp.headers["Content-Security-Policy"] = (
        "default-src 'self'; "
        f"script-src 'self' 'nonce-{nonce}'; "
        f"style-src 'self' 'nonce-{nonce}'; "
        "img-src 'self' data:; connect-src 'self'; "
        "base-uri 'none'; form-action 'self'; frame-ancestors 'none'; object-src 'none'"
    )
    resp.headers["X-Content-Type-Options"] = "nosniff"
    resp.headers["X-Frame-Options"] = "DENY"
    resp.headers["Referrer-Policy"] = "no-referrer"
    resp.headers["Permissions-Policy"] = "geolocation=(), camera=(), microphone=()"
    if app.config["SESSION_COOKIE_SECURE"]:
        resp.headers["Strict-Transport-Security"] = "max-age=63072000; includeSubDomains"
    return resp


# ======================================================================
# auth (same model as the overtime app)
# ======================================================================

OPEN_ENDPOINTS = {"login", "setup", "forgot", "reset", "manifest", "icon", "icon_animated"}
IDLE_OPTIONS = [(5, "5 minutes"), (15, "15 minutes"), (30, "30 minutes"),
                (60, "1 hour"), (240, "4 hours"), (0, "Never")]


def idle_minutes(conn):
    try:
        v = int(get_setting(conn, "idle_minutes") or 30)
    except ValueError:
        v = 30
    return v if v in dict(IDLE_OPTIONS) else 30


def locked_out(ip):
    now = time.time()
    FAILS[ip] = [t for t in FAILS.get(ip, []) if now - t < FAIL_WINDOW]
    return len(FAILS[ip]) >= MAX_FAILS


def new_epoch():
    return secrets.token_hex(8)


def clean_username(raw):
    return "".join(str(raw or "").split())[:32]


def password_problem(pw, confirm=None):
    if len(pw) < MIN_PW:
        return f"Use at least {MIN_PW} characters."
    if confirm is not None and pw != confirm:
        return "Passwords don't match."
    return None


def user_by_name(name):
    return db().execute("SELECT * FROM users WHERE username = ?", (name,)).fetchone()


def user_by_login(raw):
    """Sign-in and reset accept either the username or the account's email address."""
    s = str(raw or "").strip()
    if "@" in s:
        return db().execute(
            "SELECT * FROM users WHERE email = ? COLLATE NOCASE AND email != ''", (s,)
        ).fetchone()
    return user_by_name(clean_username(s))


def email_taken(email, user_id=None):
    return bool(email) and db().execute(
        "SELECT 1 FROM users WHERE email = ? COLLATE NOCASE AND id IS NOT ?", (email, user_id)
    ).fetchone() is not None


def set_user_password(target_id, pw):
    """Store a new password and rotate the user's epoch, which signs out their other sessions."""
    epoch = new_epoch()
    db().execute("UPDATE users SET pw_hash = ?, epoch = ? WHERE id = ?",
                 (generate_password_hash(pw), epoch, target_id))
    db().commit()
    return epoch


def uid():
    return g.user["id"]


_dummy_hash = []


@app.before_request
def gate():
    g.user = None
    if request.endpoint is None or request.endpoint in OPEN_ENDPOINTS:
        return None
    conn = db()
    if not conn.execute("SELECT 1 FROM users").fetchone():
        return redirect(url_for("setup"))
    u = conn.execute("SELECT * FROM users WHERE id = ?", (session.get("uid"),)).fetchone()
    if u and not u["disabled"] and session.get("v") == u["epoch"]:
        now = int(time.time())
        limit = idle_minutes(conn) * 60
        if limit and now - (session.get("t") or now) > limit:
            session.clear()
        else:
            session["t"] = now
            g.user = u
            if request.endpoint.startswith("admin_") and not u["is_admin"]:
                abort(403)
            return None
    if request.path.startswith("/api/"):
        return jsonify(error="auth"), 401
    return redirect(url_for("login"))


def log_in(u):
    session.clear()
    session.permanent = True
    session["uid"] = u["id"]
    session["v"] = u["epoch"]
    session["t"] = int(time.time())


@app.route("/setup", methods=["GET", "POST"])
def setup():
    conn = db()
    if conn.execute("SELECT 1 FROM users").fetchone():
        return redirect(url_for("login"))
    err = None
    if request.method == "POST":
        name = clean_username(request.form.get("username"))
        pw = request.form.get("password", "")
        err = "Enter a username." if not name else password_problem(pw, request.form.get("confirm", ""))
        if not err and "@" in name:
            err = "Usernames can't contain @."
        if not err:
            conn.execute(
                "INSERT INTO users (username, pw_hash, is_admin, epoch) VALUES (?, ?, 1, ?)",
                (name, generate_password_hash(pw), new_epoch()),
            )
            conn.commit()
            log_in(user_by_name(name))
            return redirect(url_for("index"))
    return render_template_string(AUTH, mode="setup", title="Create the admin account", err=err,
                                  msg=None, nonce=g.csp_nonce)


@app.route("/login", methods=["GET", "POST"])
def login():
    if not db().execute("SELECT 1 FROM users").fetchone():
        return redirect(url_for("setup"))
    err = None
    if request.method == "POST":
        ip = request.remote_addr or "?"
        u = user_by_login(request.form.get("username"))
        pw = request.form.get("password", "")
        if locked_out(ip):
            err = "Too many attempts. Try again in a few minutes."
        elif u and check_password_hash(u["pw_hash"], pw):
            if u["disabled"]:
                err = "This account is disabled. Ask an admin to turn it back on."
            else:
                FAILS.pop(ip, None)
                log_in(u)
                return redirect(url_for("index"))
        else:
            if not u:
                if not _dummy_hash:
                    _dummy_hash.append(generate_password_hash(secrets.token_hex(8)))
                check_password_hash(_dummy_hash[0], pw)
            FAILS.setdefault(ip, []).append(time.time())
            time.sleep(1)
            err = "Wrong username or password."
    return render_template_string(
        AUTH, mode="login", title="Sign in", err=err,
        username=request.form.get("username", ""), can_reset=smtp_ready(), nonce=g.csp_nonce,
    )


@app.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("login"))


SMTP_KEYS = ("smtp_host", "smtp_port", "smtp_security", "smtp_user", "smtp_password", "smtp_from")
SMTP_SECURITY = [("starttls", "STARTTLS (usually port 587)"), ("ssl", "SSL/TLS (usually port 465)"),
                 ("none", "None (local relay only)")]


def smtp_conf():
    conf = {k: get_setting(db(), k) or "" for k in SMTP_KEYS}
    conf["smtp_security"] = conf["smtp_security"] or "starttls"
    return conf


def smtp_ready(conf=None):
    conf = conf or smtp_conf()
    return bool(conf["smtp_host"] and conf["smtp_from"])


def send_mail(to, subject, body, conf=None):
    """Send a plain-text email with the app's SMTP settings. Raises on any failure."""
    conf = conf or smtp_conf()
    msg = EmailMessage()
    msg["From"], msg["To"], msg["Subject"] = conf["smtp_from"], to, subject
    msg.set_content(body)
    tls = conf["smtp_security"]
    port = int(conf["smtp_port"] or (465 if tls == "ssl" else 587))
    ctx = ssl.create_default_context()
    if tls == "ssl":
        server = smtplib.SMTP_SSL(conf["smtp_host"], port, context=ctx, timeout=15)
    else:
        server = smtplib.SMTP(conf["smtp_host"], port, timeout=15)
    with server:
        if tls == "starttls":
            server.starttls(context=ctx)
        if conf["smtp_user"]:
            server.login(conf["smtp_user"], conf["smtp_password"])
        server.send_message(msg)


def clean_email(raw):
    e = str(raw or "").strip()[:254]
    return e if not e or ("@" in e and " " not in e and "\n" not in e) else None


def settings_page(err=None, msg=None):
    conf = smtp_conf()
    conf["has_password"] = bool(conf.pop("smtp_password"))
    return render_template_string(
        AUTH, mode="settings", title="Settings", err=err, msg=msg, me=g.user, nonce=g.csp_nonce,
        idle=idle_minutes(db()), opts=IDLE_OPTIONS, smtp=conf, smtp_ok=smtp_ready(), security=SMTP_SECURITY,
    )


@app.route("/account")
def account_redirect():
    return redirect(url_for("settings"))


@app.route("/settings", methods=["GET", "POST"])
def settings():
    err = msg = None
    if request.method == "POST":
        current = request.form.get("current", "")
        new = request.form.get("new", "")
        if not check_password_hash(g.user["pw_hash"], current):
            err = "Current password is wrong."
        else:
            err = password_problem(new, request.form.get("confirm", ""))
        if not err:
            session["v"] = set_user_password(uid(), new)
            msg = "Password changed. Your other devices were signed out."
    return settings_page(err, msg)


@app.post("/settings/email")
def settings_email():
    email = clean_email(request.form.get("email"))
    if email is None:
        return settings_page(err="That doesn't look like an email address.")
    if email_taken(email, uid()):
        return settings_page(err="Another account already uses that email.")
    db().execute("UPDATE users SET email = ? WHERE id = ?", (email, uid()))
    db().commit()
    g.user = db().execute("SELECT * FROM users WHERE id = ?", (uid(),)).fetchone()
    return settings_page(msg="Email saved." if email else "Email removed. You won't be able to reset your password by email.")


@app.post("/settings/idle")
def admin_idle():
    try:
        v = int(request.form.get("idle", ""))
    except ValueError:
        v = -1
    if v not in dict(IDLE_OPTIONS):
        return settings_page(err="Pick one of the listed options.")
    set_setting(db(), "idle_minutes", str(v))
    return settings_page(msg="Auto sign-out updated.")


@app.post("/settings/smtp")
def admin_smtp():
    f = request.form
    conn = db()
    if f.get("smtp_security") not in dict(SMTP_SECURITY):
        return settings_page(err="Pick one of the listed security options.")
    port = f.get("smtp_port", "").strip()
    if port and not (port.isdigit() and 0 < int(port) < 65536):
        return settings_page(err="The port must be a number like 587.")
    if f.get("smtp_from", "").strip() and not clean_email(f.get("smtp_from")):
        return settings_page(err="The sender must be an email address.")
    for k in ("smtp_host", "smtp_security", "smtp_user", "smtp_from"):
        set_setting(conn, k, f.get(k, "").strip())
    set_setting(conn, "smtp_port", port)
    if f.get("clear_password") == "1":
        set_setting(conn, "smtp_password", "")
    elif f.get("smtp_password"):
        set_setting(conn, "smtp_password", f.get("smtp_password"))
    return settings_page(msg="Email settings saved. Send a test email to check them.")


@app.post("/settings/smtp/test")
def admin_smtp_test():
    if not g.user["email"]:
        return settings_page(err="Add your own email address above first; the test goes there.")
    if not smtp_ready():
        return settings_page(err="Fill in at least the server and the sender address.")
    try:
        send_mail(g.user["email"], "Invoices test email",
                  "Email from Invoices works. Password resets by email are on.\n")
    except Exception as e:
        return settings_page(err=f"Sending failed: {type(e).__name__}: {e}")
    return settings_page(msg=f"Test email sent to {g.user['email']}.")


def code_hash(code):
    return hashlib.sha256((app.secret_key + code).encode()).hexdigest()


@app.route("/forgot", methods=["GET", "POST"])
def forgot():
    if not smtp_ready():
        return redirect(url_for("login"))
    if request.method == "POST":
        ip = request.remote_addr or "?"
        if locked_out(ip):
            return render_template_string(AUTH, mode="forgot", title="Reset your password",
                                          err="Too many attempts. Try again in a few minutes.",
                                          nonce=g.csp_nonce)
        name = str(request.form.get("username", "")).strip()[:254]
        u = user_by_login(name)
        now = int(time.time())
        pending = u and db().execute(
            "SELECT created FROM reset_codes WHERE user_id = ?", (u["id"],)).fetchone()
        if u and u["email"] and not u["disabled"] and not (pending and now - pending["created"] < 60):
            code = f"{secrets.randbelow(10 ** 6):06d}"
            db().execute(
                "INSERT OR REPLACE INTO reset_codes (user_id, code_hash, created, tries) VALUES (?, ?, ?, 0)",
                (u["id"], code_hash(code), now),
            )
            db().commit()
            try:
                send_mail(u["email"], f"Your Invoices reset code: {code}",
                          f"Hi {u['username']},\n\nYour code to reset your Invoices password is:\n\n    {code}\n\n"
                          f"It works for {RESET_TTL // 60} minutes. If you didn't ask for it, ignore this email; "
                          "your password stays the same.\n")
            except Exception:
                app.logger.exception("could not send the reset email")
        session["reset_name"] = name
        return redirect(url_for("reset"))
    return render_template_string(AUTH, mode="forgot", title="Reset your password", err=None,
                                  nonce=g.csp_nonce)


@app.route("/reset", methods=["GET", "POST"])
def reset():
    name = session.get("reset_name")
    if not name:
        return redirect(url_for("forgot"))
    err = None
    if request.method == "POST":
        ip = request.remote_addr or "?"
        u = user_by_login(name)
        row = u and db().execute("SELECT * FROM reset_codes WHERE user_id = ?", (u["id"],)).fetchone()
        code = "".join(request.form.get("code", "").split())
        pw = request.form.get("password", "")
        if locked_out(ip):
            err = "Too many attempts. Try again in a few minutes."
        elif row and (time.time() - row["created"] > RESET_TTL or row["tries"] >= RESET_TRIES):
            db().execute("DELETE FROM reset_codes WHERE user_id = ?", (u["id"],))
            db().commit()
            err = "That code has expired. Ask for a new one."
        elif not row or not hmac.compare_digest(code_hash(code), row["code_hash"]):
            if row:
                db().execute("UPDATE reset_codes SET tries = tries + 1 WHERE user_id = ?", (u["id"],))
                db().commit()
            FAILS.setdefault(ip, []).append(time.time())
            time.sleep(1)
            err = "That code isn't right. Check the latest email and try again."
        elif u["disabled"]:
            err = "This account is disabled. Ask an admin to turn it back on."
        else:
            err = password_problem(pw, request.form.get("confirm", ""))
            if not err:
                db().execute("DELETE FROM reset_codes WHERE user_id = ?", (u["id"],))
                set_user_password(u["id"], pw)
                session.pop("reset_name", None)
                log_in(user_by_login(name))
                return redirect(url_for("index"))
    return render_template_string(AUTH, mode="reset", title="Enter your code", err=err,
                                  reset_name=name, nonce=g.csp_nonce)


# ---------- user administration (admins only; gate() checks the admin_ prefix) ----------

def users_page(err=None, msg=None):
    rows = db().execute(
        "SELECT id, username, email, is_admin, disabled FROM users ORDER BY username COLLATE NOCASE"
    ).fetchall()
    return render_template_string(AUTH, mode="users", title="Users", err=err, msg=msg,
                                  me=g.user, users=[dict(r) for r in rows], nonce=g.csp_nonce)


def target_user(user_id):
    u = db().execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
    if not u:
        abort(404)
    return u


def last_admin(u):
    """True when u is the only enabled admin, so demoting or disabling them would lock everyone out."""
    if not u["is_admin"] or u["disabled"]:
        return False
    return db().execute("SELECT COUNT(*) FROM users WHERE is_admin = 1 AND disabled = 0").fetchone()[0] <= 1


@app.get("/admin/users")
def admin_users():
    return users_page()


@app.post("/admin/users")
def admin_user_new():
    name = clean_username(request.form.get("username"))
    pw = request.form.get("password", "")
    email = clean_email(request.form.get("email"))
    err = "Enter a username." if not name else password_problem(pw)
    if not err and "@" in name:
        err = "Usernames can't contain @. Put the email in the Email field."
    if not err and email is None:
        err = "That doesn't look like an email address."
    elif not err and email_taken(email):
        err = "Another account already uses that email."
    if err:
        return users_page(err=err)
    try:
        db().execute(
            "INSERT INTO users (username, email, pw_hash, is_admin, epoch) VALUES (?, ?, ?, ?, ?)",
            (name, email or "", generate_password_hash(pw), int(request.form.get("admin") == "1"), new_epoch()),
        )
        db().commit()
    except sqlite3.IntegrityError:
        return users_page(err=f"The username {name} is taken.")
    return users_page(msg=f"Added {name}. Share the password with them; they can change it in Settings.")


@app.post("/admin/users/<int:user_id>/role")
def admin_user_role(user_id):
    u = target_user(user_id)
    make = request.form.get("admin") == "1"
    if not make and last_admin(u):
        return users_page(err="Keep at least one admin. Make someone else an admin first.")
    db().execute("UPDATE users SET is_admin = ? WHERE id = ?", (int(make), user_id))
    db().commit()
    return users_page(msg=f"{u['username']} is {'now' if make else 'no longer'} an admin.")


@app.post("/admin/users/<int:user_id>/password")
def admin_user_password(user_id):
    u = target_user(user_id)
    pw = request.form.get("password", "")
    err = password_problem(pw)
    if err:
        return users_page(err=err)
    epoch = set_user_password(user_id, pw)
    db().execute("DELETE FROM reset_codes WHERE user_id = ?", (user_id,))
    db().commit()
    if user_id == uid():
        session["v"] = epoch
    return users_page(msg=f"New password set for {u['username']}. They were signed out everywhere.")


@app.post("/admin/users/<int:user_id>/email")
def admin_user_email(user_id):
    u = target_user(user_id)
    email = clean_email(request.form.get("email"))
    if email is None:
        return users_page(err="That doesn't look like an email address.")
    if email_taken(email, user_id):
        return users_page(err="Another account already uses that email.")
    db().execute("UPDATE users SET email = ? WHERE id = ?", (email, user_id))
    db().commit()
    return users_page(msg=f"Email for {u['username']} {'saved' if email else 'removed'}.")


@app.post("/admin/users/<int:user_id>/disable")
def admin_user_disable(user_id):
    u = target_user(user_id)
    if user_id == uid():
        return users_page(err="You can't disable your own account.")
    if not u["disabled"] and last_admin(u):
        return users_page(err="Keep at least one admin. Make someone else an admin first.")
    db().execute("UPDATE users SET disabled = ?, epoch = ? WHERE id = ?",
                 (int(not u["disabled"]), new_epoch(), user_id))
    db().execute("DELETE FROM reset_codes WHERE user_id = ?", (user_id,))
    db().commit()
    return users_page(msg=f"{u['username']} is {'enabled again' if u['disabled'] else 'disabled and signed out'}.")


@app.post("/admin/users/<int:user_id>/delete")
def admin_user_delete(user_id):
    u = target_user(user_id)
    if user_id == uid():
        return users_page(err="You can't delete your own account.")
    if last_admin(u):
        return users_page(err="Keep at least one admin. Make someone else an admin first.")
    db().execute("DELETE FROM reset_codes WHERE user_id = ?", (user_id,))
    db().execute("DELETE FROM users WHERE id = ?", (user_id,))
    db().commit()
    return users_page(msg=f"Deleted {u['username']}.")


@app.post("/api/ping")
def ping():
    return jsonify(ok=True)


# ======================================================================
# helpers: numbers, dates, money
# ======================================================================

MONTHS = {
    "en": ["January", "February", "March", "April", "May", "June", "July",
           "August", "September", "October", "November", "December"],
    "fr": ["janvier", "février", "mars", "avril", "mai", "juin", "juillet",
           "août", "septembre", "octobre", "novembre", "décembre"],
}


def D(x):
    try:
        v = Decimal(str(x).strip().replace(",", ".").replace(" ", ""))
        return v if v.is_finite() else None
    except (InvalidOperation, AttributeError):
        return None


def qty_str(x):
    s = format(x.normalize(), "f")
    return s if s else "0"


def rate_str(x):
    s = format(x.normalize(), "f")
    if "." not in s:
        return s + ".00"
    a, b = s.split(".")
    return a + "." + b.ljust(2, "0")


def line_cents(qty, rate):
    return int((Decimal(qty) * Decimal(rate) * 100).quantize(Decimal("1"), ROUND_HALF_UP))


def fmt_money(cents, lang):
    sign = "-" if cents < 0 else ""
    s = f"{Decimal(abs(cents)) / 100:,.2f}"
    if lang == "fr":
        return sign + s.replace(",", " ").replace(".", ",") + " $"
    return sign + "$" + s


def fmt_qty(q, lang):
    return q.replace(".", ",") if lang == "fr" else q


def fmt_date(iso, lang):
    d = date.fromisoformat(iso)
    month = MONTHS[lang][d.month - 1]
    if lang == "fr":
        return f"{'1er' if d.day == 1 else d.day} {month} {d.year}"
    return f"{month} {d.day}, {d.year}"


def parse_day(v):
    try:
        return date.fromisoformat(str(v)[:10]).isoformat()
    except ValueError:
        return None


def next_number(conn, year):
    best = 0
    for (n,) in conn.execute("SELECT number FROM invoices WHERE number LIKE ?", (f"{year}-%",)):
        m = re.fullmatch(rf"{year}-(\d+)", n)
        if m:
            best = max(best, int(m.group(1)))
    last = get_profile(conn).get("last_number", "")
    m = re.fullmatch(rf"{year}-(\d+)", last or "")
    if m:
        best = max(best, int(m.group(1)))
    return f"{year}-{best + 1:03d}"


# ======================================================================
# profile (your business details) and payment QR
# ======================================================================

PROFILE_DEFAULTS = {
    "name": "",
    "address": "",
    "phone": "",
    "email": "",
    "interac_email": "",
    "net_days": 30,
    "last_number": "",
    "tax_note_en": "No GST/QST charged — supplier not registered (small supplier).",
    "tax_note_fr": "Aucune TPS/TVQ facturée — fournisseur non inscrit (petit fournisseur).",
}


def get_profile(conn):
    p = dict(PROFILE_DEFAULTS)
    raw = get_setting(conn, "profile")
    if raw:
        try:
            p.update({k: v for k, v in json.loads(raw).items() if k in PROFILE_DEFAULTS})
        except ValueError:
            pass
    return p


def get_qr(conn):
    raw = get_setting(conn, "qr")
    return base64.b64decode(raw) if raw else None


def prepare_qr(raw):
    """Validate a PNG/JPEG and trim white margins; always returns PNG bytes."""
    from PIL import Image, ImageChops

    im = Image.open(io.BytesIO(raw))
    if im.format not in ("PNG", "JPEG"):
        raise ValueError("not png/jpeg")
    im.load()
    im = im.convert("RGB")
    diff = ImageChops.difference(im, Image.new("RGB", im.size, (255, 255, 255)))
    box = diff.convert("L").point(lambda p: 255 if p > 24 else 0).getbbox()
    if box:
        pad = 12
        l, t, r, b = box
        im = im.crop((max(l - pad, 0), max(t - pad, 0), min(r + pad, im.width), min(b + pad, im.height)))
    out = io.BytesIO()
    im.save(out, "PNG", optimize=True)
    return out.getvalue()


@app.get("/api/profile")
def profile_get():
    p = get_profile(db())
    p["has_qr"] = get_setting(db(), "qr") is not None
    return jsonify(p)


@app.put("/api/profile")
def profile_put():
    d = request.get_json(silent=True) or {}
    p = get_profile(db())
    for k in ("name", "phone", "email", "interac_email", "last_number"):
        if k in d:
            p[k] = " ".join(str(d[k]).split())[:120]
    for k in ("address", "tax_note_en", "tax_note_fr"):
        if k in d:
            p[k] = "\n".join(l.rstrip() for l in str(d[k]).strip().splitlines())[:400]
    if "net_days" in d:
        try:
            p["net_days"] = min(max(int(d["net_days"]), 0), 365)
        except (TypeError, ValueError):
            return jsonify(error="Payment terms must be a number of days."), 400
    set_setting(db(), "profile", json.dumps(p))
    return jsonify(ok=True)


@app.post("/api/profile/qr")
def qr_upload():
    raw = request.get_data()
    if not raw:
        return jsonify(error="No file received."), 400
    try:
        png = prepare_qr(raw)
    except Exception:
        return jsonify(error="That file isn't a valid PNG or JPEG image."), 400
    set_setting(db(), "qr", base64.b64encode(png).decode())
    return jsonify(ok=True)


@app.delete("/api/profile/qr")
def qr_delete():
    db().execute("DELETE FROM settings WHERE key = 'qr'")
    db().commit()
    return jsonify(ok=True)


@app.get("/qr.png")
def qr_png():
    qr = get_qr(db())
    if not qr:
        return Response(status=404)
    return Response(qr, mimetype="image/png", headers={"Cache-Control": "no-store"})


# ======================================================================
# clients
# ======================================================================

def clean_name(raw, n=120):
    return " ".join(str(raw or "").split())[:n]


def clean_block(raw, n=400):
    return "\n".join(l.rstrip() for l in str(raw or "").strip().splitlines())[:n]


def client_row(r):
    return {"id": r["id"], "name": r["name"], "address": r["address"], "lang": r["lang"], "rate": r["rate"]}


def client_fields(d):
    name = clean_name(d.get("name"))
    if not name:
        return None, "Client name is required."
    lang = d.get("lang") if d.get("lang") in ("en", "fr") else "en"
    rate = ""
    if str(d.get("rate", "")).strip():
        r = D(d.get("rate"))
        if r is None or r < 0:
            return None, "Default rate must be a number."
        rate = rate_str(r)
    return (name, clean_block(d.get("address")), lang, rate), None


@app.get("/api/clients")
def clients_list():
    rows = db().execute("SELECT * FROM clients ORDER BY name COLLATE NOCASE").fetchall()
    return jsonify(clients=[client_row(r) for r in rows])


@app.post("/api/clients")
def clients_add():
    f, err = client_fields(request.get_json(silent=True) or {})
    if err:
        return jsonify(error=err), 400
    try:
        cur = db().execute("INSERT INTO clients (name, address, lang, rate) VALUES (?, ?, ?, ?)", f)
        db().commit()
    except sqlite3.IntegrityError:
        return jsonify(error="A client with that name already exists."), 409
    return jsonify(id=cur.lastrowid)


@app.put("/api/clients/<int:cid>")
def clients_update(cid):
    f, err = client_fields(request.get_json(silent=True) or {})
    if err:
        return jsonify(error=err), 400
    try:
        db().execute("UPDATE clients SET name = ?, address = ?, lang = ?, rate = ? WHERE id = ?", f + (cid,))
        db().commit()
    except sqlite3.IntegrityError:
        return jsonify(error="A client with that name already exists."), 409
    return jsonify(ok=True)


@app.delete("/api/clients/<int:cid>")
def clients_delete(cid):
    if db().execute("SELECT 1 FROM invoices WHERE client_id = ?", (cid,)).fetchone():
        return jsonify(error="This client has invoices, so it can't be deleted."), 409
    db().execute("DELETE FROM clients WHERE id = ?", (cid,))
    db().commit()
    return jsonify(ok=True)


# ======================================================================
# saved services (reusable line items)
# ======================================================================

def service_fields(d):
    name = clean_name(d.get("name"), 80)
    if not name:
        return None, "Service name is required."
    rate = ""
    if str(d.get("rate", "")).strip():
        r = D(d.get("rate"))
        if r is None or r < 0:
            return None, "Rate must be a number."
        rate = rate_str(r)
    return (name, clean_block(d.get("desc_en"), 600), clean_block(d.get("desc_fr"), 600), rate), None


@app.get("/api/services")
def services_list():
    rows = db().execute("SELECT * FROM services ORDER BY name COLLATE NOCASE").fetchall()
    return jsonify(services=[dict(r) for r in rows])


@app.post("/api/services")
def services_add():
    f, err = service_fields(request.get_json(silent=True) or {})
    if err:
        return jsonify(error=err), 400
    try:
        cur = db().execute("INSERT INTO services (name, desc_en, desc_fr, rate) VALUES (?, ?, ?, ?)", f)
        db().commit()
    except sqlite3.IntegrityError:
        return jsonify(error="A service with that name already exists."), 409
    return jsonify(id=cur.lastrowid)


@app.put("/api/services/<int:sid>")
def services_update(sid):
    f, err = service_fields(request.get_json(silent=True) or {})
    if err:
        return jsonify(error=err), 400
    try:
        db().execute("UPDATE services SET name = ?, desc_en = ?, desc_fr = ?, rate = ? WHERE id = ?", f + (sid,))
        db().commit()
    except sqlite3.IntegrityError:
        return jsonify(error="A service with that name already exists."), 409
    return jsonify(ok=True)


@app.delete("/api/services/<int:sid>")
def services_delete(sid):
    db().execute("DELETE FROM services WHERE id = ?", (sid,))  # invoices keep their own copy of each line
    db().commit()
    return jsonify(ok=True)


# ======================================================================
# invoices
# ======================================================================

def clean_invoice(d, seller):
    """Validate an invoice payload. Returns (data, total_cents, error)."""
    lang = d.get("lang") if d.get("lang") in ("en", "fr") else "en"
    number = clean_name(d.get("number"), 30)
    issue = parse_day(d.get("issue_date"))
    due = parse_day(d.get("due_date"))
    if not number or not issue or not due:
        return None, 0, "Invoice number and both dates are required."
    client = d.get("client") or {}
    cname = clean_name(client.get("name"))
    if not cname:
        return None, 0, "Client name is required."
    lines = []
    for ln in (d.get("lines") or [])[:60]:
        desc = str(ln.get("desc", "")).strip()[:600]
        qty, rate = D(ln.get("qty")), D(ln.get("rate"))
        if not desc and qty is None and rate is None:
            continue  # untouched blank row
        if not desc or qty is None or rate is None or qty <= 0:
            return None, 0, "Each line needs a description, a positive quantity and a rate."
        lines.append({"desc": desc, "qty": qty_str(qty), "rate": rate_str(rate)})
    if not lines:
        return None, 0, "Add at least one line item."
    total = sum(line_cents(l["qty"], l["rate"]) for l in lines)
    data = {
        "lang": lang,
        "number": number,
        "issue_date": issue,
        "due_date": due,
        "unit": "qty" if d.get("unit") == "qty" else "hours",
        "currency": "CAD",
        "reference": clean_name(d.get("reference"), 200),
        "notes": clean_block(d.get("notes"), 1000),
        "client": {"name": cname, "address": clean_block(client.get("address"))},
        "lines": lines,
        "seller": seller,
    }
    return data, total, None


def seller_snapshot(conn):
    p = get_profile(conn)
    p.pop("net_days", None)
    p.pop("last_number", None)
    return p


def resolve_client(conn, d, data):
    try:
        cid = int(d.get("client_id")) if d.get("client_id") not in (None, "") else None
    except (TypeError, ValueError):
        cid = None
    if cid and not conn.execute("SELECT 1 FROM clients WHERE id = ?", (cid,)).fetchone():
        cid = None
    if cid is None and d.get("save_client"):
        row = conn.execute("SELECT id FROM clients WHERE name = ?", (data["client"]["name"],)).fetchone()
        if row:
            cid = row[0]
        else:
            rate = data["lines"][0]["rate"]
            cid = conn.execute(
                "INSERT INTO clients (name, address, lang, rate) VALUES (?, ?, ?, ?)",
                (data["client"]["name"], data["client"]["address"], data["lang"], rate),
            ).lastrowid
    return cid


def invoice_row(r, full=False):
    data = json.loads(r["data"])
    out = {
        "id": r["id"], "number": r["number"], "client_id": r["client_id"],
        "issue_date": r["issue_date"], "due_date": r["due_date"], "status": r["status"],
        "paid_date": r["paid_date"], "total_cents": r["total_cents"],
        "client": data["client"]["name"], "lang": data["lang"],
    }
    if full:
        out["data"] = data
    return out


@app.get("/api/next-number")
def api_next_number():
    year = request.args.get("year", type=int) or date.today().year
    return jsonify(number=next_number(db(), year))


@app.get("/api/invoices")
def invoices_list():
    rows = db().execute("SELECT * FROM invoices ORDER BY issue_date DESC, id DESC").fetchall()
    return jsonify(invoices=[invoice_row(r) for r in rows])


@app.get("/api/invoices/<int:iid>")
def invoices_get(iid):
    r = db().execute("SELECT * FROM invoices WHERE id = ?", (iid,)).fetchone()
    if not r:
        return jsonify(error="not found"), 404
    return jsonify(invoice_row(r, full=True))


@app.post("/api/invoices")
def invoices_create():
    d = request.get_json(silent=True) or {}
    conn = db()
    data, total, err = clean_invoice(d, seller_snapshot(conn))
    if err:
        return jsonify(error=err), 400
    cid = resolve_client(conn, d, data)
    try:
        cur = conn.execute(
            "INSERT INTO invoices (number, client_id, issue_date, due_date, total_cents, data) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            (data["number"], cid, data["issue_date"], data["due_date"], total, json.dumps(data)),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify(error="That invoice number already exists."), 409
    return jsonify(id=cur.lastrowid, client_id=cid)


@app.put("/api/invoices/<int:iid>")
def invoices_update(iid):
    conn = db()
    old = conn.execute("SELECT * FROM invoices WHERE id = ?", (iid,)).fetchone()
    if not old:
        return jsonify(error="not found"), 404
    d = request.get_json(silent=True) or {}
    data, total, err = clean_invoice(d, json.loads(old["data"])["seller"])  # keep the original seller details
    if err:
        return jsonify(error=err), 400
    cid = resolve_client(conn, d, data)
    try:
        conn.execute(
            "UPDATE invoices SET number = ?, client_id = ?, issue_date = ?, due_date = ?, "
            "total_cents = ?, data = ? WHERE id = ?",
            (data["number"], cid, data["issue_date"], data["due_date"], total, json.dumps(data), iid),
        )
        conn.commit()
    except sqlite3.IntegrityError:
        return jsonify(error="That invoice number already exists."), 409
    return jsonify(id=iid, client_id=cid)


@app.post("/api/invoices/<int:iid>/status")
def invoices_status(iid):
    d = request.get_json(silent=True) or {}
    status = d.get("status")
    if status not in ("unpaid", "paid", "void"):
        return jsonify(error="bad status"), 400
    paid = (parse_day(d.get("paid_date")) or date.today().isoformat()) if status == "paid" else None
    db().execute("UPDATE invoices SET status = ?, paid_date = ? WHERE id = ?", (status, paid, iid))
    db().commit()
    return jsonify(ok=True)


# ======================================================================
# PDF
# ======================================================================

ACCENT = colors.HexColor("#1a3a5c")
GREY = colors.HexColor("#666666")
LIGHT = colors.HexColor("#f2f5f8")
RULE = colors.HexColor("#cccccc")

TXT = {
    "en": dict(title="INVOICE", no="Invoice No.", date="Date", due="Due", colon=": ",
               frm="FROM", to="BILL TO", re="Re: ", desc="Description", hours="Hours", qty="Qty",
               rate="Rate", amount="Amount", sub="Subtotal", total="Total Due (CAD)",
               terms="PAYMENT TERMS", notes="NOTES",
               net="Payment due within {n} days (Net {n}).", now="Payment due upon receipt.",
               interac="Payable by <b>Interac e-Transfer</b> to: <b>{e}</b>",
               paypal="Or pay with PayPal: scan the QR code.",
               thanks="Thank you for your business.", file="Invoice"),
    "fr": dict(title="FACTURE", no="Facture no", date="Date", due="Échéance", colon=" : ",
               frm="DE", to="FACTURER À", re="Objet : ", desc="Description", hours="Heures", qty="Qté",
               rate="Taux", amount="Montant", sub="Sous-total", total="Total dû (CAD)",
               terms="CONDITIONS DE PAIEMENT", notes="NOTES",
               net="Paiement exigible sous {n} jours (net {n}).", now="Paiement exigible à la réception.",
               interac="Payable par <b>virement Interac</b> à : <b>{e}</b>",
               paypal="Ou payez par PayPal : scannez le code QR.",
               thanks="Merci pour votre confiance.", file="Facture"),
}


def esc(text):
    return escape(str(text)).replace("\n", "<br/>")


def build_pdf(data, qr=None):
    lang = data["lang"]
    T = TXT[lang]
    seller = data["seller"]
    buf = io.BytesIO()
    doc = SimpleDocTemplate(
        buf, pagesize=letter,
        leftMargin=0.9 * inch, rightMargin=0.9 * inch, topMargin=0.8 * inch, bottomMargin=0.8 * inch,
        title=f"{T['file']} {data['number']}", author=seller.get("name") or "",
    )
    S = {
        "title": ParagraphStyle("title", fontName="Helvetica-Bold", fontSize=26, textColor=ACCENT, spaceAfter=2),
        "normal": ParagraphStyle("normal", fontName="Helvetica", fontSize=9.5, leading=13, textColor=colors.black),
        "grey": ParagraphStyle("grey", fontName="Helvetica", fontSize=9.5, leading=13, textColor=GREY),
        "label": ParagraphStyle("label", fontName="Helvetica-Bold", fontSize=9, textColor=ACCENT, spaceAfter=3),
        "right": ParagraphStyle("right", fontName="Helvetica", fontSize=9.5, leading=13, alignment=2, textColor=GREY),
        "num": ParagraphStyle("num", fontName="Helvetica", fontSize=9.5, leading=13, alignment=2),
        "head": ParagraphStyle("head", fontName="Helvetica-Bold", fontSize=9, textColor=colors.white),
        "headr": ParagraphStyle("headr", fontName="Helvetica-Bold", fontSize=9, textColor=colors.white, alignment=2),
        "cap": ParagraphStyle("cap", fontName="Helvetica", fontSize=8, textColor=GREY, alignment=1),
    }
    story = []
    W = doc.width - 12  # the page frame pads 6pt per side; sizing tables to it keeps every left edge aligned

    def cols(*parts):
        total = sum(parts)
        return [W * p / total for p in parts]

    # header
    meta = (f"{T['no']}{T['colon']}<b>{esc(data['number'])}</b><br/>"
            f"{T['date']}{T['colon']}<b>{fmt_date(data['issue_date'], lang)}</b><br/>"
            f"{T['due']}{T['colon']}<b>{fmt_date(data['due_date'], lang)}</b>")
    header = Table([[Paragraph(T["title"], S["title"]), Paragraph(meta, S["right"])]], colWidths=cols(3.4, 3.3))
    header.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                                ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0)]))
    story += [header, Spacer(1, 6), HRFlowable(width="100%", thickness=2, color=ACCENT), Spacer(1, 18)]

    # from / bill to
    from_lines = [f"<b>{esc(seller.get('name', ''))}</b>"] if seller.get("name") else []
    for key in ("address", "phone", "email"):
        if seller.get(key):
            from_lines.append(esc(seller[key]))
    to_lines = [f"<b>{esc(data['client']['name'])}</b>"]
    if data["client"]["address"]:
        to_lines.append(esc(data["client"]["address"]))
    parties = Table(
        [[[Paragraph(T["frm"], S["label"]), Paragraph("<br/>".join(from_lines) or "&nbsp;", S["normal"])],
          [Paragraph(T["to"], S["label"]), Paragraph("<br/>".join(to_lines), S["normal"])]]],
        colWidths=cols(3.4, 3.3))
    parties.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                                 ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0)]))
    story.append(parties)
    story.append(Spacer(1, 14))
    if data["reference"]:
        story += [Paragraph(f"<b>{T['re']}</b>{esc(data['reference'])}", S["normal"]), Spacer(1, 10)]
    else:
        story.append(Spacer(1, 4))

    # line items
    unit_head = T["hours"] if data["unit"] == "hours" else T["qty"]
    rows = [[Paragraph(T["desc"], S["head"]), Paragraph(unit_head, S["headr"]),
             Paragraph(T["rate"], S["headr"]), Paragraph(T["amount"], S["headr"])]]
    subtotal = 0
    for ln in data["lines"]:
        cents = line_cents(ln["qty"], ln["rate"])
        subtotal += cents
        rows.append([Paragraph(esc(ln["desc"]), S["normal"]),
                     Paragraph(fmt_qty(ln["qty"], lang), S["num"]),
                     Paragraph(fmt_money(line_cents(ln["rate"], "1"), lang), S["num"]),
                     Paragraph(fmt_money(cents, lang), S["num"])])
    items = Table(rows, colWidths=cols(3.5, 0.9, 1.0, 1.3), repeatRows=1)
    items.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), ACCENT),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8), ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("LINEBELOW", (0, 1), (-1, -1), 0.5, RULE),
    ]))
    story.append(items)

    # totals
    totals = Table([["", T["sub"], fmt_money(subtotal, lang)], ["", T["total"], fmt_money(subtotal, lang)]],
                   colWidths=cols(3.7, 1.8, 1.2))
    totals.setStyle(TableStyle([
        ("FONTNAME", (1, 0), (-1, 0), "Helvetica"), ("FONTNAME", (1, 1), (-1, 1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9.5), ("ALIGN", (1, 0), (-1, -1), "RIGHT"),
        ("TOPPADDING", (0, 0), (-1, -1), 6), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("RIGHTPADDING", (0, 0), (-1, -1), 8),
        ("BACKGROUND", (1, 1), (-1, 1), LIGHT), ("TEXTCOLOR", (1, 1), (-1, 1), ACCENT),
        ("LINEABOVE", (1, 0), (-1, 0), 0.5, RULE),
    ]))
    story += [totals, Spacer(1, 24)]

    if data["notes"]:
        story += [Paragraph(T["notes"], S["label"]), Paragraph(esc(data["notes"]), S["normal"]), Spacer(1, 18)]

    # payment terms (+ PayPal QR)
    days = (date.fromisoformat(data["due_date"]) - date.fromisoformat(data["issue_date"])).days
    terms = [T["net"].format(n=days) if days > 0 else T["now"]]
    if seller.get("interac_email"):
        terms.append(T["interac"].format(e=esc(seller["interac_email"])))
    if qr:
        terms.append(T["paypal"])
    term_block = [Paragraph(T["terms"], S["label"]), Paragraph("<br/>".join(terms), S["normal"])]
    if qr:
        w, h = ImageReader(io.BytesIO(qr)).getSize()
        size = 1.15 * inch
        img = RLImage(io.BytesIO(qr), width=size, height=size * h / w)
        img.hAlign = "RIGHT"
        pay = Table([[term_block, [img, Paragraph("PayPal", S["cap"])]]], colWidths=cols(4.9, 1.8))
        pay.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"),
                                 ("LEFTPADDING", (0, 0), (-1, -1), 0), ("RIGHTPADDING", (0, 0), (-1, -1), 0)]))
        story.append(pay)
    else:
        story += term_block

    tax_note = seller.get(f"tax_note_{lang}", "")
    if tax_note:
        story += [Spacer(1, 16), Paragraph(esc(tax_note), S["grey"])]
    story += [Spacer(1, 28), HRFlowable(width="100%", thickness=0.5, color=RULE), Spacer(1, 8),
              Paragraph(T["thanks"], S["grey"])]
    doc.build(story)
    return buf.getvalue()


def pdf_response(data, qr, download=False):
    T = TXT[data["lang"]]
    slug = re.sub(r"[^A-Za-z0-9]+", "_", data["client"]["name"]).strip("_")[:40] or "client"
    name = f"{T['file']}_{data['number']}_{slug}.pdf"
    disp = "attachment" if download else "inline"
    return Response(build_pdf(data, qr), mimetype="application/pdf",
                    headers={"Content-Disposition": f'{disp}; filename="{name}"', "Cache-Control": "no-store"})


@app.get("/invoices/<int:iid>.pdf")
def invoice_pdf(iid):
    r = db().execute("SELECT data FROM invoices WHERE id = ?", (iid,)).fetchone()
    if not r:
        return Response("Not found", status=404)
    return pdf_response(json.loads(r["data"]), get_qr(db()), download=request.args.get("download") == "1")


@app.post("/preview-pdf")
def preview_pdf():
    try:
        d = json.loads(request.form.get("payload", "{}"))
    except ValueError:
        d = {}
    data, _, err = clean_invoice(d, seller_snapshot(db()))
    if err:
        return Response(err, status=400, mimetype="text/plain")
    return pdf_response(data, get_qr(db()))


# ======================================================================
# PWA bits and pages
# ======================================================================

@app.get("/manifest.json")
def manifest():
    return jsonify(name="Invoices", short_name="Invoices", start_url="/", display="standalone",
                   background_color="#0C1322", theme_color="#14213D",
                   icons=[{"src": "/icon.svg", "sizes": "any", "type": "image/svg+xml"}])


@app.get("/icon.svg")
def icon():
    svg = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 100 100">'
           '<rect width="100" height="100" rx="22" fill="#14213D"/>'
           '<path d="M30 20h28l14 14v46H30z" fill="#fff"/>'
           '<path d="M58 20v14h14" fill="#c9d6e4"/>'
           '<path d="M38 50h26M38 60h26M38 70h16" stroke="#14213D" stroke-width="4" stroke-linecap="round"/>'
           '<circle cx="76" cy="82" r="14" fill="#0F7B5F"/>'
           '<text x="76" y="83" text-anchor="middle" dominant-baseline="central" '
           'font-family="system-ui,sans-serif" font-weight="700" font-size="16" fill="#fff">$</text>'
           '</svg>')
    return Response(svg, mimetype="image/svg+xml")


@app.get("/icon-animated.svg")
def icon_animated():
    # Same document mark as /icon.svg, but staged as a short entrance for the login screen:
    # the mark pops in, a status ring draws itself around it, the three content lines write
    # themselves in, and a $ badge pops onto the corner with a little ping.
    # The static /icon.svg stays the plain favicon/PWA icon. Pure SVG/CSS, no JS, so it still
    # plays when loaded via a plain <img> tag.
    svg = ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 140 140">'
           '<style>'
           '.mark{transform-origin:50px 50px;animation:pop .5s cubic-bezier(.2,.8,.2,1) both}'
           '.ring-track{fill:none;stroke:#D5DCE5;stroke-width:6}'
           '.ring-arc{fill:none;stroke:#0F7B5F;stroke-width:6;stroke-linecap:round;'
           'stroke-dasharray:390;stroke-dashoffset:390;transform:rotate(-90deg);transform-origin:70px 70px;'
           'animation:ring .9s cubic-bezier(.2,.8,.2,1) .35s both}'
           '.ln{fill:none;stroke:#14213D;stroke-width:3;stroke-linecap:round;animation:draw .4s ease both}'
           '.ln1,.ln2{stroke-dasharray:19;stroke-dashoffset:19}'
           '.ln3{stroke-dasharray:12;stroke-dashoffset:12}'
           '.ln1{animation-delay:.9s}'
           '.ln2{animation-delay:1.08s}'
           '.ln3{animation-delay:1.26s}'
           '.ping{fill:none;stroke:#0F7B5F;stroke-width:2;opacity:.6;transform-origin:108px 108px;'
           'animation:ping .6s ease-out 1.4s both}'
           '.badge{opacity:0;transform-origin:108px 108px;animation:badge .45s cubic-bezier(.34,1.56,.64,1) 1.35s both}'
           '@keyframes pop{from{opacity:0;transform:scale(.8)}to{opacity:1;transform:scale(1)}}'
           '@keyframes ring{to{stroke-dashoffset:0}}'
           '@keyframes draw{to{stroke-dashoffset:0}}'
           '@keyframes ping{from{transform:scale(1);opacity:.6}to{transform:scale(1.8);opacity:0}}'
           '@keyframes badge{0%{opacity:0;transform:scale(0)}60%{opacity:1;transform:scale(1.15)}100%{opacity:1;transform:scale(1)}}'
           '@media(prefers-reduced-motion:reduce){.mark,.ring-arc,.ln,.badge,.ping{animation:none}'
           '.mark{opacity:1;transform:scale(1)}.ring-arc{stroke-dashoffset:0}.ln{stroke-dashoffset:0}'
           '.badge{opacity:1;transform:scale(1)}.ping{display:none}}'
           '@media(prefers-color-scheme:dark){.ring-track{stroke:#24304A}}'
           '</style>'
           '<g transform="translate(33,33) scale(.74)">'
           '<g class="mark">'
           '<rect width="100" height="100" rx="22" fill="#14213D"/>'
           '<path d="M30 20h28l14 14v46H30z" fill="#fff"/>'
           '<path d="M58 20v14h14" fill="#c9d6e4"/>'
           '<path class="ln ln1" d="M38 50h26"/>'
           '<path class="ln ln2" d="M38 60h26"/>'
           '<path class="ln ln3" d="M38 70h16"/>'
           '</g>'
           '</g>'
           '<circle class="ring-track" cx="70" cy="70" r="62"/>'
           '<circle class="ring-arc" cx="70" cy="70" r="62"/>'
           '<circle class="ping" cx="108" cy="108" r="16"/>'
           '<g class="badge">'
           '<circle cx="108" cy="108" r="16" fill="#0F7B5F"/>'
           '<text x="108" y="109" text-anchor="middle" dominant-baseline="central" '
           'font-family="system-ui,sans-serif" font-weight="700" font-size="17" fill="#fff">$</text>'
           '</g>'
           '</svg>')
    return Response(svg, mimetype="image/svg+xml")


@app.get("/")
def index():
    page = PAGE.replace("__IDLE__", str(idle_minutes(db()))).replace("__NONCE__", g.csp_nonce)
    return Response(page, mimetype="text/html")


AUTH = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#14213D">
<link rel="manifest" href="/manifest.json">
<link rel="icon" href="/icon.svg">
<title>{{ title }} - Invoices</title>
<style nonce="{{ nonce }}">
:root{--bg:#E9EDF2;--surf:#fff;--soft:#F3F5F8;--ink:#14213D;--mut:#5B6577;--line:#D5DCE5;
--amber:#E9A100;--earn:#0F7B5F;--use:#B4234A;--onsem:#fff;--btn:#14213D;--btnfg:#fff;--focus:#2F4BD8;
--r-lg:22px;--r-sm:12px;
--round:ui-rounded,"SF Pro Rounded","Nunito","Varela Round",system-ui,sans-serif;
--sans:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color-scheme:light}
@media(prefers-color-scheme:dark){:root{--bg:#0C1322;--surf:#141E33;--soft:#1A2640;--ink:#E7ECF4;--mut:#8E9AB0;
--line:#24304A;--amber:#FFC233;--earn:#3DD6A3;--use:#FF6B8B;--onsem:#0C1322;--btn:#FFC233;--btnfg:#14213D;
--focus:#FFC233;color-scheme:dark}}
*{box-sizing:border-box}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.45 var(--sans);-webkit-font-smoothing:antialiased}
button,input,select{font:inherit;color:inherit}
:focus-visible{outline:2px solid var(--focus);outline-offset:2px}

.field{display:block;margin-bottom:12px}
.field>span{display:block;font-size:.82rem;color:var(--mut);margin:0 0 5px 2px}
input,select{width:100%;min-height:48px;padding:11px 14px;border:1px solid var(--line);border-radius:var(--r-sm);background:var(--soft);-webkit-appearance:none;appearance:none}
select{padding-right:38px;background-image:url("data:image/svg+xml,%3Csvg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 24 24' fill='none' stroke='%238E9AB0' stroke-width='2.5' stroke-linecap='round'%3E%3Cpath d='m6 9 6 6 6-6'/%3E%3C/svg%3E");
background-repeat:no-repeat;background-position:right 12px center;background-size:18px}
input:focus,select:focus{outline:none;border-color:var(--focus);background-color:var(--surf)}
.btn{display:flex;align-items:center;justify-content:center;gap:8px;width:100%;min-height:48px;padding:12px 16px;
border:0;border-radius:var(--r-sm);background:var(--btn);color:var(--btnfg);font-weight:650;cursor:pointer;margin-top:2px;text-decoration:none}
.btn:hover{filter:brightness(1.12)}
.btn.ghost{background:transparent;color:var(--ink);border:1px solid var(--line)}
.btn.danger{background:var(--use);color:var(--onsem)}
.link{background:none;border:0;padding:6px 0;color:var(--mut);cursor:pointer;font-size:.9rem;
text-decoration:underline;text-decoration-color:var(--line);text-underline-offset:3px}
.link:hover{color:var(--ink)}
.msg{border-radius:var(--r-sm);padding:10px 14px;margin:0 0 14px;font-size:.92rem}
.msg.err{color:var(--use);background:rgba(180,35,74,.1)}
.msg.ok{color:var(--earn);background:rgba(15,123,95,.1)}
.panel{background:var(--surf);border-radius:var(--r-lg);padding:20px}
.hint{color:var(--mut);font-size:.9rem;margin:0 0 16px}
.tag{display:inline-block;padding:2px 9px;border-radius:999px;background:var(--soft);color:var(--mut);font-size:.75rem;vertical-align:2px}
.tag.on{background:rgba(233,161,0,.24);color:var(--ink)}
.check{display:flex;align-items:center;gap:10px;margin:2px 0 14px;cursor:pointer;color:var(--mut)}
input[type=checkbox]{appearance:auto;width:20px;height:20px;min-height:0;padding:0;margin:0;accent-color:var(--amber);flex:none}
.support{color:var(--mut);font-size:.82rem;text-align:center;margin:22px 0 0}
.support a{color:var(--mut);text-decoration:underline;text-decoration-color:var(--line)}
.support a:hover{color:var(--ink)}

/* sign-in / setup */
body.auth{min-height:100vh;min-height:100dvh;display:grid;place-items:center;padding:28px 16px}
.authbox{width:100%;max-width:360px;text-align:center}
.authbox img.mark{width:84px;height:84px;margin:0 auto 14px;display:block}
.authbox h1{font:700 2rem/1.1 var(--round);letter-spacing:-.01em;margin:0}
.authbox .sub{color:var(--mut);margin:6px 0 24px}
.authbox .sub b{color:var(--ink)}
.authform{text-align:left;background:var(--surf);border-radius:var(--r-lg);padding:20px}
.authlinks{display:flex;justify-content:space-between;gap:12px;margin:-4px 0 12px}
.authlinks .link{margin:0}

/* settings / users */
.wrap{max-width:520px;margin:0 auto;padding:0 16px 36px}
.back{display:inline-flex;align-items:center;gap:4px;padding:16px 0 4px;color:var(--mut);text-decoration:none}
.back:hover{color:var(--ink)}
.back svg{width:18px;height:18px}
.pagetitle{font:700 2rem/1.15 var(--round);letter-spacing:-.01em;margin:6px 0 18px}
.set{margin-bottom:14px}
.set h2{font:650 1.12rem/1.3 var(--round);margin:0 0 2px}
.whoami{color:var(--mut);margin:-10px 0 18px}
.group{font:650 .95rem var(--round);color:var(--mut);margin:28px 4px 10px}
.signout{margin-top:22px}
.ulist{padding:4px 20px}
.urow{padding:16px 0;border-top:1px solid var(--line)}
.urow:first-child{border-top:0}
.uname{font-weight:650;font-size:1.05rem}
.ucount{color:var(--mut);font-size:.85rem;margin:2px 0 10px}
.uact{display:flex;flex-wrap:wrap;align-items:center;gap:6px 20px}
.uact .check{margin:0}
.uact details[open]{flex-basis:100%}
.uact details .inline{margin-top:8px}
summary.link{list-style:none;display:inline-block}
summary.link::-webkit-details-marker{display:none}
.confirm{color:var(--mut);font-size:.88rem;margin:8px 0 10px}
.inline{display:flex;gap:10px}
.inline input,.inline select{flex:1;min-width:0}
.inline .btn{width:auto;flex:none}
</style></head>
{% if mode in ('settings', 'users') %}
<body>
<main class="wrap">
{% if mode == 'settings' %}
<a class="back" href="/"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="m15 6-6 6 6 6"/></svg>Invoices</a>
<h1 class="pagetitle">Settings</h1>
<p class="whoami">Signed in as <b>{{ me.username }}</b>{% if me.is_admin %} <span class="tag on">Admin</span>{% endif %}</p>
{% else %}
<a class="back" href="/settings"><svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round"><path d="m15 6-6 6 6 6"/></svg>Settings</a>
<h1 class="pagetitle">Users</h1>
{% endif %}
{% if err %}<p class="msg err" role="alert">{{ err }}</p>{% endif %}
{% if msg %}<p class="msg ok" role="status">{{ msg }}</p>{% endif %}

{% if mode == 'settings' %}
<section class="panel set">
<h2>Password</h2>
<form method="post" action="/settings">
<label class="field"><span>Current password</span><input type="password" name="current" autocomplete="current-password" required></label>
<label class="field"><span>New password (8 characters or more)</span><input type="password" name="new" autocomplete="new-password" minlength="8" required></label>
<label class="field"><span>Confirm new password</span><input type="password" name="confirm" autocomplete="new-password" minlength="8" required></label>
<button type="submit" class="btn">Change password</button>
</form>
</section>
<section class="panel set">
<h2>Email</h2>
<p class="hint">{% if smtp_ok %}Where your password reset codes go.{% else %}Where reset codes will go once an admin sets up email.{% endif %}</p>
<form method="post" action="/settings/email" class="inline">
<input type="email" name="email" value="{{ me.email }}" placeholder="you@example.com" autocomplete="email">
<button type="submit" class="btn ghost">Save</button>
</form>
</section>
{% if me.is_admin %}
<h2 class="group">For everyone</h2>
<section class="panel set">
<h2>Users</h2>
<p class="hint">Add people, reset passwords, and choose who is an admin.</p>
<a class="btn ghost" href="/admin/users">Manage users</a>
</section>
<section class="panel set">
<h2>Auto sign-out</h2>
<p class="hint">Sign out automatically after being idle for:</p>
<form method="post" action="/settings/idle" class="inline">
<select name="idle" aria-label="Idle time">{% for v, l in opts %}<option value="{{ v }}"{% if v == idle %} selected{% endif %}>{{ l }}</option>{% endfor %}</select>
<button type="submit" class="btn ghost">Save</button>
</form>
</section>
<section class="panel set">
<h2>Email server</h2>
<p class="hint">{% if smtp_ok %}Resets by email are on.{% else %}Resets by email are off until a server and sender are saved.{% endif %}</p>
<form method="post" action="/settings/smtp">
<label class="field"><span>Server</span><input name="smtp_host" value="{{ smtp.smtp_host }}" placeholder="smtp.example.com" autocomplete="off"></label>
<label class="field"><span>Port</span><input name="smtp_port" value="{{ smtp.smtp_port }}" placeholder="587" inputmode="numeric" autocomplete="off"></label>
<label class="field"><span>Security</span><select name="smtp_security">{% for v, l in security %}<option value="{{ v }}"{% if v == smtp.smtp_security %} selected{% endif %}>{{ l }}</option>{% endfor %}</select></label>
<label class="field"><span>Username</span><input name="smtp_user" value="{{ smtp.smtp_user }}" autocomplete="off"></label>
<label class="field"><span>Password{% if smtp.has_password %} (saved; leave blank to keep it){% endif %}</span><input type="password" name="smtp_password" autocomplete="new-password"></label>
{% if smtp.has_password %}<label class="check"><input type="checkbox" name="clear_password" value="1"> Remove the saved password</label>{% endif %}
<label class="field"><span>Send from</span><input type="email" name="smtp_from" value="{{ smtp.smtp_from }}" placeholder="invoices@example.com"></label>
<button type="submit" class="btn">Save email server</button>
</form>
<form method="post" action="/settings/smtp/test">
<button type="submit" class="btn ghost">Send a test email{% if me.email %} to {{ me.email }}{% endif %}</button>
</form>
</section>
{% endif %}
<form method="post" action="/logout" class="signout"><button type="submit" class="btn ghost">Sign out</button></form>

{% else %}
<section class="panel set">
<h2>Add a user</h2>
<form method="post" action="/admin/users">
<label class="field"><span>Username</span><input name="username" autocomplete="off" required></label>
<label class="field"><span>Email (optional, for resets)</span><input type="email" name="email"></label>
<label class="field"><span>Password (8 characters or more)</span><input type="password" name="password" autocomplete="new-password" minlength="8" required></label>
<label class="check"><input type="checkbox" name="admin" value="1"> Admin: can manage users and app settings</label>
<button type="submit" class="btn">Add user</button>
</form>
</section>
<section class="panel ulist" aria-label="Users">
{% for u in users %}{% set mine = u.id == me.id %}
<div class="urow">
<div class="uname">{{ u.username }}{% if mine %} <span class="tag">You</span>{% endif %}{% if u.disabled %} <span class="tag">Disabled</span>{% endif %}</div>
<div class="ucount">{{ u.email or 'No email' }}</div>
<div class="uact">
<form method="post" action="/admin/users/{{ u.id }}/role">
<label class="check"><input type="checkbox" name="admin" value="1" data-autosubmit{% if u.is_admin %} checked{% endif %}> Admin</label>
<noscript><button type="submit" class="link">Save</button></noscript>
</form>
<details><summary class="link">Reset password</summary>
<form method="post" action="/admin/users/{{ u.id }}/password" class="inline">
<input type="password" name="password" minlength="8" autocomplete="new-password" placeholder="New password" aria-label="New password for {{ u.username }}" required>
<button type="submit" class="btn ghost">Set</button>
</form>
</details>
<details><summary class="link">Email</summary>
<form method="post" action="/admin/users/{{ u.id }}/email" class="inline">
<input type="email" name="email" value="{{ u.email }}" placeholder="name@example.com" aria-label="Email for {{ u.username }}">
<button type="submit" class="btn ghost">Save</button>
</form>
</details>
{% if not mine %}
<form method="post" action="/admin/users/{{ u.id }}/disable"><button type="submit" class="link">{{ 'Enable' if u.disabled else 'Disable' }}</button></form>
<details><summary class="link">Delete</summary>
<form method="post" action="/admin/users/{{ u.id }}/delete">
<p class="confirm">Deletes {{ u.username }}. This cannot be undone.</p>
<button type="submit" class="btn danger">Delete {{ u.username }}</button>
</form>
</details>
{% endif %}
</div>
</div>
{% endfor %}
</section>
{% endif %}
</main>

{% else %}
<body class="auth">
<main class="authbox">
<img class="mark" src="/icon-animated.svg" alt="">
{% if mode == 'login' %}
<h1>Invoices</h1>
<p class="sub">Sign in to your account</p>
{% elif mode == 'setup' %}
<h1>Welcome</h1>
<p class="sub">Create the admin account for this server</p>
{% elif mode == 'forgot' %}
<h1>Forgot your password?</h1>
<p class="sub">We'll email a 6-digit code to the address on your account</p>
{% else %}
<h1>Check your email</h1>
<p class="sub">If <b>{{ reset_name }}</b> has an email address, a 6-digit code is on its way. It works for 10 minutes.</p>
{% endif %}
<form method="post" class="authform">
{% if err %}<p class="msg err" role="alert">{{ err }}</p>{% endif %}
{% if mode == 'login' %}
<label class="field"><span>Username or email</span><input name="username" value="{{ username }}" autocomplete="username" autocapitalize="none" {% if not username %}autofocus {% endif %}required></label>
<label class="field"><span>Password</span><input type="password" name="password" data-pw autocomplete="current-password" {% if username %}autofocus {% endif %}required></label>
<div class="authlinks"><button type="button" class="link showpw">Show password</button>{% if can_reset %}<a class="link" href="/forgot">Forgot password?</a>{% endif %}</div>
<button type="submit" class="btn">Sign in</button>
{% elif mode == 'setup' %}
<label class="field"><span>Username</span><input name="username" autocomplete="username" autocapitalize="none" autofocus required></label>
<label class="field"><span>Password (8 characters or more)</span><input type="password" name="password" data-pw autocomplete="new-password" minlength="8" required></label>
<label class="field"><span>Confirm password</span><input type="password" name="confirm" data-pw autocomplete="new-password" minlength="8" required></label>
<button type="button" class="link showpw">Show passwords</button>
<button type="submit" class="btn">Create admin account</button>
{% elif mode == 'forgot' %}
<label class="field"><span>Username or email</span><input name="username" autocomplete="username" autocapitalize="none" autofocus required></label>
<button type="submit" class="btn">Email me a code</button>
<div class="authlinks"><a class="link" href="/login">Back to sign in</a></div>
{% else %}
<label class="field"><span>6-digit code</span><input name="code" inputmode="numeric" autocomplete="one-time-code" maxlength="7" autofocus required></label>
<label class="field"><span>New password (8 characters or more)</span><input type="password" name="password" data-pw autocomplete="new-password" minlength="8" required></label>
<label class="field"><span>Confirm new password</span><input type="password" name="confirm" data-pw autocomplete="new-password" minlength="8" required></label>
<button type="button" class="link showpw">Show passwords</button>
<button type="submit" class="btn">Set new password</button>
<div class="authlinks"><a class="link" href="/forgot">Send a new code</a><a class="link" href="/login">Back to sign in</a></div>
{% endif %}
</form>
{% if mode == 'login' %}<p class="support">Want to keep this alive? <a href="https://buymeacoffee.com/ttheroux" target="_blank" rel="noopener">Buy us a coffee</a></p>{% endif %}
</main>
{% endif %}
<script nonce="{{ nonce }}">
document.querySelectorAll('[data-autosubmit]').forEach(function(cb){cb.onchange=function(){cb.form.submit()}});
document.querySelectorAll('.showpw').forEach(function(b){
  var label=b.textContent;
  b.onclick=function(){
    var pw=b.closest('form').querySelectorAll('[data-pw]');
    var showing=pw.length&&pw[0].type==='text';
    pw.forEach(function(i){i.type=showing?'password':'text'});
    b.textContent=showing?label:label.replace('Show','Hide');
  };
});
</script>
</body></html>
"""

PAGE = """<!doctype html>
<html lang="en"><head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<meta name="theme-color" content="#14213D">
<link rel="manifest" href="/manifest.json">
<link rel="icon" href="/icon.svg">
<title>Invoices</title>
<style nonce="__NONCE__">
:root{--bg:#E9EDF2;--surf:#fff;--soft:#F3F5F8;--ink:#14213D;--mut:#5B6577;--line:#D5DCE5;
--amber:#E9A100;--earn:#0F7B5F;--use:#B4234A;--onsem:#fff;--btn:#14213D;--btnfg:#fff;--focus:#2F4BD8;
--round:ui-rounded,"SF Pro Rounded","Nunito","Varela Round",system-ui,sans-serif;
--sans:system-ui,-apple-system,"Segoe UI",Roboto,sans-serif;color-scheme:light}
@media(prefers-color-scheme:dark){:root{--bg:#0C1322;--surf:#141E33;--soft:#1A2640;--ink:#E7ECF4;--mut:#8E9AB0;
--line:#24304A;--amber:#FFC233;--earn:#3DD6A3;--use:#FF6B8B;--onsem:#0C1322;--btn:#FFC233;--btnfg:#14213D;
--focus:#FFC233;color-scheme:dark}}
*{box-sizing:border-box}
[hidden]{display:none!important}
body{margin:0;background:var(--bg);color:var(--ink);font:16px/1.45 var(--sans);padding:16px;max-width:620px;margin:auto;-webkit-font-smoothing:antialiased}
button,input,select,textarea{font:inherit;color:inherit}
:focus-visible{outline:2px solid var(--focus);outline-offset:2px}
.top{display:flex;align-items:center;gap:16px;margin:0 0 10px;font-size:.9rem}
.top .brand{margin-right:auto;font-weight:700;font-size:1.1rem;color:var(--btn);font-family:var(--round)}
.top a{color:var(--mut);text-decoration:none}
.top button{background:none;border:0;color:var(--mut);font-size:.9rem;padding:0;cursor:pointer}
nav{display:flex;gap:6px;margin-bottom:12px}
nav button{flex:1;padding:10px 2px;border-radius:var(--r-sm);border:1px solid var(--line);background:none;color:var(--ink);font-size:.85rem}
nav button.on{background:var(--btn);color:var(--btnfg);border-color:var(--btn)}
.card{background:var(--surf);border-radius:var(--r-lg);padding:20px;margin-bottom:14px}
h2,h3{margin:0 0 12px;font-family:var(--round);font-weight:650}
h2{font-size:1.15rem}h3{font-size:1rem}
label{display:block;font-size:.82rem;color:var(--mut);margin:0 0 5px 2px}
input,select,textarea{width:100%;min-height:48px;padding:11px 14px;margin-bottom:10px;border-radius:var(--r-sm);border:1px solid var(--line);background:var(--soft);color:var(--ink);font:inherit;-webkit-appearance:none;appearance:none}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--focus);background-color:var(--surf)}
textarea{min-height:0;resize:vertical}
.grid2{display:grid;grid-template-columns:1fr 1fr;gap:10px}
.chk{display:flex;align-items:center;gap:8px;font-size:.9rem;color:var(--ink);margin-bottom:10px}
.chk input{width:auto;min-height:0;margin:0}
button.p,.actions button{min-height:48px;padding:12px 16px;border:0;border-radius:var(--r-sm);background:var(--btn);color:var(--btnfg);font:inherit;font-weight:650;text-decoration:none}
button.sec{background:none!important;color:var(--ink)!important;border:1px solid var(--line)!important}
.actions{display:flex;gap:8px;margin-bottom:14px}
.actions button{flex:1}
.seg{display:flex;gap:6px;margin-bottom:10px}
.seg button{flex:1;padding:9px;border-radius:var(--r-sm);border:1px solid var(--line);background:none;color:var(--ink);font:inherit}
.seg button.on{background:var(--btn);color:var(--btnfg);border-color:var(--btn)}
.lbl{color:var(--mut);font-size:.85rem}
.big{font-size:2rem;font-weight:700}
.err{color:var(--use);margin:0 0 10px;font-size:.9rem}
.ln{display:grid;grid-template-columns:22px 1fr;gap:6px 8px;padding:10px 0;border-bottom:1px solid var(--line)}
.ln.drag{opacity:.4}
.ln .h{cursor:grab;color:var(--mut);user-select:none;font-size:1.2rem;line-height:1.2}
.ln .rest{display:flex;flex-direction:column}
.ln textarea{margin-bottom:8px}
.ln .nums{display:grid;grid-template-columns:1fr 1fr auto;gap:8px;align-items:center}
.ln .nums input{margin:0}
.ln .amt{font-weight:600;white-space:nowrap;text-align:right;min-width:84px}
.ln .mv{display:flex;gap:6px;margin-top:8px}
.ln select.svc{margin-bottom:8px}
.ln .mv button{padding:6px 12px;border-radius:8px;border:1px solid var(--line);background:none;color:var(--mut);font:inherit}
.tot{display:flex;justify-content:space-between;padding:6px 0}
.tot.t{font-size:1.15rem;font-weight:700;border-top:1px solid var(--line);margin-top:6px;padding-top:10px}
.inv{position:relative;border:1px solid var(--line);border-radius:12px;padding:12px 12px 12px 20px;margin-bottom:10px;background:var(--surf)}
.inv .stripe{position:absolute;left:0;top:10px;bottom:10px;width:4px;border-radius:2px}
.inv .stripe.b-paid{background:var(--earn)}
.inv .stripe.b-unpaid{background:var(--amber)}
.inv .stripe.b-over{background:var(--use)}
.inv .stripe.b-void{background:var(--mut)}
.inv .r1{display:flex;justify-content:space-between;font-weight:600}
.inv .r2{display:flex;justify-content:space-between;color:var(--mut);font-size:.88rem;margin:3px 0 8px}
.inv .btns{display:flex;flex-wrap:wrap;gap:6px}
.inv .btns button{padding:6px 10px;border-radius:8px;border:1px solid var(--line);background:none;color:var(--ink);font:inherit;font-size:.85rem}
.badge{font-size:.72rem;padding:2px 8px;border-radius:99px;border:1px solid var(--line);margin-left:6px;font-weight:600;vertical-align:middle}
.b-paid{color:var(--earn);border-color:var(--earn)}
.b-unpaid{color:var(--amber);border-color:var(--amber)}
.b-over{color:var(--use);border-color:var(--use)}
.b-void{color:var(--mut)}
.cl{display:flex;justify-content:space-between;padding:10px 0;border-bottom:1px solid var(--line);cursor:pointer}
.cl:last-child{border:0}
.cl small{color:var(--mut)}
.drop{border:2px dashed var(--line);border-radius:12px;padding:18px;text-align:center;color:var(--mut);cursor:pointer;margin-bottom:10px}
.drop.over{border-color:var(--btn);color:var(--ink)}
.drop img{max-width:160px;display:block;margin:10px auto 0;background:#fff;padding:6px;border-radius:8px}
.saved{background:var(--surf);border:1px solid var(--earn);border-radius:12px;padding:12px;margin-bottom:14px}
.saved a{color:var(--btn);margin-right:14px;font-weight:600}
.support{color:var(--mut);font-size:.8rem;text-align:center;margin:18px 0 4px}
.support a{color:var(--mut);text-decoration:underline}
.support a:hover{color:var(--ink)}
#addl{width:100%;margin:10px 0 14px}
#qrrm{padding:8px 12px;border-radius:10px;font:inherit}
</style></head><body>
<form class="top" method="post" action="/logout"><span class="brand">Invoices</span><a href="/settings">Settings</a><button type="submit">Sign out</button></form>
<nav id="nav">
  <button data-t="list" class="on">Invoices</button>
  <button data-t="edit">New</button>
  <button data-t="clients">Clients</button>
  <button data-t="services">Services</button>
  <button data-t="profile">Profile</button>
</nav>

<section id="list" class="pane">
  <div class="card"><div class="lbl">Outstanding</div><div class="big" id="owed">$0.00</div></div>
  <div class="seg" id="flt">
    <button data-f="all" class="on">All</button><button data-f="unpaid">Unpaid</button><button data-f="paid">Paid</button>
  </div>
  <div id="inv"></div>
</section>

<section id="edit" class="pane" hidden>
  <div class="card">
    <h2 id="etitle">New invoice</h2>
    <label>Client</label>
    <select id="cl"></select>
    <input id="cname" placeholder="Client name" maxlength="120">
    <textarea id="caddr" rows="3" placeholder="Client address" maxlength="400"></textarea>
    <label class="chk" id="saveclrow"><input type="checkbox" id="savecl" checked> Save to my clients</label>
    <label>Language</label>
    <div class="seg" id="lang"><button data-l="en" class="on">English</button><button data-l="fr">Français</button></div>
    <div class="grid2">
      <div><label>Invoice no.</label><input id="num" maxlength="30"></div>
      <div><label>Quantity unit</label><select id="unit"><option value="hours">Hours</option><option value="qty">Quantity</option></select></div>
    </div>
    <div class="grid2">
      <div><label>Issue date</label><input type="date" id="idate"></div>
      <div><label>Due date</label><input type="date" id="ddate"></div>
    </div>
    <label>Reference (optional)</label>
    <input id="ref" maxlength="200" placeholder="e.g. Proxmox migration, phase 1">
  </div>
  <div class="card">
    <h3>Line items</h3>
    <div id="lines"></div>
    <button type="button" id="addl" class="p sec">+ Add line</button>
    <div class="tot"><span>Subtotal</span><b id="sub">$0.00</b></div>
    <div class="tot t"><span>Total due (CAD)</span><b id="tot">$0.00</b></div>
  </div>
  <div class="card">
    <label>Notes (optional)</label>
    <textarea id="notes" rows="3" maxlength="1000"></textarea>
  </div>
  <p class="err" id="eerr"></p>
  <div class="actions"><button type="button" id="save">Save invoice</button><button type="button" id="prev" class="sec">Preview PDF</button></div>
  <div class="saved" id="saved" hidden></div>
</section>

<section id="clients" class="pane" hidden>
  <div class="card">
    <h3 id="ctitle">Add client</h3>
    <input id="kn" placeholder="Client name" maxlength="120">
    <textarea id="ka" rows="3" placeholder="Address" maxlength="400"></textarea>
    <div class="grid2">
      <div><label>Invoice language</label><select id="kl"><option value="en">English</option><option value="fr">Français</option></select></div>
      <div><label>Default rate ($ per hour)</label><input id="kr" inputmode="decimal" placeholder="e.g. 95"></div>
    </div>
    <p class="err" id="kerr"></p>
    <div class="actions"><button type="button" id="ks">Save client</button><button type="button" id="kd" class="sec" hidden>Delete</button><button type="button" id="kc" class="sec" hidden>Cancel</button></div>
  </div>
  <div class="card" id="clist"></div>
</section>

<section id="services" class="pane" hidden>
  <div class="card">
    <h3 id="stitle">Add service</h3>
    <label>Name (shown in the dropdown)</label>
    <input id="sn" placeholder="e.g. Linux sysadmin" maxlength="80">
    <label>Description on English invoices</label>
    <textarea id="se" rows="2" maxlength="600"></textarea>
    <label>Description on French invoices</label>
    <textarea id="sf" rows="2" maxlength="600"></textarea>
    <label>Default rate ($ per hour)</label>
    <input id="sr" inputmode="decimal" placeholder="e.g. 95">
    <p class="err" id="serr"></p>
    <div class="actions"><button type="button" id="ss">Save service</button><button type="button" id="sd" class="sec" hidden>Delete</button><button type="button" id="sc" class="sec" hidden>Cancel</button></div>
  </div>
  <div class="card" id="slist"></div>
</section>

<section id="profile" class="pane" hidden>
  <div class="card">
    <h3>Your details (the FROM block)</h3>
    <label>Name</label><input id="p_name" maxlength="120">
    <label>Address</label><textarea id="p_address" rows="3" maxlength="400"></textarea>
    <div class="grid2">
      <div><label>Phone</label><input id="p_phone" maxlength="120"></div>
      <div><label>Email</label><input id="p_email" maxlength="120"></div>
    </div>
  </div>
  <div class="card">
    <h3>Payment</h3>
    <label>Interac e-Transfer email</label><input id="p_interac" maxlength="120">
    <label>Default payment terms (days)</label><input id="p_net" inputmode="numeric">
    <label>PayPal QR code</label>
    <div class="drop" id="drop"><span id="droptxt">Drop your PayPal QR image here, or tap to choose</span><img id="qrimg" alt="PayPal QR" hidden></div>
    <input type="file" id="qrfile" accept="image/png,image/jpeg" hidden>
    <button type="button" id="qrrm" class="sec" hidden>Remove QR</button>
  </div>
  <div class="card">
    <h3>Numbering and tax note</h3>
    <label>Last invoice number you issued before using this app (optional)</label>
    <input id="p_last" placeholder="e.g. 2026-002" maxlength="30">
    <label>Tax note, English (shown on every English invoice)</label><textarea id="p_tne" rows="2" maxlength="400"></textarea>
    <label>Tax note, French</label><textarea id="p_tnf" rows="2" maxlength="400"></textarea>
  </div>
  <p class="err" id="perr"></p>
  <div class="actions"><button type="button" id="ps">Save profile</button></div>
</section>

<p class="support">Want to keep this alive? <a href="https://buymeacoffee.com/ttheroux" target="_blank" rel="noopener">Buy us a coffee</a></p>

<form id="pf" method="post" action="/preview-pdf" target="_blank" hidden><input type="hidden" name="payload" id="pfp"></form>

<script nonce="__NONCE__">
const $=s=>document.querySelector(s),$$=s=>[...document.querySelectorAll(s)];
let clients=[],services=[],invoices=[],profile={},lines=[],editId=null,lang='en',flt='all',dueManual=false,numManual=false,defRate='',dragI=null,kid=null,sid=null;
const today=()=>new Date().toLocaleDateString('en-CA');
const J=(m,b)=>({method:m,headers:{'Content-Type':'application/json'},body:JSON.stringify(b)});
async function api(url,opt){const r=await fetch(url,opt);if(r.status===401){location='/login';throw new Error('auth')}return r}
function money(c,l){return new Intl.NumberFormat(l==='fr'?'fr-CA':'en-CA',{style:'currency',currency:'CAD'}).format(c/100)}
function el(tag,cls,text){const e=document.createElement(tag);if(cls)e.className=cls;if(text!==undefined)e.textContent=text;return e}
function btn(label,fn){const b=el('button','',label);b.type='button';b.onclick=fn;return b}
function addDays(iso,n){const d=new Date(iso+'T12:00:00');d.setDate(d.getDate()+n);return d.toLocaleDateString('en-CA')}
function show(t){$$('.pane').forEach(p=>p.hidden=p.id!==t);$$('#nav button').forEach(b=>b.classList.toggle('on',b.dataset.t===t));window.scrollTo(0,0)}

/* ---------- data ---------- */
async function loadProfile(){profile=await(await api('/api/profile')).json();fillProfile()}
async function loadClients(){clients=(await(await api('/api/clients')).json()).clients;renderClients();renderClientSelect()}
async function loadServices(){services=(await(await api('/api/services')).json()).services;renderServices()}
function svcDesc(s,l){return (l==='fr'?(s.desc_fr||s.desc_en):(s.desc_en||s.desc_fr))||s.name}
async function loadInvoices(){invoices=(await(await api('/api/invoices')).json()).invoices;renderList()}

/* ---------- invoice list ---------- */
function renderList(){
  const owed=invoices.filter(i=>i.status==='unpaid').reduce((s,i)=>s+i.total_cents,0);
  $('#owed').textContent=money(owed,'en');
  const box=$('#inv');box.textContent='';
  const rows=invoices.filter(i=>flt==='all'||i.status===flt);
  if(!rows.length){box.append(el('p','lbl','No invoices yet.'));return}
  rows.forEach(i=>{
    const c=el('div','inv');
    const r1=el('div','r1');
    const left=el('span','',i.number);
    let label='Unpaid',cls='b-unpaid';
    if(i.status==='paid'){label='Paid';cls='b-paid'}
    else if(i.status==='void'){label='Void';cls='b-void'}
    else if(i.due_date<today()){label='Overdue';cls='b-over'}
    left.append(el('span','badge '+cls,label));
    r1.append(left,el('span','',money(i.total_cents,i.lang)));
    const r2=el('div','r2');
    r2.append(el('span','',i.client),el('span','',i.status==='paid'&&i.paid_date?'Paid '+i.paid_date:'Due '+i.due_date));
    const b=el('div','btns');
    b.append(btn('PDF',()=>window.open('/invoices/'+i.id+'.pdf','_blank')),
             btn('Edit',()=>openInvoice(i.id,false)),
             btn('Duplicate',()=>openInvoice(i.id,true)));
    if(i.status==='unpaid')b.append(btn('Mark paid',()=>setStatus(i.id,'paid')));
    if(i.status==='paid')b.append(btn('Mark unpaid',()=>setStatus(i.id,'unpaid')));
    if(i.status!=='void')b.append(btn('Void',()=>{if(confirm('Void invoice '+i.number+'? It stays in the list for your records.'))setStatus(i.id,'void')}));
    else b.append(btn('Restore',()=>setStatus(i.id,'unpaid')));
    c.append(el('div','stripe '+cls),r1,r2,b);box.append(c);
  });
}
async function setStatus(id,status){await api('/api/invoices/'+id+'/status',J('POST',{status}));loadInvoices()}
$$('#flt button').forEach(b=>b.onclick=()=>{flt=b.dataset.f;$$('#flt button').forEach(x=>x.classList.toggle('on',x===b));renderList()});

/* ---------- editor ---------- */
function renderClientSelect(){
  const s=$('#cl'),cur=s.value;s.textContent='';
  const n=el('option','','+ New client');n.value='';s.append(n);
  clients.forEach(c=>{const o=el('option','',c.name);o.value=c.id;s.append(o)});
  s.value=cur;
}
function setLang(l){
  const old=lang;lang=l;
  $$('#lang button').forEach(b=>b.classList.toggle('on',b.dataset.l===l));
  if(old!==l){let ch=false;
    lines.forEach(ln=>{const s=services.find(x=>x.id===ln.svc);
      if(s&&ln.desc===svcDesc(s,old)&&svcDesc(s,l)!==ln.desc){ln.desc=svcDesc(s,l);ch=true}});
    if(ch)renderLines()}
  calc();
}
$$('#lang button').forEach(b=>b.onclick=()=>setLang(b.dataset.l));
function pickClient(){
  const id=$('#cl').value,c=clients.find(x=>String(x.id)===id);
  $('#saveclrow').hidden=!!c;
  if(c){$('#cname').value=c.name;$('#caddr').value=c.address;setLang(c.lang);defRate=c.rate||'';
    lines.forEach(l=>{if(!l.rate&&defRate)l.rate=defRate});renderLines()}
  else{defRate=''}
}
$('#cl').onchange=()=>{const c=clients.find(x=>String(x.id)===$('#cl').value);if(!c){$('#cname').value='';$('#caddr').value=''}pickClient()};
async function suggestNumber(){
  if(editId!==null||numManual)return;
  const y=($('#idate').value||today()).slice(0,4);
  const r=await(await api('/api/next-number?year='+y)).json();$('#num').value=r.number;
}
$('#num').oninput=()=>numManual=true;
$('#ddate').oninput=()=>dueManual=true;
$('#idate').oninput=()=>{if(!dueManual)$('#ddate').value=addDays($('#idate').value,+profile.net_days||30);suggestNumber()};
$('#unit').onchange=renderLines;
function resetEditor(){
  editId=null;numManual=false;dueManual=false;defRate='';
  $('#etitle').textContent='New invoice';$('#saved').hidden=true;$('#eerr').textContent='';
  $('#cl').value='';$('#cname').value='';$('#caddr').value='';$('#savecl').checked=true;$('#saveclrow').hidden=false;
  $('#unit').value='hours';$('#ref').value='';$('#notes').value='';
  $('#idate').value=today();$('#ddate').value=addDays(today(),+profile.net_days||30);
  setLang('en');lines=[{desc:'',qty:'',rate:''}];renderLines();suggestNumber();
}
function newInvoice(){resetEditor();show('edit')}
async function openInvoice(id,dup){
  const r=await(await api('/api/invoices/'+id)).json(),d=r.data;
  resetEditor();
  $('#cl').value=r.client_id?String(r.client_id):'';
  $('#saveclrow').hidden=!!r.client_id;
  $('#cname').value=d.client.name;$('#caddr').value=d.client.address;
  setLang(d.lang);$('#unit').value=d.unit;$('#ref').value=d.reference;$('#notes').value=d.notes;
  lines=d.lines.map(l=>({desc:l.desc,qty:l.qty,rate:l.rate}));
  if(dup){$('#etitle').textContent='Duplicate of '+d.number;suggestNumber()}
  else{editId=id;numManual=true;dueManual=true;$('#etitle').textContent='Edit invoice '+d.number;
    $('#num').value=d.number;$('#idate').value=d.issue_date;$('#ddate').value=d.due_date}
  renderLines();show('edit');
}
function calc(){
  let t=0;
  $$('#lines .ln').forEach((row,i)=>{
    const q=parseFloat(String(lines[i].qty).replace(',','.')),r=parseFloat(String(lines[i].rate).replace(',','.'));
    const c=(q>0&&!isNaN(r))?Math.round(q*r*100):0;t+=c;row.querySelector('.amt').textContent=money(c,lang)});
  $('#sub').textContent=money(t,lang);$('#tot').textContent=money(t,lang);
}
function renderLines(){
  const box=$('#lines');box.textContent='';
  const unit=$('#unit').value==='hours'?'Hours':'Qty';
  lines.forEach((ln,i)=>{
    const row=el('div','ln');
    const h=el('span','h','\u22ee\u22ee');h.title='Drag to reorder';
    h.onmousedown=()=>row.draggable=true;h.onmouseup=()=>row.draggable=false;
    row.ondragstart=e=>{dragI=i;e.dataTransfer.effectAllowed='move';row.classList.add('drag')};
    row.ondragend=()=>{row.draggable=false;row.classList.remove('drag')};
    row.ondragover=e=>e.preventDefault();
    row.ondrop=e=>{e.preventDefault();if(dragI===null||dragI===i)return;const m=lines.splice(dragI,1)[0];lines.splice(i,0,m);dragI=null;renderLines()};
    const rest=el('div','rest');
    if(services.length){
      const sel=el('select','svc');const o0=el('option','','Pick a saved service...');o0.value='';sel.append(o0);
      services.forEach(s=>{const o=el('option','',s.name);o.value=s.id;sel.append(o)});
      sel.onchange=()=>{const s=services.find(x=>String(x.id)===sel.value);if(!s)return;
        ln.desc=svcDesc(s,lang);ln.svc=s.id;ln.rate=s.rate||ln.rate||defRate;renderLines()};
      rest.append(sel);
    }
    const d=el('textarea');d.rows=2;d.placeholder='Description';d.value=ln.desc;d.maxLength=600;d.oninput=()=>ln.desc=d.value;
    const nums=el('div','nums');
    const q=el('input');q.placeholder=unit;q.inputMode='decimal';q.value=ln.qty;q.oninput=()=>{ln.qty=q.value;calc()};
    const r=el('input');r.placeholder='Rate';r.inputMode='decimal';r.value=ln.rate;r.oninput=()=>{ln.rate=r.value;calc()};
    nums.append(q,r,el('span','amt','$0.00'));
    const mv=el('div','mv');
    mv.append(btn('\u25b2',()=>{if(i>0){[lines[i-1],lines[i]]=[lines[i],lines[i-1]];renderLines()}}),
              btn('\u25bc',()=>{if(i<lines.length-1){[lines[i+1],lines[i]]=[lines[i],lines[i+1]];renderLines()}}),
              btn('\u2605 Save as service',async()=>{
                if(!ln.desc.trim()){alert('Write a description first.');return}
                const name=prompt('Name for this service (shown in the dropdown):',ln.desc.trim().slice(0,40));
                if(!name)return;
                const r=await api('/api/services',J('POST',{name,rate:ln.rate,desc_en:lang==='en'?ln.desc:'',desc_fr:lang==='fr'?ln.desc:''}));
                const d=await r.json();if(!r.ok){alert(d.error);return}
                ln.svc=d.id;await loadServices();renderLines()}),
              btn('\u2715',()=>{lines.splice(i,1);if(!lines.length)lines.push({desc:'',qty:'',rate:defRate});renderLines()}));
    rest.append(d,nums,mv);row.append(h,rest);box.append(row);
  });
  calc();
}
$('#addl').onclick=()=>{lines.push({desc:'',qty:'',rate:defRate});renderLines();const t=$$('#lines textarea');t[t.length-1].focus()};
function payload(){return {lang,number:$('#num').value.trim(),issue_date:$('#idate').value,due_date:$('#ddate').value,unit:$('#unit').value,
  reference:$('#ref').value.trim(),notes:$('#notes').value.trim(),client_id:$('#cl').value?+$('#cl').value:null,
  save_client:$('#savecl').checked,client:{name:$('#cname').value.trim(),address:$('#caddr').value.trim()},
  lines:lines.map(l=>({desc:l.desc,qty:l.qty,rate:l.rate}))}}
$('#prev').onclick=()=>{$('#pfp').value=JSON.stringify(payload());$('#pf').submit()};
$('#save').onclick=async()=>{
  $('#eerr').textContent='';
  const r=await api(editId?'/api/invoices/'+editId:'/api/invoices',J(editId?'PUT':'POST',payload()));
  const d=await r.json();
  if(!r.ok){$('#eerr').textContent=d.error||'Could not save the invoice.';return}
  editId=d.id;$('#etitle').textContent='Edit invoice '+$('#num').value.trim();numManual=true;
  await loadClients();if(d.client_id){$('#cl').value=String(d.client_id);$('#saveclrow').hidden=true}
  const s=$('#saved');s.hidden=false;s.textContent='';
  s.append(el('div','','Saved. '),(()=>{const a=el('a','','View PDF');a.href='/invoices/'+d.id+'.pdf';a.target='_blank';return a})(),
    (()=>{const a=el('a','','Download');a.href='/invoices/'+d.id+'.pdf?download=1';return a})(),
    (()=>{const a=el('a','','Back to invoices');a.href='#';a.onclick=e=>{e.preventDefault();show('list')};return a})());
  loadInvoices();
};

/* ---------- clients ---------- */
function renderClients(){
  const box=$('#clist');box.textContent='';
  if(!clients.length){box.append(el('p','lbl','No clients yet. They are also saved automatically when you create an invoice.'));return}
  clients.forEach(c=>{
    const row=el('div','cl');
    row.append(el('span','',c.name),el('small','',(c.lang==='fr'?'FR':'EN')+(c.rate?' - $'+c.rate+'/h':'')));
    row.onclick=()=>editClient(c);box.append(row);
  });
}
function editClient(c){
  kid=c?c.id:null;$('#ctitle').textContent=c?'Edit client':'Add client';
  $('#kn').value=c?c.name:'';$('#ka').value=c?c.address:'';$('#kl').value=c?c.lang:'en';$('#kr').value=c?c.rate:'';
  $('#kd').hidden=!c;$('#kc').hidden=!c;$('#kerr').textContent='';
}
$('#kc').onclick=()=>editClient(null);
$('#ks').onclick=async()=>{
  const b={name:$('#kn').value,address:$('#ka').value,lang:$('#kl').value,rate:$('#kr').value};
  const r=await api(kid?'/api/clients/'+kid:'/api/clients',J(kid?'PUT':'POST',b));
  const d=await r.json();if(!r.ok){$('#kerr').textContent=d.error;return}
  editClient(null);loadClients();
};
$('#kd').onclick=async()=>{
  if(!confirm('Delete this client?'))return;
  const r=await api('/api/clients/'+kid,{method:'DELETE'});
  if(!r.ok){$('#kerr').textContent=(await r.json()).error;return}
  editClient(null);loadClients();
};

/* ---------- services ---------- */
function renderServices(){
  const box=$('#slist');box.textContent='';
  if(!services.length){box.append(el('p','lbl','No services yet. Add one above, or use "Save as service" on an invoice line.'));return}
  services.forEach(s=>{
    const row=el('div','cl');
    row.append(el('span','',s.name),el('small','',(s.desc_en&&s.desc_fr?'EN+FR':s.desc_fr?'FR':'EN')+(s.rate?' - $'+s.rate+'/h':'')));
    row.onclick=()=>editService(s);box.append(row);
  });
}
function editService(s){
  sid=s?s.id:null;$('#stitle').textContent=s?'Edit service':'Add service';
  $('#sn').value=s?s.name:'';$('#se').value=s?s.desc_en:'';$('#sf').value=s?s.desc_fr:'';$('#sr').value=s?s.rate:'';
  $('#sd').hidden=!s;$('#sc').hidden=!s;$('#serr').textContent='';
}
$('#sc').onclick=()=>editService(null);
$('#ss').onclick=async()=>{
  const b={name:$('#sn').value,desc_en:$('#se').value,desc_fr:$('#sf').value,rate:$('#sr').value};
  const r=await api(sid?'/api/services/'+sid:'/api/services',J(sid?'PUT':'POST',b));
  const d=await r.json();if(!r.ok){$('#serr').textContent=d.error;return}
  editService(null);loadServices();
};
$('#sd').onclick=async()=>{
  if(!confirm('Delete this service? Existing invoices are not affected.'))return;
  await api('/api/services/'+sid,{method:'DELETE'});editService(null);loadServices();
};

/* ---------- profile ---------- */
function fillProfile(){
  $('#p_name').value=profile.name;$('#p_address').value=profile.address;$('#p_phone').value=profile.phone;$('#p_email').value=profile.email;
  $('#p_interac').value=profile.interac_email;$('#p_net').value=profile.net_days;$('#p_last').value=profile.last_number;
  $('#p_tne').value=profile.tax_note_en;$('#p_tnf').value=profile.tax_note_fr;
  $('#qrimg').hidden=!profile.has_qr;$('#qrrm').hidden=!profile.has_qr;
  if(profile.has_qr){$('#qrimg').src='/qr.png?'+Date.now();$('#droptxt').textContent='QR saved. Drop a new image to replace it.'}
  else $('#droptxt').textContent='Drop your PayPal QR image here, or tap to choose';
}
$('#ps').onclick=async()=>{
  const b={name:$('#p_name').value,address:$('#p_address').value,phone:$('#p_phone').value,email:$('#p_email').value,
    interac_email:$('#p_interac').value,net_days:$('#p_net').value,last_number:$('#p_last').value,
    tax_note_en:$('#p_tne').value,tax_note_fr:$('#p_tnf').value};
  const r=await api('/api/profile',J('PUT',b));
  if(!r.ok){$('#perr').textContent=(await r.json()).error;return}
  $('#perr').textContent='';await loadProfile();$('#ps').textContent='Saved';setTimeout(()=>$('#ps').textContent='Save profile',1500);
};
async function upQR(f){
  if(!f||(f.type!=='image/png'&&f.type!=='image/jpeg')){alert('Use a PNG or JPEG image.');return}
  const r=await api('/api/profile/qr',{method:'POST',headers:{'Content-Type':f.type},body:f});
  if(!r.ok){alert((await r.json()).error||'Upload failed.');return}
  loadProfile();
}
const drop=$('#drop');
drop.ondragover=e=>{e.preventDefault();drop.classList.add('over')};
drop.ondragleave=()=>drop.classList.remove('over');
drop.ondrop=e=>{e.preventDefault();drop.classList.remove('over');upQR(e.dataTransfer.files[0])};
drop.onclick=()=>$('#qrfile').click();
$('#qrfile').onchange=e=>upQR(e.target.files[0]);
$('#qrrm').onclick=async()=>{await api('/api/profile/qr',{method:'DELETE'});loadProfile()};

/* ---------- navigation + idle sign-out ---------- */
$$('#nav button').forEach(b=>b.onclick=()=>{b.dataset.t==='edit'?newInvoice():show(b.dataset.t)});
const IDLE=__IDLE__*60000;
let last=Date.now(),pinged=Date.now();
async function bye(){try{await fetch('/logout',{method:'POST'})}catch(e){}location='/login'}
function act(){last=Date.now();if(IDLE&&Date.now()-pinged>60000){pinged=Date.now();fetch('/api/ping',{method:'POST'})}}
['pointerdown','keydown','touchstart','scroll','input'].forEach(ev=>addEventListener(ev,act,{passive:true}));
function check(){if(IDLE&&Date.now()-last>IDLE)bye()}
setInterval(check,15000);
document.addEventListener('visibilitychange',()=>{if(!document.hidden)check()});

(async()=>{await loadProfile();await loadClients();await loadServices();await loadInvoices();resetEditor();
  if(!profile.name)show('profile')})();
</script></body></html>
"""


if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1] == "setpw":
        # python app.py setpw <username>
        # Re-enables the account and makes it an admin, so a locked-out server can always
        # be recovered from the console.
        if len(sys.argv) != 3:
            sys.exit("Usage: python app.py setpw <username>")
        c = sqlite3.connect(DB)
        if not c.execute("SELECT 1 FROM users WHERE username = ?", (sys.argv[2],)).fetchone():
            names = ", ".join(r[0] for r in c.execute("SELECT username FROM users ORDER BY username"))
            sys.exit(f"No user named {sys.argv[2]}. Users: {names or 'none yet'}")
        pw = getpass.getpass("New password: ")
        if len(pw) < MIN_PW or pw != getpass.getpass("Confirm: "):
            sys.exit(f"Passwords must match and be at least {MIN_PW} characters.")
        c.execute(
            "UPDATE users SET pw_hash = ?, epoch = ?, disabled = 0, is_admin = 1 WHERE username = ?",
            (generate_password_hash(pw), new_epoch(), sys.argv[2]),
        )
        c.commit()
        c.close()
        print(f"Password updated for {sys.argv[2]}, who is now an enabled admin. Their devices were signed out.")
        sys.exit(0)
    app.run(host="0.0.0.0", port=PORT)
