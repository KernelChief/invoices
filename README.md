# 🧾 invoices

### A small, self-hosted invoice generator for freelancers and consultants doing work on the side.

[![Made with Python](https://img.shields.io/badge/Made%20with-Python-3776AB?logo=python&logoColor=white)](https://www.python.org/) 
[![Flask](https://img.shields.io/badge/Framework-Flask-000000?logo=flask&logoColor=white)](https://flask.palletsprojects.com/) 
[![Platform](https://img.shields.io/badge/Platform-Proxmox%20LXC%20%2F%20AlmaLinux-E95420)](https://www.proxmox.com/) 
[![Buy Me A Coffee](https://img.shields.io/badge/Support-Buy%20Me%20A%20Coffee-orange?logo=buy-me-a-coffee)](https://buymeacoffee.com/ttheroux) 
[![License: GPL-3.0](https://img.shields.io/badge/License-GPL%20v3-blue.svg)](LICENSE)

This isn't trying to be QuickBooks, FreshBooks, or any other full accounting platform, it
doesn't do taxes, expenses, bookkeeping, or payroll, and it never will. It exists for a much
smaller job: a consultant or freelancer who does some work on the side and just needs to send
a clean, professional invoice in English or French, track who's paid and who hasn't, and keep
their own client and service list, without a monthly subscription, a vendor holding their
data, or a tool built for a business ten times their size.

Clients, saved services, bilingual PDFs, payment history, a PayPal/Interac QR code on every
invoice, and multiple named accounts sharing the same books, all in one small self-hosted
Flask app you control.

![Login screen](docs/screenshots/login.png)

---

## ⚠️ Backups Are on You

This app stores everything in one SQLite file, outside the repo, inside your container. **It
is not responsible for lost data**, there is no cloud backup, no undo for a deleted invoice,
and no safety net beyond whatever backup strategy you set up yourself.

**Back up `/var/lib/invoices/invoices.db` regularly**, a Proxmox snapshot of the container, a
cron job that copies the file somewhere else, whatever fits your setup. Do this before every
update too, just in case.

---

## 📚 Quick Navigation

- [🧱 Installing](#-installing)
- [🚀 Updating the Deployed Container](#-updating-the-deployed-container)
- [👤 Accounts](#-accounts)
  - [First run](#first-run)
  - [Adding more accounts](#adding-more-accounts)
  - [Signing in](#signing-in)
  - [Forgot a password](#forgot-a-password)
  - [Completely locked out](#completely-locked-out)
- [💾 Data](#-data)
- [🧰 Troubleshooting](#-troubleshooting)

---

## 🧱 Installing

For a fresh Proxmox LXC container, one command on the Proxmox host:

```bash
bash -c "$(curl -fsSL https://raw.githubusercontent.com/KernelChief/invoices/main/ct/invoices.sh)"
```

This creates a small AlmaLinux container (1 core, 256MB RAM, 3GB disk; invoices is a single lightweight Flask process), clones this repo into it, installs Python and the app's dependencies, and starts it. The first time you open it, you'll be asked to create the admin account.

To wire up a container you created some other way instead of making a new one:

```bash
ADOPT=1 CTID=<your container id> bash -c "$(curl -fsSL https://raw.githubusercontent.com/KernelChief/invoices/main/ct/invoices.sh)"
```
> **What this does:** creates a new unprivileged AlmaLinux LXC container, picking a free
> container ID and your active storage automatically; boots it and waits for networking;
> installs git + Python inside it, clones this repo, and sets up a venv; then creates and
> starts a systemd service for the app, plus an `update` command for later.

When it finishes, it prints the container ID and the URL to open
(`http://<container-ip>:8080`). Making that reachable outside the container, Cloudflare
Tunnel, a port-forward, Nginx Proxy Manager, whatever fits your setup, is up to you; the
script doesn't do that part.

The install scripts (`ct/`, `install/`, `misc/`) live in this repo so the one-liner above is
self-contained: anyone running it only needs this repo, not access to any private
infrastructure.

### Options

Set these as environment variables before the `bash -c "..."` call, e.g.
`CORES=2 RAM=512 bash -c "..."`. Everything below is optional, sensible defaults are used if
you skip it.

| Variable | Default | What it controls |
|---|---|---|
| `CTID` | next free ID | Container ID to create (or adopt, with `ADOPT=1`) |
| `CT_HOSTNAME` | `overtime` | Hostname of the container |
| `CORES` | `1` | CPU cores |
| `RAM` | `256` | Memory in MB |
| `DISK` | `3` | Root disk size in GB |
| `STORAGE` | auto-picked | Storage for the container's root disk |
| `TEMPLATE_STORAGE` | auto-picked | Storage for the AlmaLinux template |
| `BRIDGE` | `vmbr0` | Network bridge |
| `VLAN` | none | VLAN tag, if your network needs one |
| `STATIC_IP` + `GATEWAY` | DHCP | Set both together for a static IP, e.g. `STATIC_IP=10.0.0.50/24 GATEWAY=10.0.0.1` |
| `ALMA_VER` | latest available | AlmaLinux major version |
| `FEATURES` | `nesting=1` | LXC features passed to `pct create` |
| `APP_BRANCH` | `main` | Branch of this app's repo to install |
| `SCRIPTS_BRANCH` | `main` | Branch of the install scripts themselves |
| `GIT_HOST` + `GIT_USER` | GitHub / `KernelChief` | Install from a different git host or account, e.g. your own fork |
| `AUTO_UPDATE` | `0` | Set to `1` to check for updates automatically inside the container |
| `INTERVAL` | `1h` | How often, when `AUTO_UPDATE=1` |
| `GIT_AUTH_USER` + `GIT_TOKEN` | none | Only needed if the app repo is private |
| `ADOPT` + `CTID` | off | Point an **existing** container at this installer instead of creating a new one, e.g. `ADOPT=1 CTID=121 bash -c "..."` |



---

## 🚀 Updating the Deployed Container

After pushing a change to this repo, pull it into the running container with:

```bash
pct exec <your container id> -- update
```

Or, from inside the container's own console, just run:

```bash
update
```

> **What this does:** pulls the latest code from this repo and restarts the app inside the
> container. It does **not** touch `/var/lib/invoices/invoices.db`, your clients, services,
> and invoices are untouched by an update. Back it up anyway before you update, just in case.

---

## 👤 Accounts

### First Run

On an empty database, the app asks you to create the admin account before anything else:

1. Open the app in a browser.
2. You're redirected to **Create the admin account**.
3. Enter a username and a password (8 characters or more).
4. You're signed in as the admin.

### Adding More Accounts

Only admins can add accounts. As an admin:

1. Go to **Settings**.
2. Under **Users**, click **Manage users**.
3. Fill in a username, an optional email (needed only if that person wants password resets by
   email), and a password, then **Add user**.
4. Share the password with them directly, they can change it themselves under Settings.

From the same **Users** page, an admin can also: make or remove an admin, reset anyone's
password, change anyone's email, disable (and re-enable) an account, or delete one.

> **Guardrail:** the app always keeps at least one enabled admin. You can't demote, disable,
> or delete the only admin, make someone else an admin first.

### Signing In

Sign in with your **username or your email**, whichever you have on hand.

### Forgot a Password

This only works once an admin has configured an email server:

1. An admin goes to **Settings → Email server**, fills in the SMTP host, port, security type,
   and a "send from" address, then **Save email server**.
2. The admin can click **Send a test email** to confirm it actually works.
3. Once that's saved, the sign-in page shows a **Forgot password?** link for everyone.
4. Clicking it emails a 6-digit code to the address on that account (set under **Settings →
   Email**). The code works for **10 minutes** and allows **5 guesses** before it's rejected.

### Completely Locked Out

No working account, no email configured, or the email server itself is unreachable, recover
from the container's own console:

```bash
python app.py setpw <username>
```

> **What this does:** prompts for a new password (twice, to confirm), then re-enables that
> account and makes it an admin, so the console can always get you back in, even if every
> account is currently disabled. It signs that account out everywhere else, same as any other
> password change.
>
> Give it a username that doesn't exist (or run it with none at all to see the usage line) and
> it prints every username that does exist, so you can find the right one to recover.

---

## 💾 Data

Everything lives outside this repo, in `/var/lib/invoices/invoices.db` inside the container, pushing code here, or running an update, never touches it. See
[⚠️ Backups Are on You](#️-backups-are-on-you) above: that file is the only copy unless you make
one yourself.

| What's in the database | Scope |
|---|---|
| Clients, services, invoices | Shared by every signed-in account |
| User accounts (username, password, email, admin flag) | Per-account |
| App settings (idle timeout, SMTP server) | Shared, admin-configured, applies to everyone |

---

## 🧰 Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| Stuck on **Create the admin account** after an update | Expected only on a brand-new, empty database. If this happens on an install that already had data, something deleted the DB file, check `/var/lib/invoices/invoices.db` exists in the container, and restore it from your last backup. |
| **Forgot password?** link doesn't show on the sign-in page | No admin has saved a working email server yet under Settings. |
| Reset email never arrives | Use **Send a test email** under Settings → Email server to check the SMTP settings on their own; also check the account actually has an email address saved. |
| Locked out of every account | Use `python app.py setpw <username>` from the container console, see [Completely Locked Out](#completely-locked-out). |
| "Too many attempts" on sign-in or reset | Five wrong tries within 10 minutes locks that IP out temporarily. Wait a few minutes and try again. |
