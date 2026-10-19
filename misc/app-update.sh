#!/usr/bin/env bash
# Runs inside the container. Normally reached through the `update` command, which first refreshes
# this script from the homelab-scripts repo.
#
# Pulls the latest commit of the app's repo from git. If Python code or requirements.txt changed,
# it restarts the app and checks that it comes back up. If it doesn't, it rolls back to the previous
# commit and remembers the bad one so it isn't retried until you push something different.
set -uo pipefail

CONF="${APP_UPDATE_CONF:-/etc/app-update.conf}"
# shellcheck disable=SC1090
source "$CONF"   # APP APP_BRANCH SRC VENV PORT (+ SCRIPTS_REPO ... used by `update`)
STATE="${STATE_DIR:-/var/lib/app-update}"
mkdir -p "$STATE"

log() {
  logger -t app-update -- "$*" 2>/dev/null || true
  if [ -t 1 ]; then echo "$*"; fi   # also show it when you run `update` by hand
}

healthy() {
  "$VENV/bin/python" - "$PORT" <<'PY'
import sys, urllib.request
try:
    urllib.request.urlopen(f"http://127.0.0.1:{sys.argv[1]}/login", timeout=3)
except Exception:
    sys.exit(1)
PY
}

wait_healthy() {
  for _ in $(seq 1 15); do
    sleep 1
    healthy && return 0
  done
  return 1
}

install_deps() {
  if [ -f "$SRC/requirements.txt" ]; then
    "$VENV/bin/pip" install -q -r "$SRC/requirements.txt" || log "pip install reported an error"
  fi
}

cd "$SRC" || { log "$SRC is missing"; exit 1; }

timeout 60 git fetch --quiet origin "$APP_BRANCH" || { log "git fetch failed (is remote reachable? is the token still valid?)"; exit 1; }

OLD="$(git rev-parse HEAD)"
NEW="$(git rev-parse "origin/$APP_BRANCH")"

if [ "$OLD" = "$NEW" ]; then
  if [ -t 1 ]; then echo "$APP is up to date (${OLD:0:8})."; fi
  exit 0
fi
[ "$NEW" = "$(cat "$STATE/bad-commit" 2>/dev/null || true)" ] && exit 0   # already tried and rolled back

rm -f "$STATE/bad-commit"   # we're moving to a different commit, so any old failure note is stale
git reset --hard --quiet "$NEW"

if git diff --quiet "$OLD" "$NEW" -- '*.py' requirements.txt; then
  log "$APP: updated to ${NEW:0:8} (no code change, nothing to restart)"
  exit 0
fi

log "$APP: updating ${OLD:0:8} -> ${NEW:0:8}"
install_deps
systemctl restart "$APP"

if wait_healthy; then
  log "$APP: update OK (${NEW:0:8})"
  exit 0
fi

log "$APP: failed to start on ${NEW:0:8}, rolling back to ${OLD:0:8}"
git reset --hard --quiet "$OLD"
install_deps
systemctl restart "$APP"
echo "$NEW" > "$STATE/bad-commit"
wait_healthy && log "$APP: rollback OK" || log "$APP: STILL UNHEALTHY after rollback, check: journalctl -u $APP"
exit 1
