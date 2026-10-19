#!/usr/bin/env bash
# Invoices: self-hosted invoice generator. Run this on the Proxmox host:
#
#   bash -c "$(curl -fsSL https://raw.githubusercontent.com/KernelChief/invoices/main/ct/invoices.sh)"
#
# Existing container instead of a new one:  ADOPT=1 CTID=<id> bash -c "..."
# More options (storage, static IP, auto-update, ...) are listed at the top of misc/build.func.

GIT_HOST="${GIT_HOST:-https://github.com}"
GIT_USER="${GIT_USER:-KernelChief}"
APP="invoices"
APP_TITLE="Invoices"
APP_BRANCH="${APP_BRANCH:-main}"
SCRIPTS_BRANCH="${SCRIPTS_BRANCH:-main}"
APP_REPO="${APP_REPO:-$GIT_HOST/$GIT_USER/invoices}"
SCRIPTS_REPO="${SCRIPTS_REPO:-https://raw.githubusercontent.com/$GIT_USER/invoices/$SCRIPTS_BRANCH}"
PORT=8080
CORES="${CORES:-1}"
RAM="${RAM:-256}"
DISK="${DISK:-3}"

CURL=(curl -fsSL)

BUILD="$("${CURL[@]}" "$SCRIPTS_REPO/misc/build.func")" \
  || { echo "Couldn't fetch misc/build.func from $SCRIPTS_REPO." >&2; exit 1; }
eval "$BUILD"
build_container
