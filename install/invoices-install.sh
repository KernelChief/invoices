#!/usr/bin/env bash
# Runs inside the container (pushed there by ct/invoices.sh).
EXTRA_PACKAGES=""   # extra dnf packages this app needs, if any — invoices needs none
# shellcheck disable=SC1091
. /root/install.func
install_app
