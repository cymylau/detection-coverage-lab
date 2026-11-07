#!/bin/bash
#
# install-extra-tools.sh — additional tooling for the new scenario scripts.
#
# bootstrap.sh installs the minimum for the original metadata-exfil chain.
# This installs what the newer scenarios need on top of that, without
# touching bootstrap.sh or anything it already does.
#
# Run inside the ops-console container, after bootstrap.sh:
#   bash playbooks/install-extra-tools.sh
set -eu

echo "[install-extra-tools] installing additional packages..."
apt-get update -qq
apt-get install -y --no-install-recommends \
    zip unzip sqlite3 sshpass openssh-client netcat-traditional >/dev/null

# Versions are not pinned (Kali rolling drops old ones), so record what was
# actually installed to make a run reproducible/auditable after the fact.
mkdir -p "${RESULTS_DIR:-/home/root/results}"
dpkg-query -W -f='${Package}=${Version}\n' | sort > "${RESULTS_DIR:-/home/root/results}/installed-packages-install-extra-tools.txt"

echo "[install-extra-tools] done."
