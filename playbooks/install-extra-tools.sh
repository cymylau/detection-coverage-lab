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
apt-get -o Acquire::Retries=3 update -qq || {
    echo "[install-extra-tools] !! apt-get update failed: the package mirrors are unreachable." >&2
    echo "[install-extra-tools]    If an earlier run already locked the network down, start clean with:" >&2
    echo "[install-extra-tools]    bash run-everything.sh --down   (then run again)" >&2
    exit 1; }
apt-get -o Acquire::Retries=3 install -y --no-install-recommends \
    zip unzip sqlite3 sshpass openssh-client netcat-traditional sudo cron >/dev/null
# sudo: host-recon's sudo -l (T1069.001); cron: persistence's crontab entry (T1053.003)

# Versions are not pinned (Kali rolling drops old ones), so record what was
# actually installed to make a run reproducible/auditable after the fact.
mkdir -p "${RESULTS_DIR:-/home/root/results}"
dpkg-query -W -f='${Package}=${Version}\n' | sort > "${RESULTS_DIR:-/home/root/results}/installed-packages-install-extra-tools.txt"

echo "[install-extra-tools] done."
