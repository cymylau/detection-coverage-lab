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

echo "[install-extra-tools] done."
