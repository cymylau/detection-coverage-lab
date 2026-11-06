#!/bin/bash
#
# bootstrap.sh — prepare the attacker container for the emulation.
#
# Installs tooling, aliases the link-local metadata IP onto loopback so that
# the decoy IMDS can serve on 169.254.169.254 (reproducing the real-world
# indicator of a process touching the metadata address), and starts the decoy
# IMDS in the background.
#
# Run inside the ops-console container:  bash playbooks/bootstrap.sh
set -eu

METADATA_IP="${METADATA_IP:-169.254.169.254}"
HERE="$(cd "$(dirname "$0")" && pwd)"
SERVICES="${SERVICES_DIR:-/home/root/services}"

echo "[bootstrap] installing tools..."
apt-get update -qq
apt-get install -y --no-install-recommends \
    nmap curl dnsutils iproute2 python3 coreutils ca-certificates >/dev/null

echo "[bootstrap] aliasing $METADATA_IP onto loopback..."
ip addr add "${METADATA_IP}/32" dev lo 2>/dev/null || echo "  (already present)"

echo "[bootstrap] starting decoy IMDS (decoy credentials) on ${METADATA_IP}:80..."
IMDS_BIND="$METADATA_IP" nohup python3 "${SERVICES}/metadata_api.py" \
    >/home/root/results/metadata_api.log 2>&1 &
sleep 1
echo "[bootstrap] IMDS pid $! — log: /home/root/results/metadata_api.log"

echo "[bootstrap] ready. Run: bash playbooks/run-metadata-exfil.sh"
