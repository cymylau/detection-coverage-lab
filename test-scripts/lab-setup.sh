#!/bin/bash
#
# lab-setup.sh — prepare the attacker container for the emulation.
#
# Installs tooling, aliases the link-local metadata IP onto loopback so that
# the mock IMDS can serve on 169.254.169.254 (reproducing the real-world
# indicator of a process touching the metadata address), and starts the mock
# IMDS in the background.
#
# Run inside the edr-tester container:  bash test-scripts/lab-setup.sh
set -eu

METADATA_IP="${METADATA_IP:-169.254.169.254}"
HERE="$(cd "$(dirname "$0")" && pwd)"
SERVICES="${SERVICES_DIR:-/home/root/services}"

echo "[lab-setup] installing tools..."
apt-get update -qq
apt-get install -y --no-install-recommends \
    nmap curl dnsutils iproute2 python3 coreutils ca-certificates >/dev/null

echo "[lab-setup] aliasing $METADATA_IP onto loopback..."
ip addr add "${METADATA_IP}/32" dev lo 2>/dev/null || echo "  (already present)"

echo "[lab-setup] starting mock IMDS (decoy credentials) on ${METADATA_IP}:80..."
IMDS_BIND="$METADATA_IP" nohup python3 "${SERVICES}/mock_imds.py" \
    >/home/root/results/mock_imds.log 2>&1 &
sleep 1
echo "[lab-setup] IMDS pid $! — log: /home/root/results/mock_imds.log"

echo "[lab-setup] ready. Run: bash test-scripts/simulate-metadata-exfil.sh"
