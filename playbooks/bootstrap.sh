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
SERVICES="${SERVICES_DIR:-/home/root/services}"

# SKIP_INSTALL=1 once the network is locked down (no egress for apt).
if [ "${SKIP_INSTALL:-0}" != "1" ]; then
    echo "[bootstrap] installing tools..."
    apt-get -o Acquire::Retries=3 update -qq || {
        echo "[bootstrap] !! apt-get update failed: the package mirrors are unreachable." >&2
        echo "[bootstrap]    If an earlier run already locked the network down, start clean with:" >&2
        echo "[bootstrap]    bash run-everything.sh --down   (then run again)" >&2
        exit 1; }
    apt-get -o Acquire::Retries=3 install -y --no-install-recommends \
        nmap curl dnsutils iproute2 python3 coreutils ca-certificates >/dev/null

    # Versions are not pinned (Kali rolling drops old ones), so record what was
    # actually installed to make a run reproducible/auditable after the fact.
    mkdir -p "${RESULTS_DIR:-/home/root/results}"
    dpkg-query -W -f='${Package}=${Version}\n' | sort > "${RESULTS_DIR:-/home/root/results}/installed-packages-bootstrap.txt"
fi

echo "[bootstrap] aliasing $METADATA_IP onto loopback..."
ip addr add "${METADATA_IP}/32" dev lo 2>/dev/null || echo "  (already present)"

if curl -s --max-time 2 "http://${METADATA_IP}/latest/meta-data/" >/dev/null 2>&1; then
    echo "[bootstrap] decoy IMDS already running — leaving it"
    exit 0
fi
echo "[bootstrap] starting decoy IMDS (decoy credentials) on ${METADATA_IP}:80..."
IMDS_BIND="$METADATA_IP" nohup python3 "${SERVICES}/metadata_api.py" \
    >/home/root/results/metadata_api.log 2>&1 &
sleep 1
echo "[bootstrap] IMDS pid $! — log: /home/root/results/metadata_api.log"

echo "[bootstrap] ready. Run: bash playbooks/run-metadata-exfil.sh"
