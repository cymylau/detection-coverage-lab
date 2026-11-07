#!/bin/bash
#
# run-cryptomining.sh
# ---------------------------------------------------------------------------
# CLOUD/CONTAINER EDR (CDR) DETECTION COVERAGE — NON-PRODUCTION USE ONLY
#
# Emulates resource-hijacking/cryptomining behaviour: a sustained high-CPU
# process plus periodic HTTP polling of a decoy "mining pool" (control-api's
# /pool/getwork and /pool/submit, shaped like stratum-over-HTTP check-ins).
# No real mining occurs — the CPU load is openssl benchmarking, not an
# actual miner, and the pool is the environment's own control-api.
#
#   sustained high-CPU child process      Resource Hijacking   (T1496)
#   periodic outbound "pool" check-ins     Resource Hijacking   (T1496)
#
# Usage: DURATION=20 bash playbooks/run-cryptomining.sh
# ---------------------------------------------------------------------------
set -u
source "$(cd "$(dirname "$0")" && pwd)/lib-stealth.sh"

C2_HOST="${C2_HOST:-control-api}"
C2_PORT="${C2_PORT:-8443}"
RESULTS_DIR="${RESULTS_DIR:-/home/root/results}"
DURATION="${DURATION:-15}"  # seconds of decoy "mining" load
SESSION="$(date +%s)"
LOG="${RESULTS_DIR}/cryptomining_${SESSION}.log"

mkdir -p "$RESULTS_DIR"
say() { echo -e "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
step() { echo "" | tee -a "$LOG"; say "=== $* ==="; }

say "Northline :: cryptomining/resource-hijack emulation :: session=$SESSION duration=${DURATION}s"

step "sustained high-CPU decoy load (ATT&CK T1496)"
st_mark T1496 "cpu-load"; act_here "$(command -v openssl >/dev/null && echo "openssl speed sha256" || echo "busy loop") for ${DURATION}s" "sustained CPU"
if command -v openssl >/dev/null 2>&1; then
    timeout "$DURATION" $ST_NICE openssl speed -seconds "$DURATION" sha256 >/dev/null 2>&1 &
else
    ( END=$((SECONDS + DURATION)); while [ $SECONDS -lt $END ]; do :; done ) &
fi
LOAD_PID=$!
say "decoy CPU-bound process running as pid $LOAD_PID for ${DURATION}s"

step "periodic check-ins against decoy mining pool (ATT&CK T1496)"
END=$(( $(date +%s) + DURATION ))
i=0
while [ "$(date +%s)" -lt "$END" ]; do
    i=$((i+1))
    st_mark T1496 "pool-checkin-$i"
    WORK="$(st_http GET "http://${C2_HOST}:${C2_PORT}/pool/getwork")"
    say "pool getwork #$i -> $WORK"
    st_http POST "http://${C2_HOST}:${C2_PORT}/pool/submit" "job_id=decoy-job-0001 nonce=${i}" >/dev/null
    say "pool submit #$i sent"
    st_sleep "$ST_POLL_MIN" "$ST_POLL_MAX" >/dev/null
done

wait "$LOAD_PID" 2>/dev/null

step "Done — cryptomining emulation complete."
say "artifacts: $LOG  (server-side log: results/control_api_beacons.log)"

act_summary
