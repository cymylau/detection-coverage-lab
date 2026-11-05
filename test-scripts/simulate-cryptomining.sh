#!/bin/bash
#
# simulate-cryptomining.sh
# ---------------------------------------------------------------------------
# CLOUD/CONTAINER EDR (CDR) DETECTION TEST — LAB USE ONLY
#
# Emulates resource-hijacking/cryptomining behaviour: a sustained high-CPU
# process plus periodic HTTP polling of a mock "mining pool" (mock-c2's
# /pool/getwork and /pool/submit, shaped like stratum-over-HTTP check-ins).
# No real mining occurs — the CPU load is openssl benchmarking, not an
# actual miner, and the pool is the lab's own mock-c2.
#
#   sustained high-CPU child process      Resource Hijacking   (T1496)
#   periodic outbound "pool" check-ins     Resource Hijacking   (T1496)
#
# Usage: DURATION=20 bash test-scripts/simulate-cryptomining.sh
# ---------------------------------------------------------------------------
set -u

C2_HOST="${C2_HOST:-mock-c2}"
C2_PORT="${C2_PORT:-8443}"
RESULTS_DIR="${RESULTS_DIR:-/home/root/results}"
DURATION="${DURATION:-15}"  # seconds of decoy "mining" load
SESSION="$(date +%s)"
LOG="${RESULTS_DIR}/cryptomining_${SESSION}.log"

mkdir -p "$RESULTS_DIR"
say() { echo -e "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
step() { echo "" | tee -a "$LOG"; say "=== $* ==="; }

say "CDR test lab :: cryptomining/resource-hijack emulation :: session=$SESSION duration=${DURATION}s"

step "sustained high-CPU decoy load (ATT&CK T1496)"
if command -v openssl >/dev/null 2>&1; then
    timeout "$DURATION" openssl speed -seconds "$DURATION" sha256 >/dev/null 2>&1 &
else
    ( END=$((SECONDS + DURATION)); while [ $SECONDS -lt $END ]; do :; done ) &
fi
LOAD_PID=$!
say "decoy CPU-bound process running as pid $LOAD_PID for ${DURATION}s"

step "periodic check-ins against mock mining pool (ATT&CK T1496)"
END=$(( $(date +%s) + DURATION ))
i=0
while [ "$(date +%s)" -lt "$END" ]; do
    i=$((i+1))
    WORK="$(curl -s --max-time 5 "http://${C2_HOST}:${C2_PORT}/pool/getwork")"
    say "pool getwork #$i -> $WORK"
    curl -s --max-time 5 -X POST -d "job_id=lab-decoy-job-0001 nonce=${i}" \
        "http://${C2_HOST}:${C2_PORT}/pool/submit" >/dev/null
    say "pool submit #$i sent"
    sleep 3
done

wait "$LOAD_PID" 2>/dev/null

step "Done — cryptomining emulation complete."
say "artifacts: $LOG  (server-side log: results/mock_c2_beacons.log)"
