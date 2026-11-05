#!/bin/bash
#
# simulate-impair-logging.sh
# ---------------------------------------------------------------------------
# CLOUD/CONTAINER EDR (CDR) DETECTION TEST — LAB USE ONLY
#
# Emulates the "disable audit logging, then act" sequencing seen in cloud
# intrusions (e.g. disabling CloudTrail before running further API calls).
# Calls mock-c2's /logging/disable endpoint, which only flips an in-memory
# flag on that mock process — nothing real is ever affected — then
# demonstrates a follow-on action (a beacon) to show the intended sequence.
#
#   disable cloud audit logging           Impair Defenses: Disable Cloud Logs (T1562.008)
#   follow-on action after disabling logs  (sequencing signal for correlation)
# ---------------------------------------------------------------------------
set -u

RESULTS_DIR="${RESULTS_DIR:-/home/root/results}"
C2_HOST="${C2_HOST:-mock-c2}"
C2_PORT="${C2_PORT:-8443}"
SESSION="$(date +%s)"
LOG="${RESULTS_DIR}/impairlogging_${SESSION}.log"

mkdir -p "$RESULTS_DIR"
say() { echo -e "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
step() { echo "" | tee -a "$LOG"; say "=== $* ==="; }

say "CDR test lab :: impair-cloud-logging emulation :: session=$SESSION"

step "check current (mock) logging state"
curl -s --max-time 5 "http://${C2_HOST}:${C2_PORT}/logging/status" | tee -a "$LOG"
echo "" | tee -a "$LOG"

step "impair defenses — disable mock audit logging (ATT&CK T1562.008)"
RESP="$(curl -s --max-time 5 -X POST "http://${C2_HOST}:${C2_PORT}/logging/disable")"
say "disable-logging response: $RESP"

step "follow-on action performed right after disabling logging (sequencing signal)"
curl -s --max-time 5 "http://${C2_HOST}:${C2_PORT}/beacon?post_log_disable=1" | tee -a "$LOG"
echo "" | tee -a "$LOG"

step "Done — impair-logging emulation complete."
say "note: /logging/disable only flips mock-c2's own in-memory flag; nothing"
say "real was affected. Reset it by restarting the mock-c2 container."
say "artifacts: $LOG  (server-side log: results/mock_c2_beacons.log)"
