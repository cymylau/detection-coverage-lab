#!/bin/bash
#
# run-defense-evasion.sh
# ---------------------------------------------------------------------------
# EDR DETECTION COVERAGE — NON-PRODUCTION USE ONLY
#
# Emulates common anti-forensics / evasion behaviour. All actions are
# confined to this container and to the environment's own results/decoy files —
# nothing outside the container's filesystem is touched, and no real system
# log is modified.
#
#   masquerading           copy a benign binary under a system-process name  (T1036.003/.004)
#   timestomping           backdate a decoy file's mtime                      (T1070.006)
#   indicator removal       clear shell history, truncate prior run logs        (T1070.003/.002)
# ---------------------------------------------------------------------------
set -u

HOME_DIR="${HOME:-/home/root}"
RESULTS_DIR="${RESULTS_DIR:-${HOME_DIR}/results}"
SESSION="$(date +%s)"
LOG="${RESULTS_DIR}/evasion_${SESSION}.log"
MASQ_PATH="/tmp/.edr_svchost_decoy"

mkdir -p "$RESULTS_DIR"
say() { echo -e "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
step() { echo "" | tee -a "$LOG"; say "=== $* ==="; }

say "Northline :: defense-evasion emulation :: session=$SESSION"

step "process masquerading — benign binary under a suspicious name (ATT&CK T1036.003)"
cp "$(command -v sleep)" "$MASQ_PATH" 2>/dev/null && say "copied 'sleep' -> $MASQ_PATH (looks like a renamed system process)"
"$MASQ_PATH" 0.1 &
MASQ_PID=$!
wait "$MASQ_PID" 2>/dev/null
say "ran masqueraded binary as pid $MASQ_PID, name='$(basename "$MASQ_PATH")'"
rm -f "$MASQ_PATH"

step "timestomping — backdate a decoy file's timestamp (ATT&CK T1070.006)"
DECOY_FILE="${RESULTS_DIR}/evasion_decoy_${SESSION}.txt"
echo "decoy file for timestomp demonstration" > "$DECOY_FILE"
say "created $DECOY_FILE with real mtime: $(date -r "$DECOY_FILE" 2>/dev/null || stat -c %y "$DECOY_FILE")"
touch -d "2001-01-01 00:00:00" "$DECOY_FILE"
say "backdated mtime to 2001-01-01 -> $(date -r "$DECOY_FILE" 2>/dev/null || stat -c %y "$DECOY_FILE")"

step "indicator removal — clear shell history (ATT&CK T1070.003)"
history -c 2>/dev/null && say "cleared in-memory bash history" || say "(history -c not applicable in this shell)"
: > "${HOME_DIR}/.bash_history" 2>/dev/null && say "truncated ~/.bash_history"

step "indicator removal — touch/truncate this environment's own prior run logs (ATT&CK T1070.002, scoped to this environment only)"
OLDEST_LOG="$(find "$RESULTS_DIR" -maxdepth 1 -name 'run_*.log' ! -name "*${SESSION}*" | head -n1)"
if [ -n "${OLDEST_LOG:-}" ]; then
    say "would normally truncate: $OLDEST_LOG (left intact here — demonstration only, not actually deleting environment evidence)"
else
    say "(no prior run_*.log found to demonstrate against — run run-metadata-exfil.sh first for a fuller demo)"
fi

step "Done — defense-evasion emulation complete."
say "artifacts: $LOG"
