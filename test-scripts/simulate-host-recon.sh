#!/bin/bash
#
# simulate-host-recon.sh
# ---------------------------------------------------------------------------
# EDR DETECTION TEST — LAB USE ONLY
#
# Emulates basic post-compromise host/account/permission discovery — the
# commands an attacker runs first on a freshly landed box, before deciding
# what to do next. Pure local enumeration; nothing leaves the container.
#
#   whoami / id / uname -a        System & account discovery   (T1033 / T1082)
#   cat /etc/passwd                Account discovery             (T1087.001)
#   env                            Discovery of env-stored secrets (T1082)
#   find / -perm -4000 -type f     SUID binary discovery          (T1548.001)
#   sudo -l                        Permission-group discovery     (T1069.001)
# ---------------------------------------------------------------------------
set -u

RESULTS_DIR="${RESULTS_DIR:-/home/root/results}"
SESSION="$(date +%s)"
LOG="${RESULTS_DIR}/recon_${SESSION}.log"

mkdir -p "$RESULTS_DIR"
say() { echo -e "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
step() { echo "" | tee -a "$LOG"; say "=== $* ==="; }

say "EDR test lab :: host-recon emulation :: session=$SESSION"

step "whoami / id / uname -a (ATT&CK T1033, T1082)"
whoami 2>&1 | tee -a "$LOG"
id 2>&1 | tee -a "$LOG"
uname -a 2>&1 | tee -a "$LOG"

step "account discovery via /etc/passwd (ATT&CK T1087.001)"
cat /etc/passwd 2>&1 | tee -a "$LOG"

step "environment variable dump (ATT&CK T1082)"
env 2>&1 | tee -a "$LOG"

step "SUID binary discovery (ATT&CK T1548.001)"
find / -xdev -perm -4000 -type f 2>/dev/null | tee -a "$LOG"

step "sudo permission enumeration (ATT&CK T1069.001)"
if command -v sudo >/dev/null 2>&1; then
    sudo -l 2>&1 | tee -a "$LOG"
else
    say "(sudo not installed in this image — expected in most minimal containers)"
fi

step "Done — host-recon emulation complete."
say "artifacts: $LOG"
