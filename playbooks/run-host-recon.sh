#!/bin/bash
#
# run-host-recon.sh
# ---------------------------------------------------------------------------
# EDR DETECTION COVERAGE — NON-PRODUCTION USE ONLY
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
source "$(cd "$(dirname "$0")" && pwd)/lib-stealth.sh"

RESULTS_DIR="${RESULTS_DIR:-/home/root/results}"
SESSION="$(date +%s)"
LOG="${RESULTS_DIR}/recon_${SESSION}.log"

mkdir -p "$RESULTS_DIR"
say() { echo -e "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
step() { echo "" | tee -a "$LOG"; say "=== $* ==="; }

say "Cymylau :: host-recon emulation :: session=$SESSION"

step "whoami / id / uname -a (ATT&CK T1033, T1082)"
st_mark T1033 "whoami-id"
ax_here "current user" -- whoami 2>&1 | tee -a "$LOG"
ax_here "current user" -- id 2>&1 | tee -a "$LOG"
st_mark T1082 "uname"
ax_here "kernel/os" -- uname -a 2>&1 | tee -a "$LOG"

say "$(st_banner)"

# tooling >=2 keeps recon to the three commands above (minimal footprint)
if [ "$ST_TOOLING" -ge 2 ]; then
    say "(minimal recon at this stealth level — skipping passwd/env/SUID/sudo enumeration)"
    step "Done — host-recon emulation complete."
    say "artifacts: $LOG"
    act_summary
    exit 0
fi

step "account discovery via /etc/passwd (ATT&CK T1087.001)"
st_mark T1087.001 "passwd"
ax_here /etc/passwd -- cat /etc/passwd 2>&1 | tee -a "$LOG"

if [ "$ST_TOOLING" -eq 0 ]; then
    step "environment variable dump (ATT&CK T1082)"
    st_mark T1082 "env"
    ax_here "process environment" -- env 2>&1 | tee -a "$LOG"
fi

step "SUID binary discovery (ATT&CK T1548.001)"
st_mark T1548.001 "suid-search"
# find exits 1 when some directories are unreadable; that is normal here
if [ "$ST_TOOLING" -eq 0 ]; then
    ax_here --ok 0,1 / -- find / -xdev -perm -4000 -type f 2>/dev/null | tee -a "$LOG"
else
    ax_here --ok 0,1 "/usr/bin /usr/sbin /bin /sbin" -- find /usr/bin /usr/sbin /bin /sbin -xdev -perm -4000 -type f 2>/dev/null | tee -a "$LOG"   # scoped, not a whole-filesystem walk
fi

step "sudo permission enumeration (ATT&CK T1069.001)"
st_mark T1069.001 "sudo-l"
if command -v sudo >/dev/null 2>&1; then
    # non-zero when the user may not run sudo: the enumeration still happened
    ax_here --ok any "sudo policy" -- sudo -l 2>&1 | tee -a "$LOG"
else
    say "(sudo not installed in this image — expected in most minimal containers)"
fi

step "Done — host-recon emulation complete."
say "artifacts: $LOG"

act_summary
