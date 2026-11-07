#!/bin/bash
#
# run-credential-discovery.sh
# ---------------------------------------------------------------------------
# EDR DETECTION COVERAGE — NON-PRODUCTION USE ONLY
#
# Emulates on-disk credential hunting (LaZagne/Mimikatz-adjacent file-based
# behaviour, not memory dumping). Requires decoys from seed-decoys.sh — run
# that first. Every file touched here is a DECOY planted by this environment; no
# real key material or credentials exist on disk.
#
#   find/grep for SSH keys          Unsecured credentials: SSH keys (T1552.004)
#   read cloud credentials file     Unsecured credentials: cloud creds (T1552.001)
#   read browser-login store        Credentials from password stores  (T1555.003)
# ---------------------------------------------------------------------------
set -u
source "$(cd "$(dirname "$0")" && pwd)/lib-stealth.sh"

HOME_DIR="${HOME:-/home/root}"
RESULTS_DIR="${RESULTS_DIR:-${HOME_DIR}/results}"
SESSION="$(date +%s)"
LOG="${RESULTS_DIR}/creddisco_${SESSION}.log"

mkdir -p "$RESULTS_DIR"
say() { echo -e "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
step() { echo "" | tee -a "$LOG"; say "=== $* ==="; }

say "Cymylau :: on-disk credential-discovery emulation :: session=$SESSION"

if [ ! -f "${HOME_DIR}/.ssh/id_rsa" ] && [ ! -f "${HOME_DIR}/.aws/credentials" ]; then
    say "!! no decoys found — run: bash playbooks/seed-decoys.sh first"
fi

step "SSH private key discovery (ATT&CK T1552.004)"
st_mark T1552.004 "ssh-key-discovery"
act_here "$([ "$ST_TOOLING" -eq 0 ] && echo "find -iname id_rsa*" || echo "targeted key lookup")" "$HOME_DIR"
case "$ST_TOOLING" in
    0) find "$HOME_DIR" -maxdepth 3 -iname 'id_rsa*' -o -iname '*.pem' 2>/dev/null | tee -a "$LOG" ;;
    1) find "$HOME_DIR/.ssh" -maxdepth 1 -iname 'id_*' 2>/dev/null | tee -a "$LOG" ;;
    *) [ -e "$HOME_DIR/.ssh/id_rsa" ] && echo "$HOME_DIR/.ssh/id_rsa" | tee -a "$LOG" ;;  # known path, no filesystem search
esac
if [ -f "${HOME_DIR}/.ssh/id_rsa" ]; then
    say "reading discovered key: ${HOME_DIR}/.ssh/id_rsa"
    act T1552.004 "cat (read private key)" "$LAB_NODE" "${HOME_DIR}/.ssh/id_rsa"
    cat "${HOME_DIR}/.ssh/id_rsa" > /dev/null  # read access is the signal; content not needed
fi

step "cloud credential file discovery (ATT&CK T1552.001)"
st_mark T1552.001 "cloud-cred-discovery"
act_here "$([ "$ST_TOOLING" -eq 0 ] && echo "find -iname credentials" || echo "targeted lookup")" "$HOME_DIR/.aws"
case "$ST_TOOLING" in
    0) find "$HOME_DIR" -maxdepth 3 -iname 'credentials' -path '*.aws*' 2>/dev/null | tee -a "$LOG" ;;
    1) find "$HOME_DIR/.aws" -maxdepth 1 -iname 'credentials' 2>/dev/null | tee -a "$LOG" ;;
    *) [ -e "$HOME_DIR/.aws/credentials" ] && echo "$HOME_DIR/.aws/credentials" | tee -a "$LOG" ;;
esac
if [ -f "${HOME_DIR}/.aws/credentials" ]; then
    say "reading discovered cloud credentials: ${HOME_DIR}/.aws/credentials"
    act T1552.001 "grep -i key (read cloud credentials)" "$LAB_NODE" "${HOME_DIR}/.aws/credentials"
    grep -i 'key' "${HOME_DIR}/.aws/credentials" | tee -a "$LOG"
fi

step "browser credential store discovery (ATT&CK T1555.003)"
st_mark T1555.003 "browser-cred-discovery"
act_here "$([ "$ST_TOOLING" -eq 0 ] && echo "find -iname logins.sqlite" || echo "targeted lookup")" "$HOME_DIR/.mozilla_decoy"
case "$ST_TOOLING" in
    0) find "$HOME_DIR" -maxdepth 3 -iname 'logins.sqlite' -o -iname '*Login Data*' 2>/dev/null | tee -a "$LOG" ;;
    1) find "$HOME_DIR/.mozilla_decoy" -maxdepth 1 -iname 'logins.sqlite' 2>/dev/null | tee -a "$LOG" ;;
    *) [ -e "$HOME_DIR/.mozilla_decoy/logins.sqlite" ] && echo "$HOME_DIR/.mozilla_decoy/logins.sqlite" | tee -a "$LOG" ;;
esac
LOGIN_DB="${HOME_DIR}/.mozilla_decoy/logins.sqlite"
if [ -f "$LOGIN_DB" ]; then
    say "reading discovered browser-credential store: $LOGIN_DB"
    if command -v sqlite3 >/dev/null 2>&1; then
        act T1555.003 "sqlite3 SELECT hostname, username FROM moz_logins" "$LAB_NODE" "$LOGIN_DB"
        sqlite3 "$LOGIN_DB" "SELECT hostname, username FROM moz_logins;" 2>&1 | tee -a "$LOG"
    else
        say "(sqlite3 not installed — file access alone is the detection signal)"
    fi
fi

step "Done — credential-discovery emulation complete."
say "artifacts: $LOG"

act_summary
