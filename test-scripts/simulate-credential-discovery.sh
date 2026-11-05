#!/bin/bash
#
# simulate-credential-discovery.sh
# ---------------------------------------------------------------------------
# EDR DETECTION TEST — LAB USE ONLY
#
# Emulates on-disk credential hunting (LaZagne/Mimikatz-adjacent file-based
# behaviour, not memory dumping). Requires decoys from seed-decoys.sh — run
# that first. Every file touched here is a DECOY planted by this lab; no
# real key material or credentials exist on disk.
#
#   find/grep for SSH keys          Unsecured credentials: SSH keys (T1552.004)
#   read cloud credentials file     Unsecured credentials: cloud creds (T1552.001)
#   read browser-login store        Credentials from password stores  (T1555.003)
# ---------------------------------------------------------------------------
set -u

HOME_DIR="${HOME:-/home/root}"
RESULTS_DIR="${RESULTS_DIR:-${HOME_DIR}/results}"
SESSION="$(date +%s)"
LOG="${RESULTS_DIR}/creddisco_${SESSION}.log"

mkdir -p "$RESULTS_DIR"
say() { echo -e "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
step() { echo "" | tee -a "$LOG"; say "=== $* ==="; }

say "EDR test lab :: on-disk credential-discovery emulation :: session=$SESSION"

if [ ! -f "${HOME_DIR}/.ssh/id_rsa" ] && [ ! -f "${HOME_DIR}/.aws/credentials" ]; then
    say "!! no decoys found — run: bash test-scripts/seed-decoys.sh first"
fi

step "SSH private key discovery (ATT&CK T1552.004)"
find "$HOME_DIR" -maxdepth 3 -iname 'id_rsa*' -o -iname '*.pem' 2>/dev/null | tee -a "$LOG"
if [ -f "${HOME_DIR}/.ssh/id_rsa" ]; then
    say "reading discovered key: ${HOME_DIR}/.ssh/id_rsa"
    cat "${HOME_DIR}/.ssh/id_rsa" > /dev/null  # read access is the signal; content not needed
fi

step "cloud credential file discovery (ATT&CK T1552.001)"
find "$HOME_DIR" -maxdepth 3 -iname 'credentials' -path '*.aws*' 2>/dev/null | tee -a "$LOG"
if [ -f "${HOME_DIR}/.aws/credentials" ]; then
    say "reading discovered cloud credentials: ${HOME_DIR}/.aws/credentials"
    grep -i 'key' "${HOME_DIR}/.aws/credentials" | tee -a "$LOG"
fi

step "browser credential store discovery (ATT&CK T1555.003)"
find "$HOME_DIR" -maxdepth 3 -iname 'logins.sqlite' -o -iname '*Login Data*' 2>/dev/null | tee -a "$LOG"
LOGIN_DB="${HOME_DIR}/.mozilla_decoy/logins.sqlite"
if [ -f "$LOGIN_DB" ]; then
    say "reading discovered browser-credential store: $LOGIN_DB"
    if command -v sqlite3 >/dev/null 2>&1; then
        sqlite3 "$LOGIN_DB" "SELECT hostname, username FROM moz_logins;" 2>&1 | tee -a "$LOG"
    else
        say "(sqlite3 not installed — file access alone is the detection signal)"
    fi
fi

step "Done — credential-discovery emulation complete."
say "artifacts: $LOG"
