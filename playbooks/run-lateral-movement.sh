#!/bin/bash
#
# run-lateral-movement.sh
# ---------------------------------------------------------------------------
# EDR DETECTION COVERAGE — NON-PRODUCTION USE ONLY
#
# Emulates discovery of, and SSH login to, a second host on the internal
# environment network (compose service "internal-host"), using the decoy SSH
# key/credentials seeded by seed-decoys.sh / the internal-host image's own
# decoy account. Everything stays on the environment's internal `cymylau-net` bridge;
# internal-host is a disposable container with no real data and no real
# account.
#
#   nmap sweep of cymylau-net                Network Service Discovery   (T1046)
#   SSH with password/key to peer host  Remote Services: SSH        (T1021.004)
#   use of credentials discovered earlier                            (T1552.004/.001)
# ---------------------------------------------------------------------------
set -u
source "$(cd "$(dirname "$0")" && pwd)/lib-stealth.sh"

RESULTS_DIR="${RESULTS_DIR:-/home/root/results}"
INTERNAL_HOST="${INTERNAL_HOST:-internal-host}"
SSH_USER="${INTERNAL_HOST_USER:-decoyuser}"
SSH_PASS="${INTERNAL_HOST_PASS:-DECOY-NOT-REAL-PASSWORD}"
SSH_PORT="${INTERNAL_HOST_SSH_PORT:-2222}"  # linuxserver/openssh-server listens on 2222, not 22
SESSION="$(date +%s)"
LOG="${RESULTS_DIR}/lateral_${SESSION}.log"

mkdir -p "$RESULTS_DIR"
say() { echo -e "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
step() { echo "" | tee -a "$LOG"; say "=== $* ==="; }

say "Cymylau :: lateral-movement emulation :: session=$SESSION"

TARGET_IP="$(getent hosts "$INTERNAL_HOST" 2>/dev/null | awk '{print $1; exit}')"
if [ -z "${TARGET_IP:-}" ]; then
    say "!! could not resolve $INTERNAL_HOST — is the internal-host service in compose.yml running?"
    exit 1
fi
say "internal-host resolved to $TARGET_IP"

step "network discovery — sweep internal host for open services (ATT&CK T1046)"
st_mark T1046 "scan-internal-host"
st_scan "$INTERNAL_HOST" 22,80,443,2222 | tee -a "$LOG"

step "remote services — SSH login using decoy credentials (ATT&CK T1021.004)"
if ! command -v sshpass >/dev/null 2>&1; then
    say "!! sshpass not installed — run: bash playbooks/install-extra-tools.sh"
    exit 1
fi
st_mark T1021.004 "ssh-login"
st_sshpass "$SSH_PASS"
# the same marker goes on the local sshpass process and, as a comment, into the
# remote command line, so alerts on either side tie back to this action
MARK="$(ax_marker)"; REMOTE="id; hostname"
[ "$ACT_MARKERS" = 1 ] && REMOTE="${REMOTE} # ${MARK}"
RESULT="$(ACT_MARK_PRESET="$MARK" ax T1021.004 "$INTERNAL_HOST" "${SSH_USER}@${INTERNAL_HOST}:${SSH_PORT}" -- \
    "${ST_SSHPASS[@]}" ssh -p "$SSH_PORT" -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
    "${SSH_USER}@${TARGET_IP}" "$REMOTE" 2>&1)"
say "ssh login attempt result:"
echo "$RESULT" | tee -a "$LOG"

step "Done — lateral-movement emulation complete."
say "artifacts: $LOG"

act_summary
