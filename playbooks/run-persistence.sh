#!/bin/bash
#
# run-persistence.sh
# ---------------------------------------------------------------------------
# EDR DETECTION COVERAGE — NON-PRODUCTION USE ONLY
#
# Emulates common persistence-establishment techniques. Everything created
# points at a harmless no-op decoy script and is fully removable with
# --cleanup. Nothing here achieves real persistence beyond this container.
#
#   cron entry                 Scheduled Task/Job: Cron           (T1053.003)
#   systemd user unit          Create/Modify System Process        (T1543.002)
#   .bashrc append             Boot/Logon Autostart Execution       (T1546.004)
#
# Usage:
#   bash playbooks/run-persistence.sh            # install
#   bash playbooks/run-persistence.sh --cleanup   # remove
# ---------------------------------------------------------------------------
set -u
source "$(cd "$(dirname "$0")" && pwd)/lib-stealth.sh"

source "$(cd "$(dirname "$0")" && pwd)/lib-guard.sh"
require_lab_container

HOME_DIR="${HOME:-/home/root}"
RESULTS_DIR="${RESULTS_DIR:-${HOME_DIR}/results}"
MARKER="# cymylau-persistence-decoy"
DECOY_SCRIPT="${HOME_DIR}/.edr_decoy_payload.sh"
UNIT_DIR="${HOME_DIR}/.config/systemd/user"
UNIT_FILE="${UNIT_DIR}/cymylau-decoy.service"

mkdir -p "$RESULTS_DIR"
say() { echo "[persistence] $*"; }

cleanup() {
    say "removing persistence artifacts..."
    crontab -l 2>/dev/null | grep -v "$MARKER" | crontab - 2>/dev/null || true
    rm -f "$UNIT_FILE" "$DECOY_SCRIPT"
    if [ -f "${HOME_DIR}/.bashrc" ]; then
        sed -i "/${MARKER//\//\\/}/d" "${HOME_DIR}/.bashrc" 2>/dev/null || true
    fi
    say "done."
}

if [ "${1:-}" = "--cleanup" ]; then
    cleanup
    exit 0
fi

SESSION="$(date +%s)"
LOG="${RESULTS_DIR}/persistence_${SESSION}.log"
log() { echo -e "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
step() { echo "" | tee -a "$LOG"; log "=== $* ==="; }

log "Cymylau :: persistence emulation :: session=$SESSION"

cat > "$DECOY_SCRIPT" <<EOF
#!/bin/bash
$MARKER
echo "cymylau decoy persistence payload executed at \$(date -u)" >> "$RESULTS_DIR/persistence_trigger.log"
EOF
chmod +x "$DECOY_SCRIPT"
log "wrote harmless decoy payload -> $DECOY_SCRIPT"

step "cron persistence (ATT&CK T1053.003)"
st_mark T1053.003 "cron"
if command -v crontab >/dev/null 2>&1; then
    ( crontab -l 2>/dev/null; echo "*/15 * * * * $DECOY_SCRIPT $MARKER" ) | ax_here "crontab for $(id -un) -> $DECOY_SCRIPT" -- crontab -
    log "installed cron entry (runs every 15m, tagged for cleanup):"
    crontab -l 2>&1 | tee -a "$LOG"
else
    log "(crontab not available in this image — skipped)"
fi

step "systemd user-unit persistence (ATT&CK T1543.002)"
st_mark T1543.002 "systemd-unit"
mkdir -p "$UNIT_DIR"
ax_here "$UNIT_FILE" -- tee "$UNIT_FILE" >/dev/null <<EOF
[Unit]
Description=Cymylau decoy persistence unit $MARKER

[Service]
ExecStart=$DECOY_SCRIPT

[Install]
WantedBy=default.target
EOF
log "wrote systemd user unit -> $UNIT_FILE (not enabled — file creation is the detection signal)"

step "shell-profile autostart persistence (ATT&CK T1546.004)"
st_mark T1546.004 "bashrc"
echo "${DECOY_SCRIPT} #${MARKER#\#}" | ax_here "${HOME_DIR}/.bashrc" -- tee -a "${HOME_DIR}/.bashrc" >/dev/null
log "appended decoy autostart line to ${HOME_DIR}/.bashrc"

step "Done — persistence emulation complete."
log "artifacts: $LOG"
log "remove everything with: bash playbooks/run-persistence.sh --cleanup"

act_summary
