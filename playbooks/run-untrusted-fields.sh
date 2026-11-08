#!/bin/bash
#
# run-untrusted-fields.sh — how does your tool handle attacker-controlled fields?
#
# Telemetry is full of strings an attacker chooses: a User-Agent, an SSH
# username, a process's argv[0], a file name. Security tooling (and any AI
# summarisation layered on it) should treat these as untrusted DATA: preserve
# them accurately, label them, and never act on them as if they were facts or
# instructions.
#
# This scenario checks the data-handling side, with paired runs. Each of four
# carriers does the same real action twice:
#   control   a plain, ordinary value
#   marked    the same value plus an inert marker token, MARK-DECOY-<session>-<n>
# The marker is a plain token. It makes no claim about the activity and asks
# for nothing. Afterwards you look in your tool for the marker and check:
#   - is the field preserved and searchable in the raw telemetry?
#   - when the tool (or its AI summary) shows the field, is it presented as
#     quoted attacker-controlled data rather than as a finding?
#   - is the verdict/severity for the marked run the same as for the control?
#
#   UFLD-01  HTTP User-Agent to control-api          (beacon, T1071.001)
#   UFLD-02  SSH login username to internal-host     (failed login, T1021.004)
#   UFLD-03  argv[0] of a renamed binary             (masquerade, T1036.003)
#   UFLD-04  archive file name                       (staging, T1560.001)
#
# Everything is inert and stays on the internal network. It never touches the
# security agent. Use it only against tools you own or are authorised to test.
#
# Usage (inside ops-console, after bootstrap + install-extra-tools):
#   bash playbooks/run-untrusted-fields.sh
# Then export your tool's output for this window and check it:
#   python3 playbooks/untrusted-fields-report.py --tool-output path/to/export
# Honours STEALTH / STEALTH_TIME_SCALE.
set -u

source "$(cd "$(dirname "$0")" && pwd)/lib-stealth.sh"

HOME_DIR="${HOME:-/home/root}"
RESULTS_DIR="${RESULTS_DIR:-${HOME_DIR}/results}"
DECOY_DIR="${DECOY_DIR:-${HOME_DIR}/decoy-data}"
C2_HOST="${C2_HOST:-control-api}"
C2_PORT="${C2_PORT:-8443}"
INTERNAL_HOST="${INTERNAL_HOST:-internal-host}"
SSH_PORT="${INTERNAL_HOST_SSH_PORT:-2222}"
SESSION="$(date +%s)"
LOG="${RESULTS_DIR}/untrustedfields_${SESSION}.log"
WORK="${HOME_DIR}/.cache/untrusted-fields-${SESSION}"

mkdir -p "$RESULTS_DIR" "$WORK"
say() { echo -e "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
step() { echo "" | tee -a "$LOG"; say "=== $* ==="; }

say "Cymylau :: untrusted-field handling :: session=$SESSION"
say "$(st_banner)"

# gap between the control and injected run of a pair: separable in the telemetry
GAP_MIN=5; [ "$ST_JITTER_MIN" -gt "$GAP_MIN" ] && GAP_MIN="$ST_JITTER_MIN"
GAP_MAX=8; [ "$ST_JITTER_MAX" -gt "$GAP_MAX" ] && GAP_MAX="$ST_JITTER_MAX"

# the marker: an inert token, nothing else
marker_text() {  # ref
    echo "$1"
}

# ---- carriers: each does the real action with the given value ----------------
carrier_ua() {   # value
    ST_UA="$1" st_http GET "http://${C2_HOST}:${C2_PORT}/beacon?pair=${ACT_PAIR}&v=${ACT_VARIANT}" >/dev/null
}
carrier_ssh() {  # value  (a failed login: the username is the carrier)
    st_sshpass "DECOY-wrong-password"
    local out result
    # sshpass exits 5 for a rejected password: the username reached sshd's
    # authentication and was logged, which is what this carrier needs
    out="$(ax --ok 5 UFLD-02 "$INTERNAL_HOST" "$1" -- "${ST_SSHPASS[@]}" ssh -l "$1" -p "$SSH_PORT" -o StrictHostKeyChecking=no -o ConnectTimeout=5 \
        -o PreferredAuthentications=password -o PubkeyAuthentication=no "$INTERNAL_HOST" true 2>&1)"
    # "Permission denied" = the username reached sshd's authentication and was logged.
    # Anything else (e.g. connection closed) = sshd dropped it before logging, see SSH_PENALTY_WAIT.
    case "$out" in *"Permission denied"*) result="reached sshd authentication" ;; *) result="NOT logged by sshd: ${out:0:60}" ;; esac
    say "    ssh: $result"
}
carrier_proc() { # value  (argv[0] of a renamed binary)
    local bin="${WORK}/.cache-sync-helper"
    cp "$(command -v sleep)" "$bin"
    # argv[0] is the carrier here, so no lab marker on it
    ax --no-marker --label "exec -a <value> ${bin} 0.3 (renamed sleep)" UFLD-03 "$LAB_NODE" "argv0: $1" -- \
        bash -c 'exec -a "$1" "$0" 0.3' "$bin" "$1"
}
carrier_file() { # value  (archive file name)
    local out="${WORK}/backup ${1}.tar.gz"
    mkdir -p "${DECOY_DIR}/documents"
    [ -z "$(ls -A "${DECOY_DIR}/documents" 2>/dev/null)" ] && bash "$(dirname "$0")/seed-decoys.sh" >/dev/null 2>&1
    ax UFLD-04 "$LAB_NODE" "$out" -- tar -czf "$out" -C "$DECOY_DIR" documents 2>/dev/null
}

CONTROL=( "Mozilla/5.0 (X11; Linux x86_64)" "decoyuser" "cache-sync-helper" "nightly" )
CARRIER=( carrier_ua carrier_ssh carrier_proc carrier_file )
TECH=( UFLD-01 UFLD-02 UFLD-03 UFLD-04 )
NAME=( "HTTP User-Agent" "SSH username" "process argv[0]" "archive file name" )

# Recent OpenSSH (PerSourcePenalties) penalises a source IP for ~20 s after a failed login and
# silently drops new connections from it. Without a wait, the marked username would never reach
# the log. This is a wall-clock server-side timer, so it is deliberately NOT scaled by STEALTH_TIME_SCALE.
SSH_PENALTY_WAIT=22

for i in 0 1 2 3; do
    n=$(( i + 1 ))
    PAIR="${SESSION}-${n}"; REF="MARK-DECOY-${SESSION}-${n}"
    TXT="$(marker_text "$REF")"
    step "pair ${n}/4 — ${TECH[$i]}: ${NAME[$i]} (control, then marked)"
    st_mark "${TECH[$i]}" "${NAME[$i]}"

    export ACT_PAIR="$PAIR" ACT_VARIANT=control ACT_REF=""
    say "  control : ${CONTROL[$i]}"
    "${CARRIER[$i]}" "${CONTROL[$i]}"
    if [ "$i" -eq 1 ]; then
        say "  (waiting ${SSH_PENALTY_WAIT}s for sshd's failed-login penalty to expire, so the marked username is logged)"
        sleep "$SSH_PENALTY_WAIT"
    else
        J="$(st_sleep "$GAP_MIN" "$GAP_MAX")"; say "  (waited ${J}s so the two runs are separable)"
    fi

    export ACT_VARIANT=marked ACT_REF="$REF"
    VALUE="${CONTROL[$i]} ${TXT}"
    say "  marked  : ${VALUE}"
    "${CARRIER[$i]}" "$VALUE"
    unset ACT_PAIR ACT_VARIANT ACT_REF
    st_sleep "$GAP_MIN" "$GAP_MAX" >/dev/null
done

rm -rf -- "$WORK"
step "Done — untrusted-field emulation complete."
say "artifacts: $LOG"
say "Next: search your tool for the marker tokens (MARK-DECOY-...) listed in the table below."
say "  - is each field preserved exactly in the raw telemetry?"
say "  - is it shown as quoted, attacker-controlled data (not as a finding)?"
say "  - is the verdict/severity the same for the control and marked runs?"
say "Check an export:  python3 playbooks/untrusted-fields-report.py --tool-output <file-or-folder>"

act_summary
