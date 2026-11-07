#!/bin/bash
#
# lib-activity.sh — one clear, structured record of every action a scenario
# performs. Sourced by lib-stealth.sh (so every playbook that sources that
# gets it).
#
# Each record is one JSON line in $RESULTS_DIR/activity.jsonl with:
#   ts / epoch      when (UTC, millisecond precision)
#   technique       ATT&CK technique ID, or OWASP-Axx
#   step            short label for the step within the scenario
#   command         what was run / sent
#   src / dst       source and destination container (compose service) names
#   path            URL path, file path, DNS name, or other unique identifier
#   result          exit status or note (optional)
#   scenario/profile  which playbook, which stealth profile
#
# Pure bash on purpose: logging must not spawn extra processes, or the
# bookkeeping would show up as attacker behaviour in the very telemetry
# you are testing.
#
# Functions:
#   act TECHNIQUE COMMAND DEST PATH [RESULT]   record one action
#   act_here COMMAND PATH [RESULT]             same, using the current technique, local destination
#   act_summary                                print this scenario's table + attacks-covered list
#   act_dst HOST                               map a hostname/IP to a container name

LAB_NODE="${LAB_NODE:-$(hostname)}"
ACT_SCENARIO="$(basename "${0:-scenario}" .sh)"
ACT_START="${EPOCHREALTIME:-$(date +%s.%N)}"
ST_TECH="${ST_TECH:-unknown}"
ST_STEP="${ST_STEP:-}"
ACT_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

_act_je() {   # JSON-escape a string without forking
    local LC_ALL=C s="$1"
    s=${s//\\/\\\\}; s=${s//\"/\\\"}; s=${s//$'\n'/\\n}; s=${s//$'\r'/\\r}; s=${s//$'\t'/\\t}
    s=${s//[$'\001'-$'\037']/ }
    printf '%s' "$s"
}

# hostname / IP -> container (service) name
act_dst() {
    case "$1" in
        ""|localhost|127.0.0.1|::1|self) echo "$LAB_NODE" ;;
        169.254.169.254) echo "$LAB_NODE (decoy IMDS)" ;;   # aliased onto this container's loopback
        *) echo "$1" ;;
    esac
}

act() {
    [ -n "${ACT_OFF:-}" ] && return 0   # bookkeeping/preflight calls opt out
    local tech="$1" cmd="$2" dst="$3" path="${4:-}" result="${5:-}" step="$ST_STEP"
    [ "$tech" = "$ST_TECH" ] || step=""   # a step label only applies to its own technique
    local f="${RESULTS_DIR:-/home/root/results}/activity.jsonl" ts="${EPOCHREALTIME:-0.0}" secs ms stamp
    secs="${ts%.*}"; ms="${ts#*.}"; ms="${ms:0:3}"
    printf -v stamp '%(%Y-%m-%dT%H:%M:%S)T' "$secs"
    printf '{"ts":"%s.%sZ","epoch":%s,"scenario":"%s","profile":"%s","technique":"%s","step":"%s","command":"%s","src":"%s","dst":"%s","path":"%s","result":"%s"}\n' \
        "$stamp" "$ms" "$ts" "$ACT_SCENARIO" "${STEALTH_NAME:-noisy}" "$(_act_je "$tech")" "$(_act_je "$step")" \
        "$(_act_je "$cmd")" "$LAB_NODE" "$(_act_je "$(act_dst "$dst")")" "$(_act_je "$path")" "$(_act_je "$result")" \
        >> "$f" 2>/dev/null || true
}
act_here() { act "$ST_TECH" "$1" "$LAB_NODE" "${2:-}" "${3:-}"; }

act_summary() {
    local f="${RESULTS_DIR:-/home/root/results}/activity.jsonl"
    [ -f "$f" ] || return 0
    python3 "$ACT_LIB_DIR/activity-report.py" "$f" --since "$ACT_START" --scenario "$ACT_SCENARIO" 2>/dev/null \
        | tee -a "${LOG:-/dev/null}" || true
}

# For chain scripts: everything recorded since this script started, any scenario.
act_summary_all() {
    local f="${RESULTS_DIR:-/home/root/results}/activity.jsonl"
    [ -f "$f" ] || return 0
    python3 "$ACT_LIB_DIR/activity-report.py" "$f" --since "$ACT_START" 2>/dev/null | tee -a "${LOG:-/dev/null}" || true
}
