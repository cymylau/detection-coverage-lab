#!/bin/bash
#
# lib-activity.sh — the record of every action a scenario performs. Sourced by
# lib-stealth.sh (so every playbook that sources that gets it).
#
# The record is written by the code that runs the action, not typed next to it:
#
#   ax [OPTIONS] TECHNIQUE DEST PATH -- COMMAND [ARGS...]
#       runs COMMAND and records what really ran: its argv, exit status, start
#       and end time, and a per-action marker. Output and redirections behave as
#       if COMMAND had been run directly, and ax returns COMMAND's exit status.
#       OPTIONS:
#         --ok RCS      exit statuses that count as success, e.g. --ok 0,1 or
#                       --ok any (a failed login that is meant to fail); default 0
#         --no-marker   run COMMAND with its own argv[0] (when argv[0] is the test)
#         --label TEXT  short description stored next to the real argv
#       ACT_MARK_PRESET=<marker from ax_marker> ax ...  uses that marker, so the
#       same token can also go into a remote command string (see run-lateral-movement.sh)
#
#   act_declared TECHNIQUE COMMAND DEST PATH [RESULT]
#       for steps that cannot be run on their own: commands inside a remote SSH
#       session that ax ran as one action. The record says it is declared, and
#       carries the marker of the enclosing action (ACT_PARENT) when there is one.
#
# The marker. Each executed external command gets a unique token, cdl-<run>-<n>,
# appended to its argv[0]:  cat /etc/passwd  runs as  "cat#cdl-k3f9-0412 /etc/passwd".
# The executable, its path and the kernel's process name (comm) are unchanged, so
# rules keyed on the binary still fire; the token shows wherever a tool records
# the command line, and detection-report.py uses it to tie an alert to the exact
# action that caused it. ACT_MARKERS=0 turns markers off (unmodified command
# lines; scoring then falls back to technique + time).
#
# Each record is one JSON line in $RESULTS_DIR/activity.jsonl:
#   ts / epoch / end   when it started (UTC, ms) and finished (epoch)
#   kind               exec (ran by ax) | declared (act_declared)
#   technique / step   ATT&CK ID (or OWASP-Axx, UFLD-nn) and the step label
#   command            the label, or the argv when there is no label
#   argv               the exact argv that ran, shell-quoted (exec only)
#   rc / ok            exit status, and whether it counts as success
#   marker / parent    this action's marker; the enclosing action's marker
#   src / dst / path   source and destination container, and the target
#   pair/variant/ref   paired runs only (untrusted-fields scenario)
#   scenario/profile/run
#
# Bookkeeping is pure bash on purpose: no extra processes, or the logging would
# show up as attacker behaviour in the very telemetry being tested.

LAB_NODE="${LAB_NODE:-$(hostname)}"
ACT_SCENARIO="$(basename "${0:-scenario}" .sh)"
ACT_START="${EPOCHREALTIME:-$(date +%s.%N)}"
ST_TECH="${ST_TECH:-unknown}"
ST_STEP="${ST_STEP:-}"
ACT_LIB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ACT_MARKERS="${ACT_MARKERS:-1}"
# run id: set by run-everything.sh for the whole run; otherwise one per script
if [ -z "${CDL_RUN:-}" ]; then
    _r="${EPOCHREALTIME/./}"; CDL_RUN="${_r:(-10):4}"; unset _r
fi
export CDL_RUN ACT_MARKERS

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

# a new marker in ACT_MARK; unique within the run (microsecond clock + pid)
_act_new_marker() {
    local us="${EPOCHREALTIME/./}"
    ACT_MARK="cdl-${CDL_RUN}-${us:(-7)}${BASHPID: -2}"
}

# _act_write KIND TECH COMMAND DEST PATH RESULT T0 [T1 ARGV RC OK MARKER]
_act_write() {
    [ -n "${ACT_OFF:-}" ] && return 0   # bookkeeping/preflight calls opt out
    local kind="$1" tech="$2" cmd="$3" dst="$4" path="$5" result="$6" ts="$7"
    local t1="${8:-}" argv="${9:-}" rc="${10:-}" ok="${11:-}" mark="${12:-}"
    local step="$ST_STEP" f="${RESULTS_DIR:-/home/root/results}/activity.jsonl" secs ms stamp extra=""
    [ "$tech" = "$ST_TECH" ] || step=""   # a step label only applies to its own technique
    secs="${ts%.*}"; ms="${ts#*.}"; ms="${ms:0:3}"
    printf -v stamp '%(%Y-%m-%dT%H:%M:%S)T' "$secs"
    if [ "$kind" = exec ]; then
        printf -v extra ',"end":%s,"argv":"%s","rc":%s,"ok":%s,"marker":"%s"' \
            "$t1" "$(_act_je "$argv")" "$rc" "$ok" "$mark"
    fi
    [ -n "${ACT_PARENT:-}" ] && printf -v extra '%s,"parent":"%s"' "$extra" "$ACT_PARENT"
    [ -n "${ACT_PAIR:-}" ] && printf -v extra '%s,"pair":"%s","variant":"%s","ref":"%s"' "$extra" \
        "$(_act_je "$ACT_PAIR")" "$(_act_je "${ACT_VARIANT:-}")" "$(_act_je "${ACT_REF:-}")"
    printf '{"ts":"%s.%sZ","epoch":%s,"kind":"%s","run":"%s","scenario":"%s","profile":"%s","technique":"%s","step":"%s","command":"%s","src":"%s","dst":"%s","path":"%s","result":"%s"%s}\n' \
        "$stamp" "$ms" "$ts" "$kind" "$CDL_RUN" "$ACT_SCENARIO" "${STEALTH_NAME:-noisy}" "$(_act_je "$tech")" "$(_act_je "$step")" \
        "$(_act_je "$cmd")" "$LAB_NODE" "$(_act_je "$(act_dst "$dst")")" "$(_act_je "$path")" "$(_act_je "$result")" "$extra" \
        >> "$f" 2>/dev/null || true
}

ax() {
    local okrcs="0" marker="$ACT_MARKERS" label=""
    while :; do
        case "${1:-}" in
            --ok) okrcs="$2"; shift 2 ;;
            --no-marker) marker=0; shift ;;
            --label) label="$2"; shift 2 ;;
            *) break ;;
        esac
    done
    local tech="$1" dst="$2" path="$3"; shift 3
    [ "${1:-}" = "--" ] && shift
    if [ $# -eq 0 ]; then echo "ax: no command given" >&2; return 2; fi
    local t0="$EPOCHREALTIME" t1 rc ok=false argv="" mark="" a
    for a in "$@"; do printf -v argv '%s%q ' "$argv" "$a"; done
    argv="${argv% }"
    local ACT_MARK=""
    if [ "$marker" = 1 ] && [ "$(type -t "$1")" = file ]; then
        if [ -n "${ACT_MARK_PRESET:-}" ]; then ACT_MARK="$ACT_MARK_PRESET"; else _act_new_marker; fi
        mark="$ACT_MARK"
        ( exec -a "${1##*/}#${mark}" "$@" ); rc=$?
    elif [ "$(type -t "$1")" = file ]; then
        ( exec "$@" ); rc=$?
    else
        "$@"; rc=$?      # builtin or function: no process of its own to mark
    fi
    t1="$EPOCHREALTIME"
    case ",${okrcs}," in *",any,"*|*",${rc},"*) ok=true ;; esac
    _act_write exec "$tech" "${label:-$argv}" "$dst" "$path" "" "$t0" "$t1" "$argv" "$rc" "$ok" "$mark"
    return "$rc"
}

# ax_here [OPTIONS] PATH -- COMMAND...   ax with the current technique and a local destination
ax_here() {
    local opts=()
    while :; do
        case "${1:-}" in
            --ok|--label) opts+=("$1" "$2"); shift 2 ;;
            --no-marker) opts+=("$1"); shift ;;
            *) break ;;
        esac
    done
    local path="$1"; shift
    ax ${opts[@]+"${opts[@]}"} "$ST_TECH" "$LAB_NODE" "$path" "$@"
}

# ax_marker: print a fresh marker (for embedding in a remote command string)
ax_marker() { local ACT_MARK; _act_new_marker; echo "$ACT_MARK"; }

act_declared() {
    _act_write declared "$1" "$2" "$3" "${4:-}" "${5:-}" "${EPOCHREALTIME:-0.0}"
}

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
