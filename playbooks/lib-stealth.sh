#!/bin/bash
#
# lib-stealth.sh — selectable "stealth profiles" for the scenario playbooks.
#
# Source this from a playbook:
#   source "$(cd "$(dirname "$0")" && pwd)/lib-stealth.sh"
#
# The lab is noisy by default so detections fire. A profile makes the SAME
# decoy-only techniques quieter, so you can check whether your EDR/CDR still
# detects a careful attacker. Profiles change HOW a technique is performed
# (timing, volume, tooling, naming, tidiness). They never touch, stop, or
# evade the security agent, and every target is still a lab decoy.
#
#   STEALTH=noisy|careful|quiet|covert   (or 0|1|2|3; default noisy = original behaviour)
#   STEALTH_TIMING / STEALTH_TOOLING / STEALTH_ARTIFACTS = profile name, overrides one dimension
#   STEALTH_TIME_SCALE=0.01              multiplies every sleep (fast demos/tests)
#
# Exports: STEALTH_NAME, ST_TIMING, ST_TOOLING, ST_ARTIFACTS (levels 0-3) and the
# ST_* settings below. Helpers: st_sleep, st_scan, st_http, st_sshpass, st_mark,
# st_banner.

source "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/lib-activity.sh"

ST_VALID="noisy careful quiet covert"

# name or number -> level 0-3, or non-zero status
st_level_of() {
    case "${1,,}" in
        noisy|0)   echo 0 ;;
        careful|1) echo 1 ;;
        quiet|2)   echo 2 ;;
        covert|3)  echo 3 ;;
        *) return 1 ;;
    esac
}
st_name_of() { local lvl="$1"; local names; read -ra names <<< "$ST_VALID"; echo "${names[$lvl]}"; }

_st_resolve() {
    local base dim var val lvl
    base="${STEALTH:-noisy}"
    if ! lvl="$(st_level_of "$base")"; then
        echo "[stealth] invalid STEALTH='$base' — valid: $ST_VALID (or 0-3)" >&2
        return 1
    fi
    STEALTH_NAME="$(st_name_of "$lvl")"
    ST_TIMING="$lvl"; ST_TOOLING="$lvl"; ST_ARTIFACTS="$lvl"
    for dim in TIMING TOOLING ARTIFACTS; do
        var="STEALTH_${dim}"; val="${!var:-}"
        [ -n "$val" ] || continue
        if ! lvl="$(st_level_of "$val")"; then
            echo "[stealth] invalid $var='$val' — valid: $ST_VALID (or 0-3)" >&2
            return 1
        fi
        printf -v "ST_${dim}" '%s' "$lvl"
    done
}
_st_resolve || exit 2

TIME_SCALE="${STEALTH_TIME_SCALE:-1}"

# ---- profile table (one place to tune) -------------------------------------
# index = level: noisy careful quiet covert
_pick() { local a; read -ra a <<< "$1"; echo "${a[$2]}"; }
# timing: C2 beacon jitter, mining poll interval, DNS inter-query delay (seconds)
ST_JITTER_MIN="$(_pick '1 5 30 120' "$ST_TIMING")"
ST_JITTER_MAX="$(_pick '4 15 90 300' "$ST_TIMING")"
ST_POLL_MIN="$(_pick '3 5 20 60' "$ST_TIMING")"
ST_POLL_MAX="$(_pick '3 10 40 120' "$ST_TIMING")"
ST_DNS_DELAY_MIN="$(_pick '0 1 2 5' "$ST_TIMING")"
ST_DNS_DELAY_MAX="$(_pick '0 2 5 15' "$ST_TIMING")"
# tooling/volume: DNS label length, UA, HTTP client, scan style
ST_DNS_LABEL="$(_pick '48 32 24 12' "$ST_TOOLING")"
ST_UA=""   # empty = client default
[ "$ST_TOOLING" -ge 1 ] && ST_UA="Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0 Safari/537.36"
# shellcheck disable=SC2034  # used by run-cryptomining.sh
if [ "$ST_TIMING" -ge 2 ]; then ST_NICE="nice -n 19"; else ST_NICE=""; fi
export STEALTH_NAME ST_TIMING ST_TOOLING ST_ARTIFACTS ST_JITTER_MIN ST_JITTER_MAX \
       ST_POLL_MIN ST_POLL_MAX ST_DNS_DELAY_MIN ST_DNS_DELAY_MAX ST_DNS_LABEL ST_UA

# ---- helpers ---------------------------------------------------------------

# st_sleep MIN MAX — random whole-second delay in [MIN,MAX], scaled by TIME_SCALE.
# Echoes the (unscaled) chosen value so callers can log it.
st_sleep() {
    local min="$1" max="$2" n
    [ "$max" -lt "$min" ] && max="$min"
    n=$(( min + (max > min ? RANDOM % (max - min + 1) : 0) ))
    echo "$n"
    [ "$n" -gt 0 ] && sleep "$(awk -v n="$n" -v s="$TIME_SCALE" 'BEGIN{printf "%.3f", n*s}')"
    return 0
}

# st_scan HOST PORT[,PORT...] — port discovery appropriate to the tooling level.
#   0 noisy:   nmap, all ports given        1 careful: nmap -T2, first 2 ports
#   2 quiet:   one bash /dev/tcp probe      3 covert:  no scan; connect straight to the service
st_scan() {
    local host="$1" ports="$2" first="${2%%,*}" two
    case "$ST_TOOLING" in
        0) ax "$ST_TECH" "$host" "ports $ports" -- nmap -Pn -n -p "$ports" --reason "$host" 2>&1 ;;
        1) two="${ports#*,}"; two="${ports%%,*}${two:+,${two%%,*}}"
           ax "$ST_TECH" "$host" "ports $two" -- nmap -Pn -n -T2 -p "$two" --reason "$host" 2>&1 ;;
        2) if ax --ok any --label "bash /dev/tcp connect probe" "$ST_TECH" "$host" "port $first" -- \
                _st_tcp_probe "$host" "$first"; then echo "probe ${host}:${first} open"
           else echo "probe ${host}:${first} closed"; fi ;;
        3) echo "(no scan at this level — connecting directly to ${host}:${first})" ;;
    esac
}

_st_tcp_probe() { (exec 3<>"/dev/tcp/${1}/${2}") 2>/dev/null; }

# st_http METHOD URL [DATA|@FILE] [HEADER] [OUTFILE]
# curl at tooling 0-1; python3 urllib at 2-3 (no curl process, fewer tool names).
# Body to stdout unless OUTFILE is given. Timeout: ST_HTTP_TIMEOUT (default 5s).
st_http() {
    local method="$1" url="$2" data="${3:-}" hdr="${4:-}" out="${5:-}"
    local to="${ST_HTTP_TIMEOUT:-5}"
    local hp="${url#*://}" ; local hhost="${hp%%/*}" ; local hpath="/${hp#*/}"
    [ "$hp" = "${hp#*/}" ] && hpath="/"
    local dst="${hhost%%:*}" ok="--ok 0"
    [ -n "${ST_HTTP_OK:-}" ] && ok="--ok $ST_HTTP_OK"
    if [ "$ST_TOOLING" -le 1 ]; then
        local args=(-s --max-time "$to")
        [ -n "$ST_UA" ] && args+=(-A "$ST_UA")
        [ "$method" = POST ] && args+=(-X POST)
        if [ -n "$data" ]; then
            case "$data" in @*) args+=(--data-binary "$data") ;; *) args+=(-d "$data") ;; esac
        fi
        [ -n "$hdr" ] && args+=(-H "$hdr")
        [ -n "$out" ] && args+=(-o "$out")
        case "$url" in https://*) args+=(-k) ;; esac   # the lab's TLS endpoint is self-signed
        # shellcheck disable=SC2086  # $ok is two words on purpose
        ax $ok "$ST_TECH" "$dst" "$hpath" -- curl "${args[@]}" "$url"
    else
        # shellcheck disable=SC2086
        ax $ok --label "python3 urllib $method $url" "$ST_TECH" "$dst" "$hpath" -- python3 - "$method" "$url" "$data" "$hdr" "$out" "$to" "$ST_UA" <<'PY'
import sys, urllib.request, urllib.error
method, url, data, hdr, out, to, ua = sys.argv[1:8]
body = None
if data:
    body = open(data[1:], "rb").read() if data.startswith("@") else data.encode()
import ssl
ctx = ssl._create_unverified_context()   # the lab's TLS endpoint is self-signed
req = urllib.request.Request(url, data=body, method=method)
if ua: req.add_header("User-Agent", ua)
if hdr:
    k, _, v = hdr.partition(":"); req.add_header(k.strip(), v.strip())
try:
    resp = urllib.request.urlopen(req, timeout=float(to), context=ctx).read()
except urllib.error.HTTPError as e:
    resp = e.read()   # keep 4xx/5xx bodies, like curl does
except Exception:
    resp = None   # no connection / timeout: fail like curl does
if out and resp is not None: open(out, "wb").write(resp)
elif resp is not None: sys.stdout.buffer.write(resp)
sys.exit(7 if resp is None else 0)
PY
    fi
}

# st_sshpass PASSWORD — sets the global ST_SSHPASS array (the sshpass front-end).
# noisy keeps the password on the command line (a classic detection signal);
# careful+ passes it via the environment instead. Call directly, not in $(...),
# so the exported SSHPASS survives.
st_sshpass() {
    if [ "$ST_TOOLING" -ge 1 ]; then
        export SSHPASS="$1"; ST_SSHPASS=(sshpass -e)
    else
        # shellcheck disable=SC2034  # used by the ssh scenarios via "${ST_SSHPASS[@]}"
        ST_SSHPASS=(sshpass -p "$1")
    fi
}

# st_mark TECHNIQUE STEP — local timeline for lining EDR alerts up against what ran.
# Never sent on the wire. With ACT_GAP=SECONDS (run-everything.sh --gap), waits that
# long whenever the technique changes, so alerts for different techniques do not
# land in the same time window or get grouped into one incident.
st_mark() {
    if [ "${ACT_GAP:-0}" != 0 ]; then
        # the last technique is kept in a file so the gap also applies between scenario scripts
        local lf="${RESULTS_DIR:-/home/root/results}/.act_last_tech" last=""
        [ -f "$lf" ] && read -r last < "$lf"
        if [ -n "$last" ] && [ "$last" != "$1" ]; then
            echo "[gap] ${ACT_GAP}s before ${1} (technique changed)" >&2
            sleep "$ACT_GAP"
        fi
        printf '%s\n' "$1" > "$lf" 2>/dev/null || true
    fi
    # shellcheck disable=SC2034  # ST_STEP is read by act() in lib-activity.sh
    ST_STEP="${2:-}"
    ST_TECH="$1"
    local f="${RESULTS_DIR:-/home/root/results}/stealth_timeline.jsonl"
    printf '{"ts":"%s","profile":"%s","timing":%s,"tooling":%s,"artifacts":%s,"technique":"%s","step":"%s"}\n' \
        "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$STEALTH_NAME" "$ST_TIMING" "$ST_TOOLING" "$ST_ARTIFACTS" \
        "$1" "${2:-}" >> "$f" 2>/dev/null || true
}

st_banner() {
    echo "stealth profile=${STEALTH_NAME} (timing=${ST_TIMING} tooling=${ST_TOOLING} artifacts=${ST_ARTIFACTS}) time-scale=${TIME_SCALE}"
}
