#!/bin/bash
#
# run-everything.sh
# ---------------------------------------------------------------------------
# One command: bring up the lab, install tooling, lock down the network,
# run scenarios, and hand the results back to you. Run it from your HOST
# shell (not inside a container) in the repo root.
#
#   bash run-everything.sh                    # MITRE ATT&CK + OWASP Top 10 (default)
#   bash run-everything.sh --only mitre       # ATT&CK scenarios only
#   bash run-everything.sh --only owasp       # OWASP Top 10:2025 scenarios only
#   bash run-everything.sh --only untrusted-fields   # untrusted telemetry-field handling (opt-in, not part of the default run)
#   bash run-everything.sh --stealth quiet    # quieter attacker: noisy|careful|quiet|covert
#
#   bash run-everything.sh --technique T1552.005    # just the scenario(s) that perform a technique
#   bash run-everything.sh --tactic credential-access
#   bash run-everything.sh --list                   # every technique, its tactic and its scripts
#   bash run-everything.sh --check            # preflight checks only, start nothing
#   bash run-everything.sh --down             # stop and remove the lab's containers and networks
#   bash run-everything.sh --reset [--yes]    # --down, then delete ./results (asks first unless --yes)
#
# Options combine, e.g.  bash run-everything.sh --only owasp --stealth careful
# STEALTH_TIME_SCALE=0.01 shrinks every wait for quick runs.
#
# "--only owasp" and "--only untrusted-fields" start only the base containers (no
# privileged Docker-in-Docker). Everything else starts the privileged overlay too.
#
# For anything more targeted (one scenario at a time), see docs/REFERENCE.md.
# ---------------------------------------------------------------------------
set -eu

SEL_TECH=(); SEL_TACTIC=(); DO_LIST=0
ONLY=all; DO_CHECK=0; DO_DOWN=0; DO_RESET=0; ASSUME_YES=0
while [ $# -gt 0 ]; do
    case "$1" in
        --technique) [ $# -ge 2 ] || { echo "--technique needs a value" >&2; exit 2; }; SEL_TECH+=("$2"); shift 2 ;;
        --technique=*) SEL_TECH+=("${1#*=}"); shift ;;
        --tactic) [ $# -ge 2 ] || { echo "--tactic needs a value" >&2; exit 2; }; SEL_TACTIC+=("$2"); shift 2 ;;
        --tactic=*) SEL_TACTIC+=("${1#*=}"); shift ;;
        --list) DO_LIST=1; shift ;;
        --check) DO_CHECK=1; shift ;;
        --down) DO_DOWN=1; shift ;;
        --reset) DO_RESET=1; shift ;;
        --yes|-y) ASSUME_YES=1; shift ;;
        --stealth) [ $# -ge 2 ] || { echo "--stealth needs a value" >&2; exit 2; }; export STEALTH="$2"; shift 2 ;;
        --stealth=*) export STEALTH="${1#*=}"; shift ;;
        --only) [ $# -ge 2 ] || { echo "--only needs a value" >&2; exit 2; }; ONLY="$2"; shift 2 ;;
        --only=*) ONLY="${1#*=}"; shift ;;
        -h|--help) sed -n 2,30p "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
case "${STEALTH:-noisy}" in noisy|careful|quiet|covert|0|1|2|3) ;; *)
    echo "invalid STEALTH='${STEALTH}' — valid: noisy careful quiet covert" >&2; exit 2 ;; esac
case "$ONLY" in all|mitre|owasp|untrusted-fields) ;; *)
    echo "invalid --only '$ONLY' — valid: all mitre owasp untrusted-fields" >&2; exit 2 ;; esac

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

if [ "$DO_LIST" = 1 ]; then exec python3 playbooks/scenario-index.py list; fi

# --technique / --tactic: work out which scenario scripts to run
PLAN=""; NEED_OVERLAY=0
if [ ${#SEL_TECH[@]} -gt 0 ] || [ ${#SEL_TACTIC[@]} -gt 0 ]; then
    [ "$ONLY" = all ] || { echo "--technique/--tactic cannot be combined with --only" >&2; exit 2; }
    sel_args=()
    for x in ${SEL_TECH[@]+"${SEL_TECH[@]}"}; do sel_args+=(--technique "$x"); done
    for x in ${SEL_TACTIC[@]+"${SEL_TACTIC[@]}"}; do sel_args+=(--tactic "$x"); done
    PLAN="$(python3 playbooks/scenario-index.py select "${sel_args[@]}")" || exit 2
    ONLY=select
    case "$PLAN" in *overlay=1*) NEED_OVERLAY=1 ;; esac
fi

FILES="-f compose.yml -f compose.privileged.yml"
PROJECT="${COMPOSE_PROJECT_NAME:-$(basename "$PWD" | tr 'A-Z' 'a-z' | tr -cd 'a-z0-9_-')}"

# Preflight: fail early, with a plain message, instead of half-way through a run.
PF_BAD=0
pf_ok()   { echo "  ok    $*"; }
pf_fail() { echo "  FAIL  $*"; PF_BAD=1; }
pf_warn() { echo "  warn  $*"; }
preflight() {
    PF_BAD=0
    echo "[run-everything] preflight checks"
    command -v docker >/dev/null 2>&1 && pf_ok "docker CLI found" || pf_fail "docker is not installed or not on PATH"
    if command -v docker >/dev/null 2>&1; then
        if docker info >/dev/null 2>&1; then pf_ok "docker daemon reachable"
        else pf_fail "cannot talk to the docker daemon (is it running? is your user in the 'docker' group?)"; fi
        docker compose version >/dev/null 2>&1 && pf_ok "docker compose plugin found" || pf_fail "the 'docker compose' plugin is missing (install docker-compose-plugin)"
    fi
    command -v python3 >/dev/null 2>&1 && pf_ok "python3 found (used for reports)" || pf_fail "python3 is required on the host for the reports"
    [ -f compose.yml ] && pf_ok "compose.yml present" || pf_fail "compose.yml not found: run this from the repository root"
    local kb; kb="$(df -Pk . | awk 'NR==2{print $4}')"
    if [ "${kb:-0}" -lt 4194304 ]; then pf_fail "only $((kb/1024)) MB free here; the images need about 4 GB"
    elif [ "$kb" -lt 8388608 ]; then pf_warn "only $((kb/1024)) MB free; fine for one run, tight for several"
    else pf_ok "disk space ($((kb/1024)) MB free)"; fi
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
        # only the container names this compose file actually declares can collide
        local other="" n owner
        for n in $(grep -h 'container_name:' compose.yml compose.privileged.yml 2>/dev/null | awk '{print $2}'); do
            owner="$(docker ps -a --filter "name=^/${n}$" --format '{{.Label "com.docker.compose.project"}}' | head -1)"
            [ -n "$owner" ] && [ "$owner" != "$PROJECT" ] && other="${other}${n} (project ${owner})"$'\n'
        done
        if [ -n "$other" ]; then
            pf_fail "containers from a different lab are using the northline-* names:"
            printf "%s" "$other" | sed 's/^/          /'
            echo "        remove them first:  docker rm -f \$(docker ps -aq --filter name=northline-)"
        else
            local mine; mine="$(docker ps -q --filter label=com.docker.compose.project="$PROJECT" | wc -l)"
            [ "$mine" -gt 0 ] && pf_warn "this lab is already running ($mine containers); the run will reuse it" || pf_ok "no conflicting containers"
        fi
    fi
    return $PF_BAD
}

lab_down() {
    echo "[run-everything] stopping and removing the lab..."
    docker compose $FILES down -v --remove-orphans
}

fix_results_ownership() {
    [ -d results ] || return 0
    docker run --rm -v "$PWD/results:/r" alpine:3.20 chown -R "$(id -u):$(id -g)" /r >/dev/null 2>&1 || true
}

if [ "$DO_CHECK" = 1 ]; then preflight && echo "[run-everything] all checks passed" ; exit $?; fi
if [ "$DO_DOWN" = 1 ] || [ "$DO_RESET" = 1 ]; then
    lab_down
    fix_results_ownership
    if [ "$DO_RESET" = 1 ]; then
        if [ -d results ] && [ -n "$(ls -A results 2>/dev/null)" ]; then
            if [ "$ASSUME_YES" != 1 ]; then
                printf '[run-everything] delete everything in ./results? [y/N] '; read -r ans
                case "$ans" in y|Y|yes|YES) ;; *) echo "[run-everything] kept ./results"; exit 0 ;; esac
            fi
            rm -rf results/* results/.[!.]* 2>/dev/null || docker run --rm -v "$PWD/results:/r" alpine:3.20 sh -c 'rm -rf /r/* /r/.[!.]*'
            echo "[run-everything] ./results cleared"
        fi
    fi
    echo "[run-everything] done."
    exit 0
fi

preflight || { echo "[run-everything] preflight failed; fix the items marked FAIL and run again (or run with --check)"; exit 1; }
echo

# Create results/ as the invoking user (otherwise Docker creates it as root).
mkdir -p results

if [ "$ONLY" = owasp ] || [ "$ONLY" = untrusted-fields ] || { [ "$ONLY" = select ] && [ "$NEED_OVERLAY" = 0 ]; }; then
    COMPOSE="docker compose -f compose.yml"
    WHAT="base containers only"
else
    COMPOSE="docker compose -f compose.yml -f compose.privileged.yml"
    WHAT="base + privileged overlay"
fi
ST="${STEALTH:-noisy}"
RUN_START="$(date +%s)"

echo "[run-everything] scenarios: $ONLY   stealth profile: $ST"
echo "[run-everything] bringing up the environment ($WHAT)..."
$COMPOSE up -d

echo "[run-everything] waiting for containers to be ready..."
for i in $(seq 1 15); do
    $COMPOSE exec ops-console sh -c 'true' >/dev/null 2>&1 && break
    sleep 1
done

echo "[run-everything] setup phase (needs egress): install tooling..."
$COMPOSE exec ops-console bash playbooks/bootstrap.sh
if [ "$ONLY" != owasp ]; then
    $COMPOSE exec ops-console bash playbooks/install-extra-tools.sh
fi
if [ "$ONLY" != owasp ] && [ "$ONLY" != untrusted-fields ] && { [ "$ONLY" != select ] || [ "$NEED_OVERLAY" = 1 ]; }; then
    $COMPOSE exec ops-console bash playbooks/install-container-tools.sh
fi

echo "[run-everything] locking down network (removing setup-net egress)..."
COMPOSE="$COMPOSE" bash lock-down-network.sh

if [ "$ONLY" = owasp ]; then
    echo "[run-everything] OWASP Top 10:2025 scenarios..."
    $COMPOSE exec -e STEALTH="$ST" ops-console bash playbooks/run-owasp-top10.sh
elif [ "$ONLY" = select ]; then
    echo "[run-everything] selected scenarios:"
    printf '%s\n' "$PLAN" | sed 's/ ;; .*//; s/^/    /'
    $COMPOSE exec -e STEALTH="$ST" ops-console bash playbooks/seed-decoys.sh
    while IFS= read -r line; do
        spec="${line%% ;; *}"; flags="${line#* ;; }"
        echo "[run-everything] running: $spec"
        # shellcheck disable=SC2086  (spec is "script.sh [args]", intentionally word-split)
        # -T and </dev/null: otherwise exec reads (and swallows) the rest of $PLAN from the loop's stdin
        $COMPOSE exec -T -e STEALTH="$ST" ops-console bash playbooks/$spec </dev/null
        case "$flags" in *persistence=1*)
            [ "${KEEP_PERSISTENCE:-0}" = 1 ] || $COMPOSE exec -T ops-console bash playbooks/run-persistence.sh --cleanup </dev/null ;; esac
    done <<< "$PLAN"
elif [ "$ONLY" = untrusted-fields ]; then
    echo "[run-everything] untrusted-field handling scenario..."
    $COMPOSE exec -e STEALTH="$ST" ops-console bash playbooks/run-untrusted-fields.sh
else
    SKIP_OWASP=0; [ "$ONLY" = mitre ] && SKIP_OWASP=1
    echo "[run-everything] base scenarios..."
    $COMPOSE exec -e SKIP_SETUP=1 -e SKIP_OWASP="$SKIP_OWASP" -e STEALTH="$ST" ops-console bash playbooks/run-all.sh

    echo "[run-everything] privileged/overlay scenarios..."
    $COMPOSE exec -e STEALTH="$ST" ops-console bash playbooks/run-privileged-chain.sh
fi

# Containers run as root, so everything they wrote to ./results is root-owned
# on the host. Hand it back to the invoking user.
echo "[run-everything] fixing ./results ownership -> $(id -u):$(id -g)..."
for svc in ops-console dns-sink control-api web-portal; do
    $COMPOSE exec -T "$svc" chown -R "$(id -u):$(id -g)" /home/root/results || true
done

# Confirm each action from the destination's side (their own logs), then write the
# final activity report for THIS run: readable table + CSV (every row, every field).
if [ -f results/activity.jsonl ] && command -v python3 >/dev/null 2>&1; then
    $COMPOSE exec -T internal-host cat /config/logs/openssh/current > results/server_sshd.log 2>/dev/null || true
    SRC=results/activity.jsonl
    if python3 playbooks/observe.py --results results --since "$RUN_START"; then SRC=results/activity_confirmed.jsonl; fi
    python3 playbooks/activity-report.py "$SRC" --since "$RUN_START" > results/activity_report.txt
    python3 playbooks/activity-report.py "$SRC" --since "$RUN_START" --format csv > results/activity.csv
    cat results/activity_report.txt
    echo
    echo "[run-everything] activity report: results/activity_report.txt (table)  results/activity.csv (every row)"
fi

echo "[run-everything] done. Results are in ./results/"
echo "[run-everything] tear down with: $COMPOSE down -v"
