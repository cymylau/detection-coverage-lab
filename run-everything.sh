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
# At the end it prints a stage summary and writes results/last_run.json. Exit
# status: 0 when every stage passed, non-zero if setup failed or any scenario
# stage failed (the other stages still run and the results are still reported).
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
        -h|--help) awk 'NR == 1 {next} /^#/ {sub(/^# ?/, ""); print; next} {exit}' "$0"; exit 0 ;;
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
            pf_fail "containers from a different lab are using the cymylau-* names:"
            printf "%s" "$other" | sed 's/^/          /'
            echo "        remove them first:  docker rm -f \$(docker ps -aq --filter name=cymylau-)"
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

# ---- stage bookkeeping ------------------------------------------------------
# A failed scenario does not stop the run: each stage's exit code is recorded,
# the results are still handed back and reported, and the exit status says what
# happened. A setup failure (install, lock-down, readiness) stops before any
# scenario runs. Either way finish() runs on exit, including on Ctrl-C.
STAGES=()          # "exit<TAB>name"
FAILED=0
STARTED=0          # 1 once containers are being brought up
STEP="preflight"   # what was happening, for the message if setup fails

stage_run() {      # stage_run NAME CMD...
    local name="$1" rc=0
    shift
    echo "[run-everything] running: $name"
    "$@" || rc=$?
    STAGES+=("${rc}"$'\t'"${name}")
    if [ "$rc" -ne 0 ]; then
        FAILED=$((FAILED + 1))
        echo "[run-everything] !! $name exited $rc; carrying on with the rest"
    fi
    return 0
}

# Is SERVICE listening on PORT? Reads the container's own socket table, so the
# check sends no traffic (nothing for your sensors to see before the scenarios).
listening() {      # listening SERVICE tcp|udp PORT
    local hex
    printf -v hex '%04X' "$3"
    $COMPOSE exec -T "$1" cat "/proc/net/$2" "/proc/net/${2}6" 2>/dev/null |
        awk -v p=":$hex" -v proto="$2" 'substr($2, length($2) - 4) == p && (proto == "udp" || $4 == "0A") {f = 1} END {exit !f}'
}

wait_ready() {     # wait_ready SECONDS SERVICE:PROTO:PORT...
    local limit="$1" deadline pending w svc proto port
    shift
    deadline=$(( $(date +%s) + limit ))
    while :; do
        pending=""
        for w in "$@"; do
            IFS=: read -r svc proto port <<< "$w"
            listening "$svc" "$proto" "$port" || pending="$pending $svc:$port"
        done
        [ -z "$pending" ] && return 0
        if [ "$(date +%s)" -ge "$deadline" ]; then
            echo "[run-everything] !! still not listening after ${limit}s:$pending" >&2
            echo "[run-everything]    see why with:  $COMPOSE logs <service>" >&2
            return 1
        fi
        sleep 2
    done
}

write_last_run() { # results/last_run.json: what ran, when, and how each stage ended
    python3 - "$RUN_START" "$(date +%s)" "$ONLY" "$ST" "$1" "$STEP" \
        "${SEL_TECH[*]+${SEL_TECH[*]}}" "${SEL_TACTIC[*]+${SEL_TACTIC[*]}}" ${STAGES[@]+"${STAGES[@]}"} \
        > results/last_run.json <<'PY'
import json, sys
start, end, only, profile, status, step, tech, tactic, *stages = sys.argv[1:]
out = {"start": int(start), "end": int(end), "only": only, "stealth": profile, "status": status,
       "stages": [{"name": s.split("\t", 1)[1], "exit": int(s.split("\t", 1)[0])} for s in stages]}
if status == "setup-failed":
    out["failed_during"] = step
if tech or tactic:
    out["selection"] = {"technique": tech.split(), "tactic": tactic.split()}
json.dump(out, sys.stdout, indent=1)
print()
PY
}

finish() {
    local rc=$? status r
    trap - EXIT
    set +e
    [ "$STARTED" = 1 ] || exit "$rc"
    echo
    # Containers run as root, so everything they wrote to ./results is root-owned
    # on the host. Hand it back to the invoking user.
    echo "[run-everything] fixing ./results ownership -> $(id -u):$(id -g)..."
    for svc in ops-console dns-sink control-api web-portal; do
        $COMPOSE exec -T "$svc" chown -R "$(id -u):$(id -g)" /home/root/results >/dev/null 2>&1
    done
    [ -z "$(find results ! -user "$(id -u)" -print -quit 2>/dev/null)" ] || fix_results_ownership

    # Confirm each action from the destination's side (their own logs), then write the
    # final activity report for THIS run: readable table + CSV (every row, every field).
    if [ -f results/activity.jsonl ]; then
        $COMPOSE exec -T internal-host cat /config/logs/openssh/current > results/server_sshd.log 2>/dev/null
        SRC=results/activity.jsonl
        if python3 playbooks/observe.py --results results --since "$RUN_START"; then SRC=results/activity_confirmed.jsonl; fi
        python3 playbooks/activity-report.py "$SRC" --since "$RUN_START" > results/activity_report.txt
        python3 playbooks/activity-report.py "$SRC" --since "$RUN_START" --format csv > results/activity.csv
        cat results/activity_report.txt
        echo
        echo "[run-everything] activity report: results/activity_report.txt (table)  results/activity.csv (every row)"
    fi

    if [ "$STEP" != scenarios ] && [ "$STEP" != finished ]; then status=setup-failed
    elif [ "$FAILED" -gt 0 ] || [ "$rc" -ne 0 ]; then status=failed
    else status=ok; fi
    write_last_run "$status"

    if [ ${#STAGES[@]} -gt 0 ]; then
        echo
        echo "[run-everything] stage summary"
        for r in "${STAGES[@]}"; do
            if [ "${r%%$'\t'*}" = 0 ]; then echo "  ok      ${r#*$'\t'}"
            else echo "  FAILED  ${r#*$'\t'} (exit ${r%%$'\t'*})"; fi
        done
        # name the failed scenarios inside this run's chains, so nobody has to scroll for them
        if [ "$FAILED" -gt 0 ]; then
            find results -maxdepth 1 \( -name 'full_chain_*.log' -o -name 'privileged_chain_*.log' \) \
                -newermt "@$RUN_START" 2>/dev/null | sort | while IFS= read -r f; do
                grep -h '^  FAILED  ' "$f" | sed "s|^  FAILED  |            failed inside: |; s|\$|   [$f]|"
            done
        fi
    fi
    echo
    case "$status" in
        ok)
            echo "[run-everything] done. Results are in ./results/"
            echo "[run-everything] tear down with: bash run-everything.sh --down"
            exit 0 ;;
        setup-failed)
            echo "[run-everything] STOPPED during setup ($STEP, exit $rc); no scenarios ran after that point."
            echo "[run-everything] fix the error above, then: bash run-everything.sh --down  and run again" ;;
        *)
            if [ "$FAILED" -gt 0 ]; then
                echo "[run-everything] FINISHED WITH FAILURES: $FAILED of ${#STAGES[@]} stage(s) failed (see the summary above;"
                echo "[run-everything] each chain's own log in ./results/ has a per-scenario summary at its end)."
            else
                echo "[run-everything] INTERRUPTED (exit $rc) while running scenarios."
            fi
            echo "[run-everything] results so far are in ./results/ ; tear down with: bash run-everything.sh --down" ;;
    esac
    [ "$rc" -ne 0 ] && exit "$rc"
    exit 1
}
trap finish EXIT

echo "[run-everything] scenarios: $ONLY   stealth profile: $ST"
# Stealth timing adds deliberate waits. Rough real-time totals, measured from
# the action counts each profile performs (see docs/REFERENCE.md#stealth-profiles).
case "${STEALTH_TIMING:-$ST}" in
    careful|1) EST="about 5 minutes for everything (about 2 for --only mitre, 3 for --only owasp)" ;;
    quiet|2)   EST="about 15 minutes for everything (about 9 for --only mitre, 5 for --only owasp)" ;;
    covert|3)  EST="about 40 minutes for everything (about 30 for --only mitre, 10 for --only owasp)" ;;
    *)         EST="" ;;
esac
if [ -n "$EST" ]; then
    if [ "${STEALTH_TIME_SCALE:-1}" = 1 ]; then
        echo "[run-everything] this timing profile waits on purpose: expect $EST."
        echo "[run-everything] (STEALTH_TIME_SCALE=0.1 shrinks every wait, at the cost of realism)"
    else
        echo "[run-everything] timing profile with STEALTH_TIME_SCALE=${STEALTH_TIME_SCALE}: unscaled it would be $EST."
    fi
fi

STARTED=1; STEP="bringing up containers"
echo "[run-everything] bringing up the environment ($WHAT)..."
$COMPOSE up -d

STEP="waiting for ops-console"
echo "[run-everything] waiting for containers to be ready..."
ok=0
for _ in $(seq 1 30); do
    if $COMPOSE exec -T ops-console true >/dev/null 2>&1; then ok=1; break; fi
    sleep 1
done
[ "$ok" = 1 ] || { echo "[run-everything] !! ops-console did not start within 30s; see: $COMPOSE logs ops-console" >&2; exit 1; }

STEP="installing tooling"
echo "[run-everything] setup phase (needs egress): install tooling..."
$COMPOSE exec ops-console bash playbooks/bootstrap.sh
if [ "$ONLY" != owasp ]; then
    $COMPOSE exec ops-console bash playbooks/install-extra-tools.sh
fi
if [ "$ONLY" != owasp ] && [ "$ONLY" != untrusted-fields ] && { [ "$ONLY" != select ] || [ "$NEED_OVERLAY" = 1 ]; }; then
    $COMPOSE exec ops-console bash playbooks/install-container-tools.sh
fi

STEP="locking down the network"
echo "[run-everything] locking down network (removing setup-net egress)..."
bash lock-down-network.sh

STEP="waiting for the lab services"
echo "[run-everything] waiting for every service to listen..."
wait_ready 60 dns-sink:udp:53 control-api:tcp:8443 web-portal:tcp:8080 internal-host:tcp:2222 ops-console:tcp:80
echo "[run-everything] all services ready"

STEP=scenarios
if [ "$ONLY" = owasp ]; then
    stage_run "OWASP Top 10:2025 scenarios (run-owasp-top10.sh)" \
        $COMPOSE exec -e STEALTH="$ST" ops-console bash playbooks/run-owasp-top10.sh
elif [ "$ONLY" = select ]; then
    echo "[run-everything] selected scenarios:"
    printf '%s\n' "$PLAN" | sed 's/ ;; .*//; s/^/    /'
    stage_run "seed decoys (seed-decoys.sh)" $COMPOSE exec -T -e STEALTH="$ST" ops-console bash playbooks/seed-decoys.sh </dev/null
    while IFS= read -r line; do
        spec="${line%% ;; *}"; flags="${line#* ;; }"
        # spec is "script.sh [args]", intentionally word-split.
        # -T and </dev/null: otherwise exec reads (and swallows) the rest of $PLAN from the loop's stdin
        # shellcheck disable=SC2086
        stage_run "$spec" $COMPOSE exec -T -e STEALTH="$ST" ops-console bash playbooks/$spec </dev/null
        case "$flags" in *persistence=1*)
            [ "${KEEP_PERSISTENCE:-0}" = 1 ] || stage_run "persistence cleanup (run-persistence.sh --cleanup)" \
                $COMPOSE exec -T ops-console bash playbooks/run-persistence.sh --cleanup </dev/null ;; esac
    done <<< "$PLAN"
elif [ "$ONLY" = untrusted-fields ]; then
    stage_run "untrusted-field handling (run-untrusted-fields.sh)" \
        $COMPOSE exec -e STEALTH="$ST" ops-console bash playbooks/run-untrusted-fields.sh
else
    SKIP_OWASP=0; [ "$ONLY" = mitre ] && SKIP_OWASP=1
    stage_run "base scenarios (run-all.sh -> run-full-chain.sh)" \
        $COMPOSE exec -e SKIP_SETUP=1 -e SKIP_OWASP="$SKIP_OWASP" -e STEALTH="$ST" ops-console bash playbooks/run-all.sh
    stage_run "privileged/overlay scenarios (run-privileged-chain.sh)" \
        $COMPOSE exec -e STEALTH="$ST" ops-console bash playbooks/run-privileged-chain.sh
fi
STEP=finished
