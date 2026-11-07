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
#   bash run-everything.sh --stealth quiet    # quieter attacker: noisy|careful|quiet|covert
#
# Options combine, e.g.  bash run-everything.sh --only owasp --stealth careful
# STEALTH_TIME_SCALE=0.01 shrinks every wait for quick runs.
#
# "--only owasp" starts only the base containers (no privileged
# Docker-in-Docker). Everything else starts the privileged overlay too.
#
# For anything more targeted (one scenario at a time), see docs/REFERENCE.md.
# ---------------------------------------------------------------------------
set -eu

ONLY=all
while [ $# -gt 0 ]; do
    case "$1" in
        --stealth) [ $# -ge 2 ] || { echo "--stealth needs a value" >&2; exit 2; }; export STEALTH="$2"; shift 2 ;;
        --stealth=*) export STEALTH="${1#*=}"; shift ;;
        --only) [ $# -ge 2 ] || { echo "--only needs a value" >&2; exit 2; }; ONLY="$2"; shift 2 ;;
        --only=*) ONLY="${1#*=}"; shift ;;
        -h|--help) sed -n 2,20p "$0"; exit 0 ;;
        *) echo "unknown argument: $1" >&2; exit 2 ;;
    esac
done
case "${STEALTH:-noisy}" in noisy|careful|quiet|covert|0|1|2|3) ;; *)
    echo "invalid STEALTH='${STEALTH}' — valid: noisy careful quiet covert" >&2; exit 2 ;; esac
case "$ONLY" in all|mitre|owasp) ;; *)
    echo "invalid --only '$ONLY' — valid: all mitre owasp" >&2; exit 2 ;; esac

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

# Create results/ as the invoking user (otherwise Docker creates it as root).
mkdir -p results

if [ "$ONLY" = owasp ]; then
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
    $COMPOSE exec ops-console bash playbooks/install-container-tools.sh
fi

echo "[run-everything] locking down network (removing setup-net egress)..."
COMPOSE="$COMPOSE" bash lock-down-network.sh

if [ "$ONLY" = owasp ]; then
    echo "[run-everything] OWASP Top 10:2025 scenarios..."
    $COMPOSE exec -e STEALTH="$ST" ops-console bash playbooks/run-owasp-top10.sh
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

# Final activity report for THIS run: readable table + CSV (every row, every field).
if [ -f results/activity.jsonl ] && command -v python3 >/dev/null 2>&1; then
    python3 playbooks/activity-report.py results/activity.jsonl --since "$RUN_START" > results/activity_report.txt
    python3 playbooks/activity-report.py results/activity.jsonl --since "$RUN_START" --format csv > results/activity.csv
    cat results/activity_report.txt
    echo
    echo "[run-everything] activity report: results/activity_report.txt (table)  results/activity.csv (every row)"
fi

echo "[run-everything] done. Results are in ./results/"
echo "[run-everything] tear down with: $COMPOSE down -v"
