#!/bin/bash
#
# run-everything.sh
# ---------------------------------------------------------------------------
# The one command that runs everything: setup, every base scenario, and
# every privileged/overlay scenario. Run this from your HOST shell (not
# inside a container) in the repo root, since it drives `docker compose`
# itself, including bringing up compose.privileged.yml's extra containers:
#
#   bash run-everything.sh
#
# For anything more targeted:
#   - all base scenarios only:        playbooks/run-all.sh (inside ops-console)
#   - all privileged scenarios only:  playbooks/run-privileged-chain.sh
#                                      (inside ops-console, overlay already up)
#   - one scenario:                   playbooks/run-<name>.sh
#                                      (inside ops-console)
# See README.md for the full scenario list and how to run each by hand.
# ---------------------------------------------------------------------------
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
cd "$HERE"

COMPOSE="docker compose -f compose.yml -f compose.privileged.yml"

echo "[run-everything] bringing up the environment (base + privileged overlay)..."
$COMPOSE up -d

echo "[run-everything] waiting for docker-sandbox to be ready..."
for i in $(seq 1 15); do
    $COMPOSE exec ops-console sh -c 'true' >/dev/null 2>&1 && break
    sleep 1
done

echo "[run-everything] base setup + all base scenarios..."
$COMPOSE exec ops-console bash playbooks/run-all.sh

echo "[run-everything] privileged-overlay setup..."
$COMPOSE exec ops-console bash playbooks/install-container-tools.sh

echo "[run-everything] all privileged/overlay scenarios..."
$COMPOSE exec ops-console bash playbooks/run-privileged-chain.sh

echo "[run-everything] done. Results are in ./results/"
echo "[run-everything] tear down with: docker compose -f compose.yml -f compose.privileged.yml down"
