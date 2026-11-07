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

# Create results/ as the invoking user (otherwise Docker creates it as root).
mkdir -p results

COMPOSE="docker compose -f compose.yml -f compose.privileged.yml"

echo "[run-everything] bringing up the environment (base + privileged overlay)..."
$COMPOSE up -d

echo "[run-everything] waiting for docker-sandbox to be ready..."
for i in $(seq 1 15); do
    $COMPOSE exec ops-console sh -c 'true' >/dev/null 2>&1 && break
    sleep 1
done

echo "[run-everything] setup phase (needs egress): install tooling..."
$COMPOSE exec ops-console bash playbooks/bootstrap.sh
$COMPOSE exec ops-console bash playbooks/install-extra-tools.sh
$COMPOSE exec ops-console bash playbooks/install-container-tools.sh

echo "[run-everything] locking down network (removing setup-net egress)..."
COMPOSE="$COMPOSE" bash lock-down-network.sh

echo "[run-everything] all base scenarios..."
$COMPOSE exec -e SKIP_SETUP=1 ops-console bash playbooks/run-all.sh

echo "[run-everything] all privileged/overlay scenarios..."
$COMPOSE exec ops-console bash playbooks/run-privileged-chain.sh

# Containers run as root, so everything they wrote to ./results is root-owned
# on the host. Hand it back to the invoking user.
echo "[run-everything] fixing ./results ownership -> $(id -u):$(id -g)..."
for svc in ops-console dns-sink control-api; do
    $COMPOSE exec -T "$svc" chown -R "$(id -u):$(id -g)" /home/root/results || true
done

echo "[run-everything] done. Results are in ./results/"
echo "[run-everything] tear down with: docker compose -f compose.yml -f compose.privileged.yml down"
