#!/bin/bash
#
# install-container-tools.sh — tooling for the container-escape scenarios.
#
# Installs only the Docker CLI (no local daemon — DOCKER_HOST from
# compose.privileged.yml points it at the disposable docker-sandbox
# container) and util-linux (nsenter). Run only when using the
# compose.privileged.yml overlay.
#
# Run inside the ops-console container, after bootstrap.sh:
#   bash playbooks/install-container-tools.sh
set -eu

echo "[install-container-tools] installing docker CLI + util-linux..."
apt-get -o Acquire::Retries=3 update -qq || {
    echo "[install-container-tools] !! apt-get update failed: the package mirrors are unreachable." >&2
    echo "[install-container-tools]    If an earlier run already locked the network down, start clean with:" >&2
    echo "[install-container-tools]    bash run-everything.sh --down   (then run again)" >&2
    exit 1; }
# docker-cli is the client binary; docker.io pulls in dockerd/docker-proxy
# too, which we don't need here (DOCKER_HOST points at docker-sandbox) but
# it's harmless to have installed and is a dependency on some distros.
apt-get -o Acquire::Retries=3 install -y --no-install-recommends docker-cli util-linux >/dev/null

echo "[install-container-tools] verifying DOCKER_HOST is reachable..."
if [ -z "${DOCKER_HOST:-}" ]; then
    echo "[install-container-tools] !! DOCKER_HOST is not set — bring the environment up with:"
    echo "    docker compose -f compose.yml -f compose.privileged.yml up -d"
    exit 1
fi
# docker-sandbox's daemon takes a few seconds to start after `compose up`
for _ in $(seq 1 30); do docker version >/dev/null 2>&1 && break; sleep 1; done
if docker version >/dev/null 2>&1; then
    echo "[install-container-tools] docker-sandbox reachable at \$DOCKER_HOST=$DOCKER_HOST"
else
    echo "[install-container-tools] !! could not reach \$DOCKER_HOST=$DOCKER_HOST after 30s — check: docker compose -f compose.yml -f compose.privileged.yml logs docker-sandbox" >&2
    exit 1
fi

# Versions are not pinned (Kali rolling drops old ones), so record what was
# actually installed to make a run reproducible/auditable after the fact.
mkdir -p "${RESULTS_DIR:-/home/root/results}"
dpkg-query -W -f='${Package}=${Version}\n' | sort > "${RESULTS_DIR:-/home/root/results}/installed-packages-install-container-tools.txt"

# The sandbox has no egress once the network is locked down, so pre-pull the
# only image the scenarios use (they reference alpine:3.20).
echo "[install-container-tools] pre-pulling alpine:3.20 into docker-sandbox..."
docker pull -q alpine:3.20 >/dev/null

echo "[install-container-tools] done."
