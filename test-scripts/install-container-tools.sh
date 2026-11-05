#!/bin/bash
#
# install-container-tools.sh — tooling for the container-escape scenarios.
#
# Installs only the Docker CLI (no local daemon — DOCKER_HOST from
# compose.privileged.yml points it at the disposable docker-sandbox
# container) and util-linux (nsenter). Run only when using the
# compose.privileged.yml overlay.
#
# Run inside the edr-tester container, after lab-setup.sh:
#   bash test-scripts/install-container-tools.sh
set -eu

echo "[install-container-tools] installing docker CLI + util-linux..."
apt-get update -qq
# docker-cli is the client binary; docker.io pulls in dockerd/docker-proxy
# too, which we don't need here (DOCKER_HOST points at docker-sandbox) but
# it's harmless to have installed and is a dependency on some distros.
apt-get install -y --no-install-recommends docker-cli util-linux >/dev/null

echo "[install-container-tools] verifying DOCKER_HOST is reachable..."
if [ -z "${DOCKER_HOST:-}" ]; then
    echo "[install-container-tools] !! DOCKER_HOST is not set — bring the lab up with:"
    echo "    docker compose -f compose.yml -f compose.privileged.yml up -d"
    exit 1
fi
docker version >/dev/null 2>&1 && echo "[install-container-tools] docker-sandbox reachable at \$DOCKER_HOST=$DOCKER_HOST" \
    || echo "[install-container-tools] !! could not reach \$DOCKER_HOST=$DOCKER_HOST yet — it may still be starting, retry in a few seconds"

echo "[install-container-tools] done."
