#!/bin/bash
#
# simulate-privileged-chain.sh
# ---------------------------------------------------------------------------
# CLOUD/CONTAINER EDR (CDR) DETECTION TEST — LAB USE ONLY
#
# Orchestrates the scenarios that need compose.privileged.yml's disposable
# Docker-in-Docker sandbox: Docker-socket escape, privileged-capability
# abuse, cryptomining, image/secret discovery. Also runs the two scenarios
# that don't need the overlay but round out the cloud/container-native set
# (workload-identity theft, impair-logging) so this is a complete "run the
# cloud/container batch" entrypoint, parallel to simulate-full-chain.sh for
# the base scenarios.
#
# Requires the privileged overlay to be up and tooling installed:
#   docker compose -f compose.yml -f compose.privileged.yml up -d
#   docker compose -f compose.yml -f compose.privileged.yml exec edr-tester \
#       bash test-scripts/install-container-tools.sh
#   docker compose -f compose.yml -f compose.privileged.yml exec edr-tester \
#       bash test-scripts/simulate-privileged-chain.sh
# ---------------------------------------------------------------------------
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="${RESULTS_DIR:-/home/root/results}"
SESSION="$(date +%s)"
LOG="${RESULTS_DIR}/privileged_chain_${SESSION}.log"

mkdir -p "$RESULTS_DIR"
say() { echo -e "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
stage() { echo "" | tee -a "$LOG"; say "########## STAGE: $* ##########"; }

say "CDR test lab :: privileged/cloud-native chain :: session=$SESSION"

if [ -z "${DOCKER_HOST:-}" ]; then
    say "!! DOCKER_HOST not set. Bring the lab up with the privileged overlay first:"
    say "     docker compose -f compose.yml -f compose.privileged.yml up -d"
    exit 1
fi

stage "0/7 seed decoy artifacts (incl. K8s service-account token)"
bash "$HERE/seed-decoys.sh" 2>&1 | tee -a "$LOG"

stage "1/7 Docker-socket escape"
bash "$HERE/simulate-docker-socket-escape.sh" 2>&1 | tee -a "$LOG"

stage "2/7 privileged-container capability abuse"
bash "$HERE/simulate-privileged-container-abuse.sh" 2>&1 | tee -a "$LOG"

stage "3/7 cryptomining / resource hijacking"
bash "$HERE/simulate-cryptomining.sh" 2>&1 | tee -a "$LOG"

stage "4/7 image/secret discovery"
bash "$HERE/simulate-image-secret-discovery.sh" 2>&1 | tee -a "$LOG"

stage "5/7 workload-identity theft"
bash "$HERE/simulate-workload-identity-theft.sh" 2>&1 | tee -a "$LOG"

stage "6/7 impair cloud logging"
bash "$HERE/simulate-impair-logging.sh" 2>&1 | tee -a "$LOG"

say "########## PRIVILEGED CHAIN COMPLETE — session=$SESSION ##########"
say "consolidated timeline: $LOG"
