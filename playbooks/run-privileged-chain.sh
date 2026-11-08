#!/bin/bash
#
# run-privileged-chain.sh
# ---------------------------------------------------------------------------
# CLOUD/CONTAINER EDR (CDR) DETECTION COVERAGE — NON-PRODUCTION USE ONLY
#
# Orchestrates the scenarios that need compose.privileged.yml's disposable
# Docker-in-Docker sandbox: Docker-socket escape, privileged-capability
# abuse, cryptomining, image/secret discovery. Also runs the two scenarios
# that don't need the overlay but round out the cloud/container-native set
# (workload-identity theft, impair-logging) so this is a complete "run the
# cloud/container batch" entrypoint, parallel to run-full-chain.sh for
# the base scenarios.
#
# A failing stage does not stop the chain; a stage summary is printed at the
# end and the script exits non-zero if any stage failed.
#
# Requires the privileged overlay to be up and tooling installed:
#   docker compose -f compose.yml -f compose.privileged.yml up -d
#   docker compose -f compose.yml -f compose.privileged.yml exec ops-console \
#       bash playbooks/install-container-tools.sh
#   docker compose -f compose.yml -f compose.privileged.yml exec ops-console \
#       bash playbooks/run-privileged-chain.sh
# ---------------------------------------------------------------------------
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/lib-activity.sh"   # act_summary_all prints the combined activity table at the bottom
RESULTS_DIR="${RESULTS_DIR:-/home/root/results}"
SESSION="$(date +%s)"
LOG="${RESULTS_DIR}/privileged_chain_${SESSION}.log"

mkdir -p "$RESULTS_DIR"
say() { echo -e "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
stage() { echo "" | tee -a "$LOG"; say "########## STAGE: $* ##########"; }
source "$HERE/lib-chain.sh"      # chain_stage / chain_end: run each stage, report failures at the end

say "Cymylau :: privileged/cloud-native chain :: session=$SESSION"

if [ -z "${DOCKER_HOST:-}" ]; then
    say "!! DOCKER_HOST not set. Bring the environment up with the privileged overlay first:"
    say "     docker compose -f compose.yml -f compose.privileged.yml up -d"
    exit 1
fi

chain_stage "seed decoy artifacts (incl. K8s service-account token)" bash "$HERE/seed-decoys.sh"

# the stages and their order come from the scenario manifest (scenarios.json)
mapfile -t STAGES < <(python3 "$HERE/scenario-index.py" chain privileged)
[ "${#STAGES[@]}" -gt 0 ] || { say "!! could not read the scenario manifest (scenarios.json)"; exit 1; }
n=0
for s in "${STAGES[@]}"; do
    n=$((n + 1))
    chain_stage "${n}/${#STAGES[@]} ${s#*$'\t'}" bash "$HERE/${s%%$'\t'*}"
done

say "########## PRIVILEGED CHAIN COMPLETE — session=$SESSION ##########"
say "consolidated timeline: $LOG"

act_summary_all
chain_end
