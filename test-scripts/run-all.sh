#!/bin/bash
#
# run-all.sh
# ---------------------------------------------------------------------------
# EDR DETECTION TEST — LAB USE ONLY
#
# Single entrypoint: setup + every scenario script in this lab, in order.
# Intended to be the one command you run in a fresh edr-tester container to
# exercise the whole lab end to end.
#
#   1. lab-setup.sh             install tools, start mock IMDS
#   2. install-extra-tools.sh   install tooling the newer scenarios need
#   3. simulate-full-chain.sh   seed decoys + every simulate-*.sh scenario
#                                (and cleans up persistence artifacts after,
#                                 unless KEEP_PERSISTENCE=1)
#
# Each step's own script is unchanged — this just calls them in sequence and
# stops on the first failure. Run it inside the edr-tester container:
#
#   docker compose exec edr-tester bash test-scripts/run-all.sh
#
# Or non-interactively from the host in one line:
#
#   docker compose up -d && \
#   docker compose exec edr-tester bash test-scripts/run-all.sh
# ---------------------------------------------------------------------------
set -eu

HERE="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="${RESULTS_DIR:-/home/root/results}"
SESSION="$(date +%s)"
LOG="${RESULTS_DIR}/run_all_${SESSION}.log"

mkdir -p "$RESULTS_DIR"
say() { echo -e "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
stage() { echo "" | tee -a "$LOG"; say "########## $* ##########"; }

say "EDR test lab :: run-all :: session=$SESSION"
say "this runs setup, then every scenario script, start to finish."

stage "SETUP 1/2 — lab-setup.sh"
bash "$HERE/lab-setup.sh" 2>&1 | tee -a "$LOG"

stage "SETUP 2/2 — install-extra-tools.sh"
bash "$HERE/install-extra-tools.sh" 2>&1 | tee -a "$LOG"

stage "SCENARIOS — simulate-full-chain.sh (seeds decoys + every simulate-*.sh)"
bash "$HERE/simulate-full-chain.sh" 2>&1 | tee -a "$LOG"

say "########## RUN-ALL COMPLETE — session=$SESSION ##########"
say "consolidated log: $LOG — see results/ for every stage's own artifacts."
