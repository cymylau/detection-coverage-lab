#!/bin/bash
#
# run-all.sh
# ---------------------------------------------------------------------------
# EDR DETECTION COVERAGE — NON-PRODUCTION USE ONLY
#
# Single entrypoint: setup + every scenario script in this environment, in order.
# Intended to be the one command you run in a fresh ops-console container to
# exercise the whole environment end to end.
#
#   1. bootstrap.sh             install tools, start decoy IMDS
#   2. install-extra-tools.sh   install tooling the newer scenarios need
#   3. run-full-chain.sh   seed decoys + every run-*.sh scenario
#                                (and cleans up persistence artifacts after,
#                                 unless KEEP_PERSISTENCE=1)
#
# Each step's own script is unchanged — this just calls them in sequence and
# stops on the first failure. Run it inside the ops-console container:
#
#   docker compose exec ops-console bash playbooks/run-all.sh
#
# Or non-interactively from the host in one line:
#
#   docker compose up -d && \
#   docker compose exec ops-console bash playbooks/run-all.sh
# ---------------------------------------------------------------------------
set -eu -o pipefail   # pipefail: `cmd | tee` must fail when cmd fails, not report tee's status

HERE="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="${RESULTS_DIR:-/home/root/results}"
SESSION="$(date +%s)"
LOG="${RESULTS_DIR}/run_all_${SESSION}.log"

mkdir -p "$RESULTS_DIR"
say() { echo -e "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
stage() { echo "" | tee -a "$LOG"; say "########## $* ##########"; }

say "Cymylau :: run-all :: session=$SESSION"
say "this runs setup, then every scenario script, start to finish."

# SKIP_SETUP=1: tools are already installed (run-everything.sh does setup
# first, then locks down the network, then calls this).
if [ "${SKIP_SETUP:-0}" = "1" ]; then
    say "SKIP_SETUP=1 — skipping package installs (already done); ensuring IMDS is up"
    SKIP_INSTALL=1 bash "$HERE/bootstrap.sh" 2>&1 | tee -a "$LOG"
else
    stage "SETUP 1/2 — bootstrap.sh"
    bash "$HERE/bootstrap.sh" 2>&1 | tee -a "$LOG"

    stage "SETUP 2/2 — install-extra-tools.sh"
    bash "$HERE/install-extra-tools.sh" 2>&1 | tee -a "$LOG"
fi

stage "SCENARIOS — run-full-chain.sh (seeds decoys + every run-*.sh)"
rc=0
bash "$HERE/run-full-chain.sh" 2>&1 | tee -a "$LOG" || rc=$?

if [ "$rc" -eq 0 ]; then
    say "########## RUN-ALL COMPLETE — session=$SESSION ##########"
else
    say "########## RUN-ALL FINISHED WITH FAILURES (exit $rc) — session=$SESSION; see the stage summary above ##########"
fi
say "consolidated log: $LOG — see results/ for every stage's own artifacts."
exit "$rc"
