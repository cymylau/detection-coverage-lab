#!/bin/bash
#
# run-full-chain.sh
# ---------------------------------------------------------------------------
# EDR DETECTION COVERAGE — NON-PRODUCTION USE ONLY
#
# Orchestrates the environment's individual scenario scripts into one longer,
# multi-stage kill chain, so EDR correlation (not just single-technique
# detection) can be exercised in one purple-team session. Each stage is
# also runnable standalone — see docs/REFERENCE.md for the full list.
#
#   the scenarios with "chain": "base" in scenarios.json, in that order (host
#   recon, credential discovery, persistence, defense evasion, metadata theft +
#   DNS exfil, collection staging, C2 beacon, HTTP exfil, HTTPS exfil, lateral movement, SSH
#   audit session), then the OWASP scenario unless SKIP_OWASP=1.
#   Print the list:  python3 playbooks/scenario-index.py chain base
#
# Persistence artifacts are cleaned up at the end unless
# KEEP_PERSISTENCE=1 is set.
#
# A failing stage does not stop the chain: the next stage runs, a stage summary
# is printed at the end, and the script exits non-zero if any stage failed.
#
# Usage: bash playbooks/run-full-chain.sh
# ---------------------------------------------------------------------------
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
source "$HERE/lib-activity.sh"   # act_summary_all prints the combined activity table at the bottom
RESULTS_DIR="${RESULTS_DIR:-/home/root/results}"
SESSION="$(date +%s)"
LOG="${RESULTS_DIR}/full_chain_${SESSION}.log"

mkdir -p "$RESULTS_DIR"
say() { echo -e "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
stage() { echo "" | tee -a "$LOG"; say "########## STAGE: $* ##########"; }
source "$HERE/lib-chain.sh"      # chain_stage / chain_end: run each stage, report failures at the end

say "Cymylau :: FULL CHAIN emulation :: session=$SESSION"
say "this orchestrates multiple independent scenario scripts — see each"
say "script's own header for its ATT&CK technique mapping."

chain_stage "seed decoy artifacts" bash "$HERE/seed-decoys.sh"

# the stages and their order come from the scenario manifest (scenarios.json)
mapfile -t STAGES < <(python3 "$HERE/scenario-index.py" chain base)
# SKIP_OWASP=1 runs the ATT&CK stages only (run-everything.sh --only mitre)
[ "${SKIP_OWASP:-0}" != "1" ] && mapfile -t -O "${#STAGES[@]}" STAGES < <(python3 "$HERE/scenario-index.py" chain owasp)
[ "${#STAGES[@]}" -gt 0 ] || { say "!! could not read the scenario manifest (scenarios.json)"; exit 1; }
n=0
for s in "${STAGES[@]}"; do
    n=$((n + 1))
    chain_stage "${n}/${#STAGES[@]} ${s#*$'\t'}" bash "$HERE/${s%%$'\t'*}"
done

if [ "${KEEP_PERSISTENCE:-0}" != "1" ]; then
    chain_stage "cleanup: persistence artifacts (KEEP_PERSISTENCE=1 keeps them)" bash "$HERE/run-persistence.sh" --cleanup
fi

say "########## FULL CHAIN COMPLETE — session=$SESSION ##########"
say "consolidated timeline: $LOG"

act_summary_all
chain_end
