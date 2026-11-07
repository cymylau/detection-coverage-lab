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
#   1. Host recon                run-host-recon.sh
#   2. Credential discovery      run-credential-discovery.sh
#   3. Persistence               run-persistence.sh
#   4. Defense evasion           run-defense-evasion.sh
#   5. Metadata theft + staging  run-metadata-exfil.sh, run-collection-staging.sh
#   6. C2 beacon                 run-c2-beacon.sh
#   7. HTTPS exfil               run-https-exfil.sh
#   8. Lateral movement          run-lateral-movement.sh
#   9. SSH audit session         run-ssh-audit-session.sh
#
# Persistence artifacts from stage 3 are cleaned up at the end unless
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

chain_stage "0/10 seed decoy artifacts" bash "$HERE/seed-decoys.sh"

chain_stage "1/10 host recon" bash "$HERE/run-host-recon.sh"

chain_stage "2/10 credential discovery" bash "$HERE/run-credential-discovery.sh"

chain_stage "3/10 persistence" bash "$HERE/run-persistence.sh"

chain_stage "4/10 defense evasion" bash "$HERE/run-defense-evasion.sh"

chain_stage "5a/10 metadata theft + DNS exfil" bash "$HERE/run-metadata-exfil.sh"
chain_stage "5b/10 collection staging" bash "$HERE/run-collection-staging.sh"

chain_stage "6/10 C2 beacon" bash "$HERE/run-c2-beacon.sh"

chain_stage "7/10 HTTPS exfil" bash "$HERE/run-https-exfil.sh"

chain_stage "8/10 lateral movement" bash "$HERE/run-lateral-movement.sh"

chain_stage "9/10 SSH audit session" bash "$HERE/run-ssh-audit-session.sh"

# SKIP_OWASP=1 runs the ATT&CK stages only (run-everything.sh --only mitre)
if [ "${SKIP_OWASP:-0}" != "1" ]; then
    chain_stage "10/10 OWASP Top 10:2025 application attacks" bash "$HERE/run-owasp-top10.sh"
fi

if [ "${KEEP_PERSISTENCE:-0}" != "1" ]; then
    chain_stage "cleanup: persistence artifacts (KEEP_PERSISTENCE=1 keeps them)" bash "$HERE/run-persistence.sh" --cleanup
fi

say "########## FULL CHAIN COMPLETE — session=$SESSION ##########"
say "consolidated timeline: $LOG"

act_summary_all
chain_end
