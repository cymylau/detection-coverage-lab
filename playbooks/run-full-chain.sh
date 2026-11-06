#!/bin/bash
#
# run-full-chain.sh
# ---------------------------------------------------------------------------
# EDR DETECTION COVERAGE — NON-PRODUCTION USE ONLY
#
# Orchestrates the environment's individual scenario scripts into one longer,
# multi-stage kill chain, so EDR correlation (not just single-technique
# detection) can be exercised in one purple-team session. Each stage is
# also runnable standalone — see README.md for the full list.
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
# Usage: bash playbooks/run-full-chain.sh
# ---------------------------------------------------------------------------
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="${RESULTS_DIR:-/home/root/results}"
SESSION="$(date +%s)"
LOG="${RESULTS_DIR}/full_chain_${SESSION}.log"

mkdir -p "$RESULTS_DIR"
say() { echo -e "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
stage() { echo "" | tee -a "$LOG"; say "########## STAGE: $* ##########"; }

say "Northline :: FULL CHAIN emulation :: session=$SESSION"
say "this orchestrates multiple independent scenario scripts — see each"
say "script's own header for its ATT&CK technique mapping."

stage "0/9 seed decoy artifacts"
bash "$HERE/seed-decoys.sh" 2>&1 | tee -a "$LOG"

stage "1/9 host recon"
bash "$HERE/run-host-recon.sh" 2>&1 | tee -a "$LOG"

stage "2/9 credential discovery"
bash "$HERE/run-credential-discovery.sh" 2>&1 | tee -a "$LOG"

stage "3/9 persistence"
bash "$HERE/run-persistence.sh" 2>&1 | tee -a "$LOG"

stage "4/9 defense evasion"
bash "$HERE/run-defense-evasion.sh" 2>&1 | tee -a "$LOG"

stage "5/9 metadata theft + collection staging"
bash "$HERE/run-metadata-exfil.sh" 2>&1 | tee -a "$LOG"
bash "$HERE/run-collection-staging.sh" 2>&1 | tee -a "$LOG"

stage "6/9 C2 beacon"
bash "$HERE/run-c2-beacon.sh" 2>&1 | tee -a "$LOG"

stage "7/9 HTTPS exfil"
bash "$HERE/run-https-exfil.sh" 2>&1 | tee -a "$LOG"

stage "8/9 lateral movement"
bash "$HERE/run-lateral-movement.sh" 2>&1 | tee -a "$LOG"

stage "9/9 SSH audit session"
bash "$HERE/run-ssh-audit-session.sh" 2>&1 | tee -a "$LOG"

if [ "${KEEP_PERSISTENCE:-0}" != "1" ]; then
    say "cleaning up persistence artifacts (set KEEP_PERSISTENCE=1 to keep them)"
    bash "$HERE/run-persistence.sh" --cleanup 2>&1 | tee -a "$LOG"
fi

say "########## FULL CHAIN COMPLETE — session=$SESSION ##########"
say "consolidated timeline: $LOG"
