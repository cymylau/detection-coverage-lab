#!/bin/bash
#
# simulate-full-chain.sh
# ---------------------------------------------------------------------------
# EDR DETECTION TEST — LAB USE ONLY
#
# Orchestrates the lab's individual scenario scripts into one longer,
# multi-stage kill chain, so EDR correlation (not just single-technique
# detection) can be exercised in one purple-team session. Each stage is
# also runnable standalone — see README.md for the full list.
#
#   1. Host recon                simulate-host-recon.sh
#   2. Credential discovery      simulate-credential-discovery.sh
#   3. Persistence               simulate-persistence.sh
#   4. Defense evasion           simulate-defense-evasion.sh
#   5. Metadata theft + staging  simulate-metadata-exfil.sh, simulate-collection-staging.sh
#   6. C2 beacon                 simulate-c2-beacon.sh
#   7. HTTPS exfil               simulate-https-exfil.sh
#   8. Lateral movement          simulate-lateral-movement.sh
#
# Persistence artifacts from stage 3 are cleaned up at the end unless
# KEEP_PERSISTENCE=1 is set.
#
# Usage: bash test-scripts/simulate-full-chain.sh
# ---------------------------------------------------------------------------
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
RESULTS_DIR="${RESULTS_DIR:-/home/root/results}"
SESSION="$(date +%s)"
LOG="${RESULTS_DIR}/full_chain_${SESSION}.log"

mkdir -p "$RESULTS_DIR"
say() { echo -e "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
stage() { echo "" | tee -a "$LOG"; say "########## STAGE: $* ##########"; }

say "EDR test lab :: FULL CHAIN emulation :: session=$SESSION"
say "this orchestrates multiple independent scenario scripts — see each"
say "script's own header for its ATT&CK technique mapping."

stage "0/8 seed decoy artifacts"
bash "$HERE/seed-decoys.sh" 2>&1 | tee -a "$LOG"

stage "1/8 host recon"
bash "$HERE/simulate-host-recon.sh" 2>&1 | tee -a "$LOG"

stage "2/8 credential discovery"
bash "$HERE/simulate-credential-discovery.sh" 2>&1 | tee -a "$LOG"

stage "3/8 persistence"
bash "$HERE/simulate-persistence.sh" 2>&1 | tee -a "$LOG"

stage "4/8 defense evasion"
bash "$HERE/simulate-defense-evasion.sh" 2>&1 | tee -a "$LOG"

stage "5/8 metadata theft + collection staging"
bash "$HERE/simulate-metadata-exfil.sh" 2>&1 | tee -a "$LOG"
bash "$HERE/simulate-collection-staging.sh" 2>&1 | tee -a "$LOG"

stage "6/8 C2 beacon"
bash "$HERE/simulate-c2-beacon.sh" 2>&1 | tee -a "$LOG"

stage "7/8 HTTPS exfil"
bash "$HERE/simulate-https-exfil.sh" 2>&1 | tee -a "$LOG"

stage "8/8 lateral movement"
bash "$HERE/simulate-lateral-movement.sh" 2>&1 | tee -a "$LOG"

if [ "${KEEP_PERSISTENCE:-0}" != "1" ]; then
    say "cleaning up persistence artifacts (set KEEP_PERSISTENCE=1 to keep them)"
    bash "$HERE/simulate-persistence.sh" --cleanup 2>&1 | tee -a "$LOG"
fi

say "########## FULL CHAIN COMPLETE — session=$SESSION ##########"
say "consolidated timeline: $LOG"
