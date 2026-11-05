#!/bin/bash
#
# seed-decoys.sh — create decoy "sensitive" artifacts for later scenarios.
#
# Nothing created here is real: no real SSH key, no real cloud credential, no
# real document content. This just gives the credential-discovery, staging,
# and impact-emulation scripts realistic-looking files to find/collect/touch
# without ever risking real data. Safe to re-run (idempotent) and to remove
# with --cleanup.
#
# Run inside the edr-tester container:  bash test-scripts/seed-decoys.sh
set -u

HOME_DIR="${HOME:-/home/root}"
DECOY_DIR="${DECOY_DIR:-${HOME_DIR}/decoy-data}"
RESULTS_DIR="${RESULTS_DIR:-${HOME_DIR}/results}"
SA_DIR="/var/run/secrets/kubernetes.io/serviceaccount"

say() { echo "[seed-decoys] $*"; }

cleanup() {
    say "removing decoy artifacts..."
    rm -rf "${HOME_DIR}/.ssh/id_rsa" "${HOME_DIR}/.ssh/id_rsa.pub" \
           "${HOME_DIR}/.aws" \
           "${HOME_DIR}/.mozilla_decoy" \
           "$DECOY_DIR" \
           "$SA_DIR"
    say "done."
}

if [ "${1:-}" = "--cleanup" ]; then
    cleanup
    exit 0
fi

mkdir -p "${HOME_DIR}/.ssh" "${HOME_DIR}/.aws" "${HOME_DIR}/.mozilla_decoy" \
         "${DECOY_DIR}/documents"

# --- Decoy SSH key (NOT a real keypair, just key-shaped bytes) -------------
if [ ! -f "${HOME_DIR}/.ssh/id_rsa" ]; then
    {
        echo "-----BEGIN OPENSSH PRIVATE KEY-----"
        echo "RURSLUxBQi1ERUNPWS1OT1QtQS1SRUFMLUtFWS1EBE0tTk9ULURFQ1JZUFQtTUU"
        echo "VGhpcyBpcyBhIGRlY295IGtleSBmb3IgdGhlIEVEUiB0ZXN0IGxhYi4gTm90IHJlYWwu"
        echo "-----END OPENSSH PRIVATE KEY-----"
    } > "${HOME_DIR}/.ssh/id_rsa"
    chmod 600 "${HOME_DIR}/.ssh/id_rsa"
    echo "ssh-rsa EDR-LAB-DECOY-NOT-A-REAL-KEY lab-decoy@edr-test-lab" \
        > "${HOME_DIR}/.ssh/id_rsa.pub"
    say "seeded decoy SSH keypair -> ${HOME_DIR}/.ssh/id_rsa"
fi

# --- Decoy cloud credentials file ------------------------------------------
if [ ! -f "${HOME_DIR}/.aws/credentials" ]; then
    cat > "${HOME_DIR}/.aws/credentials" <<'EOF'
[default]
aws_access_key_id = AKIA_LAB_DECOY_DO_NOT_USE
aws_secret_access_key = LAB+DECOY+SECRET+NOT+A+REAL+KEY+00000000
EOF
    say "seeded decoy ~/.aws/credentials"
fi

# --- Decoy "browser saved logins" sqlite-ish file ---------------------------
LOGIN_DB="${HOME_DIR}/.mozilla_decoy/logins.sqlite"
if [ ! -f "$LOGIN_DB" ]; then
    if command -v python3 >/dev/null 2>&1; then
        python3 - "$LOGIN_DB" <<'PYEOF'
import sqlite3, sys
db = sys.argv[1]
con = sqlite3.connect(db)
con.execute("CREATE TABLE moz_logins (hostname TEXT, username TEXT, password TEXT)")
con.execute(
    "INSERT INTO moz_logins VALUES (?, ?, ?)",
    ("https://lab-decoy.example", "decoy-user", "LAB-DECOY-NOT-A-REAL-PASSWORD"),
)
con.commit()
con.close()
PYEOF
    else
        echo "LAB-DECOY-NOT-REAL-SQLITE-CONTENT" > "$LOGIN_DB"
    fi
    say "seeded decoy browser-credential store -> $LOGIN_DB"
fi

# --- Decoy "sensitive" documents for staging / exfil / impact scenarios ----
for i in 1 2 3 4 5; do
    f="${DECOY_DIR}/documents/customer-records-${i}.txt"
    [ -f "$f" ] && continue
    {
        echo "LAB DECOY DOCUMENT — customer-records-${i}"
        echo "This file exists only to be discovered/staged/encrypted by EDR"
        echo "test-lab scenarios. It contains no real data."
        head -c 2048 /dev/urandom | base64
    } > "$f"
done
say "seeded $(ls "${DECOY_DIR}/documents" | wc -l) decoy documents -> ${DECOY_DIR}/documents"

# --- Decoy Kubernetes service-account token (real mount path, decoy content) --
if [ ! -f "${SA_DIR}/token" ]; then
    mkdir -p "$SA_DIR"
    # Header/payload are real-looking base64url JWT shapes but decode to decoy
    # text, not a signed token — not usable against any real API server.
    printf 'eyJhbGciOiJSUzI1NiIsImtpZCI6ImxhYi1kZWNveSJ9.eyJzdWIiOiJsYWItZGVjb3kiLCJuYW1lIjoiRURSLUxBQi1ERUNPWS1OT1QtQS1SRUFMLVRPS0VOIn0.bGFiLWRlY295LXNpZ25hdHVyZS1ub3QtcmVhbA==' \
        > "${SA_DIR}/token"
    echo "-----BEGIN CERTIFICATE-----
TEFCLURFQ09ZLUNFUlRJRklDQVRFLU5PVC1BLVJFQUwtQ0VSVC1GT1ItVEhFLUVESi1URVNULUxBQg==
-----END CERTIFICATE-----" > "${SA_DIR}/ca.crt"
    echo "lab-decoy-namespace" > "${SA_DIR}/namespace"
    say "seeded decoy Kubernetes service-account token -> ${SA_DIR}/token"
fi

say "done. Use --cleanup to remove everything this script created."
