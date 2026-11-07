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
# Run inside the ops-console container:  bash playbooks/seed-decoys.sh
set -u

source "$(cd "$(dirname "$0")" && pwd)/lib-guard.sh"
require_lab_container

HOME_DIR="${HOME:-/home/root}"
DECOY_DIR="${DECOY_DIR:-${HOME_DIR}/decoy-data}"
RESULTS_DIR="${RESULTS_DIR:-${HOME_DIR}/results}"
SA_DIR="/var/run/secrets/kubernetes.io/serviceaccount"

say() { echo "[seed-decoys] $*"; }

MANIFEST="${HOME_DIR}/.cymylau-seeded"
# Record each path this script creates, so --cleanup removes ONLY those and
# never a pre-existing real file.
record() { echo "$1" >> "$MANIFEST"; }

cleanup() {
    say "removing decoy artifacts..."
    if [ -f "$MANIFEST" ]; then
        while IFS= read -r path; do
            [ -n "$path" ] && rm -rf -- "$path"
        done < "$MANIFEST"
        rm -f -- "$MANIFEST"
        # drop dirs we may have created, only if now empty
        rmdir "${HOME_DIR}/.ssh" "${HOME_DIR}/.aws" 2>/dev/null || true
    else
        say "no manifest at $MANIFEST — nothing this script created, removing nothing"
    fi
    say "done."
}

if [ "${1:-}" = "--cleanup" ]; then
    cleanup
    exit 0
fi

[ -e "$DECOY_DIR" ] || record "$DECOY_DIR"
[ -e "${HOME_DIR}/.mozilla_decoy" ] || record "${HOME_DIR}/.mozilla_decoy"
mkdir -p "${HOME_DIR}/.ssh" "${HOME_DIR}/.aws" "${HOME_DIR}/.mozilla_decoy" \
         "${DECOY_DIR}/documents"

# --- Decoy SSH key (NOT a real keypair, just key-shaped bytes) -------------
if [ ! -f "${HOME_DIR}/.ssh/id_rsa" ]; then
    record "${HOME_DIR}/.ssh/id_rsa"; record "${HOME_DIR}/.ssh/id_rsa.pub"
    {
        echo "-----BEGIN OPENSSH PRIVATE KEY-----"
        echo "RURSLUxBQi1ERUNPWS1OT1QtQS1SRUFMLUtFWS1EBE0tTk9ULURFQ1JZUFQtTUU"
        echo "VGhpcyBpcyBhIGRlY295IGtleSBmb3IgdGhlIEVEUiB0ZXN0IGxhYi4gTm90IHJlYWwu"
        echo "-----END OPENSSH PRIVATE KEY-----"
    } > "${HOME_DIR}/.ssh/id_rsa"
    chmod 600 "${HOME_DIR}/.ssh/id_rsa"
    echo "ssh-rsa CYMYLAU-DECOY-NOT-A-REAL-KEY cymylau-decoy@cymylau-ops-console" \
        > "${HOME_DIR}/.ssh/id_rsa.pub"
    say "seeded decoy SSH keypair -> ${HOME_DIR}/.ssh/id_rsa"
fi

# --- Decoy cloud credentials file ------------------------------------------
if [ ! -f "${HOME_DIR}/.aws/credentials" ]; then
    record "${HOME_DIR}/.aws/credentials"
    cat > "${HOME_DIR}/.aws/credentials" <<'EOF'
[default]
aws_access_key_id = AKIA_DECOY_DO_NOT_USE
aws_secret_access_key = DECOY+SECRET+NOT+A+REAL+KEY+00000000
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
    ("https://cymylau-decoy.example", "decoy-user", "DECOY-NOT-A-REAL-PASSWORD"),
)
con.commit()
con.close()
PYEOF
    else
        echo "DECOY-NOT-REAL-SQLITE-CONTENT" > "$LOGIN_DB"
    fi
    say "seeded decoy browser-credential store -> $LOGIN_DB"
fi

# --- Decoy "sensitive" documents for staging / exfil / impact scenarios ----
for i in 1 2 3 4 5; do
    f="${DECOY_DIR}/documents/customer-records-${i}.txt"
    [ -f "$f" ] && continue
    {
        echo "DECOY DOCUMENT — customer-records-${i}"
        echo "This file exists only to be discovered/staged/encrypted by EDR"
        echo "these scenarios. It contains no real data."
        head -c 2048 /dev/urandom | base64
    } > "$f"
done
say "seeded $(ls "${DECOY_DIR}/documents" | wc -l) decoy documents -> ${DECOY_DIR}/documents"

# --- Decoy Kubernetes service-account token (real mount path, decoy content) --
if [ ! -f "${SA_DIR}/token" ]; then
    [ -e "$SA_DIR" ] || record "$SA_DIR"
    mkdir -p "$SA_DIR"
    # Header/payload are real-looking base64url JWT shapes but decode to decoy
    # text, not a signed token — not usable against any real API server.
    printf 'eyJhbGciOiJSUzI1NiIsImtpZCI6ImxhYi1kZWNveSJ9.eyJzdWIiOiJsYWItZGVjb3kiLCJuYW1lIjoiRURSLUxBQi1ERUNPWS1OT1QtQS1SRUFMLVRPS0VOIn0.bGFiLWRlY295LXNpZ25hdHVyZS1ub3QtcmVhbA==' \
        > "${SA_DIR}/token"
    echo "-----BEGIN CERTIFICATE-----
TEFCLURFQ09ZLUNFUlRJRklDQVRFLU5PVC1BLVJFQUwtQ0VSVC1GT1ItVEhFLUVESi1URVNULUxBQg==
-----END CERTIFICATE-----" > "${SA_DIR}/ca.crt"
    echo "cymylau-decoy-namespace" > "${SA_DIR}/namespace"
    say "seeded decoy Kubernetes service-account token -> ${SA_DIR}/token"
fi

say "done. Use --cleanup to remove everything this script created."
