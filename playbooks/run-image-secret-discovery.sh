#!/bin/bash
#
# run-image-secret-discovery.sh
# ---------------------------------------------------------------------------
# CLOUD/CONTAINER EDR (CDR) DETECTION COVERAGE — NON-PRODUCTION USE ONLY
#
# Emulates hunting for secrets accidentally baked into container image
# layers: build a small decoy image (secret set as an ENV in one layer,
# then "removed" in a later layer — the classic mistake), then discover it
# via `docker history` and by grepping the exported layer tarballs. All of
# this runs against the disposable docker-sandbox daemon from
# compose.privileged.yml — see that file's header for how to bring it up.
#
#   enumerate local images/containers    Container and Resource Discovery (T1613)
#   inspect image history for secrets     Unsecured Credentials in images  (T1552.007)
#   export + grep layers for leftover secrets   T1552.007
# ---------------------------------------------------------------------------
set -u

RESULTS_DIR="${RESULTS_DIR:-/home/root/results}"
SESSION="$(date +%s)"
LOG="${RESULTS_DIR}/imagesecrets_${SESSION}.log"
BUILD_DIR="/tmp/northline-image-secret-${SESSION}"
IMAGE_TAG="northline-decoy-image:${SESSION}"

mkdir -p "$RESULTS_DIR"
say() { echo -e "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
step() { echo "" | tee -a "$LOG"; say "=== $* ==="; }

say "Northline :: image/secret-discovery emulation :: session=$SESSION"

if [ -z "${DOCKER_HOST:-}" ]; then
    say "!! DOCKER_HOST not set. Bring the environment up with the privileged overlay:"
    say "     docker compose -f compose.yml -f compose.privileged.yml up -d"
    exit 1
fi
if ! command -v docker >/dev/null 2>&1; then
    say "!! docker CLI not installed — run: bash playbooks/install-container-tools.sh"
    exit 1
fi

step "build a decoy image with secrets baked into early layers (setup, not the attack)"
mkdir -p "$BUILD_DIR"
# Two realistic mistakes in one image:
#  1. a secret set via ENV — stays visible forever in image config/history
#  2. a secret written to a FILE then deleted in a later layer — gone from
#     the final filesystem view, but still physically present in the
#     earlier layer's tar and recoverable by exporting+grepping layers
cat > "$BUILD_DIR/Dockerfile" <<'EOF'
FROM alpine:3.20
ENV DECOY_API_KEY="DECOY-BAKED-IN-SECRET-NOT-REAL-00000000"
RUN echo "DECOY-SECRET-FILE-CONTENT-NOT-REAL-11111111" > /tmp/build-secret.txt \
    && echo "(secret file exists in this layer)"
RUN rm -f /tmp/build-secret.txt
RUN echo layer-without-network-access
EOF
docker build -q -t "$IMAGE_TAG" "$BUILD_DIR" 2>&1 | tee -a "$LOG"

step "discovery — enumerate local images (ATT&CK T1613)"
docker images 2>&1 | tee -a "$LOG"

step "discovery — inspect image history for the ENV secret (ATT&CK T1552.007)"
docker history --no-trunc "$IMAGE_TAG" 2>&1 | tee -a "$LOG"
say "^ the ENV secret is visible directly in history — it never leaves image metadata."

step "discovery — export layers and grep for the 'deleted' secret file (ATT&CK T1552.007)"
EXPORT_TAR="${RESULTS_DIR}/image_export_${SESSION}.tar"
docker save -o "$EXPORT_TAR" "$IMAGE_TAG" 2>&1 | tee -a "$LOG"
# Modern `docker save` emits an OCI layout (blobs/sha256/<digest>, no file
# extension); older Docker emits per-layer <id>/layer.tar. Handle both by
# just trying every entry as a gzip-or-plain tar and grepping its contents.
FOUND=""
for entry in $(tar -tf "$EXPORT_TAR" 2>/dev/null | grep -E '(blobs/sha256/.+|/layer\.tar)$'); do
    # Blobs may be gzip-compressed (older docker) or plain tar (newer docker
    # with containerd snapshotter) — try gunzip, fall back to raw bytes.
    # Two separate extractions (not a shell variable) to stay binary-safe.
    CONTENT="$(tar -xOf "$EXPORT_TAR" "$entry" 2>/dev/null | zcat 2>/dev/null \
        | grep -a -m1 'DECOY-SECRET-FILE-CONTENT')"
    if [ -z "$CONTENT" ]; then
        CONTENT="$(tar -xOf "$EXPORT_TAR" "$entry" 2>/dev/null \
            | grep -a -m1 'DECOY-SECRET-FILE-CONTENT')"
    fi
    if [ -n "$CONTENT" ]; then
        say "!! found 'deleted' secret still present in layer $entry: $CONTENT"
        FOUND="yes"
        break
    fi
done
[ -z "$FOUND" ] && say "(secret file not found via layer grep — unexpected; check export format above)"

step "Done — image/secret-discovery emulation complete."
say "artifacts: $LOG  $EXPORT_TAR"
say "cleanup: docker rmi $IMAGE_TAG   (runs against docker-sandbox, not any real registry/host)"
