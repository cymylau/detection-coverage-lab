#!/bin/bash
#
# run-collection-staging.sh
# ---------------------------------------------------------------------------
# EDR DETECTION COVERAGE — NON-PRODUCTION USE ONLY
#
# Emulates bulk collection of "sensitive" files into a staged archive ahead
# of exfiltration. Operates only on decoy documents created by
# seed-decoys.sh — run that first. Generalizes the single base64-blob
# staging step in run-metadata-exfil.sh to realistic multi-file
# archive tooling (tar/zip), which trips different detections.
#
#   find sensitive-looking files    Automated Collection          (T1119)
#   tar/zip the results             Archive Collected Data        (T1560.001)
# ---------------------------------------------------------------------------
set -u

HOME_DIR="${HOME:-/home/root}"
DECOY_DIR="${DECOY_DIR:-${HOME_DIR}/decoy-data}"
RESULTS_DIR="${RESULTS_DIR:-${HOME_DIR}/results}"
SESSION="$(date +%s)"
LOG="${RESULTS_DIR}/staging_${SESSION}.log"
STAGE_DIR="${RESULTS_DIR}/staged_${SESSION}"

mkdir -p "$RESULTS_DIR"
say() { echo -e "[$(date -u +%H:%M:%S)] $*" | tee -a "$LOG"; }
step() { echo "" | tee -a "$LOG"; say "=== $* ==="; }

say "Northline :: collection & staging emulation :: session=$SESSION"

if [ ! -d "$DECOY_DIR/documents" ]; then
    say "!! no decoys found — run: bash playbooks/seed-decoys.sh first"
    exit 1
fi

step "collection — find sensitive-looking decoy documents (ATT&CK T1119)"
mapfile -t FOUND < <(find "$DECOY_DIR" -type f \( -iname '*record*' -o -iname '*.txt' \) 2>/dev/null)
say "found ${#FOUND[@]} candidate files:"
printf '  %s\n' "${FOUND[@]}" | tee -a "$LOG"

mkdir -p "$STAGE_DIR"
cp "${FOUND[@]}" "$STAGE_DIR/" 2>/dev/null
say "copied candidates into staging dir -> $STAGE_DIR"

step "archive — tar.gz the staged files (ATT&CK T1560.001)"
TARBALL="${RESULTS_DIR}/staged_${SESSION}.tar.gz"
tar -czf "$TARBALL" -C "$RESULTS_DIR" "staged_${SESSION}" 2>&1 | tee -a "$LOG"
say "created archive -> $TARBALL ($(wc -c < "$TARBALL" 2>/dev/null || echo 0) bytes)"

step "archive — also zip, if available, for tooling diversity (ATT&CK T1560.001)"
if command -v zip >/dev/null 2>&1; then
    ZIPFILE="${RESULTS_DIR}/staged_${SESSION}.zip"
    (cd "$RESULTS_DIR" && zip -qr "$ZIPFILE" "staged_${SESSION}") 2>&1 | tee -a "$LOG"
    say "created archive -> $ZIPFILE"
else
    say "(zip not installed — tar.gz only; install zip in bootstrap.sh to exercise both)"
fi

step "Done — collection & staging emulation complete."
say "artifacts: $LOG  $TARBALL  (staged copies in $STAGE_DIR)"
