#!/bin/bash
# lib-chain.sh — run the stages of a chain script, keep going when one fails,
# and say at the end which ones failed.
#
#   source "$HERE/lib-chain.sh"        # after defining LOG, say() and stage()
#   chain_stage "1/10 host recon" bash "$HERE/run-host-recon.sh"
#   ...
#   chain_end || exit 1                 # prints the stage table; non-zero if any stage failed
#
# Each stage's output goes to the terminal and to $LOG. Without this, `cmd | tee`
# reports tee's exit status, so a failed scenario looked exactly like a passing one.

CHAIN_RESULTS=()
CHAIN_FAILED=0

chain_stage() {
    local name="$1" rc
    shift
    stage "$name"
    "$@" 2>&1 | tee -a "$LOG"
    rc=${PIPESTATUS[0]}
    CHAIN_RESULTS+=("${rc}"$'\t'"${name}")
    if [ "$rc" -ne 0 ]; then
        CHAIN_FAILED=$((CHAIN_FAILED + 1))
        say "!! stage '${name}' exited ${rc}; continuing with the next stage"
    fi
    return 0
}

chain_end() {
    local r rc name
    {
        echo ""
        echo "=== Stage summary ==="
        for r in ${CHAIN_RESULTS[@]+"${CHAIN_RESULTS[@]}"}; do
            rc="${r%%$'\t'*}"; name="${r#*$'\t'}"
            if [ "$rc" = 0 ]; then printf '  ok      %s\n' "$name"
            else printf '  FAILED  %s (exit %s)\n' "$name" "$rc"; fi
        done
        if [ "$CHAIN_FAILED" -eq 0 ]; then echo "  all ${#CHAIN_RESULTS[@]} stages passed"
        else echo "  ${CHAIN_FAILED} of ${#CHAIN_RESULTS[@]} stages FAILED (details above and in ${LOG#/home/root/})"; fi
    } | tee -a "$LOG"
    [ "$CHAIN_FAILED" -eq 0 ]
}
