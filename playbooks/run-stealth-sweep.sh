#!/bin/bash
#
# run-stealth-sweep.sh — run the base scenario chain once per stealth profile
# and print a side-by-side summary, so you can compare what your EDR/CDR
# detected at each noise level.
#
#   bash playbooks/run-stealth-sweep.sh                    # all four profiles
#   bash playbooks/run-stealth-sweep.sh quiet covert       # just these
#   STEALTH_TIME_SCALE=0.01 bash playbooks/run-stealth-sweep.sh   # fast demo
#
# Each profile's logs and stealth_timeline.jsonl go to results/stealth_<profile>/.
# Line your EDR/CDR alerts up against the timeline timestamps.
# Run inside ops-console (after bootstrap + install-extra-tools).
set -u

HERE="$(cd "$(dirname "$0")" && pwd)"
BASE="${RESULTS_DIR:-/home/root/results}"
PROFILES=("$@"); [ ${#PROFILES[@]} -gt 0 ] || PROFILES=(noisy careful quiet covert)

for p in "${PROFILES[@]}"; do
    case "$p" in noisy|careful|quiet|covert) ;; *) echo "invalid profile '$p' — valid: noisy careful quiet covert" >&2; exit 2 ;; esac
done

for p in "${PROFILES[@]}"; do
    out="$BASE/stealth_$p"
    mkdir -p "$out"; : > "$out/stealth_timeline.jsonl"
    echo "[sweep] ===== profile: $p -> $out ====="
    start=$(date +%s)
    STEALTH="$p" RESULTS_DIR="$out" KEEP_PERSISTENCE=0 bash "$HERE/run-full-chain.sh" > "$out/chain.log" 2>&1
    rc=$?
    echo "$(( $(date +%s) - start )) $rc" > "$out/.elapsed"
    echo "[sweep] $p finished (exit $rc, $(cut -d' ' -f1 "$out/.elapsed")s)"
done

python3 - "$BASE" "${PROFILES[@]}" <<'PY'
import json, sys, os, collections
base, profiles = sys.argv[1], sys.argv[2:]
print("\n%-9s %8s %6s %s" % ("profile", "elapsed", "steps", "techniques marked"))
for p in profiles:
    d = os.path.join(base, "stealth_" + p)
    el, rc = open(os.path.join(d, ".elapsed")).read().split()
    ev = [json.loads(l) for l in open(os.path.join(d, "stealth_timeline.jsonl")) if l.strip()]
    techs = collections.OrderedDict((e["technique"], 1) for e in ev)
    print("%-9s %7ss %6d %s%s" % (p, el, len(ev), ",".join(techs), "" if rc == "0" else "  (exit %s)" % rc))
print("\nTimelines: %s/stealth_<profile>/stealth_timeline.jsonl" % base)
PY
