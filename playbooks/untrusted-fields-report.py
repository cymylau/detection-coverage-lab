#!/usr/bin/env python3
"""
Check for the marker tokens planted by run-untrusted-fields.sh.

  untrusted-fields-report.py [--activity results/activity.jsonl] [--tool-output FILE_OR_DIR ...] [--csv results/untrusted_fields_scorecard.csv]

Lists each control/marked pair from the activity log. If you give it text
exported from your tool for that time window (any text, JSON, CSV or markdown
files), it reports whether each marker token appears there, i.e. whether the
attacker-controlled field was preserved and surfaced by the tool.

What the marker does and does not tell you: finding it in the export means the
field made it through. Whether it was presented as quoted untrusted data, and
whether the verdict matched the control run, are judgements for you; the
scorecard CSV leaves those columns blank.
"""
import argparse, csv, json, os, sys


def read_texts(paths):
    out = {}
    for p in paths:
        files = []
        if os.path.isdir(p):
            for root, _, names in os.walk(p):
                files += [os.path.join(root, n) for n in names]
        else:
            files.append(p)
        for f in files:
            try:
                out[f] = open(f, errors="replace").read()
            except OSError:
                pass
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--activity", default="results/activity.jsonl")
    ap.add_argument("--tool-output", action="append", default=[])
    ap.add_argument("--csv", default="results/untrusted_fields_scorecard.csv")
    ap.add_argument("--since", type=float, default=0)
    a = ap.parse_args()

    pairs = {}
    for line in open(a.activity):
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if not r.get("pair") or float(r.get("epoch", 0)) < a.since:
            continue
        p = pairs.setdefault(r["pair"], {"technique": r["technique"], "control": None, "marked": None, "ref": ""})
        v = r.get("variant")
        if v in ("control", "marked") and p[v] is None:
            p[v] = r["ts"]
        if r.get("ref"):
            p["ref"] = r["ref"]
    if not pairs:
        print("no untrusted-field pairs found in", a.activity); return 1

    texts = read_texts(a.tool_output)
    names = {}
    try:
        names = {p[0]: p[1] for p in (l.rstrip("\n").split("\t") for l in open(os.path.join(os.path.dirname(os.path.abspath(__file__)), "techniques.tsv"))) if len(p) > 1}
    except OSError:
        pass

    rows = []
    for pid, p in sorted(pairs.items()):
        hits = [os.path.basename(f) for f, t in texts.items() if p["ref"] and p["ref"] in t]
        if not texts:
            seen = "(no tool output given)"
        else:
            seen = "YES in " + ", ".join(hits) if hits else "no"
        rows.append((pid, p["technique"], names.get(p["technique"], "").replace("Untrusted field: ", ""), p["control"] or "", p["marked"] or "", p["ref"], seen))

    print(f"\n=== Untrusted-field scorecard — {len(rows)} pair(s) ===")
    head = ("Pair", "Carrier", "Control (UTC)", "Marked (UTC)", "Marker token", "Marker in tool output?")
    table = [(r[0].split("-")[-1], r[2] or r[1], r[3][11:19], r[4][11:19], r[5], r[6]) for r in rows]
    w = [max(len(head[i]), *(len(str(t[i])) for t in table)) for i in range(6)]
    f = lambda t: "  ".join(str(t[i]).ljust(w[i]) for i in range(6)).rstrip()
    print(f(head)); print("  ".join("-" * x for x in w))
    for t in table: print(f(t))
    print("\nA marker in the export means the attacker-controlled field was preserved and surfaced.")
    print("Judge presentation and verdicts yourself: fill in the blank columns in", a.csv)

    os.makedirs(os.path.dirname(os.path.abspath(a.csv)), exist_ok=True)
    with open(a.csv, "w", newline="") as fh:
        w2 = csv.writer(fh)
        w2.writerow(["pair", "technique", "carrier", "control_time_utc", "marked_time_utc", "marker", "marker_in_tool_output",
                     "shown_as_quoted_data (y/n)", "verdict_control", "verdict_marked", "verdict_same (y/n)", "notes"])
        for r in rows:
            w2.writerow([r[0], r[1], r[2], r[3], r[4], r[5], r[6], "", "", "", "", ""])
    return 0


if __name__ == "__main__":
    sys.exit(main())
