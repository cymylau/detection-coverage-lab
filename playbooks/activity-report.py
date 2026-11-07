#!/usr/bin/env python3
"""
Render results/activity.jsonl as a readable table.

  activity-report.py FILE [--since EPOCH] [--scenario NAME] [--format table|csv|json] [--full]

table (default): Time | Technique | Command | Source | Destination | Path / ID,
  followed by an "Attacks covered" list. Runs of the same action against the
  same target (a brute-force burst, say) are collapsed to one row with a count;
  --full shows every row. csv/json always include every row and every field.
"""
import argparse, csv, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))


def load_names():
    names = {}
    try:
        for line in open(os.path.join(HERE, "techniques.tsv")):
            k, _, v = line.rstrip("\n").partition("\t")
            if k:
                names[k] = v
    except OSError:
        pass
    return names


def clip(s, n):
    s = " ".join(str(s).split())
    return s if len(s) <= n else s[: n - 1] + "…"


def collapse(rows):
    """merge consecutive rows that are the same action against the same target and
    whose paths differ only by numbers (brute-force counters, sequential IDs).
    Rows whose paths differ in any other way stay separate."""
    out = []
    for r in rows:
        key = (r["technique"], r.get("variant", ""), r.get("step", ""), r["command"], r["src"], r["dst"], re.sub(r"\d+", "#", r["path"]))
        if out and out[-1]["_key"] == key:
            out[-1]["_n"] += 1
            out[-1]["_last"] = r
            continue
        out.append(dict(r, _key=key, _n=1, _last=r))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("file")
    ap.add_argument("--since", type=float, default=0)
    ap.add_argument("--scenario")
    ap.add_argument("--format", choices=["table", "csv", "json"], default="table")
    ap.add_argument("--full", action="store_true")
    a = ap.parse_args()

    rows = []
    for line in open(a.file):
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if float(r.get("epoch", 0)) < a.since:
            continue
        if a.scenario and r.get("scenario") != a.scenario:
            continue
        rows.append(r)
    rows.sort(key=lambda r: float(r.get("epoch", 0)))

    if a.format == "json":
        json.dump(rows, sys.stdout, indent=1); print(); return
    if a.format == "csv":
        w = csv.writer(sys.stdout)
        w.writerow(["time_utc", "technique", "command", "source", "destination", "path_or_id", "step", "result", "scenario", "profile", "pair", "variant", "ref"])
        for r in rows:
            w.writerow([r["ts"], r["technique"], r["command"], r["src"], r["dst"], r["path"], r.get("step", ""), r.get("result", ""), r.get("scenario", ""), r.get("profile", ""), r.get("pair", ""), r.get("variant", ""), r.get("ref", "")])
        return

    names = load_names()
    title = a.scenario or "all scenarios"
    print()
    print(f"=== Activity log: {title} — {len(rows)} action(s) ===")
    if not rows:
        print("(no actions recorded)"); return
    day = rows[0]["ts"][:10]
    print(f"All times UTC, {day}. Source/destination are container (compose service) names.")
    shown = rows if a.full else collapse(rows)
    table = []
    for r in shown:
        n = r.get("_n", 1)
        path = r["path"]
        if n > 1:
            span = float(r["_last"]["epoch"]) - float(r["epoch"])
            path = f"{path} (x{n} over {span:.0f}s)"
        table.append((r["ts"][11:23], r["technique"] + (f" ({r['variant']})" if r.get("variant") else ""), clip(r["command"], 46), r["src"], r["dst"], clip(path, 56)))
    head = ("Time", "Technique", "Command", "Source", "Destination", "Path / ID")
    widths = [max(len(head[i]), *(len(t[i]) for t in table)) for i in range(6)]
    line = lambda t: "  ".join(str(t[i]).ljust(widths[i]) for i in range(6)).rstrip()
    print(line(head)); print("  ".join("-" * w for w in widths))
    for t in table:
        print(line(t))
    if not a.full and len(shown) < len(rows):
        print(f"({len(rows) - len(shown)} repeated action(s) collapsed; use --full or the CSV for every row)")

    # attacks covered
    cov = {}
    for r in rows:
        c = cov.setdefault(r["technique"], {"n": 0, "sc": set()})
        c["n"] += 1; c["sc"].add(r.get("scenario", ""))
    print()
    print(f"=== Attacks covered — {len(cov)} technique(s) ===")
    h2 = ("ID", "Technique", "Actions")
    body = [(k, clip(names.get(k, "(unmapped)"), 70), str(v["n"])) for k, v in sorted(cov.items())]
    w2 = [max(len(h2[i]), *(len(b[i]) for b in body)) for i in range(3)]
    l2 = lambda t: "  ".join(str(t[i]).ljust(w2[i]) for i in range(3)).rstrip()
    print(l2(h2)); print("  ".join("-" * w for w in w2))
    for b in body:
        print(l2(b))


if __name__ == "__main__":
    main()
