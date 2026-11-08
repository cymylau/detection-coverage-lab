#!/usr/bin/env python3
"""
Which scenario scripts perform a given technique or tactic?

  scenario-index.py list
  scenario-index.py select [--technique T1552.005,T1046] [--tactic "Credential Access"] ...
  scenario-index.py chain base|privileged|owasp|untrusted

`list` prints every technique with its tactic and the scripts that perform it.
`select` prints, one per line, the scripts to run:  <script> [args] ;; overlay=<0|1> persistence=<0|1>
`chain` prints the scripts of one chain, in run order:  <script>.sh<TAB><title>
Exits 2 with a message if an ID or tactic is unknown.

The mapping comes from playbooks/scenarios.json (the scenario manifest). observe.py
checks every run against the same manifest, so a script that starts or stops
performing a technique without the manifest being updated shows up as a mismatch.
Selecting a technique runs the whole scenario script that performs it, which may
also perform neighbouring techniques.
Accepted IDs: ATT&CK (T1552.005, or the parent T1552 for all its sub-techniques),
OWASP-A01..A10 (or A01..A10), UFLD-01..04. Accepted tactics: any tactic in
techniques.tsv, case-insensitive, spaces or hyphens ("credential-access").
"""
import argparse, json, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))


def manifest():
    return json.load(open(os.path.join(HERE, "scenarios.json")))["scenarios"]


def load():
    meta = {}
    for line in open(os.path.join(HERE, "techniques.tsv")):
        p = line.rstrip("\n").split("\t")
        if len(p) >= 3:
            meta[p[0]] = (p[1], p[2])
    scen = manifest()
    tech_scripts = {}
    for s in scen:
        for t in s["techniques"]:
            tech_scripts.setdefault(t, set()).add(s["script"])
    return tech_scripts, meta, scen


def norm_tactic(s):
    return re.sub(r"[\s_-]+", " ", s.strip().lower())


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    sp = sub.add_parser("select")
    sp.add_argument("--technique", action="append", default=[])
    sp.add_argument("--tactic", action="append", default=[])
    cp = sub.add_parser("chain")
    cp.add_argument("name")
    a = ap.parse_args()
    ts, meta, scen = load()
    by_script = {s["script"]: s for s in scen}

    if a.cmd == "chain":
        rows = [s for s in scen if s["chain"] == a.name]
        if not rows:
            print(f"unknown chain {a.name}", file=sys.stderr); return 2
        for s in rows:
            print(f"{s['script']}.sh\t{s['title']}")
        return 0

    if a.cmd == "list":
        print(f"{'Technique':<11} {'Tactic':<22} Scripts")
        for t in sorted(k for k in meta):
            scr = ", ".join(sorted(ts.get(t, [])))
            if t.startswith("OWASP"):
                scr += " " + t[-3:]
            print(f"{t:<11} {meta[t][1]:<22} {scr}")
        return 0

    chosen = {}   # script -> set(owasp categories)
    def add(script, cat=None):
        chosen.setdefault(script, set())
        if cat: chosen[script].add(cat)

    def add_tech(k):
        for s in ts.get(k, []):
            add(s, k[-3:] if k.startswith("OWASP-") else None)

    ids = [x.strip() for arg in a.technique for x in arg.split(",") if x.strip()]
    for raw in ids:
        t = raw.upper()
        if re.fullmatch(r"A\d\d", t): t = "OWASP-" + t
        if t.startswith(("OWASP-", "UFLD-")):
            if t not in ts: print(f"unknown id {raw}", file=sys.stderr); return 2
            add_tech(t)
        else:
            hits = [k for k in ts if k == t or k.startswith(t + ".")]
            if not hits:
                print(f"unknown or unimplemented technique {raw}. Run:  scenario-index.py list", file=sys.stderr); return 2
            for k in hits: add_tech(k)
    for tac in [x.strip() for arg in a.tactic for x in arg.split(",") if x.strip()]:
        want = norm_tactic(tac)
        hits = [k for k, (_, tc) in meta.items() if norm_tactic(tc) == want]
        if not hits:
            known = sorted({tc for _, tc in meta.values()})
            print(f"unknown tactic '{tac}'. Known: {', '.join(known)}", file=sys.stderr); return 2
        for k in hits: add_tech(k)
    if not chosen:
        print("nothing selected: give --technique and/or --tactic", file=sys.stderr); return 2

    order = [s["script"] for s in scen]
    for s in sorted(chosen, key=order.index):
        args = " ".join(sorted(chosen[s]))
        m = by_script[s]
        print(f"{s}.sh {args}".rstrip() + f" ;; overlay={int(m['overlay'])} persistence={int(m['cleanup'])}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
