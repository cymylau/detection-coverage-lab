#!/usr/bin/env python3
"""
Which scenario scripts perform a given technique or tactic?

  scenario-index.py list
  scenario-index.py select [--technique T1552.005,T1046] [--tactic "Credential Access"] ...

`list` prints every technique with its tactic and the scripts that record it.
`select` prints, one per line, the scripts to run:  <script> [args] ;; overlay=<0|1> persistence=<0|1>
It exits 2 with a message if an ID or tactic is unknown.

The mapping is read from the scripts themselves (their st_mark / act calls), so it
cannot drift from what actually runs. Selecting a technique runs the whole
scenario script that performs it, which may also perform neighbouring techniques.
Accepted IDs: ATT&CK (T1552.005, or the parent T1552 for all its sub-techniques),
OWASP-A01..A10 (or A01..A10), UFLD-01..04. Accepted tactics: any tactic in
techniques.tsv, case-insensitive, spaces or hyphens ("credential-access").
"""
import argparse, glob, os, re, sys

HERE = os.path.dirname(os.path.abspath(__file__))
# run order for a selection: same dependency order the full chain uses
ORDER = ["run-host-recon", "run-credential-discovery", "run-persistence", "run-defense-evasion", "run-metadata-exfil",
         "run-collection-staging", "run-c2-beacon", "run-https-exfil", "run-lateral-movement", "run-ssh-audit-session",
         "run-docker-socket-escape", "run-privileged-container-abuse", "run-cryptomining", "run-image-secret-discovery",
         "run-workload-identity-theft", "run-impair-logging", "run-owasp-top10", "run-untrusted-fields"]
OVERLAY = {"run-docker-socket-escape", "run-privileged-container-abuse", "run-image-secret-discovery"}


def load():
    tech_scripts, meta = {}, {}
    for line in open(os.path.join(HERE, "techniques.tsv")):
        p = line.rstrip("\n").split("\t")
        if len(p) >= 3:
            meta[p[0]] = (p[1], p[2])
    for f in glob.glob(os.path.join(HERE, "run-*.sh")):
        name = os.path.basename(f)[:-3]
        text = open(f).read()
        for m in re.finditer(r"(?:st_mark|\bact)\s+(T\d{4}(?:\.\d{3})?)\b", text):
            tech_scripts.setdefault(m.group(1), set()).add(name)
    tech_scripts.setdefault("__owasp__", set()).add("run-owasp-top10")
    tech_scripts.setdefault("__ufld__", set()).add("run-untrusted-fields")
    return tech_scripts, meta


def norm_tactic(s):
    return re.sub(r"[\s_-]+", " ", s.strip().lower())


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    sub.add_parser("list")
    sp = sub.add_parser("select")
    sp.add_argument("--technique", action="append", default=[])
    sp.add_argument("--tactic", action="append", default=[])
    a = ap.parse_args()
    ts, meta = load()

    if a.cmd == "list":
        print(f"{'Technique':<11} {'Tactic':<22} Scripts")
        for t in sorted(k for k in meta):
            if t.startswith("OWASP"):
                scr = "run-owasp-top10 " + t[-3:]
            elif t.startswith("UFLD"):
                scr = "run-untrusted-fields"
            else:
                scr = ", ".join(sorted(ts.get(t, [])))
            print(f"{t:<11} {meta[t][1]:<22} {scr}")
        return 0

    chosen = {}   # script -> set(owasp categories)
    def add(script, cat=None):
        chosen.setdefault(script, set())
        if cat: chosen[script].add(cat)

    ids = [x.strip() for arg in a.technique for x in arg.split(",") if x.strip()]
    for raw in ids:
        t = raw.upper()
        if re.fullmatch(r"A\d\d", t): t = "OWASP-" + t
        if t.startswith("OWASP-A"):
            if t not in meta: print(f"unknown OWASP category {raw}", file=sys.stderr); return 2
            add("run-owasp-top10", t[-3:])
        elif t.startswith("UFLD-"):
            if t not in meta: print(f"unknown id {raw}", file=sys.stderr); return 2
            add("run-untrusted-fields")
        else:
            hits = [k for k in ts if not k.startswith("__") and (k == t or k.startswith(t + "."))]
            if not hits:
                print(f"unknown or unimplemented technique {raw}. Run:  scenario-index.py list", file=sys.stderr); return 2
            for k in hits:
                for s in ts[k]: add(s)
    for tac in [x.strip() for arg in a.tactic for x in arg.split(",") if x.strip()]:
        want = norm_tactic(tac)
        hits = [k for k, (_, tc) in meta.items() if norm_tactic(tc) == want]
        if not hits:
            known = sorted({tc for _, tc in meta.values()})
            print(f"unknown tactic '{tac}'. Known: {', '.join(known)}", file=sys.stderr); return 2
        for k in hits:
            if k.startswith("OWASP"): add("run-owasp-top10", k[-3:])
            elif k.startswith("UFLD"): add("run-untrusted-fields")
            else:
                for s in ts.get(k, []): add(s)
    if not chosen:
        print("nothing selected: give --technique and/or --tactic", file=sys.stderr); return 2

    for s in sorted(chosen, key=lambda x: ORDER.index(x) if x in ORDER else 99):
        args = " ".join(sorted(chosen[s]))
        print(f"{s}.sh {args}".rstrip() + f" ;; overlay={1 if s in OVERLAY else 0} persistence={1 if s == 'run-persistence' else 0}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
