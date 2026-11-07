#!/usr/bin/env python3
"""
Documentation drift check. Fails (exit 1) when the docs and the code disagree.

  python3 tests/check-docs.py            # offline checks
  python3 tests/check-docs.py --online   # also fetch every external link in the README (slow)

Checks:
  1. every ATT&CK technique the scripts record (st_mark / act calls in playbooks/run-*.sh)
     is listed in the README "Every test in this lab" table, and nothing else is;
  2. every recorded ID has a name in playbooks/techniques.tsv;
  3. the README lists all ten OWASP Top 10:2025 categories and the untrusted-field IDs
     the scenario really uses;
  4. the technique count stated in the README matches the table;
  5. every local link and #anchor in README.md, SECURITY.md and docs/*.md resolves.
"""
import glob, os, re, subprocess, sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.chdir(ROOT)
problems = []


def bad(msg):
    problems.append(msg)


readme = open("README.md").read()

# 1. techniques recorded by the scripts vs the README table
recorded = set()
for f in glob.glob("playbooks/run-*.sh"):
    for line in open(f):
        for m in re.finditer(r"(?:st_mark|\bact)\s+(T\d{4}(?:\.\d{3})?)\b", line):
            recorded.add(m.group(1))
in_readme = set(re.findall(r"\[(T\d{4}(?:\.\d{3})?)\]\(https://attack\.mitre\.org/techniques/", readme))
for t in sorted(recorded - in_readme):
    bad(f"{t} is recorded by a script but missing from the README test list")
for t in sorted(in_readme - recorded):
    bad(f"{t} is in the README test list but no script records it")

# 2. names
names = {}
for line in open("playbooks/techniques.tsv"):
    p = line.rstrip("\n").split("\t")
    if p[0]:
        names[p[0]] = p[1:] 
for t in sorted(recorded):
    if t not in names or not names[t] or not names[t][0]:
        bad(f"{t} has no name in playbooks/techniques.tsv")

# 3. OWASP + untrusted-field IDs
for n in range(1, 11):
    if not re.search(rf"\[A{n:02d}:2025 ", readme):
        bad(f"README OWASP table is missing A{n:02d}")
    if f"OWASP-A{n:02d}" not in names:
        bad(f"OWASP-A{n:02d} has no name in techniques.tsv")
ufld_script = set(re.findall(r"UFLD-\d\d", open("playbooks/run-untrusted-fields.sh").read()))
ufld_readme = set(re.findall(r"UFLD-\d\d", readme))
if ufld_script != ufld_readme:
    bad(f"untrusted-field IDs differ: scripts {sorted(ufld_script)} vs README {sorted(ufld_readme)}")
for u in ufld_script:
    if u not in names:
        bad(f"{u} has no name in techniques.tsv")

# 4. stated count
m = re.search(r"\((\d+) techniques below\)", readme)
if m and int(m.group(1)) != len(in_readme):
    bad(f"README says {m.group(1)} techniques but the table has {len(in_readme)}")


# 5. local links and anchors
def slug(h):
    return re.sub(r"[^\w\- ]", "", h.lower()).replace(" ", "-")


def anchors(path):
    return {slug(m.group(2)) for m in re.finditer(r"^(#+) (.+)$", open(path).read(), re.M)}


docs = ["README.md", "SECURITY.md"] + sorted(glob.glob("docs/*.md"))
externals = set()
for d in docs:
    text = open(d).read()
    base = os.path.dirname(d)
    for m in re.finditer(r"\]\(([^)#]*)(#[^)]*)?\)", text):
        link, anc = m.group(1), (m.group(2) or "")[1:]
        if link.startswith("http"):
            externals.add(link + (("#" + anc) if anc else ""))
            continue
        target = os.path.normpath(os.path.join(base, link)) if link else d
        if not os.path.exists(target):
            bad(f"{d}: link to missing file {link}")
        elif anc and os.path.isfile(target) and anc not in anchors(target):
            bad(f"{d}: anchor #{anc} not found in {target}")

if "--online" in sys.argv:
    for u in sorted(externals):
        code = subprocess.run(["curl", "-s", "-o", "/dev/null", "-L", "-m", "20", "-w", "%{http_code}", u.split("#")[0]],
                              capture_output=True, text=True).stdout
        if code != "200":
            bad(f"external link returned {code}: {u}")

if problems:
    print("docs check FAILED:")
    for p in problems:
        print("  -", p)
    sys.exit(1)
print(f"docs check passed: {len(recorded)} techniques recorded = README list; OWASP A01-A10 present; "
      f"{len(docs)} doc files, local links ok" + (f"; {len(externals)} external links ok" if "--online" in sys.argv else ""))
