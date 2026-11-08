#!/usr/bin/env python3
"""
Confirm each action from the destination's point of view.

  observe.py [--results results] [--since EPOCH] [--out results/activity_confirmed.jsonl]
             [--check-out results/run_check.json]

Two checks.

1. Each action against its destination. The activity log is the attacker's view,
written by the code that ran each command (argv, exit status, times). This checks
it against what the destinations recorded (control-api, web-portal, dns-sink and
the decoy metadata service each keep results/server_<name>.jsonl; sshd's auth log
is saved as results/server_sshd.log by run-everything.sh) and writes
activity_confirmed.jsonl: every action plus
  observed   yes       ran, and a matching record exists at the destination
             NO        ran, but the destination should have logged it and did not
             ran       a local action that ran and exited as expected (its exit
                       status is the evidence; there is no destination log)
             FAILED    the command exited with a status the scenario does not
                       expect, so the technique may not have happened
             declared  a step inside an action that ran as a whole (a command
                       inside an SSH session); confirmed through that action
             n/a       nothing to check (port scan, a destination with no log)
  evidence   what matched

2. The run against the scenario manifest (scenarios.json): every technique a
scenario recorded must be listed for it there, and at the noisy profile every
listed technique must have been performed. The result goes to run_check.json.

Exit status: 0 when every action ran as expected and the run matches the
manifest; 1 otherwise (FAILED actions, or a manifest mismatch).

A "NO" is worth investigating before reading anything into a missing detection:
the traffic may never have arrived (for example sshd drops connections for ~20 s
after a failed login).
"""
import argparse, glob, json, os, re, sys
from datetime import datetime, timezone

BEFORE, AFTER = 1.0, 6.0


def load_jsonl(path):
    out = []
    try:
        for line in open(path):
            try: out.append(json.loads(line))
            except ValueError: pass
    except OSError:
        pass
    return out


def load_sshd(path):
    out = []
    try:
        for line in open(path, errors="replace"):
            m = re.match(r"^(\d{4}-\d\d-\d\d \d\d:\d\d:\d\d)(\.\d+)?\s+(.*)$", line.rstrip("\n"))
            if m:
                t = datetime.strptime(m.group(1), "%Y-%m-%d %H:%M:%S").replace(tzinfo=timezone.utc).timestamp()
                if m.group(2): t += float("0" + m.group(2))
                out.append({"epoch": t, "line": m.group(3)})
    except OSError:
        pass
    return out


def near(recs, t0):
    return [r for r in recs if t0 - BEFORE <= float(r["epoch"]) <= t0 + AFTER]


def check(a, logs):
    kind = a.get("kind", "")
    if kind == "declared":
        return "declared", "step inside action " + (a.get("parent") or "(none)") + ", not run on its own"
    if kind == "exec" and not a.get("ok", True):
        return "FAILED", f"exited {a.get('rc')}, which this step does not expect"
    seen, ev = check_destination(a, logs)
    if seen == "n/a" and kind == "exec" and ev in ("local action", "port scans are not logged by the services"):
        return "ran", f"exit {a.get('rc')}" + ("" if ev == "local action" else "; " + ev)
    return seen, ev


def check_destination(a, logs):
    dst, path, cmd, t0 = a.get("dst", ""), a.get("path", ""), a.get("command", ""), float(a["epoch"])
    src = a.get("src", "")
    if "(remote)" in cmd:
        return "n/a", "runs inside an SSH session confirmed separately"
    if cmd.startswith(("nmap", "bash /dev/tcp")):
        return "n/a", "port scans are not logged by the services"
    if dst == "docker-sandbox":
        return "n/a", "docker-sandbox keeps no per-request log"
    if dst in ("", src) and "decoy IMDS" not in dst:
        return "n/a", "local action"
    if dst == "control-api":
        hit = [r for r in near(logs["control-api"], t0) if r.get("path") == path]
        return ("yes", f"control-api received {hit[0]['method']} {path[:50]}") if hit else ("NO", "no matching request in server_control-api.jsonl")
    if dst == "web-portal":
        hit = [r for r in near(logs["web-portal"], t0) if r.get("path") == path]
        return ("yes", f"web-portal received {hit[0]['method']} {path[:50]}") if hit else ("NO", "no matching request in server_web-portal.jsonl")
    if dst == "dns-sink":
        hit = [r for r in near(logs["dns-sink"], t0) if r.get("qname", "").lower() == path.lower()]
        return ("yes", "dns-sink saw the query") if hit else ("NO", "dns-sink did not log this query")
    if "decoy IMDS" in dst:
        hit = [r for r in near(logs["imds"], t0) if r.get("path") == path and r.get("host") != "web-portal"]
        return ("yes", f"metadata service served {path[:50]}") if hit else ("NO", "metadata service did not log this request")
    if dst == "internal-host":
        user = path.split("@")[0] if "@" in path else path
        hit = [r for r in near(logs["sshd"], t0) if user and user in r["line"] and re.search(r"Accepted|Failed|Invalid user", r["line"])]
        return ("yes", "sshd: " + hit[0]["line"][:60]) if hit else ("NO", "sshd did not log a login for this username")
    return "n/a", "no destination log for " + dst


def run_check(rows, manifest_path):
    """Compare what each scenario recorded with scenarios.json."""
    try:
        man = {s["script"]: s for s in json.load(open(manifest_path))["scenarios"]}
    except (OSError, ValueError, KeyError) as e:
        return {"error": f"cannot read {manifest_path}: {e}"}
    seen, performed, profile = {}, {}, {}
    for r in rows:
        sc = r.get("scenario", "")
        if sc not in man:
            continue
        seen.setdefault(sc, set()).add(r["technique"])
        profile.setdefault(sc, set()).add(r.get("profile", "noisy"))
        if r.get("observed") in ("yes", "ran", "declared", "n/a"):
            performed.setdefault(sc, set()).add(r["technique"])
    unexpected, missing = [], []
    for sc in sorted(seen):
        listed = set(man[sc]["techniques"])
        for t in sorted(seen[sc] - listed):
            unexpected.append(f"{sc} recorded {t}, which scenarios.json does not list for it")
        # only the noisy profile performs every step; OWASP categories can be run one at a time
        if profile[sc] == {"noisy"} and sc != "run-owasp-top10":
            for t in sorted(listed - performed.get(sc, set()) - set(man[sc].get("conditional", {}))):
                missing.append(f"{sc} did not perform {t} (listed in scenarios.json)")
    failed = [f"{r.get('scenario')}: {r['technique']} {r.get('command', '')[:70]} (exit {r.get('rc')})"
              for r in rows if r.get("observed") == "FAILED"]
    return {"scenarios": sorted(seen), "failed_actions": failed, "unexpected": unexpected, "missing": missing}


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default="results")
    ap.add_argument("--since", type=float, default=0)
    ap.add_argument("--out")
    ap.add_argument("--check-out")
    ap.add_argument("--manifest", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "scenarios.json"))
    a = ap.parse_args()
    out = a.out or os.path.join(a.results, "activity_confirmed.jsonl")
    logs = {k: load_jsonl(os.path.join(a.results, f"server_{k}.jsonl")) for k in ("control-api", "web-portal", "dns-sink", "imds")}
    logs["sshd"] = load_sshd(os.path.join(a.results, "server_sshd.log"))
    rows = [r for r in load_jsonl(os.path.join(a.results, "activity.jsonl")) if float(r.get("epoch", 0)) >= a.since]
    cnt = {"yes": 0, "NO": 0, "ran": 0, "FAILED": 0, "declared": 0, "n/a": 0}
    with open(out, "w") as f:
        for r in rows:
            r["observed"], r["evidence"] = check(r, logs)
            cnt[r["observed"]] += 1
            f.write(json.dumps(r) + "\n")
    print(f"destination confirmation: {cnt['yes']} confirmed, {cnt['NO']} NOT seen at the destination, "
          f"{cnt['ran']} local actions ran, {cnt['FAILED']} FAILED, {cnt['declared']} declared steps, "
          f"{cnt['n/a']} not applicable -> {out}")
    rc = run_check(rows, a.manifest)
    rc["counts"] = cnt
    json.dump(rc, open(a.check_out or os.path.join(a.results, "run_check.json"), "w"), indent=1)
    if "error" in rc:
        print("run check: " + rc["error"]); return 1
    problems = rc["failed_actions"] + rc["unexpected"] + rc["missing"]
    if not problems:
        print(f"run check: ok ({len(rc['scenarios'])} scenario(s) match scenarios.json, no failed actions)")
        return 0
    print(f"run check: {len(rc['failed_actions'])} failed action(s), {len(rc['unexpected'])} unlisted technique(s), "
          f"{len(rc['missing'])} listed technique(s) not performed")
    for p in problems[:20]:
        print("  - " + p)
    if len(problems) > 20:
        print(f"  ... {len(problems) - 20} more in run_check.json")
    return 1


if __name__ == "__main__":
    sys.exit(main())
