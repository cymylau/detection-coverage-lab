#!/usr/bin/env python3
"""
Confirm each action from the destination's point of view.

  observe.py [--results results] [--since EPOCH] [--out results/activity_confirmed.jsonl]

The activity log is the attacker's view: it says what the lab tried to do. This
checks it against what the destinations recorded (control-api, web-portal,
dns-sink and the decoy metadata service each keep results/server_<name>.jsonl;
sshd's auth log is saved as results/server_sshd.log by run-everything.sh) and
writes activity_confirmed.jsonl: every action plus
  observed   yes   a matching record exists at the destination, within a few seconds
             NO    the destination should have logged it and did not
             n/a   nothing to check (local action, port scan, command inside an
                   already-confirmed SSH session, or a destination with no log)
  evidence   what matched

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


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--results", default="results")
    ap.add_argument("--since", type=float, default=0)
    ap.add_argument("--out")
    a = ap.parse_args()
    out = a.out or os.path.join(a.results, "activity_confirmed.jsonl")
    logs = {k: load_jsonl(os.path.join(a.results, f"server_{k}.jsonl")) for k in ("control-api", "web-portal", "dns-sink", "imds")}
    logs["sshd"] = load_sshd(os.path.join(a.results, "server_sshd.log"))
    rows = [r for r in load_jsonl(os.path.join(a.results, "activity.jsonl")) if float(r.get("epoch", 0)) >= a.since]
    cnt = {"yes": 0, "NO": 0, "n/a": 0}
    with open(out, "w") as f:
        for r in rows:
            r["observed"], r["evidence"] = check(r, logs)
            cnt[r["observed"]] += 1
            f.write(json.dumps(r) + "\n")
    print(f"destination confirmation: {cnt['yes']} confirmed, {cnt['NO']} NOT seen at the destination, {cnt['n/a']} not applicable -> {out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
