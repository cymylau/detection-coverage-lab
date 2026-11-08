#!/usr/bin/env python3
"""
Score your EDR/CDR/WAF against what the lab actually did.

  detection-report.py --alerts EXPORT [--activity results/activity.jsonl] [--since EPOCH | --all-runs]
                      [--window SECONDS] [--time-offset HOURS] [--csv FILE] [--layer FILE]

Reads the activity log (every action the lab performed, with a UTC time and a
technique ID) and an alert export from your tool (CSV, JSON, or JSON lines),
then reports for every technique whether it was detected, partly detected or
missed.

Which run: activity.jsonl accumulates across runs. By default only the latest
run-everything.sh run is scored (its start time is read from last_run.json next
to the activity log); --since EPOCH picks another start, --all-runs scores
everything.

An alert counts for an action when its time falls from 2 seconds before the
action to --window seconds after it (default 120), and then:
  detected   the alert names the same technique (a parent ID such as T1552
             matches the sub-technique T1552.005), or
  partial    an alert fired in the window but names no technique or a different
             one, so it may be unrelated or only a generic hit.
  missed     no alert in the window.

Alert fields are found by name, case-insensitively:
  time       time, timestamp, ts, _time, created_at, detected_at, first_seen, event_time
             (ISO 8601 with or without zone, or epoch seconds/milliseconds)
  technique  technique, techniques, mitre, mitre_technique, attack_id, tags, ...
             any text in the alert containing T1234 / T1234.567 / OWASP-A05 / A05:2025
Times without a zone are taken as UTC; if your export is in local time, give
--time-offset HOURS (for example 1 for UTC+1, -5 for UTC-5).

--layer writes an ATT&CK Navigator layer (green detected, amber partial, red
missed) that you can load at https://mitre-attack.github.io/attack-navigator/
"""
import argparse, csv, json, os, re, sys
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
TIME_KEYS = ["time", "timestamp", "ts", "_time", "created_at", "detected_at", "first_seen", "event_time", "datetime", "date"]
ID_RE = re.compile(r"\bT\d{4}(?:\.\d{3})?\b|OWASP-A\d{2}|\bA(\d{2}):20\d\d\b", re.I)


ISO_RE = re.compile(r"^\d{4}-\d\d-\d\d[T ]\d\d:\d\d")


def parse_time(v, offset_h=0.0):
    """epoch seconds/ms or ISO 8601 -> epoch seconds. offset_h applies only to
    ISO times with no zone (local-time exports)."""
    if v is None or v == "" or isinstance(v, bool):
        return None
    if isinstance(v, (int, float)) or re.fullmatch(r"\d+(\.\d+)?", str(v).strip()):
        x = float(v)
        return x / 1000.0 if x > 1e11 else x
    s = str(v).strip().replace("Z", "+00:00")
    s = re.sub(r"\s+UTC$", "+00:00", s)
    for cand in (s, s.replace(" ", "T", 1)):
        try:
            d = datetime.fromisoformat(cand)
        except ValueError:
            continue
        if d.tzinfo:
            return d.timestamp()
        return d.replace(tzinfo=timezone.utc).timestamp() - offset_h * 3600
    return None


def ids_in(text):
    out = set()
    for m in ID_RE.finditer(text):
        t = m.group(0).upper()
        if m.group(1):
            t = "OWASP-A" + m.group(1)
        out.add(t)
    return out


def load_alerts(path, offset_h=0.0):
    """-> (alerts, rows_without_a_time, field_names_seen)"""
    raw = open(path, errors="replace").read()
    rows = []
    stripped = raw.lstrip()
    if stripped.startswith("[") or stripped.startswith("{"):
        try:
            data = json.loads(raw)
            if isinstance(data, dict):
                for k in ("alerts", "items", "results", "data", "events", "hits"):
                    if isinstance(data.get(k), list):
                        data = data[k]; break
                else:
                    data = [data]
            rows = [r for r in data if isinstance(r, dict)]
        except ValueError:
            rows = []
            for line in raw.splitlines():
                try:
                    r = json.loads(line)
                    if isinstance(r, dict): rows.append(r)
                except ValueError:
                    pass
    else:
        rows = list(csv.DictReader(raw.splitlines()))
    alerts, no_time, fields = [], 0, set()
    for r in rows:
        low = {str(k).lower(): v for k, v in r.items()}
        fields.update(low)
        t = None
        for k in TIME_KEYS:
            if k in low:
                t = parse_time(low[k], offset_h)
                if t: break
        if not t:
            # fall back to any ISO-looking date string (never a bare number: that is
            # far more likely to be an alert or event ID than a time)
            for v in low.values():
                if isinstance(v, str) and ISO_RE.match(v.strip()):
                    t = parse_time(v, offset_h)
                    if t: break
        if not t:
            no_time += 1
            continue
        alerts.append({"t": t, "ids": ids_in(json.dumps(r, default=str)), "raw": r})
    return alerts, no_time, sorted(fields)


def utc(t):
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def warn(msg):
    print("warning: " + msg, file=sys.stderr)


def matches(action_tech, alert_ids):
    if action_tech in alert_ids:
        return True
    return any("." in action_tech and action_tech.split(".")[0] == i for i in alert_ids)  # parent ID


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--alerts", required=True)
    ap.add_argument("--activity", default="results/activity.jsonl")
    ap.add_argument("--since", type=float, help="score actions from this epoch time (default: the latest run)")
    ap.add_argument("--all-runs", action="store_true", help="score every run in the activity log")
    ap.add_argument("--window", type=float, default=120)
    ap.add_argument("--time-offset", type=float, default=0.0, metavar="HOURS",
                    help="UTC offset of zone-less alert times, e.g. 1 for UTC+1 (default 0 = UTC)")
    ap.add_argument("--csv")
    ap.add_argument("--layer")
    a = ap.parse_args()

    since = a.since
    if since is None and not a.all_runs:
        lr = os.path.join(os.path.dirname(a.activity) or ".", "last_run.json")
        try:
            since = float(json.load(open(lr))["start"])
            print(f"scoring the latest run (started {utc(since)}, from {lr}); --all-runs scores every run")
        except (OSError, ValueError, KeyError, TypeError):
            since = 0
    since = since or 0

    acts = []
    for line in open(a.activity):
        try:
            r = json.loads(line)
        except ValueError:
            continue
        if float(r.get("epoch", 0)) >= since:
            acts.append(r)
    alerts, no_time, fields = load_alerts(a.alerts, a.time_offset)
    if not acts:
        print("no actions in", a.activity, f"since {utc(since)}" if since else ""); return 1
    if no_time:
        warn(f"{no_time} alert row(s) had no recognisable time and were ignored. Fields seen: "
             + ", ".join(fields[:15]) + (" ..." if len(fields) > 15 else ""))
    if not alerts:
        warn(f"no alerts with a usable time were read from {a.alerts}: every action will show as missed")
    else:
        lo, hi = min(float(r["epoch"]) for r in acts), max(float(r["epoch"]) for r in acts)
        if not any(lo - 2 <= al["t"] <= hi + a.window for al in alerts):
            warn(f"none of the {len(alerts)} alerts fall inside the run ({utc(lo)} to {utc(hi)}); alerts span "
                 f"{utc(min(al['t'] for al in alerts))} to {utc(max(al['t'] for al in alerts))}. "
                 "Check the export's time range, or --time-offset if its times are local.")
    names = {}
    try:
        for l in open(os.path.join(HERE, "techniques.tsv")):
            p = l.rstrip("\n").split("\t")
            names[p[0]] = p[1] if len(p) > 1 else ""
    except OSError:
        pass

    per_action = []
    for r in acts:
        t0 = float(r["epoch"]); tech = r["technique"]
        win = [al for al in alerts if t0 - 2 <= al["t"] <= t0 + a.window]
        if any(matches(tech, al["ids"]) for al in win):
            status = "detected"
        elif win:
            status = "partial"
        else:
            status = "missed"
        per_action.append((r, status))

    by = {}
    for r, st in per_action:
        d = by.setdefault(r["technique"], {"detected": 0, "partial": 0, "missed": 0})
        d[st] += 1

    def overall(d):
        if d["detected"]: return "detected" if not d["missed"] and not d["partial"] else "partial"
        if d["partial"]: return "partial"
        return "missed"

    print(f"\n=== Detection report — {len(acts)} action(s), {len(alerts)} alert(s), window {a.window:.0f}s ===")
    head = ("Technique", "Name", "Actions", "Detected", "Partial", "Missed", "Result")
    rows = []
    for k, d in sorted(by.items()):
        rows.append((k, (names.get(k) or "")[:48], str(sum(d.values())), str(d["detected"]), str(d["partial"]), str(d["missed"]), overall(d).upper()))
    w = [max(len(head[i]), *(len(r[i]) for r in rows)) for i in range(7)]
    f = lambda t: "  ".join(str(t[i]).ljust(w[i]) for i in range(7)).rstrip()
    print(f(head)); print("  ".join("-" * x for x in w))
    for r in rows: print(f(r))
    res = [overall(d) for d in by.values()]
    n = len(res)
    print(f"\n{res.count('detected')}/{n} techniques detected, {res.count('partial')} partial, {res.count('missed')} missed.")
    print("'partial' = an alert fired in the time window but did not name the technique; confirm it by hand.")

    if a.csv:
        with open(a.csv, "w", newline="") as fh:
            wr = csv.writer(fh)
            wr.writerow(["time_utc", "technique", "command", "source", "destination", "path_or_id", "status"])
            for r, st in per_action:
                wr.writerow([r["ts"], r["technique"], r["command"], r["src"], r["dst"], r["path"], st])
        print("per-action detail:", a.csv)
    if a.layer:
        col = {"detected": "#31a354", "partial": "#fdae6b", "missed": "#de2d26"}
        score = {"detected": 100, "partial": 50, "missed": 0}
        techs = []
        for k, d in sorted(by.items()):
            if not re.fullmatch(r"T\d{4}(\.\d{3})?", k): continue
            o = overall(d)
            techs.append({"techniqueID": k, "score": score[o], "color": col[o], "enabled": True,
                          "comment": f"{d['detected']} detected, {d['partial']} partial, {d['missed']} missed of {sum(d.values())} action(s)"})
        layer = {"name": "Cymylau detection coverage", "domain": "enterprise-attack",
                 "versions": {"layer": "4.5", "navigator": "5.1.0"},
                 "description": "Generated by detection-report.py from the lab's activity log and your alert export. Green = detected, amber = partial, red = missed.",
                 "sorting": 0, "hideDisabled": False, "techniques": techs,
                 "legendItems": [{"label": "detected", "color": col["detected"]}, {"label": "partial", "color": col["partial"]}, {"label": "missed", "color": col["missed"]}]}
        json.dump(layer, open(a.layer, "w"), indent=1)
        print("Navigator layer:", a.layer)
    return 0


if __name__ == "__main__":
    sys.exit(main())
