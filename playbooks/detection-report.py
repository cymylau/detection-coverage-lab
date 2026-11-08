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

How an alert is tied to an action, strongest first:

  marker     Every command the lab runs carries a marker, cdl-<run>-<n>, on its
             argv[0] (and SSH sessions carry it in the remote command line). An
             alert whose text contains an action's marker was caused by that
             action: no time window, no reliance on technique tags. Export the
             command-line field (process command line, parent command line) for
             this to work. The marker of an SSH session also covers the commands
             run inside it; those match when the alert also names their technique.
  tag+time   No marker in any alert for the action: an alert that names the
             action's exact technique and falls from 2 s before the action to
             --window seconds after it (default 120). Alerts that carry a marker
             are already attributed and are not reused here.

Each action is then:
  detected   tied by marker (and the alert names this technique or none), or by
             tag+time with the exact technique ID;
  partial    tied by marker but the tool named a different technique; or only an
             alert naming the parent technique (T1552 for T1552.005), or an
             alert naming nothing or something else, in the time window;
  missed     nothing;
  not-run    the action did not run as expected (observe.py marked it FAILED, or
             its exit status was unexpected), so it is not scored.

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


MARK_RE = re.compile(r"cdl-[0-9a-z]{4}-\d{5,}")
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
        text = json.dumps(r, default=str)
        alerts.append({"t": t, "ids": ids_in(text), "marks": set(MARK_RE.findall(text)), "raw": r})
    return alerts, no_time, sorted(fields)


def utc(t):
    return datetime.fromtimestamp(t, timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")


def warn(msg):
    print("warning: " + msg, file=sys.stderr)


def parent_match(action_tech, alert_ids):
    return "." in action_tech and action_tech.split(".")[0] in alert_ids


def score_action(r, alerts, window):
    """-> (status, how, alert_count) for one action. See the module docstring."""
    if r.get("kind") == "exec" and r.get("ok") is False or r.get("observed") == "FAILED":
        return "not-run", f"exited {r.get('rc')}", 0
    tech = r["technique"]
    own = r.get("marker") if r.get("kind") == "exec" else r.get("parent")
    if own:
        hits = [al for al in alerts if own in al["marks"]]
        if r.get("kind") == "declared":
            hits = [al for al in hits if tech in al["ids"]]   # a session's marker: the tag says which step
            if hits:
                return "detected", "marker+tag", len(hits)
        elif hits:
            if any(not al["ids"] or tech in al["ids"] or parent_match(tech, al["ids"]) for al in hits):
                return "detected", "marker", len(hits)
            return "partial", "marker; tool named " + ",".join(sorted(set().union(*(al["ids"] for al in hits)))), len(hits)
    t0 = float(r["epoch"])
    win = [al for al in alerts if not al["marks"] and t0 - 2 <= al["t"] <= t0 + window]
    exact = [al for al in win if tech in al["ids"]]
    if exact:
        return "detected", "tag+time", len(exact)
    par = [al for al in win if parent_match(tech, al["ids"])]
    if par:
        return "partial", "parent tag+time", len(par)
    if win:
        return "partial", "other alert in window", len(win)
    return "missed", "", 0


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

    # only markers from these actions count (an old run's marker is not this run's)
    known = {r.get("marker") for r in acts if r.get("marker")} | {r.get("parent") for r in acts if r.get("parent")}
    known.discard(None)
    for al in alerts:
        al["marks"] &= known
    marked = [al for al in alerts if al["marks"]]
    if known and alerts and not marked:
        warn("no alert carries a marker from this run (cdl-...), so every match below is by technique tag and time. "
             "Include the process command line (and parent command line) in the export for exact attribution.")

    per_action = []
    for r in acts:
        per_action.append((r,) + score_action(r, alerts, a.window))

    by = {}
    for r, st, how, n in per_action:
        if st == "not-run":
            continue
        d = by.setdefault(r["technique"], {"detected": 0, "partial": 0, "missed": 0})
        d[st] += 1

    def overall(d):
        if d["detected"]: return "detected" if not d["missed"] and not d["partial"] else "partial"
        if d["partial"]: return "partial"
        return "missed"

    print(f"\n=== Detection report — {len(acts)} action(s), {len(alerts)} alert(s), window {a.window:.0f}s ===")
    hows = {}
    for _, st, how, _ in per_action:
        if st != "not-run" and how:
            k = how.split(";")[0]; hows[k] = hows.get(k, 0) + 1
    in_window = {id(al) for r, *_ in per_action for al in alerts
                 if not al["marks"] and float(r["epoch"]) - 2 <= al["t"] <= float(r["epoch"]) + a.window}
    print(f"alerts: {len(marked)} carry a marker from this run, {len(in_window)} unmarked ones fall in an action's "
          f"time window, {len(alerts) - len(marked) - len(in_window)} are unrelated to this run")
    print("actions matched by: " + (", ".join(f"{k} {v}" for k, v in sorted(hows.items())) or "nothing") +
          ("" if known else "   (markers were off for this run: tag+time only)"))
    notrun = sum(1 for _, st, _, _ in per_action if st == "not-run")
    if notrun:
        print(f"{notrun} action(s) did not run as expected and are not scored (see results/run_check.json)")
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
    print("'partial' = the tool named a different or only the parent technique, or an untagged alert fired in the")
    print("time window; confirm it by hand. Matches by marker are exact; tag+time matches can be coincidence.")

    if a.csv:
        with open(a.csv, "w", newline="") as fh:
            wr = csv.writer(fh)
            wr.writerow(["time_utc", "technique", "command", "source", "destination", "path_or_id", "kind", "marker",
                         "status", "matched_by", "alerts"])
            for r, st, how, n in per_action:
                wr.writerow([r["ts"], r["technique"], r["command"], r["src"], r["dst"], r["path"], r.get("kind", ""),
                             r.get("marker") or r.get("parent") or "", st, how, n])
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
