#!/usr/bin/env python3
"""
Unit tests for the host-side Python tools (no Docker needed).

  python3 -m unittest discover -s tests -v

Each test runs the real script as a subprocess against small synthetic inputs
in a temporary directory, so what is tested is exactly what users run.
"""
import csv, io, json, os, subprocess, sys, tempfile, unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PB = os.path.join(ROOT, "playbooks")
from datetime import datetime, timezone
T0 = datetime(2026, 11, 8, 10, 40, tzinfo=timezone.utc).timestamp()   # a fixed run start: 10:40:00 UTC


def run(script, *args, cwd=None):
    p = subprocess.run([sys.executable, os.path.join(PB, script), *args], cwd=cwd,
                       capture_output=True, text=True, env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    return p.returncode, p.stdout, p.stderr


def action(epoch, tech, cmd="curl -s -X GET", dst="control-api", path="/x", **kw):
    from datetime import datetime, timezone
    ts = datetime.fromtimestamp(epoch, timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%f")[:23] + "Z"
    r = {"ts": ts, "epoch": epoch, "scenario": "run-test", "profile": "noisy", "technique": tech,
         "step": "", "command": cmd, "src": "ops-console", "dst": dst, "path": path, "result": ""}
    r.update(kw)
    return r


def read(path):
    with open(path) as f:
        return f.read()


def write(path, text):
    with open(path, "w") as f:
        f.write(text)


def write_json(path, obj):
    write(path, json.dumps(obj))


def write_jsonl(path, rows):
    with open(path, "w") as f:
        for r in rows:
            f.write(json.dumps(r) + "\n")


class Tmp(unittest.TestCase):
    def setUp(self):
        self._td = tempfile.TemporaryDirectory()
        self.d = self._td.name

    def tearDown(self):
        self._td.cleanup()

    def p(self, name):
        return os.path.join(self.d, name)


class ActivityReport(Tmp):
    def setUp(self):
        super().setUp()
        rows = [action(T0 + i, "OWASP-A07", path=f"/login?try={i}", dst="web-portal") for i in range(3)]
        rows.append(action(T0 + 5, "T1046", cmd="nmap -Pn", dst="internal-host", path="ports 22"))
        write_jsonl(self.p("activity.jsonl"), rows)

    def test_burst_is_collapsed_with_count(self):
        rc, out, _ = run("activity-report.py", self.p("activity.jsonl"))
        self.assertEqual(rc, 0)
        self.assertIn("(x3 over 2s)", out)
        self.assertIn("4 action(s)", out)
        self.assertIn("Network Service Discovery", out)   # name from techniques.tsv

    def test_full_shows_every_row(self):
        _, out, _ = run("activity-report.py", self.p("activity.jsonl"), "--full")
        self.assertEqual(out.count("/login?try="), 3)

    def test_csv_has_every_row_and_header(self):
        _, out, _ = run("activity-report.py", self.p("activity.jsonl"), "--format", "csv")
        rows = list(csv.reader(io.StringIO(out)))
        self.assertEqual(rows[0][:3], ["time_utc", "technique", "command"])
        self.assertEqual(len(rows), 5)

    def test_since_filters(self):
        _, out, _ = run("activity-report.py", self.p("activity.jsonl"), "--since", str(T0 + 4))
        self.assertIn("1 action(s)", out)


class DetectionReport(Tmp):
    def setUp(self):
        super().setUp()
        self.acts = [
            action(T0, "T1552.005", path="/latest/meta-data/"),
            action(T0 + 400, "T1046", cmd="nmap -Pn", path="ports 80"),
            action(T0 + 800, "T1071.001", path="/beacon"),
        ]
        write_jsonl(self.p("activity.jsonl"), self.acts)

    def report(self, alerts_name, *extra):
        return run("detection-report.py", "--alerts", self.p(alerts_name), "--activity", self.p("activity.jsonl"), *extra)

    def status(self, out, tech):
        for line in out.splitlines():
            if line.startswith(tech + " "):
                return line.split()[-1]
        return None

    def test_csv_parent_id_partial_and_missed(self):
        write(self.p("a.csv"), "time,rule,mitre\n" + "2026-11-08 10:40:05,IMDS access,T1552\n" + "2026-11-08 10:46:45,Generic alert,\n")
        rc, out, err = self.report("a.csv")
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.status(out, "T1552.005"), "DETECTED")
        self.assertEqual(self.status(out, "T1046"), "PARTIAL")
        self.assertEqual(self.status(out, "T1071.001"), "MISSED")

    def test_json_wrapper_epoch_ms_and_layer(self):
        write_json(self.p("a.json"), {"alerts": [{"detected_at": int((T0 + 800 + 3) * 1000), "tags": ["mitre:T1071.001"]}]})
        rc, out, err = self.report("a.json", "--layer", self.p("layer.json"), "--csv", self.p("d.csv"))
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.status(out, "T1071.001"), "DETECTED")
        layer = json.loads(read(self.p("layer.json")))
        got = {t["techniqueID"]: t["score"] for t in layer["techniques"]}
        self.assertEqual(got["T1071.001"], 100)
        self.assertEqual(got["T1552.005"], 0)
        self.assertEqual(len(list(csv.reader(io.StringIO(read(self.p("d.csv")))))), 4)

    def test_jsonl_and_owasp_style_ids(self):
        write_jsonl(self.p("act2.jsonl"), [action(T0, "OWASP-A05", dst="web-portal", path="/search")])
        write_jsonl(self.p("a.jsonl"), [{"timestamp": "2026-11-08T10:40:01Z", "name": "SQLi A05:2025"},
                                        {"timestamp": "2026-11-08T10:40:02Z", "name": "other"}])
        rc, out, err = run("detection-report.py", "--alerts", self.p("a.jsonl"), "--activity", self.p("act2.jsonl"))
        self.assertEqual(rc, 0, err)
        self.assertEqual(self.status(out, "OWASP-A05"), "DETECTED")

    def test_time_offset_for_local_time_exports(self):
        write(self.p("a.csv"), "time,mitre\n2026-11-08 11:40:03,T1552.005\n")
        _, out, _ = self.report("a.csv")
        self.assertEqual(self.status(out, "T1552.005"), "MISSED")
        _, out, _ = self.report("a.csv", "--time-offset", "1")
        self.assertEqual(self.status(out, "T1552.005"), "DETECTED")

    def test_numeric_id_is_not_mistaken_for_a_time(self):
        write_json(self.p("a.json"), [{"alert_id": int(T0 + 1), "rule": "T1552.005"}])
        rc, out, err = self.report("a.json")
        self.assertEqual(rc, 0)
        self.assertIn("no recognisable time", err)
        self.assertIn("no alerts with a usable time", err)
        self.assertEqual(self.status(out, "T1552.005"), "MISSED")

    def test_warns_when_alerts_are_outside_the_run(self):
        write(self.p("a.csv"), "time,mitre\n2020-01-01 00:00:00,T1046\n")
        _, _, err = self.report("a.csv")
        self.assertIn("none of the 1 alerts fall inside the run", err)

    def test_defaults_to_latest_run_and_all_runs_overrides(self):
        write_json(self.p("last_run.json"), {"start": T0 + 300})
        write(self.p("a.csv"), "time,mitre\n")
        _, out, _ = self.report("a.csv")
        self.assertIn("2 action(s)", out)
        self.assertIn("scoring the latest run", out)
        _, out, _ = self.report("a.csv", "--all-runs")
        self.assertIn("3 action(s)", out)
        _, out, _ = self.report("a.csv", "--since", str(T0 + 700))
        self.assertIn("1 action(s)", out)


class Observe(Tmp):
    def test_yes_no_and_not_applicable(self):
        acts = [
            action(T0, "T1071.001", dst="control-api", path="/beacon?i=1"),
            action(T0 + 10, "OWASP-A01", dst="web-portal", path="/admin/export"),
            action(T0 + 20, "T1082", cmd="uname -a", dst="ops-console", path="kernel"),
            action(T0 + 30, "T1033", cmd="whoami (remote)", dst="internal-host", path="decoyuser@internal-host"),
            action(T0 + 40, "T1021.004", cmd="ssh", dst="internal-host", path="decoyuser@internal-host:2222"),
        ]
        write_jsonl(self.p("activity.jsonl"), acts)
        write_jsonl(self.p("server_control-api.jsonl"), [{"epoch": T0 + 0.2, "method": "GET", "path": "/beacon?i=1"}])
        write_jsonl(self.p("server_web-portal.jsonl"), [{"epoch": T0 + 30, "method": "GET", "path": "/admin/export"}])  # too late
        from datetime import datetime, timezone
        stamp = datetime.fromtimestamp(T0 + 41, timezone.utc).strftime("%Y-%m-%d %H:%M:%S")
        write(self.p("server_sshd.log"), f"{stamp}.123 Accepted password for decoyuser from 172.18.0.5\n")
        rc, out, err = run("observe.py", "--results", self.d)
        self.assertEqual(rc, 0, err)
        got = {r["technique"]: r["observed"] for r in map(json.loads, read(self.p("activity_confirmed.jsonl")).splitlines())}
        self.assertEqual(got, {"T1071.001": "yes", "OWASP-A01": "NO", "T1082": "n/a", "T1033": "n/a", "T1021.004": "yes"})
        self.assertIn("2 confirmed, 1 NOT seen", out)


class ScenarioIndex(unittest.TestCase):
    def select(self, *args):
        rc, out, err = run("scenario-index.py", "select", *args)
        return rc, [l.split(" ;; ") for l in out.splitlines()], err

    def test_parent_id_selects_sub_techniques_and_flags_overlay(self):
        rc, lines, _ = self.select("--technique", "T1552")
        self.assertEqual(rc, 0)
        scripts = {l[0].split()[0]: l[1] for l in lines}
        self.assertIn("run-metadata-exfil.sh", scripts)
        self.assertIn("overlay=1", scripts["run-image-secret-discovery.sh"])
        self.assertIn("overlay=0", scripts["run-metadata-exfil.sh"])

    def test_tactic_spelling_is_normalised(self):
        a = self.select("--tactic", "credential-access")[1]
        b = self.select("--tactic", "Credential Access")[1]
        self.assertEqual(a, b)
        self.assertTrue(a)

    def test_owasp_category_is_passed_as_an_argument(self):
        rc, lines, _ = self.select("--technique", "a05,OWASP-A01")
        self.assertEqual(rc, 0)
        self.assertEqual(lines[0][0], "run-owasp-top10.sh A01 A05")

    def test_persistence_flag_and_run_order(self):
        _, lines, _ = self.select("--technique", "T1048.003,T1053.003")
        self.assertEqual([l[0] for l in lines], ["run-persistence.sh", "run-metadata-exfil.sh"])
        self.assertIn("persistence=1", lines[0][1])

    def test_unknown_ids_exit_2(self):
        for args in (["--technique", "T9999"], ["--technique", "OWASP-A11"], ["--tactic", "nope"], []):
            rc, _, err = self.select(*args)
            self.assertEqual(rc, 2, args)
            self.assertTrue(err)

    def test_list_covers_every_named_technique(self):
        rc, out, _ = run("scenario-index.py", "list")
        self.assertEqual(rc, 0)
        listed = {l.split()[0] for l in out.splitlines()[1:]}
        named = {l.split("\t")[0] for l in read(os.path.join(PB, "techniques.tsv")).splitlines() if l.strip()}
        self.assertEqual(listed, named)


if __name__ == "__main__":
    unittest.main()
