#!/usr/bin/env python3
"""Stop hook: before Claude finishes a turn, run the fast offline checks.

  python3 tests/check-docs.py              (manifest, docs, hand-written records)
  python3 -m unittest discover -s tests    (reporting, scoring, ax wrapper)

If either fails, stopping is blocked once and the failure is fed back so Claude
fixes it (or reports it) instead of saying "done". On the retry
(stop_hook_active) it never blocks again, so it cannot loop. Takes about 1 s.
"""
import json, os, subprocess, sys


def run(cmd, cwd):
    p = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, timeout=120,
                       env=dict(os.environ, PYTHONDONTWRITEBYTECODE="1"))
    return p.returncode, (p.stdout + p.stderr).strip()


def main():
    try:
        data = json.load(sys.stdin)
    except ValueError:
        data = {}
    if data.get("stop_hook_active"):
        return 0
    root = os.environ.get("CLAUDE_PROJECT_DIR") or os.getcwd()
    if not os.path.isfile(os.path.join(root, "tests", "check-docs.py")):
        return 0
    failures = []
    rc, out = run([sys.executable, "tests/check-docs.py"], root)
    if rc:
        failures.append("tests/check-docs.py failed:\n" + out[-2500:])
    rc, out = run([sys.executable, "-m", "unittest", "discover", "-s", "tests", "-q"], root)
    if rc:
        failures.append("unit tests failed:\n" + out[-2500:])
    if failures:
        print(json.dumps({
            "decision": "block",
            "reason": "Offline checks fail on the working tree. Fix them before finishing, or tell the user plainly "
                      "that they fail and why:\n\n" + "\n\n".join(failures),
        }))
    return 0


if __name__ == "__main__":
    sys.exit(main())
