# Detection Coverage Lab — notes for Claude

A Docker Compose lab that performs decoy-only attacker techniques (MITRE ATT&CK,
OWASP Top 10:2025) so EDR/CDR/WAF tools can be scored. Cymylau Ltd is a
fictitious company. User-facing docs: `README.md`, `docs/REFERENCE.md`.

## Safety and scope
- Run the lab only on a disposable VM. The privileged overlay is not a security
  boundary. Confirm with the user before running it on a machine you have not
  been told is disposable.
- Every target, credential and document is a decoy. Keep it that way.
- Do not add new offensive tooling, external downloads (GitHub releases,
  container images, scripts from the internet) or new attack techniques without
  asking first. Setup installs only Kali/Debian packages.

## Invariants (check-docs.py enforces most of these)
- **Every scenario action runs through `ax`** (`playbooks/lib-activity.sh`), which
  runs the command and records its real argv, exit status and marker. Never write
  a record by hand with `act`/`act_here`. Use `--ok 0,1` (or `any`) when a
  non-zero exit is expected, so the step is not reported as FAILED.
  `act_declared` is only for commands inside an SSH session that `ax` ran as one action.
- Calling `ax_here` uses the *current* technique (`st_mark`). For a different
  technique, call `ax TECH DST PATH -- cmd`.
- Do not wrap shell functions such as `st_http` or `st_scan` in `ax`. They call
  `ax` themselves.
- **`playbooks/scenarios.json` is the source of truth** for scenarios, chains and
  techniques. A new or changed technique needs: the manifest (with `conditional`
  if only some profiles perform it), `playbooks/techniques.tsv`, and the README
  "Every test in this lab" table and technique count.
- Markers (`cdl-<run>-<n>` on argv[0]) must keep working. Commands whose argv[0]
  is itself the test value use `--no-marker`.
- Stealth profiles (`lib-stealth.sh`) change how a step runs. A change to a
  scenario must keep working at every profile.

## Checking a change
Offline (the Stop hook runs the last two automatically):
```bash
for f in run-everything.sh lock-down-network.sh playbooks/*.sh services/*.sh; do bash -n "$f"; done
docker run --rm -v "$PWD:/mnt" -w /mnt koalaman/shellcheck:v0.10.0 -S warning run-everything.sh lock-down-network.sh playbooks/*.sh services/*.sh
python3 -m unittest discover -s tests
python3 tests/check-docs.py
```
Live, for anything touching scenarios, services or `run-everything.sh` (the
noisy full run takes about 80 s):
```bash
bash run-everything.sh --down
bash run-everything.sh                       # must end "done" with "run check: ok"
STEALTH_TIME_SCALE=0.02 bash run-everything.sh --stealth careful
STEALTH_TIME_SCALE=0.02 bash run-everything.sh --stealth covert
bash run-everything.sh --technique <ID>      # for a changed scenario, incl. re-use without --down
bash run-everything.sh --down
```
Before reporting a change as done, say which of these ran. If a mode was not
exercised (a profile, a fallback path), say so explicitly.

## Conventions
- Bash scenarios: `set -u`, source `lib-stealth.sh`, a `say`/`step` log, and
  `act_summary` at the end. Python tools use the standard library only.
- Exact edits only. Avoid global search-and-replace across scripts; re-run
  ShellCheck after shell edits (the PostToolUse hook does this).
- Git: work on a branch and open a PR, never commit straight to `main`. Commit
  only when asked. Commit messages get a summary line, a body in short sections,
  and the Co-Authored-By trailer.
