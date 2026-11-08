# Reference

Everything beyond the quick-start guide in the [README](../README.md).

> **About the name.** *Cymylau* is Welsh for "clouds" (roughly "kuh-MUL-eye"). **Cymylau Ltd is a fictitious company**, invented as the victim in this lab's decoy data: the made-up web portal, email addresses, credentials and documents all belong to it. It is not a real organisation, and any resemblance to a real company of that name is coincidental. Decoy addresses use the reserved `.example` domain.

Contents: [The activity log](#the-activity-log) · [Untrusted-field handling](#untrusted-field-handling) · [Scoring your tool](#scoring-your-tool) · [Destination confirmation](#destination-confirmation) · [One technique or tactic](#running-one-technique-or-tactic) · [Preflight and CI](#preflight-teardown-and-ci) · [Safety design](#safety-design) · [Components](#components) ·
[Running pieces separately](#running-pieces-separately) ·
[Stealth profiles](#stealth-profiles) ·
[OWASP Top 10:2025 scenarios](#owasp-top-10-2025-scenarios) ·
[MITRE ATT&CK coverage](#mitre-attck-coverage) · [Artifacts](#artifacts)

## The activity log

Every action a scenario performs is recorded in `results/activity.jsonl`,
one JSON line each, and shown as a table at the bottom of every scenario,
every chain, and the end of `run-everything.sh`:

```
Time          Technique  Command              Source       Destination   Path / ID
09:43:44.808  OWASP-A06  curl -s -X GET       ops-console  web-portal    /reset?user=alice&code=0000 (x91 over 2s)
09:41:15.898  T1048.003  dig +short @dns-sink A  ops-console  dns-sink   0.1794044475.ewogICJD…exfil.internal
```

| column | meaning |
|---|---|
| Time | UTC, millisecond precision |
| Technique | ATT&CK technique ID, or `OWASP-Axx` |
| Command | what was run or sent |
| Source / Destination | container (compose service) names; the decoy metadata service is shown as `ops-console (decoy IMDS)`, and `docker` commands show `docker-sandbox` |
| Path / ID | URL path, file path, DNS name, or other unique identifier |

Under the table, **Attacks covered** lists every technique that ran, with
its name and how many actions it comprised.

Bursts of the same action (a brute-force loop, sequential IDs) are
collapsed to one row with a count in the printed table. Nothing is lost:
`activity.csv` and `activity.jsonl` hold every row and extra fields
(`step`, `result`, `scenario`, `profile`).

```bash
python3 playbooks/activity-report.py results/activity.jsonl --full          # every row, as a table
python3 playbooks/activity-report.py results/activity.jsonl --format csv    # CSV
python3 playbooks/activity-report.py results/activity.jsonl --scenario run-owasp-top10
python3 playbooks/activity-report.py results/activity.jsonl --since 1794044400   # epoch seconds
```

The log is written by plain bash built-ins on purpose: recording it never
starts an extra process, so the bookkeeping cannot show up as attacker
behaviour in your telemetry. Technique names come from
`playbooks/techniques.tsv`. `activity.jsonl` accumulates across runs; the
report from `run-everything.sh` covers only that run.

## Untrusted-field handling

`run-everything.sh --only untrusted-fields` (or `playbooks/run-untrusted-fields.sh`)
checks how a tool treats strings an attacker controls. It is optional and not
part of the default run.

Four carriers each do the same real action twice, a few seconds apart, as a
**control** (ordinary value) and **marked** (same value plus an inert token,
`MARK-DECOY-<session>-<n>`): HTTP User-Agent (UFLD-01), SSH username
(UFLD-02), `argv[0]` of a renamed binary (UFLD-03), archive file name
(UFLD-04). The activity log records `pair`, `variant` (`control`/`marked`) and
`marker` for these rows.

`playbooks/untrusted-fields-report.py --tool-output <file-or-folder>` scans an
export from your tool for the marker tokens and writes
`results/untrusted_fields_scorecard.csv`. A marker in the export means the field
was preserved and surfaced. The judgements that matter (was it presented as
quoted untrusted data; was the verdict the same as for the control run) are left
blank for you.

Notes from building it:
- Recent OpenSSH (`PerSourcePenalties`) drops new connections from an address for
  about 20 seconds after a failed login, so the scenario waits 22 real seconds
  (not scaled by `STEALTH_TIME_SCALE`) before the marked SSH attempt. The
  `result` field in the activity log records whether each attempt reached sshd.
- The OpenSSH client rejects some characters in a username, which is why the
  marker is a single plain token.

What good looks like: attacker-controlled fields are preserved verbatim, clearly
labelled as untrusted, never treated as instructions or as evidence about the
activity, and the verdict does not depend on their content.

## Scoring your tool

`playbooks/detection-report.py --alerts EXPORT` compares an alert export from
your EDR/CDR/WAF with the activity log and reports, per technique, whether it was
detected, partly detected or missed.

- **Input:** CSV, JSON, or JSON lines. The alert time is found by field name (`time`,
  `timestamp`, `ts`, `_time`, `created_at`, `detected_at`, ...; ISO 8601 or epoch
  seconds/milliseconds; no zone means UTC). Any technique IDs in the alert
  (`T1552.005`, `OWASP-A05`, `A05:2025`, or in tags and rule names) are picked up.
- **Match:** an alert counts for an action if its time is from 2 seconds before
  the action to `--window` seconds after it (default 120). **Detected** means the
  alert names the same technique (a parent such as `T1552` matches `T1552.005`).
  **Partial** means an alert fired in the window but named no technique or a
  different one, so it may be unrelated; confirm by hand. **Missed** means no alert.
- **Which run:** `activity.jsonl` accumulates across runs, so by default only the
  latest `run-everything.sh` run is scored (its start time comes from
  `results/last_run.json`). `--since EPOCH` picks a different start; `--all-runs`
  scores everything.
- **Local-time exports:** times without a zone are read as UTC. If your console
  exports local time, add `--time-offset HOURS` (`1` for UTC+1, `-5` for UTC-5).
- **Output:** a summary table, `--csv` for per-action detail, and `--layer` for an
  ATT&CK Navigator layer.

It warns (on stderr) when alert rows have no recognisable time field, when no
alerts could be read at all, and when none of the alerts fall inside the run's
time range: the usual causes of an "everything missed" result that is really an
export or time-zone problem. A bare number is never taken as a time unless it is
in a time-named field, so numeric alert IDs are not mistaken for timestamps.

A noisy tool that fires generic alerts will show many `partial` results. Treat
`detected` as the reliable column and review `partial` by hand.

## Destination confirmation

The activity log is the attacker's view. `observe.py` (run by `run-everything.sh`)
checks each remote action against what the destination recorded, and adds a
"Seen at dest" column to the report: `yes`, `NO` or `n/a`.

The services keep timestamped `results/server_<name>.jsonl` records
(`control-api`, `web-portal`, `dns-sink`, and the decoy metadata service as
`imds`); sshd's auth log is saved as `results/server_sshd.log`. An action is
confirmed if a matching record appears from 1 second before to 6 seconds after
it. `n/a` means there is nothing to check: local actions, port scans, commands
inside an already-confirmed SSH session, and `docker-sandbox` (no per-request
log). `NO` is worth investigating before reading anything into a missing
detection: the traffic may never have arrived. The result is written to
`results/activity_confirmed.jsonl`.

## Running one technique or tactic

`bash run-everything.sh --technique T1552.005`, `--tactic credential-access`, or
`--list`. `playbooks/scenario-index.py` reads the scripts' own `st_mark`/`act`
calls to map techniques to scripts, so the mapping cannot drift from what runs.
IDs can be ATT&CK (a parent such as `T1552` selects its sub-techniques),
`OWASP-A05`/`A05`, or `UFLD-01`. Tactics come from the third column of
`playbooks/techniques.tsv`. Selected scripts run in the same order as the full
chain; the privileged sandbox starts only if a selected script needs it. It
cannot be combined with `--only`.

## Preflight, teardown and CI

`run-everything.sh` checks Docker, the Compose plugin, Python, disk space and
container-name clashes before starting (`--check` does only that). `--down`
removes the lab; `--reset` also clears `./results` after asking (`--yes` skips
the question).

**During a run** it waits until every service is listening before the scenarios
start. It checks each container's own socket table, so the readiness check puts
no traffic on the network. After lock-down it checks that no lab container still
has a default route, and stops before any scenario if one does.

**At the end** it prints a stage summary (`ok` or `FAILED (exit N)` for each
scenario script) and writes `results/last_run.json`: start and end time,
`--only`, stealth profile and each stage's exit code. One failed scenario does
not stop the others. The ownership fix, destination confirmation and activity
report still run, and the command exits non-zero. The last line is
`[run-everything] done.` only when every stage passed. Inside the chains
(`run-full-chain.sh`, `run-privileged-chain.sh`) each scenario's exit code is
recorded the same way and printed as a table at the end of the chain's log.

`.github/workflows/ci.yml` runs on every push and pull request. The lint job
covers:
- shell syntax and Python compile;
- compose validation;
- ShellCheck at warning level (intentional exceptions are marked inline with `# shellcheck disable=` and a reason);
- `tests/test_tools.py`, unit tests for the reporting, scoring, confirmation
  and selection tools (`python3 -m unittest discover -s tests`, no Docker
  needed);
- `tests/check-docs.py`, which fails if the README's test list disagrees with
  what the scripts record, a technique has no name, a `run-everything.sh` option
  is undocumented, or a local link or anchor is broken (`--online` also checks
  external links).

A smoke job then runs the OWASP scenarios, then `--technique T1552.005` on the
same lab without tearing it down. It fails if any web-app category was not
exercised, an action never reached its destination, or a stage failed.

## Safety design

This lab intentionally runs attacker-style behaviour and weak
configurations, so safety comes from how it is contained:

- **Disposable VM.** The only real isolation. The privileged
  Docker-in-Docker sandbox (`compose.privileged.yml`) shares the host
  kernel and has an unauthenticated Docker API, so it is **not** a
  security boundary. Never run this on a workstation, shared server or
  production system.
- **Internal network.** `cymylau-net` is `internal: true`: no internet,
  no route to the Docker host. Only the setup phase uses a separate
  `setup-net` for installs, and `lock-down-network.sh` removes it before
  any scenario runs (`run-everything.sh` does this for you). It disconnects
  *every* container attached to the project's `setup-net` (ops-console and,
  with the overlay, docker-sandbox), whichever compose files you used. It then
  checks that no lab container still has a default route, and exits non-zero
  if one does. If you run scenarios by hand, run `bash lock-down-network.sh`
  after installing tools and check that it ends with `egress removed`.
- **No published ports.** Nothing is reachable from outside the VM.
- **Decoys only.** Every credential, key, token and document is fabricated
  and marked `DECOY`.
- **Guards.** Playbooks that touch `~/.ssh`, `~/.aws`, `~/.bashrc`, crontab
  or shell history refuse to run outside `ops-console` (`LAB_CONTAINER=1`),
  and `seed-decoys.sh --cleanup` only removes files it created.
- **Read-only mounts.** `ops-console` cannot modify the service code that
  other containers run.
- **Decoy web app.** `web-portal` is deliberately vulnerable, runs shell
  injection as `nobody`, and has no egress.

To report a problem, see [SECURITY.md](../SECURITY.md).

## Components

| | |
|---|---|
| `compose.yml` | base setup: `ops-console` (Kali attacker box), `dns-sink`, `control-api`, `internal-host`, `web-portal` (decoy vulnerable web app) |
| `compose.privileged.yml` | overlay adding a Docker-in-Docker sandbox for the container-escape scenarios, see its header |
| `run-everything.sh` | host-side one-command runner (`--only`, `--stealth`, `--technique`, ...); stage summary, `results/last_run.json` |
| `lock-down-network.sh` | host-side: disconnects every container from the setup-phase egress network, then verifies that no lab container has a default route |
| `services/metadata_api.py` | decoy cloud instance-metadata service, serves decoy IAM creds |
| `services/dns_sink.py` | DNS sink; logs queries, reassembles DNS-tunnel exfil |
| `services/control_api.py` | decoy C2/cloud API: beacon/tasking, mining-pool, cloud-identity, logging-control and decoy-package endpoints |
| `services/webapp.py` | deliberately vulnerable decoy web app for the OWASP scenarios (`web-portal`) |
| `playbooks/` | setup + one script per scenario |
| `playbooks/lib-stealth.sh` | stealth profile definitions and helpers |
| `playbooks/detection-report.py` | scores an alert export against the activity log; writes an ATT&CK Navigator layer |
| `playbooks/observe.py` | confirms each action in the destination's own logs |
| `playbooks/scenario-index.py` | maps techniques and tactics to scripts for `--technique` / `--tactic` |
| `tests/check-docs.py`, `tests/test_tools.py`, `.github/workflows/ci.yml` | docs-vs-code drift check, unit tests for the Python tools, and CI |
| `playbooks/lib-chain.sh` | runs each stage of a chain script, keeps going past a failure, prints a stage summary and sets the exit code |
| `playbooks/lib-activity.sh`, `playbooks/activity-report.py`, `playbooks/techniques.tsv` | the activity log: recording, table/CSV report, technique names |
| `playbooks/run-stealth-sweep.sh` | runs the base chain at every stealth profile and prints a comparison |
| `playbooks/run-untrusted-fields.sh`, `playbooks/untrusted-fields-report.py` | optional untrusted-telemetry-field scenario and its marker checker |
| `playbooks/run-owasp-top10.sh` | OWASP Top 10:2025 application-attack scenarios |

## Running pieces separately

`run-everything.sh` covers the common cases (`--only`, `--technique`,
`--tactic`) and does the setup, lock-down, readiness checks and reporting for
you. To drive the containers yourself, set up once and then run whatever you
like. Run every command from the host, in the repository root.

**1. Set up** (pick the base lab, or base plus the privileged overlay):

```bash
mkdir -p results                 # create it as you; otherwise Docker creates it as root
docker compose up -d                                              # base only
# or: docker compose -f compose.yml -f compose.privileged.yml up -d   # base + overlay

docker compose exec ops-console bash playbooks/bootstrap.sh            # tools + decoy IMDS
docker compose exec ops-console bash playbooks/install-extra-tools.sh  # zip, sshpass, ssh, ...
# overlay only:
docker compose exec ops-console bash playbooks/install-container-tools.sh

bash lock-down-network.sh        # remove internet access; must end with "egress removed"
docker compose exec ops-console bash playbooks/seed-decoys.sh          # plant the decoy files
```

Plain `docker compose exec ops-console ...` works with the overlay up too, since
ops-console is defined in `compose.yml`.

**2. Run** a whole chain, or one scenario at a time, in any order and as often as
you like:

```bash
docker compose exec ops-console bash playbooks/run-full-chain.sh        # every base scenario
docker compose exec ops-console bash playbooks/run-privileged-chain.sh  # overlay scenarios
docker compose exec ops-console bash playbooks/run-host-recon.sh        # just one
```

Each scenario writes its own log to `./results/`. Their prerequisites, which
the setup above covers:

| Needs | Scenarios |
|---|---|
| `bootstrap.sh` (the decoy IMDS on 169.254.169.254) | `metadata-exfil` |
| `seed-decoys.sh` | `credential-discovery`, `collection-staging`, `workload-identity-theft` (`https-exfil` and `untrusted-fields` seed for themselves) |
| `install-extra-tools.sh` | `lateral-movement`, `ssh-audit-session`, `collection-staging` (zip) |
| the overlay + `install-container-tools.sh` | `docker-socket-escape`, `privileged-container-abuse`, `image-secret-discovery` |

**3. Report and tear down.** Files written by the containers are owned by root
on the host. Use `bash run-everything.sh --down` to remove the lab; it also
hands `./results` back to you. The activity table is printed at the end of each
scenario. For the combined report and destination confirmation:

```bash
docker compose exec -T internal-host cat /config/logs/openssh/current > results/server_sshd.log  # else SSH rows show NO
python3 playbooks/observe.py --results results
python3 playbooks/activity-report.py results/activity_confirmed.jsonl
```

## Stealth profiles

The lab is noisy by default so detections fire. Stealth profiles let you
run the **same decoy scenarios more quietly**, to check whether your
EDR/CDR still detects a careful attacker.

```bash
bash run-everything.sh --stealth quiet          # or STEALTH=quiet ...
docker compose exec ops-console bash playbooks/run-stealth-sweep.sh   # all four, side by side
STEALTH_TIME_SCALE=0.01 ...                      # shrink every wait for quick demos
```

| profile | timing | tooling | artifacts |
|---|---|---|---|
| `noisy` (default) | 1-4 s beacon jitter, no DNS delay, no request pacing | `nmap`, `curl`, 48-char DNS labels, `sshpass -p`, broad `find`, full recon | obvious names, staged in `results/`, history cleared, timestomp |
| `careful` | 5-15 s jitter, 1-2 s DNS delay | `nmap -T2` on fewer ports, realistic UA, 32-char labels, `sshpass -e`, scoped `find`/SUID search, no `env` dump | staged under `~/.cache`, quieter process name |
| `quiet` | 30-90 s jitter, 2-5 s DNS delay, niced load | single `/dev/tcp` probe instead of `nmap`, `python3` instead of `curl`, 24-char labels, known-path credential checks, minimal recon | staging copy removed, no history-clear/timestomp |
| `covert` | 120-300 s jitter, 5-15 s DNS delay | no port scan, 12-char labels | as `quiet`, less obvious binary name |

**How long a run takes.** Timing adds deliberate waits: beacon jitter, a delay
between DNS queries, and the same delay between OWASP requests. Rough real-time
totals, worked out from the number of actions each profile performs and the
average wait:

| timing | everything | `--only mitre` | `--only owasp` |
|---|---|---|---|
| `noisy` | about 80 s (measured) | about 80 s | about 30 s |
| `careful` | about 5 min | about 2 min | about 3 min |
| `quiet` | about 15 min | about 9 min | about 5 min |
| `covert` | about 40 min | about 30 min | about 10 min |

`run-everything.sh` prints the estimate when it starts. `STEALTH_TIME_SCALE`
multiplies every wait (`0.1` makes a covert run take about 5 minutes) but
compresses the timing your sensors would see, so use it to check the plumbing,
not to measure stealth.

Override one dimension with `STEALTH_TIMING`, `STEALTH_TOOLING` or
`STEALTH_ARTIFACTS` (e.g. `STEALTH=quiet STEALTH_TOOLING=noisy`).
Every action is recorded in the [activity log](#the-activity-log), with
the profile used, so you can line EDR/CDR alerts up against exactly what
ran (`stealth_timeline.jsonl` keeps the older, step-level view). The profile table is in one place:
`playbooks/lib-stealth.sh`.

`run-stealth-sweep.sh` runs the base chain once per profile into
`results/stealth_<profile>/`. Two limits: the services (`control-api`,
`dns-sink`, `web-portal`) still log to `results/`, so there is no per-profile
destination confirmation; and all four profiles back to back take about an hour
at real timing. It is not wired into `run-everything.sh`; run it inside
ops-console after the set-up in [Running pieces separately](#running-pieces-separately).

**Scope:** profiles only change *how* the existing decoy techniques are
performed (timing, volume, tooling, naming, tidiness). They never stop,
blind, unhook or modify the security agent, and every target remains a
lab decoy.

## OWASP Top 10 2025 scenarios

The ATT&CK scenarios test host and cloud behaviour. These test
**application attacks**: `run-owasp-top10.sh` drives a deliberately
vulnerable decoy web app (`web-portal`, `services/webapp.py`) so WAF, API,
CDR and runtime sensors have genuine application-layer telemetry to detect.

The actions are real (the app really runs the SQL, shell, outbound fetch,
file read and `pickle.loads`); the payloads are inert and `DECOY`-tagged,
and only touch decoy data in an isolated container (internal network only,
no published ports, no egress, command injection runs as `nobody`).
This is a telemetry generator, not a training target.

```bash
docker compose exec ops-console bash playbooks/run-owasp-top10.sh          # all ten
docker compose exec ops-console bash playbooks/run-owasp-top10.sh A01 A05  # selected
STEALTH=quiet ...                                                          # honours stealth profiles
```

The ten categories and the tests run for each are listed in the
[README](../README.md#every-test-in-this-lab).

Ground truth for what the app really did is `results/webapp_events.jsonl`
(category, vulnerability, endpoint, client); the app's own deliberately weak
log is `results/webapp_app.log`; the playbook's steps go to
`stealth_timeline.jsonl` as `OWASP-A0x`. Some categories (A01, A05, A07) are
visible from a single request. Others (A02, A03, A06, A09, A10) are design or
configuration weaknesses, so what a sensor sees is the exploitation traffic,
not the weakness itself: read a missing alert there with that in mind.
Category names and links were checked against the published
[OWASP Top 10:2025](https://owasp.org/Top10/2025/) list.

## MITRE ATT&CK coverage

The complete, linked list of techniques and the scripts that run them is the last
section of the [README](../README.md#every-test-in-this-lab); it is built from
what the scripts actually record.

Setup/orchestration scripts, not mapped to a technique:

| Script | Purpose |
|---|---|
| `seed-decoys.sh` | plants decoy SSH key, cloud creds, browser-login store, K8s service-account token, decoy documents (prereq for several scenarios above) |
| `run-full-chain.sh` | runs every base scenario above in one multi-stage, correlatable kill chain |
| `run-all.sh` | setup plus `run-full-chain.sh` in one command |
| `run-privileged-chain.sh` | runs all the overlay scenarios, plus the two cloud-native ones that need no extra privileges |

## Artifacts

All scenarios write to `./results/` (gitignored): per-scenario run logs,
the decoy credential blob, the DNS sink's reassembled
`exfil_<session>.decoded`, staged archives, and `control-api`'s beacon/pool/
identity/logging logs.
