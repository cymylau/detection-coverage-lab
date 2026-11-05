# Cloud & Container Detection Test Lab (EDR/CDR)

A **self-contained, lab-only** environment for validating detection
coverage against attacker behaviour targeting **cloud and containerised
platforms** — the kind of telemetry a CDR (Cloud Detection & Response)
solution is specifically built to catch, alongside the host-level
behaviour a traditional EDR agent watches for. Runs entirely in Docker
Compose. Every credential, key, token, and "sensitive" document used is a
decoy; all traffic stays on the lab's internal `labnet` bridge network.

> ⚠️ **Lab use only, by design.** Nothing here is a real credential or
> connected to any real account/host outside the lab. This reproduces
> attacker *behaviour* for detection testing, not a working attack. Where a
> technique's real-world version can cause genuine host compromise (see
> `compose.privileged.yml` below), the lab substitutes a disposable sandbox
> so detection testing never risks the machine actually running it.

## Components

| | |
|---|---|
| `compose.yml` | base lab: `edr-tester` (Kali attacker box), `dns-sink`, `mock-c2`, `internal-host` |
| `compose.privileged.yml` | **opt-in** overlay adding a disposable Docker-in-Docker sandbox for container-escape scenarios — see its header |
| `services/mock_imds.py` | mock cloud instance-metadata service, serves decoy IAM creds |
| `services/dns_sink.py` | DNS sink; logs queries, reassembles DNS-tunnel exfil |
| `services/mock_c2.py` | mock C2/cloud-API; beacon/tasking, mining-pool, cloud-identity, and logging-control endpoints |
| `test-scripts/` | setup + one script per scenario (tables below) |

## Setup

```bash
docker compose up -d
docker compose exec edr-tester bash test-scripts/lab-setup.sh
docker compose exec edr-tester bash test-scripts/install-extra-tools.sh
```

## Run everything

```bash
docker compose exec edr-tester bash test-scripts/run-all.sh
```

Runs setup + every base scenario below in sequence, logging a consolidated
timeline to `results/run_all_<session>.log`. Or run any scenario on its
own the same way, e.g.:

```bash
docker compose exec edr-tester bash test-scripts/simulate-host-recon.sh
```

## Base scenarios

Each script is independently runnable and ATT&CK-tagged in its own header.
No extra privileges needed beyond the default `compose.yml`.

| Script | Emulates | ATT&CK |
|---|---|---|
| `seed-decoys.sh` | plants decoy SSH key, cloud creds, browser-login store, K8s service-account token, decoy documents (prereq for several scripts below) | — |
| `simulate-host-recon.sh` | account/system/permission discovery | T1033, T1082, T1087.001, T1548.001, T1069.001 |
| `simulate-credential-discovery.sh` | on-disk credential hunting (SSH keys, cloud creds, browser store) | T1552.004, T1552.001, T1555.003 |
| `simulate-persistence.sh` (`--cleanup` to remove) | cron, systemd user unit, shell-profile autostart | T1053.003, T1543.002, T1546.004 |
| `simulate-defense-evasion.sh` | process masquerading, timestomping, history clearing | T1036.003, T1070.006, T1070.003 |
| `simulate-metadata-exfil.sh` | nmap → IMDS credential theft → base64 → DNS-tunnel exfil | T1046, T1552.005, T1560.001, T1048.003 |
| `simulate-collection-staging.sh` | bulk-collect decoy documents, tar/zip into an archive | T1119, T1560.001 |
| `simulate-c2-beacon.sh` | jittered HTTP check-in + decoy task execution against `mock-c2` | T1071.001, T1573, T1059/T1105 |
| `simulate-https-exfil.sh` | POST a staged archive to `mock-c2` (non-DNS exfil channel) | T1041 |
| `simulate-lateral-movement.sh` | nmap sweep + SSH login to `internal-host` with decoy creds | T1046, T1021.004 |
| `simulate-workload-identity-theft.sh` | read a decoy K8s service-account token, present it to a mock cloud/K8s API | T1552.007, T1528 |
| `simulate-impair-logging.sh` | "disable audit logging, then act" sequencing against a mock cloud API | T1562.008 |
| `simulate-full-chain.sh` | orchestrates all the scenarios above into one multi-stage, correlatable kill chain | (combined) |
| `run-all.sh` | setup + `simulate-full-chain.sh` in one command | (combined) |

## Cloud/container-native scenarios (opt-in: `compose.privileged.yml`)

These need the privileged overlay's disposable Docker-in-Docker sandbox —
see that file's header for the safety model and exact commands:

```bash
docker compose -f compose.yml -f compose.privileged.yml up -d
docker compose -f compose.yml -f compose.privileged.yml exec edr-tester \
    bash test-scripts/install-container-tools.sh
docker compose -f compose.yml -f compose.privileged.yml exec edr-tester \
    bash test-scripts/simulate-privileged-chain.sh   # runs all of the below
```

| Script | Emulates | ATT&CK |
|---|---|---|
| `simulate-docker-socket-escape.sh` | discover an accessible Docker control plane, spawn a privileged container with the daemon's host fs mounted | T1609, T1611 |
| `simulate-privileged-container-abuse.sh` | capability discovery, nsenter-into-pid-1 attempt, cgroup `release_agent` breakout surface probe (read-only) | T1611 |
| `simulate-cryptomining.sh` | sustained high-CPU decoy process + periodic check-ins against a mock mining pool | T1496 |
| `simulate-image-secret-discovery.sh` | build a decoy image with secrets baked into layers, discover them via `docker history`/layer export | T1613, T1552.007 |

## Artifacts

All scenarios write to `./results/` (gitignored): per-scenario run logs,
the decoy credential blob, the DNS sink's reassembled
`exfil_<session>.decoded`, staged archives, and `mock-c2`'s beacon/pool/
identity/logging logs.

## Teardown

```bash
docker compose down
# or, if you brought up the privileged overlay:
docker compose -f compose.yml -f compose.privileged.yml down
```
