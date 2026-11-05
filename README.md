# EDR Test Lab

A **self-contained, lab-only** environment for validating EDR / detection
coverage against common attacker behaviour, in Docker Compose. Every
credential, key, and "sensitive" document used is a decoy; all traffic
stays on the lab's internal `labnet` bridge network.

> ⚠️ **Lab use only, by design.** Nothing here is a real credential or
> connected to any real account/host outside the lab. This reproduces
> attacker *behaviour* for detection testing, not a working attack.

## Components

| | |
|---|---|
| `compose.yml` | 4 services: `edr-tester` (Kali attacker box), `dns-sink`, `mock-c2`, `internal-host` |
| `services/mock_imds.py` | mock cloud instance-metadata service, serves decoy IAM creds |
| `services/dns_sink.py` | DNS sink; logs queries, reassembles DNS-tunnel exfil |
| `services/mock_c2.py` | mock C2; hands out one no-op decoy task, logs beacons/exfil |
| `test-scripts/` | setup + one script per scenario (table below) |

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

Runs setup + every scenario below in sequence, logging a consolidated
timeline to `results/run_all_<session>.log`. Or run any scenario on its
own the same way, e.g.:

```bash
docker compose exec edr-tester bash test-scripts/simulate-host-recon.sh
```

## Scenarios

Each script is independently runnable and ATT&CK-tagged in its own header.

| Script | Emulates | ATT&CK |
|---|---|---|
| `seed-decoys.sh` | plants decoy SSH key, cloud creds, browser-login store, decoy documents (prereq for several scripts below) | — |
| `simulate-host-recon.sh` | account/system/permission discovery | T1033, T1082, T1087.001, T1548.001, T1069.001 |
| `simulate-credential-discovery.sh` | on-disk credential hunting (SSH keys, cloud creds, browser store) | T1552.004, T1552.001, T1555.003 |
| `simulate-persistence.sh` (`--cleanup` to remove) | cron, systemd user unit, shell-profile autostart | T1053.003, T1543.002, T1546.004 |
| `simulate-defense-evasion.sh` | process masquerading, timestomping, history clearing | T1036.003, T1070.006, T1070.003 |
| `simulate-metadata-exfil.sh` | nmap → IMDS credential theft → base64 → DNS-tunnel exfil | T1046, T1552.005, T1560.001, T1048.003 |
| `simulate-collection-staging.sh` | bulk-collect decoy documents, tar/zip into an archive | T1119, T1560.001 |
| `simulate-c2-beacon.sh` | jittered HTTP check-in + decoy task execution against `mock-c2` | T1071.001, T1573, T1059/T1105 |
| `simulate-https-exfil.sh` | POST a staged archive to `mock-c2` (non-DNS exfil channel) | T1041 |
| `simulate-lateral-movement.sh` | nmap sweep + SSH login to `internal-host` with decoy creds | T1046, T1021.004 |
| `simulate-full-chain.sh` | orchestrates all scenarios above into one multi-stage, correlatable kill chain | (combined) |
| `run-all.sh` | setup + `simulate-full-chain.sh` in one command | (combined) |

Artifacts land in `./results/` (gitignored): per-scenario run logs, the
decoy credential blob, the DNS sink's reassembled `exfil_<session>.decoded`,
staged archives, and `mock-c2`'s beacon/exfil logs.

## Teardown

```bash
docker compose down
```
