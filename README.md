# Cloud & Container Detection Test Lab (EDR/CDR)

## Author

The scenarios, scripts, and documentation in this repository were
written by Claude (Anthropic), co-authored with human review and
direction throughout. Treat it accordingly: review it before relying
on it, the way you would any AI-authored code.

---

## Introduction

A self-contained, lab-only environment for validating detection coverage
against attacker behaviour targeting cloud and containerised platforms:
the kind of telemetry a CDR (Cloud Detection & Response) solution is
specifically built to catch, alongside the host-level behaviour a
traditional EDR agent watches for. Runs entirely in Docker Compose. Every
credential, key, token, and "sensitive" document used is a decoy; all
traffic stays on the lab's internal `labnet` bridge network.

**Lab use only, by design.** Nothing here is a real credential or
connected to any real account/host outside the lab. This reproduces
attacker behaviour for detection testing, not a working attack.

## Components

| | |
|---|---|
| `compose.yml` | base lab: `edr-tester` (Kali attacker box), `dns-sink`, `mock-c2`, `internal-host` |
| `compose.privileged.yml` | overlay adding a Docker-in-Docker sandbox for the container-escape scenarios, see its header |
| `services/mock_imds.py` | mock cloud instance-metadata service, serves decoy IAM creds |
| `services/dns_sink.py` | DNS sink; logs queries, reassembles DNS-tunnel exfil |
| `services/mock_c2.py` | mock C2/cloud API: beacon/tasking, mining-pool, cloud-identity, and logging-control endpoints |
| `test-scripts/` | setup + one script per scenario (table below) |

## Run everything, one command

```bash
bash run-everything.sh
```

Run this from your host shell in the repo root, not inside a container:
it drives `docker compose` itself, including the privileged overlay. It
brings up every container, runs setup, and runs every scenario, base and
overlay, start to finish, logging a consolidated timeline per stage to
`./results/`. Tears down with `docker compose -f compose.yml -f
compose.privileged.yml down` when you're done (printed at the end).

## Finer-grained control

Three levels, from broadest to narrowest. Each is independent: pick
whichever matches what you want to test.

**All base scenarios:**

```bash
docker compose up -d
docker compose exec edr-tester bash test-scripts/lab-setup.sh
docker compose exec edr-tester bash test-scripts/install-extra-tools.sh
docker compose exec edr-tester bash test-scripts/run-all.sh
```

**All overlay scenarios** (the ones marked (overlay) in the table below):

```bash
docker compose -f compose.yml -f compose.privileged.yml up -d
docker compose -f compose.yml -f compose.privileged.yml exec edr-tester \
    bash test-scripts/lab-setup.sh
docker compose -f compose.yml -f compose.privileged.yml exec edr-tester \
    bash test-scripts/install-container-tools.sh
docker compose -f compose.yml -f compose.privileged.yml exec edr-tester \
    bash test-scripts/simulate-privileged-chain.sh
```

**One scenario at a time**, against whichever of the above you brought up:

```bash
docker compose exec edr-tester bash test-scripts/simulate-host-recon.sh
```

Any scenario script can be run on its own this way, in any order, as many
times as you like; each one is self-contained and writes its own log to
`./results/`.

## Scenario coverage (ATT&CK)

One row per technique, grouped by tactic in standard ATT&CK order, so
this can be checked off against a vendor's own detection-coverage matrix
or an ATT&CK Navigator layer. Each script's own header has the full
rationale. Scripts marked (overlay) need `compose.privileged.yml`.

| Tactic | Technique ID | Technique | Script |
|---|---|---|---|
| Execution | T1059 | Command and Scripting Interpreter | `simulate-c2-beacon.sh` |
| Execution | T1609 | Container Administration Command | `simulate-docker-socket-escape.sh` (overlay) |
| Persistence | T1053.003 | Scheduled Task/Job: Cron | `simulate-persistence.sh` |
| Persistence | T1543.002 | Create or Modify System Process: Systemd Service | `simulate-persistence.sh` |
| Persistence | T1546.004 | Event Triggered Execution: Unix Shell Configuration Modification | `simulate-persistence.sh` |
| Privilege Escalation | T1548.001 | Abuse Elevation Control Mechanism: Setuid and Setgid Binaries | `simulate-host-recon.sh` |
| Privilege Escalation | T1548.003 | Abuse Elevation Control Mechanism: Sudo and Sudo Caching | `simulate-ssh-audit-session.sh` |
| Privilege Escalation | T1611 | Escape to Host | `simulate-docker-socket-escape.sh`, `simulate-privileged-container-abuse.sh` (overlay) |
| Defense Evasion | T1036.003 | Masquerading: Rename System Utilities | `simulate-defense-evasion.sh` |
| Defense Evasion | T1070.006 | Indicator Removal: Timestomp | `simulate-defense-evasion.sh` |
| Defense Evasion | T1070.003 | Indicator Removal: Clear Command History | `simulate-defense-evasion.sh` |
| Defense Evasion | T1562.008 | Impair Defenses: Disable Cloud Logs | `simulate-impair-logging.sh` |
| Credential Access | T1552.004 | Unsecured Credentials: Private Keys | `simulate-credential-discovery.sh` |
| Credential Access | T1552.001 | Unsecured Credentials: Credentials In Files | `simulate-credential-discovery.sh`, `simulate-ssh-audit-session.sh` |
| Credential Access | T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | `simulate-credential-discovery.sh` |
| Credential Access | T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | `simulate-metadata-exfil.sh` |
| Credential Access | T1552.007 | Unsecured Credentials: Container API | `simulate-workload-identity-theft.sh`, `simulate-image-secret-discovery.sh` (overlay) |
| Credential Access | T1528 | Steal Application Access Token | `simulate-workload-identity-theft.sh` |
| Credential Access | T1003.008 | OS Credential Dumping: /etc/passwd and /etc/shadow | `simulate-ssh-audit-session.sh` |
| Discovery | T1033 | System Owner/User Discovery | `simulate-host-recon.sh` |
| Discovery | T1082 | System Information Discovery | `simulate-host-recon.sh` |
| Discovery | T1087.001 | Account Discovery: Local Account | `simulate-host-recon.sh` |
| Discovery | T1069.001 | Permission Groups Discovery: Local Groups | `simulate-host-recon.sh` |
| Discovery | T1046 | Network Service Discovery | `simulate-metadata-exfil.sh`, `simulate-lateral-movement.sh` |
| Discovery | T1613 | Container and Resource Discovery | `simulate-image-secret-discovery.sh` (overlay) |
| Lateral Movement | T1021.004 | Remote Services: SSH | `simulate-lateral-movement.sh`, `simulate-ssh-audit-session.sh` |
| Collection | T1119 | Automated Collection | `simulate-collection-staging.sh` |
| Collection | T1560.001 | Archive Collected Data: Archive via Utility | `simulate-metadata-exfil.sh`, `simulate-collection-staging.sh` |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | `simulate-c2-beacon.sh` |
| Command and Control | T1573 | Encrypted Channel | `simulate-c2-beacon.sh` |
| Command and Control | T1105 | Ingress Tool Transfer | `simulate-c2-beacon.sh` |
| Exfiltration | T1048.003 | Exfiltration Over Alternative Protocol | `simulate-metadata-exfil.sh` |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | `simulate-https-exfil.sh` |
| Impact | T1496 | Resource Hijacking | `simulate-cryptomining.sh` (overlay) |

Setup/orchestration scripts, not mapped to a technique:

| Script | Purpose |
|---|---|
| `seed-decoys.sh` | plants decoy SSH key, cloud creds, browser-login store, K8s service-account token, decoy documents (prereq for several scenarios above) |
| `simulate-full-chain.sh` | runs every base scenario above in one multi-stage, correlatable kill chain |
| `run-all.sh` | setup plus `simulate-full-chain.sh` in one command |
| `simulate-privileged-chain.sh` | runs all the overlay scenarios, plus the two cloud-native ones that need no extra privileges |

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

## License

MIT, see [LICENSE](LICENSE).
