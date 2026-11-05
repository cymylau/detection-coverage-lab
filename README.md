# Cloud & Container Detection Test Lab (EDR/CDR)

A self-contained, lab-only environment for validating detection coverage
against attacker behaviour targeting cloud and containerised platforms:
the kind of telemetry a CDR (Cloud Detection & Response) solution is
specifically built to catch, alongside the host-level behaviour a
traditional EDR agent watches for. Runs entirely in Docker Compose. Every
credential, key, token, and "sensitive" document used is a decoy; all
traffic stays on the lab's internal `labnet` bridge network.

**Lab use only, by design.** Nothing here is a real credential or
connected to any real account/host outside the lab. This reproduces
attacker behaviour for detection testing, not a working attack. Where a
technique's real-world version can cause genuine host compromise (see
`compose.privileged.yml` below), the lab substitutes a disposable sandbox
so detection testing never risks the machine actually running it.

## Components

| | |
|---|---|
| `compose.yml` | base lab: `edr-tester` (Kali attacker box), `dns-sink`, `mock-c2`, `internal-host` |
| `compose.privileged.yml` | opt-in overlay adding a disposable Docker-in-Docker sandbox for container-escape scenarios, see its header |
| `services/mock_imds.py` | mock cloud instance-metadata service, serves decoy IAM creds |
| `services/dns_sink.py` | DNS sink; logs queries, reassembles DNS-tunnel exfil |
| `services/mock_c2.py` | mock C2/cloud API: beacon/tasking, mining-pool, cloud-identity, and logging-control endpoints |
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

Runs setup and every base scenario in sequence, logging a consolidated
timeline to `results/run_all_<session>.log`. Or run any scenario on its
own the same way, for example:

```bash
docker compose exec edr-tester bash test-scripts/simulate-host-recon.sh
```

## Base scenario coverage (ATT&CK)

One row per technique, grouped by tactic in standard ATT&CK order, so
this can be checked off against a vendor's own detection-coverage matrix
or an ATT&CK Navigator layer. Each script's own header has the full
rationale. No extra privileges needed beyond the default `compose.yml`.

| Tactic | Technique ID | Technique | Script |
|---|---|---|---|
| Execution | T1059 | Command and Scripting Interpreter | `simulate-c2-beacon.sh` |
| Persistence | T1053.003 | Scheduled Task/Job: Cron | `simulate-persistence.sh` |
| Persistence | T1543.002 | Create or Modify System Process: Systemd Service | `simulate-persistence.sh` |
| Persistence | T1546.004 | Event Triggered Execution: Unix Shell Configuration Modification | `simulate-persistence.sh` |
| Privilege Escalation | T1548.001 | Abuse Elevation Control Mechanism: Setuid and Setgid Binaries | `simulate-host-recon.sh` |
| Defense Evasion | T1036.003 | Masquerading: Rename System Utilities | `simulate-defense-evasion.sh` |
| Defense Evasion | T1070.006 | Indicator Removal: Timestomp | `simulate-defense-evasion.sh` |
| Defense Evasion | T1070.003 | Indicator Removal: Clear Command History | `simulate-defense-evasion.sh` |
| Defense Evasion | T1562.008 | Impair Defenses: Disable Cloud Logs | `simulate-impair-logging.sh` |
| Credential Access | T1552.004 | Unsecured Credentials: Private Keys | `simulate-credential-discovery.sh` |
| Credential Access | T1552.001 | Unsecured Credentials: Credentials In Files | `simulate-credential-discovery.sh` |
| Credential Access | T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | `simulate-credential-discovery.sh` |
| Credential Access | T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | `simulate-metadata-exfil.sh` |
| Credential Access | T1552.007 | Unsecured Credentials: Container API | `simulate-workload-identity-theft.sh` |
| Credential Access | T1528 | Steal Application Access Token | `simulate-workload-identity-theft.sh` |
| Discovery | T1033 | System Owner/User Discovery | `simulate-host-recon.sh` |
| Discovery | T1082 | System Information Discovery | `simulate-host-recon.sh` |
| Discovery | T1087.001 | Account Discovery: Local Account | `simulate-host-recon.sh` |
| Discovery | T1069.001 | Permission Groups Discovery: Local Groups | `simulate-host-recon.sh` |
| Discovery | T1046 | Network Service Discovery | `simulate-metadata-exfil.sh`, `simulate-lateral-movement.sh` |
| Lateral Movement | T1021.004 | Remote Services: SSH | `simulate-lateral-movement.sh` |
| Collection | T1119 | Automated Collection | `simulate-collection-staging.sh` |
| Collection | T1560.001 | Archive Collected Data: Archive via Utility | `simulate-metadata-exfil.sh`, `simulate-collection-staging.sh` |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | `simulate-c2-beacon.sh` |
| Command and Control | T1573 | Encrypted Channel | `simulate-c2-beacon.sh` |
| Command and Control | T1105 | Ingress Tool Transfer | `simulate-c2-beacon.sh` |
| Exfiltration | T1048.003 | Exfiltration Over Alternative Protocol | `simulate-metadata-exfil.sh` |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | `simulate-https-exfil.sh` |

Setup/orchestration scripts, not mapped to a technique:

| Script | Purpose |
|---|---|
| `seed-decoys.sh` | plants decoy SSH key, cloud creds, browser-login store, K8s service-account token, decoy documents (prereq for several scenarios above) |
| `simulate-full-chain.sh` | runs every scenario above in one multi-stage, correlatable kill chain |
| `run-all.sh` | setup plus `simulate-full-chain.sh` in one command |

## Cloud/container-native scenario coverage (opt-in: `compose.privileged.yml`)

These need the privileged overlay's disposable Docker-in-Docker sandbox,
see that file's header for the safety model and exact commands:

```bash
docker compose -f compose.yml -f compose.privileged.yml up -d
docker compose -f compose.yml -f compose.privileged.yml exec edr-tester \
    bash test-scripts/install-container-tools.sh
docker compose -f compose.yml -f compose.privileged.yml exec edr-tester \
    bash test-scripts/simulate-privileged-chain.sh
```

| Tactic | Technique ID | Technique | Script |
|---|---|---|---|
| Execution | T1609 | Container Administration Command | `simulate-docker-socket-escape.sh` |
| Privilege Escalation | T1611 | Escape to Host | `simulate-docker-socket-escape.sh`, `simulate-privileged-container-abuse.sh` |
| Discovery | T1613 | Container and Resource Discovery | `simulate-image-secret-discovery.sh` |
| Credential Access | T1552.007 | Unsecured Credentials: Container API | `simulate-image-secret-discovery.sh` |
| Impact | T1496 | Resource Hijacking | `simulate-cryptomining.sh` |

`simulate-privileged-chain.sh` runs all of the above plus
`simulate-workload-identity-theft.sh` and `simulate-impair-logging.sh`
from the base table, since those two are also cloud/container-native but
need no extra privileges.

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
