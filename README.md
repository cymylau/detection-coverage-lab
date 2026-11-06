# Northline — Cloud & Container Detection Coverage Environment (EDR/CDR)

## Author

The scenarios, scripts, and documentation in this repository were
written by Claude (Anthropic), co-authored with human review and
direction throughout. Treat it accordingly: review it before relying
on it, the way you would any AI-authored code.

---

## Introduction

A self-contained, non-production environment for validating detection
coverage against attacker behaviour targeting cloud and containerised
platforms: the kind of telemetry a CDR (Cloud Detection & Response)
solution is specifically built to catch, alongside the host-level
behaviour a traditional EDR agent watches for. Runs entirely in Docker
Compose. Every credential, key, token, and "sensitive" document used is
a synthetic decoy; all traffic stays on the environment's internal
`northline-net` bridge network.

**Non-production use only, by design.** Nothing here is a real
credential, and nothing is connected to any real account or host
outside this environment. It reproduces attacker behaviour for
detection-coverage validation, not a working attack — every credential,
key, token, and document is fabricated and clearly marked `DECOY`.

## Disposable hosts only

**Run this only on a machine you will delete afterwards. Do not leave
it lurking.** This environment intentionally runs attacker-style behaviour and
weak configurations: a Kali box with extra capabilities, an SSH host
with passwordless sudo, and (with the privileged overlay) a privileged
Docker-in-Docker daemon with no authentication. It also installs
tooling and writes logs and decoy data as it goes.

Recommended workflow:

1. Commission a fresh VM (or cloud instance) for this.
2. Install Docker, clone this repo, and run the scenarios.
3. Collect what you need from `./results/` and your EDR/CDR console.
4. Tear down (`docker compose -f compose.yml -f compose.privileged.yml
   down -v`), then **delete the VM**.

Never run it on a workstation, shared server, or production system.
Never publish any of its ports or attach it to a network you don't
control. Provided as-is, with no warranty; you run it at your own risk
(see `LICENSE`). To report a problem, see `SECURITY.md`.

## Components

| | |
|---|---|
| `compose.yml` | base setup: `ops-console` (Kali attacker box), `dns-sink`, `control-api`, `internal-host` |
| `compose.privileged.yml` | overlay adding a Docker-in-Docker sandbox for the container-escape scenarios, see its header |
| `services/metadata_api.py` | decoy cloud instance-metadata service, serves decoy IAM creds |
| `services/dns_sink.py` | DNS sink; logs queries, reassembles DNS-tunnel exfil |
| `services/control_api.py` | decoy C2/cloud API: beacon/tasking, mining-pool, cloud-identity, and logging-control endpoints |
| `playbooks/` | setup + one script per scenario (table below) |

## Run everything, one command

On your disposable VM (see above), you need `git`, Docker, and the
Docker Compose plugin installed. Then:

```bash
git clone https://github.com/cymylau/edr-test-lab.git
cd edr-test-lab
bash run-everything.sh
```

Run these from your host shell, not inside a container. The script
drives `docker compose` itself, including the privileged overlay. It
brings up every container, runs setup, and runs every scenario, base and
overlay, start to finish, logging a consolidated timeline per stage to
`./results/`.

When it finishes, it prints the teardown command:
`docker compose -f compose.yml -f compose.privileged.yml down`. Run it,
then delete the VM.

## Finer-grained control

Three levels, from broadest to narrowest. Each is independent: pick
whichever matches what you want to validate.

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

## Scenario coverage (ATT&CK)

One row per technique, grouped by tactic in standard ATT&CK order, so
this can be checked off against a vendor's own detection-coverage matrix
or an ATT&CK Navigator layer. Each script's own header has the full
rationale. Scripts marked (overlay) need `compose.privileged.yml`.

| Tactic | Technique ID | Technique | Script |
|---|---|---|---|
| Execution | T1059 | Command and Scripting Interpreter | `run-c2-beacon.sh` |
| Execution | T1609 | Container Administration Command | `run-docker-socket-escape.sh` (overlay) |
| Persistence | T1053.003 | Scheduled Task/Job: Cron | `run-persistence.sh` |
| Persistence | T1543.002 | Create or Modify System Process: Systemd Service | `run-persistence.sh` |
| Persistence | T1546.004 | Event Triggered Execution: Unix Shell Configuration Modification | `run-persistence.sh` |
| Privilege Escalation | T1548.001 | Abuse Elevation Control Mechanism: Setuid and Setgid Binaries | `run-host-recon.sh` |
| Privilege Escalation | T1548.003 | Abuse Elevation Control Mechanism: Sudo and Sudo Caching | `run-ssh-audit-session.sh` |
| Privilege Escalation | T1611 | Escape to Host | `run-docker-socket-escape.sh`, `run-privileged-container-abuse.sh` (overlay) |
| Defense Evasion | T1036.003 | Masquerading: Rename System Utilities | `run-defense-evasion.sh` |
| Defense Evasion | T1070.006 | Indicator Removal: Timestomp | `run-defense-evasion.sh` |
| Defense Evasion | T1070.003 | Indicator Removal: Clear Command History | `run-defense-evasion.sh` |
| Defense Evasion | T1562.008 | Impair Defenses: Disable Cloud Logs | `run-impair-logging.sh` |
| Credential Access | T1552.004 | Unsecured Credentials: Private Keys | `run-credential-discovery.sh` |
| Credential Access | T1552.001 | Unsecured Credentials: Credentials In Files | `run-credential-discovery.sh`, `run-ssh-audit-session.sh` |
| Credential Access | T1555.003 | Credentials from Password Stores: Credentials from Web Browsers | `run-credential-discovery.sh` |
| Credential Access | T1552.005 | Unsecured Credentials: Cloud Instance Metadata API | `run-metadata-exfil.sh` |
| Credential Access | T1552.007 | Unsecured Credentials: Container API | `run-workload-identity-theft.sh`, `run-image-secret-discovery.sh` (overlay) |
| Credential Access | T1528 | Steal Application Access Token | `run-workload-identity-theft.sh` |
| Credential Access | T1003.008 | OS Credential Dumping: /etc/passwd and /etc/shadow | `run-ssh-audit-session.sh` |
| Discovery | T1033 | System Owner/User Discovery | `run-host-recon.sh` |
| Discovery | T1082 | System Information Discovery | `run-host-recon.sh` |
| Discovery | T1087.001 | Account Discovery: Local Account | `run-host-recon.sh` |
| Discovery | T1069.001 | Permission Groups Discovery: Local Groups | `run-host-recon.sh` |
| Discovery | T1046 | Network Service Discovery | `run-metadata-exfil.sh`, `run-lateral-movement.sh` |
| Discovery | T1613 | Container and Resource Discovery | `run-image-secret-discovery.sh` (overlay) |
| Lateral Movement | T1021.004 | Remote Services: SSH | `run-lateral-movement.sh`, `run-ssh-audit-session.sh` |
| Collection | T1119 | Automated Collection | `run-collection-staging.sh` |
| Collection | T1560.001 | Archive Collected Data: Archive via Utility | `run-metadata-exfil.sh`, `run-collection-staging.sh` |
| Command and Control | T1071.001 | Application Layer Protocol: Web Protocols | `run-c2-beacon.sh` |
| Command and Control | T1573 | Encrypted Channel | `run-c2-beacon.sh` |
| Command and Control | T1105 | Ingress Tool Transfer | `run-c2-beacon.sh` |
| Exfiltration | T1048.003 | Exfiltration Over Alternative Protocol | `run-metadata-exfil.sh` |
| Exfiltration | T1041 | Exfiltration Over C2 Channel | `run-https-exfil.sh` |
| Impact | T1496 | Resource Hijacking | `run-cryptomining.sh` (overlay) |

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

## Teardown

```bash
docker compose down
# or, if you brought up the privileged overlay:
docker compose -f compose.yml -f compose.privileged.yml down
```

## Acknowledgements

Security is a team effort, and this environment stands on a lot of
other people's work. With thanks to:

- **[Kali Linux](https://www.kali.org/)** and the Offensive Security
  team and contributors, for the attacker workstation image.
- **[MITRE ATT&CK](https://attack.mitre.org/)**, for the shared
  vocabulary of tactics and techniques that every scenario here is
  mapped to. Defenders and red teams alike owe it a great deal.
- **[Anthropic](https://www.anthropic.com/)**, whose Claude model wrote
  the scenarios, scripts, and documentation (see Author above).
- **[Docker](https://www.docker.com/)**, for Compose and the
  Docker-in-Docker image that make this environment disposable.
- **[LinuxServer.io](https://www.linuxserver.io/)**, for the OpenSSH
  server image used as the lateral-movement target.
- **[Python Software Foundation](https://www.python.org/)** and the
  Python community, for the runtime behind the decoy services.
- **[Debian](https://www.debian.org/)** and the open-source maintainers
  of nmap, curl, netcat, OpenSSH, sqlite, and the other tools the
  scenarios drive.
- **The EDR/CDR vendors, detection engineers, and threat researchers**
  whose published detections, write-ups, and tradecraft analysis shaped
  what good detection-coverage validation needs to exercise.
- **The wider security community**, for decades of shared research,
  open tooling, and responsible disclosure. Without it there would be
  nothing worth detecting, and no one to detect it.

If you contributed to something this environment relies on and aren't
credited, that's an oversight, not a statement. Open an issue or PR and
it will be fixed.

## License

MIT, see [LICENSE](LICENSE).
