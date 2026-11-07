# Cymylau — Detection Coverage Lab (EDR / CDR / WAF)

A self-contained, non-production environment that **generates attack
telemetry on purpose**, so you can check whether your security tooling
detects it. It runs entirely in Docker Compose and covers two things:

- **MITRE ATT&CK**: attacker behaviour on hosts, containers and cloud
  (credential theft, C2 beaconing, DNS exfiltration, container escapes,
  log tampering, and more).
- **OWASP Top 10:2025**: application attacks against a deliberately
  vulnerable decoy web app (injection, broken access control, SSRF,
  unsafe deserialization, and more).

The actions are real; the payloads are not. Every credential, key, token
and document is a synthetic decoy marked `DECOY`, and nothing leaves the
lab's internal network.

> **Author:** the scenarios, scripts and documentation were written by
> Claude (Anthropic), with human review and direction. Review it before
> relying on it, as you would any AI-authored code.

> **About the name.** *Cymylau* is Welsh for "clouds" (roughly "kuh-MUL-eye"). **Cymylau Ltd is a fictitious company**, invented as the victim in this lab's decoy data: the made-up web portal, email addresses, credentials and documents all belong to it. It is not a real organisation, and any resemblance to a real company of that name is coincidental. Decoy addresses use the reserved `.example` domain.

## Read this first: disposable machines only

This lab runs attacker-style behaviour and weak configurations on
purpose (a privileged Docker-in-Docker daemon with no authentication,
passwordless sudo, a vulnerable web app). **Run it only on a throwaway
VM that you will delete afterwards.** Never on a workstation, a shared
server or a production system. Provided as-is, with no warranty (see
[LICENSE](LICENSE)). To report a problem, see [SECURITY.md](SECURITY.md).

## What you need

- A fresh Linux VM (or cloud instance) that you can delete afterwards
- `git`, Docker Engine, and the Docker Compose plugin
- Optional but the point: your EDR / CDR / WAF agent installed on that VM
  **before** you run anything, so it can see what happens

## Get it

```bash
git clone https://github.com/cymylau/detection-coverage-lab.git
cd detection-coverage-lab
```

Run every command below from this folder, in your host shell (not inside
a container). The first run also downloads the container images, which
adds a few minutes; after that each run takes one to two minutes.

---

## Walkthrough 1: everything (the default)

MITRE ATT&CK and OWASP Top 10 together. Start here.

```bash
bash run-everything.sh
```

**What happens**

1. Starts the lab containers, including the container-escape sandbox.
2. Installs the attacker tooling, then cuts the lab off from the internet.
3. Runs every ATT&CK scenario, then the OWASP Top 10 scenarios, then the
   container-escape scenarios.
4. Hands the results back to you in `./results/` and prints the teardown
   command.

**It worked if** it ends with `[run-everything] done. Results are in ./results/`.
It takes about 70 seconds once the images are cached.

**What to look at**

| File in `results/` | What it tells you |
|---|---|
| `activity_report.txt` | **start here**: one table of every attack action (time, technique, command, source container, destination container, path or ID, and whether the destination's own logs confirm it), then a list of every attack covered |
| `activity.csv` | the same, every row, ready for a spreadsheet or SIEM |
| `full_chain_*.log`, `privileged_chain_*.log`, `owasp_*.log` | the detailed log of each part, with the same table at the bottom |
| `webapp_events.jsonl` | what the vulnerable web app *really* did for each OWASP request |

Then open your EDR / CDR / WAF console and compare what it flagged
against `activity_report.txt` (all times are UTC). Any row in that table
with no matching alert is a detection gap.

**Clean up** (then delete the VM):

```bash
docker compose -f compose.yml -f compose.privileged.yml down -v
```

---

## Walkthrough 2: MITRE ATT&CK only

Host, container and cloud attacker behaviour, without the web app.

```bash
bash run-everything.sh --only mitre
```

**What happens:** the same as Walkthrough 1, minus the OWASP scenarios.
It runs credential discovery, persistence, defence evasion, metadata
theft with DNS exfiltration, C2 beaconing, lateral movement over SSH,
cryptomining, container escapes and more.

**It worked if** it ends with `[run-everything] done.` (about 70 seconds)
and there is no `owasp_*.log` in `results/`.

**What to look at:** `activity_report.txt` (every action, with ATT&CK
technique IDs), `full_chain_*.log` and `privileged_chain_*.log`. The
full technique list is in the
[list of every test](#every-test-in-this-lab), so you
can check it against your vendor's coverage matrix.

**Clean up:**

```bash
docker compose -f compose.yml -f compose.privileged.yml down -v
```

---

## Walkthrough 3: OWASP Top 10 only

Application attacks against the decoy web app, without the host and
container scenarios. This is also the lightest option, because it does
not start the privileged container-escape sandbox.

```bash
bash run-everything.sh --only owasp
```

**What happens:** starts the base containers only, installs the tooling,
cuts off the internet, then sends real attack requests for all ten
categories (A01 to A10) to the decoy web app `web-portal`. The app really
runs the vulnerable code (SQL, a shell command, an outbound fetch, a file
read, a deserialization) but every payload is inert and tagged `DECOY`.

**It worked if** it ends with `[run-everything] done.` (about 30 seconds)
and `results/webapp_events.jsonl` has events for `A01` through `A10`.

**What to look at:** `activity_report.txt` (every request, with its OWASP
category), `owasp_*.log` (your requests and the responses) and
`webapp_events.jsonl` (ground truth for each request). Some categories (injection, access control,
credential stuffing) show up in a single request. Others (misconfiguration,
insecure design, logging failures) are weaknesses the app has rather than
something a sensor sees, so what you can detect there is the exploitation
traffic. The [list of every test](#every-test-in-this-lab)
explains each one.

**Clean up:**

```bash
docker compose -f compose.yml down -v
```

---

## Walkthrough 4: untrusted telemetry fields (optional)

Attackers choose some of the strings that end up in your logs: a User-Agent,
an SSH username, a process name, a file name. Your tool, and any AI summary
layered on it, should treat those as untrusted *data*. This scenario checks
that. It is optional and not part of the default run.

```bash
bash run-everything.sh --only untrusted-fields
```

**What happens:** starts the base containers, then performs four real actions
twice each: once with an ordinary value (control) and once with the same value
plus an inert marker token such as `MARK-DECOY-<session>-<n>` (marked). The
marker makes no claim and asks for nothing.

**It worked if** it ends with `[run-everything] done.` (about a minute, mostly
a deliberate 22-second wait for SSH's failed-login penalty).

**What to look at:** search your tool for the marker tokens listed in
`activity_report.txt`, then ask: is the field preserved exactly in the raw
telemetry? Is it shown as quoted, attacker-controlled data rather than as a
finding? Is the verdict the same for the control and marked runs? To check an
export from your tool:

```bash
python3 playbooks/untrusted-fields-report.py --tool-output path/to/export
```

It reports which markers appear and writes a scorecard for the judgements only
you can make. Use it only against tools you own or are authorised to test.

**Clean up:**

```bash
docker compose -f compose.yml down -v
```

---

## Want it quieter?

By default the lab is noisy so detections fire. To check whether your tool
still catches a *careful* attacker, add `--stealth` to any walkthrough:

```bash
bash run-everything.sh --stealth quiet                 # everything, quieter
bash run-everything.sh --only owasp --stealth careful  # combine the options
```

The levels are `noisy` (default), `careful`, `quiet` and `covert`. Details
are in [Stealth profiles](docs/REFERENCE.md#stealth-profiles).

## Score your tool

After a run, export your tool's alerts for that time window (CSV or JSON) and
let the lab tell you what it caught:

```bash
python3 playbooks/detection-report.py --alerts path/to/alerts.csv \
    --csv results/detection_detail.csv --layer results/attack_layer.json
```

You get a table of every technique as detected, partial or missed, and an
ATT&CK Navigator layer (green, amber, red) to load at
<https://mitre-attack.github.io/attack-navigator/>. How the matching works is in
[Scoring your tool](docs/REFERENCE.md#scoring-your-tool).

## Just one technique?

Re-test a single detection after tuning a rule:

```bash
bash run-everything.sh --list                      # every technique, its tactic and its scripts
bash run-everything.sh --technique T1552.005       # the scenario that performs it
bash run-everything.sh --tactic credential-access  # every scenario for a tactic
```

This runs the whole script that performs the technique, which may perform
neighbouring ones too.

## Something went wrong?

- **Check your machine first:** `bash run-everything.sh --check` tests for
  Docker, the Compose plugin, Python, disk space and name clashes, and says
  what to fix. The same checks run automatically before every run.
- **A run stopped half-way:** `bash run-everything.sh --down` removes the lab,
  then run the walkthrough again. `bash run-everything.sh --reset` also clears
  `./results` (it asks first).
- **A name conflict with `cymylau-*` containers:** an earlier lab is still
  running. `--down` removes it, or the preflight shows the exact command.

## Advanced use

Everything else is in **[docs/REFERENCE.md](docs/REFERENCE.md)**: running
one scenario at a time, stealth profile details, the activity log, the
safety design, and what every file does. The full list of tests is the last
section of this page: [Every test in this lab](#every-test-in-this-lab).

## Acknowledgements

Security is a team effort, and this environment stands on a lot of other
people's work. With thanks to:

- **[MITRE ATT&CK](https://attack.mitre.org/)**, for the shared vocabulary
  of tactics and techniques that every host and cloud scenario here is
  mapped to.
- **[OWASP](https://owasp.org/)** and the volunteers behind the
  [OWASP Top 10](https://owasp.org/Top10/), for the shared language of
  application risk that the web scenarios follow.
- **[Kali Linux](https://www.kali.org/)** and the OffSec team and
  contributors, for the attacker workstation image.
- **[Anthropic](https://www.anthropic.com/)**, whose Claude model wrote the
  scenarios, scripts and documentation (see the note at the top).
- **[Docker](https://www.docker.com/)**, for Compose and the
  Docker-in-Docker image that make this environment disposable.
- **[LinuxServer.io](https://www.linuxserver.io/)**, for the OpenSSH server
  image used as the lateral-movement target.
- **[Python Software Foundation](https://www.python.org/)** and the Python
  community, for the runtime behind the decoy services and the vulnerable
  web app, and **[Alpine Linux](https://alpinelinux.org/)** and
  **[Debian](https://www.debian.org/)**, for the base images underneath.
- **The authors and maintainers of the open-source tools the scenarios
  drive:** [Nmap](https://nmap.org/), [curl](https://curl.se/),
  [OpenSSH](https://www.openssh.com/), [OpenSSL](https://www.openssl.org/),
  [SQLite](https://www.sqlite.org/), and netcat, sshpass and the other
  packages installed from the Kali and Debian archives.
- **[GitHub](https://github.com/)**, for hosting and for Dependabot, which
  keeps the pinned container images current.
- **The EDR, CDR and WAF vendors, detection engineers and threat
  researchers** whose published detections, write-ups and tradecraft
  analysis shaped what good detection-coverage validation needs to exercise.
- **The wider security community**, for decades of shared research, open
  tooling and responsible disclosure. Without it there would be nothing
  worth detecting, and no one to detect it.

If you contributed to something this environment relies on and aren't
credited, that's an oversight, not a statement. Open an issue or PR and it
will be fixed.

## License

MIT, see [LICENSE](LICENSE).

## Every test in this lab

The complete list of what the lab runs, with a link to each technique or
category on the parent site. Each row is something the scripts really do and
record in the [activity log](docs/REFERENCE.md#the-activity-log), so what
you see in your tool can be matched against this list.

- **MITRE ATT&CK**: <https://attack.mitre.org/> (33 techniques below)
- **OWASP Top 10:2025**: <https://owasp.org/Top10/2025/> (all 10 categories below)

### MITRE ATT&CK tests

Grouped by tactic, in ATT&CK order. "Scripts" are in
[`playbooks/`](playbooks/); the ones marked (overlay) need the privileged
container-escape sandbox and are not run by `--only owasp`.

| Tactic | Technique | What the lab does | Scripts |
|---|---|---|---|
| [Execution](https://attack.mitre.org/tactics/TA0002/) | [T1059](https://attack.mitre.org/techniques/T1059/) Command and Scripting Interpreter | runs a task handed back by the decoy C2 | [`c2-beacon`](playbooks/run-c2-beacon.sh) |
| [Execution](https://attack.mitre.org/tactics/TA0002/) | [T1609](https://attack.mitre.org/techniques/T1609/) Container Administration Command | talks to the Docker API of `docker-sandbox` | [`docker-socket-escape`](playbooks/run-docker-socket-escape.sh) (overlay) |
| [Persistence](https://attack.mitre.org/tactics/TA0003/) | [T1053.003](https://attack.mitre.org/techniques/T1053/003/) Scheduled Task/Job: Cron | adds a cron entry | [`persistence`](playbooks/run-persistence.sh) |
| [Persistence](https://attack.mitre.org/tactics/TA0003/) | [T1543.002](https://attack.mitre.org/techniques/T1543/002/) Create or Modify System Process: Systemd Service | writes a systemd user unit | [`persistence`](playbooks/run-persistence.sh) |
| [Persistence](https://attack.mitre.org/tactics/TA0003/) | [T1546.004](https://attack.mitre.org/techniques/T1546/004/) Event Triggered Execution: Unix Shell Configuration Modification | appends an autostart line to `.bashrc` | [`persistence`](playbooks/run-persistence.sh) |
| [Privilege Escalation](https://attack.mitre.org/tactics/TA0004/) | [T1548.001](https://attack.mitre.org/techniques/T1548/001/) Abuse Elevation Control Mechanism: Setuid and Setgid Binaries | searches the filesystem for setuid binaries | [`host-recon`](playbooks/run-host-recon.sh) |
| [Privilege Escalation](https://attack.mitre.org/tactics/TA0004/) | [T1548.003](https://attack.mitre.org/techniques/T1548/003/) Abuse Elevation Control Mechanism: Sudo and Sudo Caching | `sudo -l` / `sudo` use inside the SSH session | [`ssh-audit-session`](playbooks/run-ssh-audit-session.sh) |
| [Privilege Escalation](https://attack.mitre.org/tactics/TA0004/) | [T1611](https://attack.mitre.org/techniques/T1611/) Escape to Host | privileged-container escape, `nsenter` into PID 1, cgroup `release_agent` probe | [`docker-socket-escape`](playbooks/run-docker-socket-escape.sh) (overlay), [`privileged-container-abuse`](playbooks/run-privileged-container-abuse.sh) (overlay) |
| [Defense Evasion](https://attack.mitre.org/tactics/TA0005/) | [T1036.003](https://attack.mitre.org/techniques/T1036/003/) Masquerading: Rename System Utilities | copies `sleep` to a suspicious name and runs it | [`defense-evasion`](playbooks/run-defense-evasion.sh) |
| [Defense Evasion](https://attack.mitre.org/tactics/TA0005/) | [T1070.003](https://attack.mitre.org/techniques/T1070/003/) Indicator Removal: Clear Command History | clears shell history | [`defense-evasion`](playbooks/run-defense-evasion.sh) |
| [Defense Evasion](https://attack.mitre.org/tactics/TA0005/) | [T1070.004](https://attack.mitre.org/techniques/T1070/004/) Indicator Removal: File Deletion | deletes the staging directory after archiving | [`collection-staging`](playbooks/run-collection-staging.sh) |
| [Defense Evasion](https://attack.mitre.org/tactics/TA0005/) | [T1070.006](https://attack.mitre.org/techniques/T1070/006/) Indicator Removal: Timestomp | backdates a file's timestamp | [`defense-evasion`](playbooks/run-defense-evasion.sh) |
| [Defense Evasion](https://attack.mitre.org/tactics/TA0005/) | [T1562.008](https://attack.mitre.org/techniques/T1562/008/) Impair Defenses: Disable Cloud Logs | disables decoy cloud audit logging, then acts in the gap | [`impair-logging`](playbooks/run-impair-logging.sh) |
| [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [T1003.008](https://attack.mitre.org/techniques/T1003/008/) OS Credential Dumping: /etc/passwd and /etc/shadow | reads `/etc/shadow` with `sudo` inside an SSH session on `internal-host` | [`ssh-audit-session`](playbooks/run-ssh-audit-session.sh) |
| [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [T1528](https://attack.mitre.org/techniques/T1528/) Steal Application Access Token | presents a stolen service-account token to a decoy cloud API | [`workload-identity-theft`](playbooks/run-workload-identity-theft.sh) |
| [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [T1552.001](https://attack.mitre.org/techniques/T1552/001/) Unsecured Credentials: Credentials In Files | reads decoy cloud credentials and `/etc/sudoers` | [`credential-discovery`](playbooks/run-credential-discovery.sh), [`ssh-audit-session`](playbooks/run-ssh-audit-session.sh) |
| [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [T1552.004](https://attack.mitre.org/techniques/T1552/004/) Unsecured Credentials: Private Keys | finds and reads a decoy SSH private key | [`credential-discovery`](playbooks/run-credential-discovery.sh) |
| [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [T1552.005](https://attack.mitre.org/techniques/T1552/005/) Unsecured Credentials: Cloud Instance Metadata API | queries the decoy cloud instance-metadata service | [`metadata-exfil`](playbooks/run-metadata-exfil.sh) |
| [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [T1552.007](https://attack.mitre.org/techniques/T1552/007/) Unsecured Credentials: Container API | reads the decoy Kubernetes token; mines image history and layers for baked-in secrets | [`image-secret-discovery`](playbooks/run-image-secret-discovery.sh) (overlay), [`workload-identity-theft`](playbooks/run-workload-identity-theft.sh) |
| [Credential Access](https://attack.mitre.org/tactics/TA0006/) | [T1555.003](https://attack.mitre.org/techniques/T1555/003/) Credentials from Password Stores: Credentials from Web Browsers | reads a decoy browser password store | [`credential-discovery`](playbooks/run-credential-discovery.sh) |
| [Discovery](https://attack.mitre.org/tactics/TA0007/) | [T1033](https://attack.mitre.org/techniques/T1033/) System Owner/User Discovery | `whoami` / `id` on the attacker box and inside the SSH session | [`host-recon`](playbooks/run-host-recon.sh), [`ssh-audit-session`](playbooks/run-ssh-audit-session.sh) |
| [Discovery](https://attack.mitre.org/tactics/TA0007/) | [T1046](https://attack.mitre.org/techniques/T1046/) Network Service Discovery | port scan of the decoy metadata IP and of `internal-host` | [`lateral-movement`](playbooks/run-lateral-movement.sh), [`metadata-exfil`](playbooks/run-metadata-exfil.sh) |
| [Discovery](https://attack.mitre.org/tactics/TA0007/) | [T1069.001](https://attack.mitre.org/techniques/T1069/001/) Permission Groups Discovery: Local Groups | `sudo -l` | [`host-recon`](playbooks/run-host-recon.sh) |
| [Discovery](https://attack.mitre.org/tactics/TA0007/) | [T1082](https://attack.mitre.org/techniques/T1082/) System Information Discovery | `uname`, `env`, capability and session discovery | [`host-recon`](playbooks/run-host-recon.sh), [`privileged-container-abuse`](playbooks/run-privileged-container-abuse.sh) (overlay), [`ssh-audit-session`](playbooks/run-ssh-audit-session.sh) |
| [Discovery](https://attack.mitre.org/tactics/TA0007/) | [T1087.001](https://attack.mitre.org/techniques/T1087/001/) Account Discovery: Local Account | reads `/etc/passwd` | [`host-recon`](playbooks/run-host-recon.sh) |
| [Discovery](https://attack.mitre.org/tactics/TA0007/) | [T1613](https://attack.mitre.org/techniques/T1613/) Container and Resource Discovery | lists images and containers on `docker-sandbox` | [`image-secret-discovery`](playbooks/run-image-secret-discovery.sh) (overlay) |
| [Lateral Movement](https://attack.mitre.org/tactics/TA0008/) | [T1021.004](https://attack.mitre.org/techniques/T1021/004/) Remote Services: SSH | SSH login to `internal-host` with decoy credentials | [`lateral-movement`](playbooks/run-lateral-movement.sh), [`ssh-audit-session`](playbooks/run-ssh-audit-session.sh) |
| [Collection](https://attack.mitre.org/tactics/TA0009/) | [T1119](https://attack.mitre.org/techniques/T1119/) Automated Collection | finds and copies decoy documents to a staging directory | [`collection-staging`](playbooks/run-collection-staging.sh) |
| [Collection](https://attack.mitre.org/tactics/TA0009/) | [T1560.001](https://attack.mitre.org/techniques/T1560/001/) Archive Collected Data: Archive via Utility | base64, `tar` and `zip` of collected data | [`collection-staging`](playbooks/run-collection-staging.sh), [`metadata-exfil`](playbooks/run-metadata-exfil.sh) |
| [Command and Control](https://attack.mitre.org/tactics/TA0011/) | [T1071.001](https://attack.mitre.org/techniques/T1071/001/) Application Layer Protocol: Web Protocols | jittered HTTP beaconing to the decoy C2 | [`c2-beacon`](playbooks/run-c2-beacon.sh) |
| [Exfiltration](https://attack.mitre.org/tactics/TA0010/) | [T1041](https://attack.mitre.org/techniques/T1041/) Exfiltration Over C2 Channel | POSTs a staged archive to the decoy C2 (`control-api`) | [`https-exfil`](playbooks/run-https-exfil.sh) |
| [Exfiltration](https://attack.mitre.org/tactics/TA0010/) | [T1048.003](https://attack.mitre.org/techniques/T1048/003/) Exfiltration Over Alternative Protocol | DNS tunnel: base64 chunks as subdomains to `dns-sink` | [`metadata-exfil`](playbooks/run-metadata-exfil.sh) |
| [Impact](https://attack.mitre.org/tactics/TA0040/) | [T1496](https://attack.mitre.org/techniques/T1496/) Resource Hijacking | sustained CPU load plus decoy mining-pool check-ins | [`cryptomining`](playbooks/run-cryptomining.sh) |

(Script names are shown without the `run-` prefix and `.sh` suffix.)

Some steps depend on the [stealth profile](docs/REFERENCE.md#stealth-profiles):
T1070.003 (clear history) and T1070.006 (timestomp) run only at `noisy` and
`careful`, T1070.004 (delete the staging directory) only at `quiet` and
`covert`, and the scan, credential-search and recon techniques use quieter
methods, or are skipped, at the higher levels. This list is the full set at the
default `noisy` profile.

### OWASP Top 10:2025 tests

All run by [`run-owasp-top10`](playbooks/run-owasp-top10.sh) against the
decoy web app `web-portal`. Real requests, inert `DECOY` payloads.

| Category | Tests performed |
|---|---|
| [A01:2025 Broken Access Control](https://owasp.org/Top10/2025/A01_2025-Broken_Access_Control/) | IDOR on user IDs 1-3; unauthenticated admin export; path traversal to `/etc/passwd`; SSRF to the decoy metadata service and to an internal service |
| [A02:2025 Security Misconfiguration](https://owasp.org/Top10/2025/A02_2025-Security_Misconfiguration/) | debug endpoint (environment dump); exposed `.env`; directory listing |
| [A03:2025 Software Supply Chain Failures](https://owasp.org/Top10/2025/A03_2025-Software_Supply_Chain_Failures/) | installs and runs an unsigned package fetched from an arbitrary URL |
| [A04:2025 Cryptographic Failures](https://owasp.org/Top10/2025/A04_2025-Cryptographic_Failures/) | cleartext login over HTTP; unsalted MD5 hash dump; forged session token accepted |
| [A05:2025 Injection](https://owasp.org/Top10/2025/A05_2025-Injection/) | SQL injection (tautology and UNION); command injection (marker only); stored XSS (inert payload) |
| [A06:2025 Insecure Design](https://owasp.org/Top10/2025/A06_2025-Insecure_Design/) | coupon redeemed repeatedly with no limit; negative-quantity order; password-reset code brute force |
| [A07:2025 Authentication Failures](https://owasp.org/Top10/2025/A07_2025-Authentication_Failures/) | default credentials; credential-stuffing burst with no lockout; session fixation |
| [A08:2025 Software or Data Integrity Failures](https://owasp.org/Top10/2025/A08_2025-Software_or_Data_Integrity_Failures/) | unsafe deserialization of a pickled object (inert marker); unsigned update accepted |
| [A09:2025 Security Logging and Alerting Failures](https://owasp.org/Top10/2025/A09_2025-Security_Logging_and_Alerting_Failures/) | failed login and admin export that the app never logs; log injection through the comment author; reading the app's audit log |
| [A10:2025 Mishandling of Exceptional Conditions](https://owasp.org/Top10/2025/A10_2025-Mishandling_of_Exceptional_Conditions/) | stack-trace leak (divide by zero, bad input); authorization check that fails open |

Some of these (A02, A03, A06, A09, A10) are weaknesses in the app rather than
single malicious requests, so what a sensor can see is the exploitation
traffic, not the weakness itself. Keep that in mind when reading a missing alert.

### Untrusted-field tests (optional)

Run by [`run-untrusted-fields`](playbooks/run-untrusted-fields.sh)
(`--only untrusted-fields`). Each carrier performs the same action as a control
and again with an inert marker token. This checks how a tool preserves and
presents attacker-controlled data; it is not a bypass test.

| ID | Carrier | Telemetry it appears in |
|---|---|---|
| UFLD-01 | HTTP `User-Agent` on a beacon to `control-api` | network and web logs |
| UFLD-02 | SSH username on a failed login to `internal-host` | sshd auth log |
| UFLD-03 | `argv[0]` of a renamed binary | process-creation events |
| UFLD-04 | archive file name | file events |
