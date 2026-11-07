# Northline — Detection Coverage Lab (EDR / CDR / WAF)

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
git clone https://github.com/cymylau/edr-test-lab.git
cd edr-test-lab
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
| `activity_report.txt` | **start here**: one table of every attack action (time, technique, command, source container, destination container, path or ID), then a list of every attack covered |
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
[ATT&CK coverage table](docs/REFERENCE.md#mitre-attck-coverage), so you
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
traffic. The [OWASP table](docs/REFERENCE.md#owasp-top-10-2025-scenarios)
explains each one.

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

## Something went wrong?

- **A run stopped half-way:** run the clean-up command for your
  walkthrough, then run the walkthrough again from the start.
- **A name conflict with existing `northline-*` containers:** an earlier
  lab is still running. Take it down with the same clean-up command.
- **Permission denied on `results/`:** it was created by a container as
  root in an earlier run. Remove it with `sudo rm -rf results`.

## Advanced use

Everything else is in **[docs/REFERENCE.md](docs/REFERENCE.md)**: running
one scenario at a time, the full ATT&CK and OWASP coverage tables, stealth
profile details, the safety design, and what every file does.

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
