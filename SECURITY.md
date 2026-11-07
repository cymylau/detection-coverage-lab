# Security Policy

## What this repository is

A non-production environment for validating EDR/CDR detection
coverage. It deliberately reproduces attacker behaviour (credential
discovery, C2 beaconing, DNS exfiltration, container escapes, log
tampering). Every credential, key, token, and document in it is a
**synthetic decoy**. The weak settings (passwordless sudo, password
SSH, a privileged Docker-in-Docker daemon with no auth) are
intentional and exist only inside this throwaway environment.

The decoy web app (`web-portal`) is intentionally vulnerable (injection,
unsafe deserialization, SSRF, and so on) and is likewise not a
vulnerability report. It must stay on the internal network.

Those intentional weaknesses are **not** vulnerabilities and need no
report.

Stealth profiles (`STEALTH=...`) only make the decoy techniques quieter
(timing, volume, tooling, naming). They never target, stop, or evade the
security agent, and are not a vulnerability.

The optional untrusted-fields scenario plants inert marker tokens in fields such
as a User-Agent or username; it makes no claims about the activity and never
targets a security agent. Run it only against tools you own or are authorised
to test.

## Where to run it

Only on a disposable machine that you will delete afterwards. See the
"Disposable hosts only" section of the README. Do not run it on a
shared, production, or long-lived system, and do not expose any of its
services to a network.

## What to report

- A real secret or credential committed to this repository.
- A scenario that can affect something outside this environment (the
  host, other containers, or external networks) when run as documented.
- A weakness in this environment's isolation, such as a published port
  or a host mount that could be abused.

## How to report

Use GitHub's private vulnerability reporting: the **Security** tab,
then **Report a vulnerability**. Please do not open a public issue
for these. Reports are handled on a best-effort basis.

## Supported versions

Only the current `main` branch.
