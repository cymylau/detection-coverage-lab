# Security Policy

## What this repository is

A lab-only environment for testing EDR/CDR detection coverage. It
deliberately reproduces attacker behaviour (credential discovery,
C2 beaconing, DNS exfiltration, container escapes, log tampering).
Every credential, key, token, and document in it is a **decoy**. The
weak settings (passwordless sudo, password SSH, a privileged
Docker-in-Docker daemon with no auth) are intentional and exist only
inside a throwaway lab.

Those intentional weaknesses are **not** vulnerabilities and need no
report.

## Where to run it

Only on a disposable machine that you will delete afterwards. See the
"Disposable hosts only" section of the README. Do not run it on a
shared, production, or long-lived system, and do not expose any of its
services to a network.

## What to report

- A real secret or credential committed to this repository.
- A scenario that can affect something outside the lab (the host,
  other containers, or external networks) when run as documented.
- A weakness in the lab's isolation, such as a published port or a
  host mount that could be abused.

## How to report

Use GitHub's private vulnerability reporting: the **Security** tab,
then **Report a vulnerability**. Please do not open a public issue
for these. Reports are handled on a best-effort basis.

## Supported versions

Only the current `main` branch.
