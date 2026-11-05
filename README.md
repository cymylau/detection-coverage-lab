# EDR Test Lab — Metadata Theft & DNS Exfil Emulation

A **self-contained, lab-only** environment for validating EDR / detection
coverage against a common cloud attack chain. It emulates an adversary
stealing IAM credentials from the instance metadata service (IMDS) and
exfiltrating them over DNS — generating deliberately **noisy** telemetry so
you can confirm your sensors and alerts fire.

> ⚠️ **Lab use only, by design.** The metadata service serves **decoy**
> credentials (`AKIA_LAB_DECOY_DO_NOT_USE`, etc.) — nothing here is a real
> token or connected to any cloud account. The DNS "exfiltration" is addressed
> to a **local sink** container inside the lab, so no real data exists and
> nothing is sent to any external resolver. This reproduces attacker
> *behaviour* for detection testing, not a working attack.

## The emulated chain (MITRE ATT&CK)

| Step | Action | Technique |
|------|--------|-----------|
| 1. Discovery | `nmap` scan of `169.254.169.254` | T1046 Network Service Discovery |
| 2. Credential access | `curl` the IMDS IAM credentials endpoint | T1552.005 Cloud Instance Metadata API |
| 3. Collection / staging | `base64`-encode the retrieved blob | T1560.001 Archive Collected Data |
| 4. Exfiltration | send the b64 as DNS subdomain queries | T1048.003 Exfil over Alternative Protocol |

## Components

- `services/mock_imds.py` — mock IMDS serving decoy creds on `169.254.169.254:80`.
- `services/dns_sink.py` — local DNS sink; logs every query, reassembles and
  decodes the exfil into `./results/exfil_<session>.decoded` for analyst review.
- `test-scripts/lab-setup.sh` — installs tools, aliases the metadata IP onto
  loopback, starts the mock IMDS.
- `test-scripts/simulate-metadata-exfil.sh` — runs the noisy 4-step chain.

## Run it

```bash
# 1. Bring up the attacker box + DNS sink
docker compose up -d

# 2. Prepare the attacker container (tools + mock IMDS on 169.254.169.254)
docker compose exec edr-tester bash test-scripts/lab-setup.sh

# 3. Fire the emulation
docker compose exec edr-tester bash test-scripts/simulate-metadata-exfil.sh

# 4. Watch the sink receive the exfil
docker compose logs -f dns-sink
```

Artifacts land in `./results/`: the run log, the retrieved decoy blob, the
mock-IMDS access log, and the sink's reassembled `exfil_<session>.decoded`.

## What your EDR should catch

Use these as detection test cases:

- A process (`curl`) connecting to the link-local metadata IP `169.254.169.254`.
- `nmap` port-scan behaviour against that address.
- Credential material being `base64`-encoded shortly after metadata access
  (collection/staging).
- A burst of outbound DNS queries with long, high-entropy subdomain labels to a
  single domain (`*.exfil.lab`) — classic DNS-tunnel signature.

## Additional scenarios

Beyond the metadata-theft + DNS-exfil chain above, the lab includes
standalone scenario scripts, each independently runnable and ATT&CK-tagged
in its own header. All use decoy data only and stay on the lab's internal
`labnet` network.

| Script | Emulates | ATT&CK |
|---|---|---|
| `seed-decoys.sh` | plants decoy SSH key, cloud creds, browser-login store, decoy documents (prereq for several scripts below) | — |
| `simulate-host-recon.sh` | account/system/permission discovery | T1033, T1082, T1087.001, T1548.001, T1069.001 |
| `simulate-credential-discovery.sh` | on-disk credential hunting (SSH keys, cloud creds, browser store) | T1552.004, T1552.001, T1555.003 |
| `simulate-persistence.sh` (`--cleanup` to remove) | cron, systemd user unit, shell-profile autostart | T1053.003, T1543.002, T1546.004 |
| `simulate-defense-evasion.sh` | process masquerading, timestomping, history clearing | T1036.003, T1070.006, T1070.003 |
| `simulate-collection-staging.sh` | bulk-collect decoy documents, tar/zip into an archive | T1119, T1560.001 |
| `simulate-c2-beacon.sh` | jittered HTTP check-in + decoy task execution against `mock-c2` | T1071.001, T1573, T1059/T1105 |
| `simulate-https-exfil.sh` | POST a staged archive to `mock-c2` (non-DNS exfil channel) | T1041 |
| `simulate-lateral-movement.sh` | nmap sweep + SSH login to `internal-host` with decoy creds | T1046, T1021.004 |
| `simulate-full-chain.sh` | orchestrates all of the above into one multi-stage, correlatable kill chain | (combined) |

New supporting services: `services/mock_c2.py` (mock C2 for beacon/exfil
scenarios) and the `internal-host` compose service (SSH target for lateral
movement), both decoy-only and lab-internal.

### Run everything in one go

```bash
docker compose up -d
docker compose exec edr-tester bash test-scripts/run-all.sh
```

`run-all.sh` runs setup (`lab-setup.sh`, `install-extra-tools.sh`) and then
every scenario script via `simulate-full-chain.sh`, logging a consolidated
timeline to `results/run_all_<session>.log` alongside each stage's own
artifacts. Stops on the first failure (`set -e`).

Or install extra tooling the newer scripts need (on top of `lab-setup.sh`)
and run scenarios individually:

```bash
docker compose exec edr-tester bash test-scripts/install-extra-tools.sh
```

Then run any scenario the same way as the original chain, e.g.:

```bash
docker compose exec edr-tester bash test-scripts/seed-decoys.sh
docker compose exec edr-tester bash test-scripts/simulate-host-recon.sh
docker compose exec edr-tester bash test-scripts/simulate-full-chain.sh
```

> A proposed ransomware-style impact/encryption scenario (mass file
> rename + transform + ransom note) was scoped but not implemented here —
> generating that content was blocked by a safety system during this
> session. If you still want impact/T1486-style coverage, consider testing
> it with a purpose-built commercial ransomware-simulator tool instead.

## Teardown

```bash
docker compose down
```
