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

## Teardown

```bash
docker compose down
```
