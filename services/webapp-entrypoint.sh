#!/bin/sh
# Entrypoint for the web-portal container (python:alpine).
# Aliases the link-local metadata IP onto loopback and starts the decoy IMDS,
# so the SSRF scenario (A01) fetches the same decoy credentials as the
# metadata-theft scenario, then starts the deliberately vulnerable decoy app.
set -eu
ip addr add 169.254.169.254/32 dev lo 2>/dev/null || true
IMDS_BIND=169.254.169.254 python3 /app/metadata_api.py &
exec python3 /app/webapp.py
