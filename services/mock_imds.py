#!/usr/bin/env python3
"""
Mock Instance Metadata Service (IMDS) for the EDR test lab.

Serves DECOY credentials only. Nothing here is a real token and nothing
is connected to any cloud account. Its sole purpose is to give the
attack-emulation script a link-local metadata endpoint to touch so that
EDR/telemetry pipelines can be exercised against MITRE ATT&CK T1552.005
(Unsecured Credentials: Cloud Instance Metadata API).

Bind address defaults to 169.254.169.254:80 to reproduce the real-world
indicator (a process connecting to the link-local metadata IP). In the
lab the attacker container aliases that address onto loopback first.
"""
import http.server
import json
import os
import socketserver

BIND_ADDR = os.environ.get("IMDS_BIND", "169.254.169.254")
BIND_PORT = int(os.environ.get("IMDS_PORT", "80"))

# Obvious decoys. Not valid anywhere.
FAKE_ROLE = "edr-lab-decoy-role"
FAKE_CREDS = {
    "Code": "Success",
    "Type": "AWS-HMAC",
    "AccessKeyId": "AKIA_LAB_DECOY_DO_NOT_USE",
    "SecretAccessKey": "LAB+DECOY+SECRET+NOT+A+REAL+KEY+00000000",
    "Token": "LAB-DECOY-SESSION-TOKEN-" + ("A" * 128),
    "Expiration": "2099-01-01T00:00:00Z",
}


class IMDSHandler(http.server.BaseHTTPRequestHandler):
    def _send(self, body: str, ctype: str = "text/plain"):
        payload = body.encode()
        self.send_response(200)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Server", "EC2ws")  # mimic for realism
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self):
        p = self.path.rstrip("/")
        base = "/latest/meta-data/iam/security-credentials"
        if p in ("", "/latest", "/latest/meta-data"):
            self._send("iam/\nhostname\ninstance-id\n")
        elif p == base:
            self._send(FAKE_ROLE + "\n")
        elif p == f"{base}/{FAKE_ROLE}":
            self._send(json.dumps(FAKE_CREDS, indent=2), "application/json")
        elif p == "/latest/meta-data/instance-id":
            self._send("i-0labdecoy0000000")
        else:
            self.send_error(404, "Not Found")

    def log_message(self, fmt, *args):
        # Surface access as structured telemetry on stdout.
        print(f"[mock-imds] {self.address_string()} {fmt % args}", flush=True)


if __name__ == "__main__":
    with socketserver.TCPServer((BIND_ADDR, BIND_PORT), IMDSHandler) as httpd:
        print(f"[mock-imds] serving DECOY metadata on {BIND_ADDR}:{BIND_PORT}", flush=True)
        httpd.serve_forever()
