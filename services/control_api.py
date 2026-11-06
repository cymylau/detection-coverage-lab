#!/usr/bin/env python3
"""
Command-and-control relay for the cloud/container EDR (CDR) detection-coverage environment.

A minimal HTTP server that stands in for an attacker-controlled command and
control server, purely to give beacon/exfil emulation scripts a destination
inside the environment's network. It never reaches, proxies to, or is reachable from
anything outside the environment's `northline-net` bridge. All "tasking" is a hardcoded
harmless string; nothing it returns is ever executed as a privileged or
persistent action unless a scenario script explicitly says so, and when it
does, it is always a no-op decoy command run only inside the ephemeral
attacker container.

Endpoints:
  GET  /beacon             -- check-in; logs source + headers, returns a task
  POST /task-result        -- scenario posts back a decoy "result"
  POST /exfil              -- scenario POSTs a decoy archive here (HTTPS-exfil emulation)
  GET  /pool/getwork       -- decoy mining-pool work request (resource-hijack emulation)
  POST /pool/submit        -- decoy mining-pool share submission
  POST /cloud/identity     -- decoy cloud/K8s token-exchange endpoint; logs any bearer
                               token presented (workload-identity-theft emulation)
  POST /logging/disable    -- decoy cloud audit-log control-plane call (impair-logging
                               emulation); never actually disables anything real
  GET  /logging/status     -- reports the relay's own (in-memory only) logging flag
"""
import json
import os
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

BIND_ADDR = os.environ.get("C2_BIND", "0.0.0.0")
BIND_PORT = int(os.environ.get("C2_PORT", "8443"))
RESULTS_DIR = os.environ.get("RESULTS_DIR", "/home/root/results")

# The only "task" this relay ever hands out: an explicitly harmless,
# no-op decoy command. Scenario scripts may choose to run it to demonstrate
# C2-directed execution, but it does nothing beyond writing a log line.
DECOY_TASK = {
    "task_id": "decoy-task-0001",
    "command": "echo decoy-task-executed",
}

os.makedirs(RESULTS_DIR, exist_ok=True)
BEACON_LOG = os.path.join(RESULTS_DIR, "control_api_beacons.log")
EXFIL_DIR = os.path.join(RESULTS_DIR, "c2_exfil_received")
os.makedirs(EXFIL_DIR, exist_ok=True)

# In-memory only — never a real control-plane setting. Lets
# run-impair-logging.sh demonstrate "disable logging then act" sequencing
# against this relay, with no effect on anything outside this process.
_mock_state = {"logging_enabled": True}


def log(line: str):
    stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    entry = f"[{stamp}] {line}"
    print(f"[control-api] {entry}", flush=True)
    with open(BEACON_LOG, "a") as f:
        f.write(entry + "\n")


class C2Handler(BaseHTTPRequestHandler):
    def _send_json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/beacon"):
            ua = self.headers.get("User-Agent", "-")
            log(f"beacon from {self.client_address[0]} ua='{ua}' path={self.path}")
            self._send_json({"status": "ok", "task": DECOY_TASK})
        elif self.path.startswith("/pool/getwork"):
            log(f"mining-pool getwork from {self.client_address[0]} path={self.path}")
            self._send_json({"job_id": "decoy-job-0001", "target": "00000000ffff0000000000000000000000000000000000000000000000000"})
        elif self.path.startswith("/logging/status"):
            self._send_json({"logging_enabled": _mock_state["logging_enabled"]})
        else:
            self.send_error(404, "Not Found")

    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(length) if length else b""
        if self.path.startswith("/task-result"):
            log(f"task-result from {self.client_address[0]}: {body[:200]!r}")
            self._send_json({"status": "received"})
        elif self.path.startswith("/exfil"):
            stamp = time.strftime("%Y%m%dT%H%M%S", time.gmtime())
            out = os.path.join(EXFIL_DIR, f"exfil_https_{stamp}.bin")
            with open(out, "wb") as f:
                f.write(body)
            log(f"exfil POST from {self.client_address[0]}: {len(body)} bytes -> {out}")
            self._send_json({"status": "received", "bytes": len(body)})
        elif self.path.startswith("/pool/submit"):
            log(f"mining-pool share submit from {self.client_address[0]}: {body[:200]!r}")
            self._send_json({"status": "accepted"})
        elif self.path.startswith("/cloud/identity"):
            auth = self.headers.get("Authorization", "-")
            log(f"cloud/K8s identity-exchange call from {self.client_address[0]} "
                f"Authorization='{auth[:80]}' body={body[:200]!r}")
            self._send_json({"status": "ok", "decoy_session_token": "DECOY-EXCHANGED-TOKEN-NOT-REAL"})
        elif self.path.startswith("/logging/disable"):
            _mock_state["logging_enabled"] = False
            log(f"!! logging/disable call from {self.client_address[0]} — "
                f"decoy audit-log state set to disabled (in-memory only, nothing real affected)")
            self._send_json({"status": "ok", "logging_enabled": False})
        else:
            self.send_error(404, "Not Found")

    def log_message(self, fmt, *args):
        pass  # structured logging handled above; suppress default access log noise


if __name__ == "__main__":
    log(f"control-api listening on {BIND_ADDR}:{BIND_PORT} (decoy tasking only)")
    server = ThreadingHTTPServer((BIND_ADDR, BIND_PORT), C2Handler)
    server.serve_forever()
