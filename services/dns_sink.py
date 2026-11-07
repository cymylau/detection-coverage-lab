#!/usr/bin/env python3
"""
DNS sink for the detection-coverage environment.

A minimal UDP DNS server that answers every A query with a fixed decoy IP and
LOGS the full queried name. It stands in for the attacker-controlled
nameserver in a DNS-exfiltration scenario (MITRE ATT&CK T1048.003 /
T1071.004) so the emulation can "exfil" base64 chunks as subdomain labels
without any data ever leaving the environment's network.

It reassembles chunks per session and writes the decoded payload to the
results directory, purely so an analyst can confirm what was staged.
"""
import base64
import os
import re
import socket
import struct

BIND_ADDR = os.environ.get("DNS_BIND", "0.0.0.0")
BIND_PORT = int(os.environ.get("DNS_PORT", "53"))
EXFIL_DOMAIN = os.environ.get("EXFIL_DOMAIN", "exfil.internal").lower().strip(".")
RESULTS_DIR = os.environ.get("RESULTS_DIR", "/home/root/results")
ANSWER_IP = os.environ.get("ANSWER_IP", "10.13.37.53")

# Limits: this is fed by an untrusted network, so bound everything.
MAX_SESSIONS = 256         # distinct sessions kept in memory
MAX_CHUNKS = 512           # chunks per session
MAX_DECODED = 64 * 1024    # bytes of decoded output per session
SESSION_RE = re.compile(r"^[0-9]{1,12}$")   # session id becomes part of a filename
SEQ_RE = re.compile(r"^[0-9]{1,6}$")

sessions = {}  # session_id -> {seq: chunk}
_written = {}  # session_id -> last bytes written (skip identical rewrites)


def parse_qname(data: bytes):
    labels, i = [], 12  # skip 12-byte header
    while True:
        length = data[i]
        if length == 0:
            i += 1
            break
        labels.append(data[i + 1:i + 1 + length].decode("ascii", "replace"))
        i += 1 + length
    return labels, i


def build_response(data: bytes, qend: int):
    tid = data[:2]
    header = tid + struct.pack(">HHHHH", 0x8180, 1, 1, 0, 0)
    question = data[12:qend + 4]  # qname + qtype + qclass
    answer = b"\xc0\x0c" + struct.pack(">HHIH", 1, 1, 0, 4) + socket.inet_aton(ANSWER_IP)
    return header + question + answer


def try_decode(session: str):
    parts = sessions.get(session, {})
    try:
        ordered = "".join(parts[str(k)] for k in sorted(int(x) for x in parts))
    except (KeyError, ValueError):
        return
    try:
        decoded = base64.urlsafe_b64decode(ordered + "=" * (-len(ordered) % 4))
    except Exception:
        return
    os.makedirs(RESULTS_DIR, exist_ok=True)
    if len(decoded) > MAX_DECODED or _written.get(session) == decoded:
        return
    _written[session] = decoded
    out = os.path.join(RESULTS_DIR, f"exfil_{session}.decoded")
    with open(out, "wb") as f:
        f.write(decoded)
    print(f"[dns-sink] reassembled session={session} -> {out} ({len(decoded)} bytes)", flush=True)


def record(labels):
    # Expect: <seq>.<session>.<b64chunk...>.exfil.internal
    dom_parts = EXFIL_DOMAIN.split(".")
    if len(labels) < len(dom_parts) + 3:
        return
    if [l.lower() for l in labels[-len(dom_parts):]] != dom_parts:
        return
    body = labels[:-len(dom_parts)]
    seq, session = body[0], body[1]
    if not SEQ_RE.match(seq) or not SESSION_RE.match(session):
        return  # not a well-formed exfil query; still answered, just not recorded
    if session not in sessions and len(sessions) >= MAX_SESSIONS:
        return
    if len(sessions.get(session, {})) >= MAX_CHUNKS and seq not in sessions[session]:
        return
    chunk = "".join(body[2:])
    sessions.setdefault(session, {})[seq] = chunk
    print(f"[dns-sink] exfil session={session} seq={seq} chunk={chunk[:40]}...", flush=True)
    try_decode(session)


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.bind((BIND_ADDR, BIND_PORT))
    print(f"[dns-sink] listening on {BIND_ADDR}:{BIND_PORT} for *.{EXFIL_DOMAIN}", flush=True)
    while True:
        data, addr = sock.recvfrom(4096)
        try:
            labels, qend = parse_qname(data)
            qname = ".".join(labels)
            print(f"[dns-sink] query from {addr[0]} name={qname}", flush=True)
            record(labels)
            sock.sendto(build_response(data, qend), addr)
        except Exception as e:  # keep the sink alive on malformed packets
            print(f"[dns-sink] error: {e}", flush=True)


if __name__ == "__main__":
    main()
