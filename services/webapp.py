#!/usr/bin/env python3
"""
Decoy web application ("Northline Portal") for the OWASP Top 10:2025 scenarios.

PURPOSE: generate real application-layer telemetry and artefacts (requests,
payloads, process spawns, file reads, outbound fetches) so WAF / API / CDR /
runtime sensors have something genuine to detect. Not a training target.

DELIBERATELY VULNERABLE. Every flaw below is intentional, runs as real code,
and is exercised with inert, DECOY-tagged payloads against decoy data only.
Runs only on the internal `northline-net` network (no published ports, no
egress). Never expose this to any other network.

One endpoint (or small group) per category. Every request that reaches a
vulnerable code path is recorded as ground truth in webapp_events.jsonl
(category, vuln, endpoint, client, detail) so analysts can line sensor
alerts up against what really happened. The app's own, deliberately weak
log is app.log (see A09).

  A01 Broken Access Control      /api/users/<id> (IDOR)  /admin/export  /files?name= (path traversal)
                                 /fetch?url= (SSRF; folded into A01 in the 2025 list)
  A02 Security Misconfiguration  /debug  /.env  /static/ (listing)  verbose errors, open CORS
  A03 Software Supply Chain      /plugins/install (fetch + load unsigned package)
  A04 Cryptographic Failures     /login (unsalted MD5, cleartext)  weak forgeable session token  /api/me
  A05 Injection                  /search?q= (SQLi)  /lookup?host= (command injection)  /comments (stored XSS)
  A06 Insecure Design            /api/coupon (no limit)  /api/order (negative qty)  /reset (guessable code)
  A07 Authentication Failures    /login (default creds, no lockout)  session fixation via ?sid=
  A08 Software/Data Integrity    /api/import (unsafe pickle)  /api/update (unsigned update accepted)
  A09 Logging & Alerting Failures  failures/admin access never logged; /comments author log-injection
  A10 Mishandling Exceptional Conditions  /api/divide (stack trace leak)  /api/authz (fails open)
"""
import base64
import hashlib
import json
import os
import pickle
import sqlite3
import subprocess
import sys
import threading
import time
import traceback
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse

BIND = os.environ.get("WEB_BIND", "0.0.0.0")
PORT = int(os.environ.get("WEB_PORT", "8080"))
RESULTS_DIR = os.environ.get("RESULTS_DIR", "/home/root/results")
DATA_DIR = os.environ.get("WEB_DATA_DIR", "/tmp/portal")
MAX_BODY = 1024 * 1024
NOBODY = 65534

os.makedirs(RESULTS_DIR, exist_ok=True)
os.makedirs(os.path.join(DATA_DIR, "files"), exist_ok=True)
os.makedirs(os.path.join(DATA_DIR, "static"), exist_ok=True)
os.makedirs(os.path.join(DATA_DIR, "plugins"), exist_ok=True)
EVENTS = os.path.join(RESULTS_DIR, "webapp_events.jsonl")
APPLOG = os.path.join(RESULTS_DIR, "webapp_app.log")  # the app's own (weak) log
PICKLE_MARKER = os.path.join(RESULTS_DIR, "webapp_pickle_marker.txt")
_lock = threading.Lock()

# ---- decoy data -------------------------------------------------------------
db = sqlite3.connect(":memory:", check_same_thread=False)
db.executescript("""
CREATE TABLE users (id INTEGER PRIMARY KEY, name TEXT, role TEXT, pw_md5 TEXT, email TEXT, note TEXT);
CREATE TABLE products (id INTEGER PRIMARY KEY, name TEXT, price REAL);
CREATE TABLE comments (id INTEGER PRIMARY KEY, author TEXT, body TEXT);
""")
md5 = lambda s: hashlib.md5(s.encode()).hexdigest()  # A04: unsalted, fast hash
db.executemany("INSERT INTO users VALUES (?,?,?,?,?,?)", [
    (1, "admin", "admin", md5("admin"), "admin@northline-decoy.example", "DECOY-ADMIN-NOTE"),
    (2, "alice", "user", md5("alice123"), "alice@northline-decoy.example", "DECOY-CUSTOMER-RECORD-2"),
    (3, "bob", "user", md5("bob456"), "bob@northline-decoy.example", "DECOY-CUSTOMER-RECORD-3"),
])
db.executemany("INSERT INTO products VALUES (?,?,?)", [(1, "decoy-widget", 9.99), (2, "decoy-gadget", 19.99)])
db.commit()
with open(os.path.join(DATA_DIR, "files", "welcome.txt"), "w") as f:
    f.write("DECOY welcome file\n")
with open(os.path.join(DATA_DIR, "static", "app.js"), "w") as f:
    f.write("// DECOY static asset\n")

coupons = {"used": 0}
resets = {}  # user -> 4-digit code
DECOY_ENV = ("DB_PASSWORD=DECOY-NOT-A-REAL-PASSWORD\nAWS_ACCESS_KEY_ID=AKIA_DECOY_DO_NOT_USE\n"
             "AWS_SECRET_ACCESS_KEY=DECOY+SECRET+NOT+A+REAL+KEY+00000000\nJWT_SECRET=DECOY-JWT-SECRET\n")


def now():
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def event(category, vuln, endpoint, client, **detail):
    rec = {"ts": now(), "category": category, "vuln": vuln, "endpoint": endpoint, "client": client, "detail": detail}
    with _lock, open(EVENTS, "a") as f:
        f.write(json.dumps(rec) + "\n")
    print(f"[webapp] {category} {vuln} {endpoint} from {client}", flush=True)


def applog(line):
    # A09: the app's own log. Intentionally records almost nothing useful.
    with _lock, open(APPLOG, "a") as f:
        f.write(f"{now()} {line}\n")


def make_token(user, role):
    # A04: forgeable, no signature. token = base64(user:role:md5(user))
    return base64.urlsafe_b64encode(f"{user}:{role}:{md5(user)}".encode()).decode()


def parse_token(tok):
    try:
        user, role, _ = base64.urlsafe_b64decode(tok.encode()).decode().split(":", 2)
        return user, role  # trusts the role claim; checksum never verified
    except Exception:
        return None


def _server_log(server, **fields):
    """Timestamped record of what this service actually received, so the lab can
    confirm each client-side action from the destination's point of view."""
    now = time.time()
    rec = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(now)) + ".%03dZ" % int((now % 1) * 1000), "epoch": round(now, 3), "server": server}
    rec.update(fields)
    try:
        with open(os.path.join(RESULTS_DIR, f"server_{server}.jsonl"), "a") as f:
            f.write(json.dumps(rec) + "\n")
    except OSError:
        pass


class H(BaseHTTPRequestHandler):
    server_version = "Northline-Portal/1.0 (python)"  # A02: verbose banner

    # ---- plumbing ----
    def _send(self, code, body, ctype="application/json", extra=None):
        data = body if isinstance(body, bytes) else (json.dumps(body) if not isinstance(body, str) else body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Access-Control-Allow-Origin", "*")  # A02: open CORS
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        try:
            n = int(self.headers.get("Content-Length", 0))
        except ValueError:
            n = -1
        if n < 0 or n > MAX_BODY:
            return None
        return self.rfile.read(n) if n else b""

    def _who(self):
        c = self.headers.get("Cookie", "")
        for part in c.split(";"):
            k, _, v = part.strip().partition("=")
            if k == "token":
                return parse_token(v)
        return None

    @property
    def cl(self):
        return self.client_address[0]

    def log_message(self, fmt, *a):
        pass

    def do_GET(self):
        self.route("GET")

    def do_POST(self):
        self.route("POST")

    def route(self, method):
        _server_log("web-portal", method=method, path=self.path, client=self.cl)
        u = urlparse(self.path)
        q = {k: v[0] for k, v in parse_qs(u.query).items()}
        p = u.path
        try:
            body = self._body() if method == "POST" else b""
            if body is None:
                return self._send(413, {"error": "payload too large"})
            self.dispatch(method, p, q, body)
        except Exception:
            # A10: unhandled exception leaks a stack trace to the client
            tb = traceback.format_exc()
            event("A10", "stack-trace-leak", p, self.cl, error=tb.strip().splitlines()[-1])
            self._send(500, {"error": "internal error", "trace": tb})

    # ---- routing ----
    def dispatch(self, m, p, q, body):
        if p == "/" or p == "/health":
            return self._send(200, {"app": "Northline Portal", "decoy": True})

        # ===== A01 Broken Access Control =====
        if p.startswith("/api/users/") and m == "GET":
            uid = p.rsplit("/", 1)[1]  # IDOR: no ownership/role check
            row = db.execute("SELECT id,name,role,email,note FROM users WHERE id=?", (uid,)).fetchone()
            event("A01", "idor", p, self.cl, requested=uid, found=bool(row))
            return self._send(200 if row else 404, dict(zip(("id", "name", "role", "email", "note"), row)) if row else {"error": "no such user"})
        if p == "/admin/export" and m == "GET":
            # no authentication or authorization at all (and, per A09, never logged)
            rows = db.execute("SELECT id,name,role,pw_md5,email FROM users").fetchall()
            event("A01", "missing-authz-admin", p, self.cl, rows=len(rows))
            return self._send(200, [dict(zip(("id", "name", "role", "pw_md5", "email"), r)) for r in rows])
        if p == "/files" and m == "GET":
            name = q.get("name", "welcome.txt")
            path = os.path.join(DATA_DIR, "files", name)  # path traversal: no normalisation
            event("A01", "path-traversal", p, self.cl, name=name)
            try:
                with open(path, "rb") as f:
                    return self._send(200, f.read(65536), "application/octet-stream")
            except OSError as e:
                return self._send(404, {"error": str(e)})
        if p == "/fetch" and m == "GET":
            url = q.get("url", "")
            event("A01", "ssrf", p, self.cl, url=url)
            if not url.startswith(("http://", "https://")):
                return self._send(400, {"error": "http(s) only"})
            try:
                with urllib.request.urlopen(url, timeout=3) as r:  # SSRF: fetches any internal URL
                    return self._send(200, r.read(65536), r.headers.get("Content-Type", "text/plain"))
            except Exception as e:
                return self._send(502, {"error": str(e)})

        # ===== A02 Security Misconfiguration =====
        if p == "/debug":
            event("A02", "debug-endpoint", p, self.cl)
            return self._send(200, {"env": dict(os.environ), "cwd": os.getcwd(), "pid": os.getpid(), "argv": sys.argv})
        if p == "/.env":
            event("A02", "exposed-dotenv", p, self.cl)
            return self._send(200, DECOY_ENV, "text/plain")
        if p.startswith("/static"):
            d = os.path.join(DATA_DIR, "static")
            event("A02", "directory-listing", p, self.cl)
            if p in ("/static", "/static/"):
                return self._send(200, "<h1>Index of /static/</h1>" + "".join(f"<a href='{n}'>{n}</a><br>" for n in os.listdir(d)), "text/html")
            try:
                with open(os.path.join(d, p[len("/static/"):]), "rb") as f:
                    return self._send(200, f.read(), "application/javascript")
            except OSError:
                return self._send(404, {"error": "not found"})

        # ===== A03 Software Supply Chain Failures =====
        if p == "/plugins/install" and m == "POST":
            src = json.loads(body or b"{}").get("url", "")
            event("A03", "unsigned-package-install", p, self.cl, url=src)
            # fetches a package from any URL, no signature / hash / allow-list, then loads it
            with urllib.request.urlopen(src, timeout=5) as r:
                code = r.read(65536)
            dest = os.path.join(DATA_DIR, "plugins", "plugin_" + md5(src)[:8] + ".py")
            with open(dest, "wb") as f:
                f.write(code)
            out = subprocess.run([sys.executable, dest], capture_output=True, text=True, timeout=5, user=NOBODY, group=NOBODY, extra_groups=[])
            return self._send(200, {"installed": dest, "loaded": True, "output": out.stdout.strip()})

        # ===== A04 / A07 login & session =====
        if p == "/login" and m == "POST":
            d = json.loads(body or b"{}")
            user, pw = str(d.get("username", "")), str(d.get("password", ""))
            row = db.execute("SELECT name,role FROM users WHERE name=? AND pw_md5=?", (user, md5(pw))).fetchone()
            # A07: no lockout, no rate limit, default credentials work.  A04: cleartext transport, MD5 compare.
            # A09: failed logins are NOT logged at all.
            event("A07", "login-attempt", p, self.cl, username=user[:64], success=bool(row))
            if row:
                applog(f"login ok user={user}")
                sid = q.get("sid") or make_token(*row)
                event("A04", "weak-session-token", p, self.cl, user=user)
                return self._send(200, {"ok": True, "role": row[1]}, extra={"Set-Cookie": f"token={sid}; Path=/"})
            return self._send(401, {"ok": False})
        if p == "/api/me" and m == "GET":
            who = self._who()
            event("A04", "forgeable-token-accepted", p, self.cl, claims=who)
            return self._send(200 if who else 401, {"user": who[0], "role": who[1]} if who else {"error": "no session"})

        # ===== A05 Injection =====
        if p == "/search" and m == "GET":
            term = q.get("q", "")
            sql = f"SELECT id,name,price FROM products WHERE name LIKE '%{term}%'"  # SQL injection
            event("A05", "sql-injection", p, self.cl, q=term)
            try:
                rows = db.execute(sql).fetchall()
                return self._send(200, rows)
            except sqlite3.Error as e:
                return self._send(500, {"error": str(e), "sql": sql})  # A02/A10: leaks the query
        if p == "/lookup" and m == "GET":
            host = q.get("host", "localhost")
            event("A05", "command-injection", p, self.cl, host=host)
            # command injection: user input interpolated into a shell, run as an unprivileged user
            out = subprocess.run(f"getent hosts {host}", shell=True, capture_output=True, text=True, timeout=5, user=NOBODY, group=NOBODY, extra_groups=[])
            return self._send(200, {"stdout": out.stdout, "stderr": out.stderr})
        if p == "/comments":
            if m == "POST":
                d = json.loads(body or b"{}")
                db.execute("INSERT INTO comments (author,body) VALUES (?,?)", (d.get("author", "anon"), d.get("body", "")))  # stored raw
                event("A05", "stored-xss", p, self.cl, body=str(d.get("body", ""))[:120])
                applog(f"comment posted by {d.get('author', 'anon')}")  # A09: unsanitised author -> log injection
                return self._send(201, {"ok": True})
            rows = db.execute("SELECT author,body FROM comments").fetchall()
            return self._send(200, "".join(f"<p><b>{a}</b>: {b}</p>" for a, b in rows), "text/html")  # unescaped output

        # ===== A06 Insecure Design =====
        if p == "/api/coupon" and m == "POST":
            coupons["used"] += 1  # no per-user limit, no rate limit, no single-use flag
            event("A06", "unlimited-coupon", p, self.cl, redeemed=coupons["used"])
            return self._send(200, {"discount": 10, "redeemed_total": coupons["used"]})
        if p == "/api/order" and m == "POST":
            d = json.loads(body or b"{}")
            qty, price = d.get("qty", 1), 9.99
            event("A06", "negative-quantity-order", p, self.cl, qty=qty)
            return self._send(200, {"total": round(qty * price, 2)})  # negative qty -> negative total
        if p == "/reset":
            user = q.get("user", "alice")
            if m == "POST":
                resets[user] = f"{(int(md5(user + str(time.time())[:7]), 16) % 10000):04d}"  # 4 digits
                event("A06", "weak-reset-code-issued", p, self.cl, user=user)
                return self._send(200, {"sent": True})
            guess = q.get("code", "")
            ok = resets.get(user) == guess  # unlimited guesses
            event("A06", "reset-code-guess", p, self.cl, user=user, ok=ok)
            return self._send(200 if ok else 403, {"reset": ok})

        # ===== A08 Software or Data Integrity Failures =====
        if p == "/api/import" and m == "POST":
            event("A08", "unsafe-deserialization", p, self.cl, bytes=len(body))
            obj = pickle.loads(body)  # unsafe: attacker-controlled pickle executes code
            return self._send(200, {"imported": repr(obj)[:200]})
        if p == "/api/update" and m == "POST":
            d = json.loads(body or b"{}")
            event("A08", "unsigned-update-accepted", p, self.cl, version=d.get("version"), sig=d.get("signature"))
            return self._send(200, {"applied": True, "version": d.get("version"), "signature_checked": False})

        # ===== A09 Logging & Alerting Failures =====
        if p == "/admin/audit-log":
            event("A09", "audit-log-is-empty", p, self.cl)
            try:
                with open(APPLOG) as f:
                    return self._send(200, f.read(), "text/plain")
            except OSError:
                return self._send(200, "", "text/plain")

        # ===== A10 Mishandling of Exceptional Conditions =====
        if p == "/api/divide" and m == "GET":
            a, b = q.get("a", "1"), q.get("b", "1")
            return self._send(200, {"result": float(a) / float(b)})  # unhandled ValueError/ZeroDivisionError -> trace
        if p == "/api/authz" and m == "GET":
            try:
                role = {"admin": "admin", "alice": "user"}[q["user"]]  # KeyError for unknown user
                allowed = role == "admin"
            except Exception:
                allowed = True  # fails OPEN on error
                event("A10", "authz-fails-open", p, self.cl, user=q.get("user"))
            return self._send(200, {"allowed": allowed})

        return self._send(404, {"error": "not found"})


if __name__ == "__main__":
    print(f"[webapp] Northline Portal (DECOY, deliberately vulnerable) on {BIND}:{PORT}", flush=True)
    ThreadingHTTPServer((BIND, PORT), H).serve_forever()
