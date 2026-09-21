#!/usr/bin/env python3
"""
smuggler.py — HTTP request smuggling / desync detection (INTERNAL edition).

Detects front-end/back-end disagreement over request boundaries (CL.TE and
TE.CL) using the *timing* technique only: a crafted request makes the
back-end wait for bytes that never come, so a desynced pair hangs while a
safe stack answers immediately. It never sends a socket-poisoning payload
that could affect another user's request — this is a detector, not a live
exploit that pollutes a shared queue.

To beat header normalisation it tries a battery of Transfer-Encoding
obfuscations (space/tab/newline tricks, duplicate CL) that real front-ends
mishandle. A finding is only reported when the delayed response is both far
slower than the endpoint's own baseline *and* over an absolute floor, then
re-tested to rule out jitter.

    python TOOLS/smuggler.py --url http://127.0.0.1:8080/
    python TOOLS/smuggler.py --url https://your-owned-host.example/ --threshold 5
"""
import argparse
import os
import socket
import ssl
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool, FRAMEWORK_VERSION

# Transfer-Encoding header obfuscations that front-ends commonly fail to parse
# the same way the back-end does. The value is the raw header line bytes.
TE_MUTATIONS = [
    ("plain", "Transfer-Encoding: chunked"),
    ("space-before-colon", "Transfer-Encoding : chunked"),
    ("tab-prefix", "Transfer-Encoding:\tchunked"),
    ("leading-space-value", "Transfer-Encoding:  chunked"),
    ("vertical-tab", "Transfer-Encoding: \x0bchunked"),
    ("duplicate", "Transfer-Encoding: cow\r\nTransfer-Encoding: chunked"),
    ("x-prefix", "X: X\r\nTransfer-Encoding: chunked"),
    ("nul-suffix", "Transfer-Encoding: chunked\x00"),
]


class Smuggler(VibeTool):
    def __init__(self, url, threshold):
        super().__init__("Smuggler", "HTTP Request Smuggling / Desync Detection")
        self.url = url
        self.threshold = threshold
        p = urllib.parse.urlparse(url)
        self.host = p.hostname
        self.tls = p.scheme == "https"
        self.port = p.port or (443 if self.tls else 80)
        self.path = p.path or "/"
        self.findings = 0

    def _send_raw(self, raw, read_timeout):
        """Send raw request bytes; return seconds until first byte (or timeout)."""
        start = time.time()
        sock = socket.create_connection((self.host, self.port), timeout=read_timeout)
        try:
            if self.tls:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                sock = ctx.wrap_socket(sock, server_hostname=self.host)
            sock.sendall(raw.encode("latin-1"))
            sock.settimeout(read_timeout)
            try:
                data = sock.recv(64)
                if not data:
                    return time.time() - start, "closed"
                return time.time() - start, "ok"
            except socket.timeout:
                return read_timeout, "timeout"
        finally:
            try:
                sock.close()
            except OSError:
                pass

    def _baseline(self):
        req = (f"POST {self.path} HTTP/1.1\r\nHost: {self.host}\r\n"
               f"Content-Length: 0\r\nConnection: close\r\n\r\n")
        samples = []
        for _ in range(3):
            dt, _st = self._send_raw(req, read_timeout=10)
            samples.append(dt)
        return min(samples)

    def _clte_payload(self, te_line):
        body = "1\r\nA\r\nX"  # chunked reader stalls waiting for the next chunk
        return (f"POST {self.path} HTTP/1.1\r\nHost: {self.host}\r\n"
                f"{te_line}\r\nContent-Length: 4\r\nConnection: close\r\n\r\n{body}")

    def _tecl_payload(self, te_line):
        body = "0\r\n\r\nX"  # CL reader stalls waiting for more body bytes
        return (f"POST {self.path} HTTP/1.1\r\nHost: {self.host}\r\n"
                f"{te_line}\r\nContent-Length: 6\r\nConnection: close\r\n\r\n{body}")

    def _delayed(self, baseline, dt, status):
        floor = max(self.threshold, baseline * 3 + 1)
        return status == "timeout" or dt >= floor

    def _probe(self, label, payload, baseline):
        dt, status = self._send_raw(payload, read_timeout=max(10, self.threshold + 2))
        if not self._delayed(baseline, dt, status):
            return False
        # Re-test to reject jitter — the delay must reproduce.
        dt2, status2 = self._send_raw(payload, read_timeout=max(10, self.threshold + 2))
        if not self._delayed(baseline, dt2, status2):
            self.log(f"  {label}: first probe slow ({dt:.1f}s) but did not reproduce "
                     f"({dt2:.1f}s) — treating as jitter, not a finding.", "info")
            return False
        self.log(f"DESYNC SIGNAL — {label}: back-end hung ({dt:.1f}s / {dt2:.1f}s) vs "
                 f"baseline {baseline:.2f}s", "hack")
        self.findings += 1
        return True

    def run(self):
        self.banner()
        self.log(f"Target: {self.url}  (host={self.host} port={self.port} tls={self.tls})")
        try:
            baseline = self._baseline()
        except OSError as e:
            self.log(f"Cannot reach target for baseline: {e}", "fail")
            return 1
        self.log(f"Baseline response time: {baseline:.2f}s")
        self.log("Timing-based detection only — no shared-queue poisoning is sent.")

        for label, te in TE_MUTATIONS:
            self._probe(f"CL.TE [{label}]", self._clte_payload(te), baseline)
            self._probe(f"TE.CL [{label}]", self._tecl_payload(te), baseline)

        self.log("=" * 40)
        if self.findings:
            self.log(f"SMUGGLING SWEEP COMPLETE — {self.findings} desync signal(s). "
                     "Confirm manually before weaponising; timing can be noisy over the internet.", "hack")
        else:
            self.log("No desync detected — front-end and back-end agree on request "
                     "boundaries (or a single server is answering).", "pass")
        return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="Smuggler - HTTP request smuggling / desync detection")
    p.add_argument("--url", required=True, help="Target base URL (front-end / proxy)")
    p.add_argument("--threshold", type=float, default=5.0,
                   help="Absolute delay floor in seconds to call a hang (default 5)")
    p.add_argument("-v", "--version", action="version", version=f"Smuggler {FRAMEWORK_VERSION}")
    args = p.parse_args(argv)
    return Smuggler(args.url, args.threshold).run()


if __name__ == "__main__":
    raise SystemExit(main())
