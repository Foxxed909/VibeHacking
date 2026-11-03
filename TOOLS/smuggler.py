#!/usr/bin/env python3
"""smuggler.py — HTTP request smuggling / desync detection (INTERNAL).

Timing-only technique: a crafted request makes the back-end wait for bytes
that never come, so a desynced stack hangs while a safe stack answers fast.
Never sends a socket-poisoning payload that could affect other users.
Tries all common TE header obfuscations (space, tab, newline, duplicate, NUL).

    python TOOLS/smuggler.py --url http://127.0.0.1:8080/
    python TOOLS/smuggler.py --url https://your-host.example/ --threshold 5
"""
import argparse
import os
import socket
import ssl
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool

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
                return time.time() - start, ("closed" if not data else "ok")
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
        return min(self._send_raw(req, 10)[0] for _ in range(3))

    def _clte(self, te): return (
        f"POST {self.path} HTTP/1.1\r\nHost: {self.host}\r\n{te}\r\n"
        f"Content-Length: 4\r\nConnection: close\r\n\r\n1\r\nA\r\nX")

    def _tecl(self, te): return (
        f"POST {self.path} HTTP/1.1\r\nHost: {self.host}\r\n{te}\r\n"
        f"Content-Length: 6\r\nConnection: close\r\n\r\n0\r\n\r\nX")

    def _delayed(self, baseline, dt, status):
        return status == "timeout" or dt >= max(self.threshold, baseline * 3 + 1)

    def _probe(self, label, payload, baseline):
        to = max(10, self.threshold + 2)
        dt, st = self._send_raw(payload, to)
        if not self._delayed(baseline, dt, st):
            return False
        dt2, st2 = self._send_raw(payload, to)
        if not self._delayed(baseline, dt2, st2):
            self.log(f"  {label}: first probe slow ({dt:.1f}s) but did not reproduce "
                     f"({dt2:.1f}s) — jitter, not a finding.", "info")
            return False
        self.log(f"DESYNC SIGNAL — {label}: back-end hung ({dt:.1f}s / {dt2:.1f}s) vs "
                 f"baseline {baseline:.2f}s", "hack")
        self.findings += 1
        return True

    def run(self):
        self.banner()
        self.log(f"Target: {self.url}  host={self.host} port={self.port} tls={self.tls}")
        try:
            baseline = self._baseline()
        except OSError as e:
            self.log(f"Cannot reach target for baseline: {e}", "fail")
            return 1
        self.log(f"Baseline: {baseline:.2f}s. Timing-only — no queue poisoning sent.")
        for label, te in TE_MUTATIONS:
            self._probe(f"CL.TE [{label}]", self._clte(te), baseline)
            self._probe(f"TE.CL [{label}]", self._tecl(te), baseline)
        self.log("=" * 40)
        if self.findings:
            self.log(f"SMUGGLING SWEEP COMPLETE — {self.findings} desync signal(s). "
                     "Confirm manually; timing can be noisy over internet.", "hack")
        else:
            self.log("No desync detected.", "pass")
        return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="Smuggler - HTTP request smuggling detector")
    p.add_argument("--url", required=True)
    p.add_argument("--threshold", type=float, default=5.0)
    p.add_argument("-v", "--version", action="version", version="Smuggler 1.0.0")
    args = p.parse_args(argv)
    return Smuggler(args.url, args.threshold).run()


if __name__ == "__main__":
    raise SystemExit(main())
