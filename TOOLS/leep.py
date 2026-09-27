#!/usr/bin/env python3
"""Logic-flow / auth-bypass auditor with baseline control."""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool, DEFAULT_TARGET_BASE

class Leep(VibeTool):
    def __init__(self):
        super().__init__("leep", "Logic-flow / auth-bypass auditor")

    def run(self, base_url):
        self.banner()
        base = base_url.rstrip("/")
        baseline = self.baseline_probe(base)
        candidates = ["/admin", "/dashboard", "/api/admin", "/settings", "/account", "/api/me"]
        findings = []
        for path in candidates:
            url = base + path
            status, body, _ = self.safe_request(url)
            body = body or ""
            if status == 200 and not self.matches_baseline(body, baseline):
                if baseline.get("catch_all"):
                    continue
                findings.append({"path": path, "status": status})
                self.log(f"Unauthenticated access candidate: {path}", "warn")
        if not findings:
            self.log("No obvious unauthenticated sensitive surfaces beyond baseline", "info")
        return findings

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--url", default=DEFAULT_TARGET_BASE)
    args = p.parse_args()
    Leep().run(args.url)
