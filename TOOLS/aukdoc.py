#!/usr/bin/env python3
"""Authentication boundary auditor — baselines unauthenticated response."""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool, DEFAULT_TARGET_BASE

class Aukdoc(VibeTool):
    def __init__(self):
        super().__init__("aukdoc", "Authentication boundary auditor")

    def run(self, base_url):
        self.banner()
        base = base_url.rstrip("/")
        # Baseline: unauthenticated root / random path
        baseline = self.baseline_probe(base)
        candidates = ["/", "/home", "/app", "/dashboard", "/api", "/api/v1"]
        findings = []
        for path in candidates:
            url = base.rstrip("/") + path
            status, body, _ = self.safe_request(url)
            body = body or ""
            if status == 200:
                if baseline.get("catch_all") or self.matches_baseline(body, baseline):
                    self.log(f"{path} looks public / catch-all (not a boundary breach)", "info")
                    continue
                # Only flag if it looks like an authenticated surface that is open
                if any(k in body.lower() for k in ["logout", "profile", "settings", "admin", "welcome back"]):
                    findings.append({"path": path, "status": status})
                    self.log(f"Possible open authenticated surface: {path}", "warn")
        if not findings:
            self.log("No unexpected open authenticated surfaces", "info")
        return findings

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--url", default=DEFAULT_TARGET_BASE)
    args = p.parse_args()
    Aukdoc().run(args.url)
