#!/usr/bin/env python3
"""IDOR / object-ID exposure scanner with baseline control."""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool, DEFAULT_TARGET_BASE

class Axios(VibeTool):
    def __init__(self):
        super().__init__("axios", "IDOR / object-ID exposure scanner")

    def run(self, base_url):
        self.banner()
        base = base_url.rstrip("/")
        baseline = self.baseline_probe(base)
        # Probe common ID patterns; only flag when response differs from baseline
        findings = []
        for i in range(1, 6):
            for path in [f"/api/user/{i}", f"/api/users/{i}", f"/user/{i}", f"/api/profile/{i}"]:
                url = base + path
                status, body, _ = self.safe_request(url)
                body = body or ""
                if status in (200, 201) and not self.matches_baseline(body, baseline):
                    if baseline.get("catch_all") and status == 200:
                        continue
                    findings.append({"path": path, "status": status})
                    self.log(f"Possible IDOR surface: {path} → {status}", "warn")
        if not findings:
            self.log("No distinct IDOR-like responses beyond baseline", "info")
        return findings

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--url", default=DEFAULT_TARGET_BASE)
    args = p.parse_args()
    Axios().run(args.url)
