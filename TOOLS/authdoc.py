#!/usr/bin/env python3
"""WAF & input-filter auditor with baseline control."""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool, DEFAULT_TARGET_BASE

class Authdoc(VibeTool):
    def __init__(self):
        super().__init__("authdoc", "WAF & input-filter auditor")

    def run(self, base_url):
        self.banner()
        base = base_url.rstrip("/")
        baseline = self.baseline_probe(base)
        probes = ["'", "\"", "<script>", "../", "{{7*7}}", "${7*7}"]
        findings = []
        for probe in probes:
            url = base + "/?q=" + probe
            status, body, _ = self.safe_request(url)
            body = body or ""
            if status in (200, 500) and not self.matches_baseline(body, baseline):
                findings.append({"probe": probe, "status": status})
                self.log(f"Interesting reaction to probe {probe!r} → {status}", "info")
        if not findings:
            self.log("No distinct reactions beyond baseline", "info")
        return findings

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--url", default=DEFAULT_TARGET_BASE)
    args = p.parse_args()
    Authdoc().run(args.url)
