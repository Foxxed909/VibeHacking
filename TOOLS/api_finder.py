#!/usr/bin/env python3
"""Hidden endpoint discovery — guesses paths, skips catch-all baseline responses."""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool, DEFAULT_TARGET_BASE

CANDIDATES = [
    "/api", "/api/v1", "/api/v2", "/graphql", "/admin", "/debug",
    "/health", "/status", "/metrics", "/.env", "/config", "/swagger",
    "/openapi.json", "/api/docs", "/internal", "/private",
]

class APIFinder(VibeTool):
    def __init__(self):
        super().__init__("api_finder", "Hidden endpoint discovery")

    def run(self, base_url):
        self.banner()
        base = base_url.rstrip("/")
        baseline = self.baseline_probe(base)
        found = []
        for path in CANDIDATES:
            url = base + path
            status, body, headers = self.safe_request(url)
            body = body or ""
            if status == 0:
                continue
            if baseline.get("catch_all") and self.matches_baseline(body, baseline):
                continue  # identical to not-found → skip
            if status in (200, 201, 301, 302, 401, 403):
                found.append({"path": path, "status": status, "len": len(body)})
                self.log(f"Interesting: {path} → {status}", "info")
        if not found:
            self.log("No distinct endpoints beyond baseline", "info")
        return found

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--url", default=DEFAULT_TARGET_BASE)
    args = p.parse_args()
    APIFinder().run(args.url)
