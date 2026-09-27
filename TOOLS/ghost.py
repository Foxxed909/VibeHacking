#!/usr/bin/env python3
"""Sensitive asset finder — requires config/JS-shaped content, not just a 200."""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool, DEFAULT_TARGET_BASE

SENSITIVE = [
    "/.env", "/.env.local", "/.git/config", "/backup.zip", "/db.sql",
    "/config.json", "/secrets.yml", "/wp-config.php", "/.htaccess",
    "/package.json", "/composer.json", "/robots.txt", "/sitemap.xml",
]

class Ghost(VibeTool):
    def __init__(self):
        super().__init__("ghost", "Sensitive asset finder")

    def run(self, base_url):
        self.banner()
        base = base_url.rstrip("/")
        baseline = self.baseline_probe(base)
        found = []
        for path in SENSITIVE:
            url = base + path
            status, body, headers = self.safe_request(url)
            body = body or ""
            if status != 200:
                continue
            if self.matches_baseline(body, baseline):
                continue
            # Require some content shape that looks like a real asset
            interesting = any(x in body.lower() for x in ["=", "{", "password", "secret", "key", "database", "user"])
            if interesting or path.endswith((".json", ".yml", ".env", ".sql", ".php")):
                found.append({"path": path, "status": status, "len": len(body)})
                self.log(f"Possible sensitive asset: {path}", "warn")
        if not found:
            self.log("No distinct sensitive assets beyond baseline", "info")
        return found

if __name__ == "__main__":
    p = argparse.ArgumentParser()
    p.add_argument("--url", default=DEFAULT_TARGET_BASE)
    args = p.parse_args()
    Ghost().run(args.url)
