import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool


class VibeAPI(VibeTool):
    def __init__(self):
        super().__init__("Vibe API", "JSON Endpoint Stressor")

    def run(self, url):
        self.banner()
        self.log(f"Targeting: {url}")

        payloads = [
            "Admin'--",
            "<img src=x onerror=alert(1)>",
            "A" * 10000,
            {"nested": "object"},
            -1,
            None,
            "user@example.com' OR '1'='1"
        ]

        vulnerabilities = 0

        for payload in payloads:
            test_body = {
                "name": payload if isinstance(payload, str) else str(payload),
                "email": "test-vibe@vibe.hacking",
                "password": "VibePassword123!"
            }

            self.log(f"Sending: {repr(payload)[:40]}")
            status, body, _ = self.safe_request(url, method='POST', data=test_body)

            if status == 500:
                self.log("500 Internal Server Error — possible crash on this payload", "crit")
                vulnerabilities += 1
            elif status == 200:
                self.log(f"HTTP 200 — payload accepted/handled", "pass")
            elif status == 0:
                self.log(f"Connection issue: {body}", "fail")
            else:
                self.log(f"HTTP {status} — input blocked or rejected", "warn")

        self.log("=" * 32)
        if vulnerabilities > 0:
            self.log(f"{vulnerabilities} server-side flaw(s) detected", "crit")
        else:
            self.log("Backend appears resilient", "pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vibe API - JSON Endpoint Stressor")
    parser.add_argument("--url", required=True, help="Target JSON API endpoint (e.g. http://localhost:3456/api/auth/signup)")
    parser.add_argument('-v', '--version', action='version', version='Vibe API 1.0.0')
    args = parser.parse_args()

    VibeAPI().run(args.url)
