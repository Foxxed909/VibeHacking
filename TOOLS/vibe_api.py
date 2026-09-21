import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool, FRAMEWORK_VERSION


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

        # Control: a benign payload first. If the endpoint 500s on everything,
        # a 500 on a crafted payload is not evidence of a crash bug.
        control_status, _, _ = self.safe_request(url, method='POST', data={
            "name": "vibe-control", "email": "control@vibe.hacking",
            "password": "VibePassword123!"})
        if control_status == 500:
            self.log("Control payload also returned 500 — the endpoint is unstable on "
                     "all input; 500s below are not payload-specific.", "warn")

        for payload in payloads:
            test_body = {
                "name": payload if isinstance(payload, str) else str(payload),
                "email": "test-vibe@vibe.hacking",
                "password": "VibePassword123!"
            }

            self.log(f"Sending: {repr(payload)[:40]}")
            status, body, _ = self.safe_request(url, method='POST', data=test_body)

            if status == 500 and control_status != 500:
                self.log("500 Internal Server Error — possible crash on this payload", "crit")
                vulnerabilities += 1
            elif status == 500:
                self.log("500 on this payload, but the control request also 500s", "warn")
            elif status == 200:
                self.log("HTTP 200 — payload accepted/handled", "pass")
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
    parser.add_argument('-v', '--version', action='version', version=f"Vibe API {FRAMEWORK_VERSION}")
    args = parser.parse_args()

    VibeAPI().run(args.url)
