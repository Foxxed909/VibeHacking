import sys
import os
import argparse
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool


class AuthDoc(VibeTool):
    def __init__(self):
        super().__init__("AuthDoc", "WAF & Input Filter Auditor")

    def run(self, url, payload_type=None):
        self.banner()
        self.log(f"Analyzing input filters on: {url}")

        payloads = {
            "SQLi":           {"q": "1' OR '1'='1"},
            "XSS":            {"q": "<script>alert(1)</script>"},
            "Path Traversal": {"file": "../../../etc/passwd"},
        }

        if payload_type and payload_type in payloads:
            payloads = {payload_type: payloads[payload_type]}

        blocked = 0
        exposed = 0

        for name, data in payloads.items():
            self.log(f"Firing: {name}")
            query = urllib.parse.urlencode(data)
            full_url = f"{url.rstrip('/')}?{query}"

            status, content, _ = self.safe_request(full_url, method='GET')

            if status == 200:
                self.log(f"{name} payload accepted — filter is missing (200 OK)", "crit")
                exposed += 1
            elif status == 500:
                self.log(f"{name} payload crashed the server (500) — critical injection point", "crit")
                exposed += 1
            elif status in (403, 406):
                self.log(f"{name} blocked ({status}) — WAF or filter active", "pass")
                blocked += 1
            elif status == 429:
                self.log(f"{name} rate-limited ({status}) — defensive layer active", "pass")
                blocked += 1
            elif status == 404:
                self.log(f"{name} — endpoint not found ({status})", "warn")
            elif status == 0:
                self.log(f"Connection issue: {content}", "fail")
            else:
                self.log(f"{name} — unexpected response ({status})", "warn")

        self.log("=" * 32)
        if exposed > 0:
            self.log(f"{exposed} unfiltered payload(s) — input validation is missing", "crit")
        elif blocked > 0:
            self.log(f"All tested payloads blocked — filters appear active", "pass")
        else:
            self.log("Inconclusive — no clear block or pass results", "warn")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AuthDoc - WAF & Input Filter Auditor")
    parser.add_argument("--url", required=True, help="Target endpoint (e.g. http://localhost:3456/search)")
    parser.add_argument("--type", choices=["SQLi", "XSS", "Path Traversal"], help="Run a specific payload type only")
    parser.add_argument('-v', '--version', action='version', version='AuthDoc 1.0.0')
    args = parser.parse_args()

    AuthDoc().run(args.url, args.type)
