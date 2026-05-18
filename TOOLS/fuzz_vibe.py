import sys
import os
import argparse
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool


class FuzzVibe(VibeTool):
    def __init__(self):
        super().__init__("Fuzz Vibe", "URL Parameter Fuzzer")

    def run(self, url):
        self.banner()
        self.log(f"Fuzzing: {url}")

        payloads = [
            "A" * 5000,
            "\x00",
            "ሴ噸",
            "';--",
            "{{7*7}}",
            "NaN",
            "Infinity",
            "-1",
            "[], {}",
            "<script>alert(1)</script>",
        ]

        crashes = 0

        for payload in payloads:
            query = urllib.parse.urlencode({"q": payload})
            target = f"{url.rstrip('/')}?{query}"
            self.log(f"Sending: {repr(payload)[:40]}")

            status, body, _ = self.safe_request(target, method='GET')

            if status == 500:
                self.log("Server crash (500) — unhandled exception on this payload", "crit")
                crashes += 1
            elif status == 200:
                if payload in body:
                    self.log("Payload reflected without sanitization", "warn")
                else:
                    self.log("Payload handled (200 OK)", "pass")
            elif status == 0:
                self.log(f"Connection issue: {body}", "fail")
            else:
                self.log(f"Blocked or rejected ({status})", "pass")

        self.log("=" * 32)
        if crashes > 0:
            self.log(f"{crashes} server crash(es) detected — check backend error handling", "crit")
        else:
            self.log("Input handling appears stable", "pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fuzz Vibe - URL Parameter Fuzzer")
    parser.add_argument("--url", required=True, help="Target endpoint (e.g. http://localhost:3456/search)")
    parser.add_argument('-v', '--version', action='version', version='Fuzz Vibe 1.0.0')
    args = parser.parse_args()

    FuzzVibe().run(args.url)
