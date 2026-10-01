import sys
import os
import argparse
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool


class FuzzVibe(VibeTool):
    def __init__(self):
        super().__init__("Fuzz Vibe", "URL Parameter Fuzzer")

    def run(self, url, param="q"):
        self.banner()
        self.log(f"Fuzzing: {url} (param='{param}')")

        payloads = [
            ("buffer_overflow_probe", "A" * 5000),
            ("null_byte", "\x00"),
            ("unicode_edge", "ሴ噸"),
            ("sqli_probe", "';--"),
            ("ssti_canary", "{{9731*9817}}"),
            ("nan_coerce", "NaN"),
            ("infinity_coerce", "Infinity"),
            ("negative_boundary", "-1"),
            ("json_structure", "[], {}"),
            ("xss_canary", "<script>vibe_fuzz_canary()</script>"),
        ]

        crashes = 0
        confirmed_sinks = 0

        for label, payload in payloads:
            sep = "&" if "?" in url else "?"
            query = urllib.parse.urlencode({param: payload})
            target = f"{url}{sep}{query}"
            self.log(f"Sending [{label}]: {repr(payload)[:40]}")

            status, body, _ = self.safe_request(target, method='GET')
            body = body or ""

            if status == 500:
                self.log(f"Server crash (500) on [{label}] — unhandled exception", "crit")
                crashes += 1
            elif status == 200:
                if label == "ssti_canary" and "95529227" in body:
                    self.log("SSTI canary evaluated (9731*9817 == 95529227) — template injection confirmed", "crit")
                    confirmed_sinks += 1
                elif label == "xss_canary" and payload in body:
                    self.log("XSS payload reflected without HTML encoding", "crit")
                    confirmed_sinks += 1
                elif payload in body and len(payload) > 3:
                    self.log(f"Payload [{label}] reflected in body", "warn")
                else:
                    self.log("Payload handled safely (200 OK)", "pass")
            elif status == 0:
                self.log(f"Connection issue: {body}", "fail")
            else:
                self.log(f"Blocked or rejected ({status})", "pass")

        self.log("=" * 32)
        if crashes > 0 or confirmed_sinks > 0:
            self.log(
                f"{crashes} crash(es) and {confirmed_sinks} injection sink(s) detected — check backend handling",
                "crit",
            )
        else:
            self.log("Input handling appears stable", "pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Fuzz Vibe - URL Parameter Fuzzer")
    parser.add_argument("--url", required=True, help="Target endpoint (e.g. http://localhost:3456/search)")
    parser.add_argument("--param", default="q", help="Query parameter name to fuzz (default: q)")
    parser.add_argument('-v', '--version', action='version', version='Fuzz Vibe 1.0.0')
    args = parser.parse_args()

    FuzzVibe().run(args.url, param=args.param)
