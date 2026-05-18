import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool


class AukDoc(VibeTool):
    def __init__(self):
        super().__init__("AukDoc", "Authentication Boundary Auditor")

    def run(self, url):
        self.banner()
        self.log(f"Deep auth audit on: {url}")

        test_cases = {
            "No Auth Header":           {},
            "Empty Bearer":             {"Authorization": "Bearer "},
            "Malformed Token":          {"Authorization": "Bearer not.a.real.token123"},
            "Basic Auth Swap":          {"Authorization": "Basic YWRtaW46YWRtaW4="},
            "SQLi in Header":           {"Authorization": "Bearer ' OR 1=1--"},
            "JWT None Algorithm":       {"Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwZSI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ."},
            "Admin Header Spoof":       {"X-Admin": "true"},
            "Localhost Bypass Spoof":   {"X-Forwarded-For": "127.0.0.1"},
        }

        vulnerabilities = 0

        for case_name, headers in test_cases.items():
            self.log(f"Testing: {case_name}")
            status, content, _ = self.safe_request(url, headers=headers)

            if status == 200:
                sensitive_keywords = ["welcome", "dashboard", "vault", "admin", "profile", "token"]
                if any(kw in content.lower() for kw in sensitive_keywords):
                    self.log(f"BOUNDARY BREACH — {case_name} granted access to sensitive content", "crit")
                    vulnerabilities += 1
                else:
                    self.log(f"Suspicious 200 on {case_name} — no sensitive keywords but check manually", "warn")
                    vulnerabilities += 1
            elif status in (401, 403):
                self.log(f"Blocked ({status}) — properly protected", "pass")
            elif status == 0:
                self.log(f"Connection issue: {content}", "fail")
            else:
                self.log(f"Unexpected response ({status})", "warn")

        self.log("=" * 32)
        if vulnerabilities > 0:
            self.log(f"{vulnerabilities} potential bypass vector(s) found", "crit")
        else:
            self.log("Auth boundaries are secure", "pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AukDoc - Authentication Boundary Auditor")
    parser.add_argument("--url", required=True, help="Protected endpoint to test (e.g. http://localhost:3456/api/profile)")
    parser.add_argument('-v', '--version', action='version', version='AukDoc 1.0.0')
    args = parser.parse_args()

    AukDoc().run(args.url)
