import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool, FRAMEWORK_VERSION


class AukDoc(VibeTool):
    def __init__(self):
        super().__init__("AukDoc", "Authentication Boundary Auditor")

    SENSITIVE_KEYWORDS = ["welcome", "dashboard", "vault", "admin", "profile", "token", "secret"]

    def run(self, url):
        self.banner()
        self.log(f"Deep auth audit on: {url}")

        # Step 1 — establish the baseline: what does an ordinary unauthenticated
        # request get? An "auth bypass" is only meaningful relative to this.
        base_status, base_content, _ = self.safe_request(url, headers={})
        base_content_l = (base_content or "").lower()
        if base_status == 0:
            self.log(f"Connection issue: {base_content}", "fail")
            return

        endpoint_protected = base_status in (401, 403)
        if endpoint_protected:
            self.log(f"Baseline: unauthenticated request blocked ({base_status}) — this IS an auth boundary. Testing bypasses.", "pass")
        elif base_status == 200:
            self.log(
                "Baseline: unauthenticated request returns 200 — this endpoint is PUBLIC. "
                "A 200 here is not a bypass. Point aukdoc at a protected endpoint "
                "(e.g. /api/admin) to test an actual boundary.",
                "info",
            )
        else:
            self.log(f"Baseline: unauthenticated request returns {base_status}. Testing header manipulation.", "info")

        # Header-manipulation cases (the baseline no-auth case is handled above).
        test_cases = {
            "Empty Bearer":           {"Authorization": "Bearer "},
            "Malformed Token":        {"Authorization": "Bearer not.a.real.token123"},
            "Basic Auth Swap":        {"Authorization": "Basic YWRtaW46YWRtaW4="},
            "SQLi in Header":         {"Authorization": "Bearer ' OR 1=1--"},
            "JWT None Algorithm":     {"Authorization": "Bearer eyJhbGciOiJub25lIiwidHlwZSI6IkpXVCJ9.eyJ1c2VyIjoiYWRtaW4ifQ."},
            "Admin Header Spoof":     {"X-Admin": "true"},
            "Localhost Bypass Spoof": {"X-Forwarded-For": "127.0.0.1"},
        }

        vulnerabilities = 0
        for case_name, headers in test_cases.items():
            self.log(f"Testing: {case_name}")
            status, content, _ = self.safe_request(url, headers=headers)
            content_l = (content or "").lower()

            if status != 200:
                if status in (401, 403):
                    self.log(f"Blocked ({status}) — properly rejected", "pass")
                elif status == 0:
                    self.log(f"Connection issue on {case_name}", "warn")
                else:
                    self.log(f"{case_name}: {status}", "info")
                continue

            if endpoint_protected:
                # Protected baseline + a 200 from a crafted header = real bypass.
                self.log(f"BOUNDARY BREACH — {case_name} turned a {base_status} into 200 access", "crit")
                vulnerabilities += 1
            else:
                # Public baseline: only a finding if the crafted header unlocks
                # NEW sensitive content the anonymous request didn't already get
                # (privilege escalation), not just the same public 200.
                new_hits = [kw for kw in self.SENSITIVE_KEYWORDS
                            if kw in content_l and kw not in base_content_l]
                if new_hits:
                    self.log(f"PRIVILEGE ESCALATION — {case_name} exposed new content ({', '.join(new_hits)}) "
                             f"not visible to an anonymous request", "crit")
                    vulnerabilities += 1
                else:
                    self.log(f"{case_name}: 200, same as the public baseline — not a bypass", "pass")

        self.log("=" * 32)
        if vulnerabilities > 0:
            self.log(f"{vulnerabilities} confirmed auth bypass / escalation vector(s)", "crit")
        elif endpoint_protected:
            self.log("Auth boundary held against all bypass attempts", "pass")
        else:
            self.log("No auth boundary here to break (public endpoint) — nothing to report", "pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AukDoc - Authentication Boundary Auditor")
    parser.add_argument("--url", required=True, help="Protected endpoint to test (e.g. http://localhost:3456/api/profile)")
    parser.add_argument('-v', '--version', action='version', version=f"AukDoc {FRAMEWORK_VERSION}")
    args = parser.parse_args()

    AukDoc().run(args.url)
