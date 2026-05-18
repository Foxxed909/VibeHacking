import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool


class VibeHeaders(VibeTool):
    def __init__(self):
        super().__init__("Header Auditor", "HTTP Security Policy Auditor")

    def run(self, url):
        self.banner()
        self.log(f"Starting audit on: {url}")

        security_headers = {
            "Content-Security-Policy":   "Mitigates XSS and data injection",
            "X-Frame-Options":           "Prevents Clickjacking",
            "X-Content-Type-Options":    "Blocks MIME-sniffing",
            "Strict-Transport-Security": "Enforces HTTPS (HSTS)",
            "Referrer-Policy":           "Controls information leak in Referer",
            "Permissions-Policy":        "Restricts browser features (Camera, Mic)",
            "X-XSS-Protection":          "Legacy XSS filter (useful for older browsers)"
        }

        status, content, headers = self.safe_request(url, method='GET')

        if status == 0:
            self.log(f"Connection failed: {content}", "fail")
            return

        self.log(f"Target responded with HTTP {status}", "pass")

        server = headers.get('Server', None)
        if server:
            self.log(f"Server header discloses: '{server}'", "warn")
        else:
            self.log("Server header not disclosed", "pass")

        found_count = 0
        for header, description in security_headers.items():
            val = headers.get(header)
            if val:
                display = val[:60] + "..." if len(val) > 60 else val
                self.log(f"{header}: {display}", "pass")
                found_count += 1
            else:
                self.log(f"MISSING: {header} — {description}", "crit")

        score = int((found_count / len(security_headers)) * 100)
        self.log(f"Security Score: {score}%", "info")

        if score < 50:
            self.log("Host is highly vulnerable — critical headers missing", "crit")
        elif score < 100:
            self.log("Some policies absent — recommend hardening headers", "warn")
        else:
            self.log("All security headers present — fully fortified", "pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vibe Headers - HTTP Security Policy Auditor")
    parser.add_argument("--url", required=True, help="Target URL (e.g. http://localhost:3456)")
    parser.add_argument('-v', '--version', action='version', version='Header Auditor 1.0.0')
    args = parser.parse_args()

    VibeHeaders().run(args.url)
