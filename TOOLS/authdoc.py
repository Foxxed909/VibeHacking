import sys
import os
import argparse
import re
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool

SQL_ERROR_PATTERNS = re.compile(
    r"(sqlite3\.|syntax error|unrecognized token|you have an error in your sql syntax|"
    r"pg_query|psql:|ora-\d{5}|sqlstate\[|unclosed quotation mark|prisma\.|sequelize)",
    re.IGNORECASE,
)


class AuthDoc(VibeTool):
    def __init__(self):
        super().__init__("AuthDoc", "WAF & Input Filter Auditor")

    def run(self, url, payload_type=None):
        self.banner()
        self.log(f"Analyzing input filters & injection sinks on: {url}")

        base_status, base_body, _ = self.safe_request(url, method="GET")
        if base_status == 0:
            self.log(f"Baseline connection failed: {base_body}", "fail")
            return

        payloads = {
            "SQLi":           {"q": "1' OR '1'='1"},
            "XSS":            {"q": "<script>vibe_xss_canary()</script>"},
            "SSTI":           {"q": "{{9731*9817}}"},
            "Path Traversal": {"file": "../../../etc/passwd", "path": "../.env"},
        }

        if payload_type and payload_type in payloads:
            payloads = {payload_type: payloads[payload_type]}

        blocked = 0
        confirmed = 0
        reflected_or_accepted = 0

        for name, data in payloads.items():
            self.log(f"Firing: {name}")
            sep = "&" if "?" in url else "?"
            query = urllib.parse.urlencode(data)
            full_url = f"{url}{sep}{query}"

            status, content, _ = self.safe_request(full_url, method='GET')
            content = content or ""

            if status == 0:
                self.log(f"Connection issue on {name}: {content}", "fail")
                continue

            if status in (400, 403, 406, 422):
                self.log(f"{name} rejected/blocked ({status}) — WAF or input validation active", "pass")
                blocked += 1
                continue

            if status == 429:
                self.log(f"{name} rate-limited ({status}) — defensive throttling active", "pass")
                blocked += 1
                continue

            if status >= 500:
                self.log(f"{name} payload crashed the server ({status}) — unhandled injection sink", "crit")
                confirmed += 1
                continue

            if status == 200:
                # Perform deterministic verification rather than flagging every 200 OK
                if name == "SQLi" and SQL_ERROR_PATTERNS.search(content):
                    self.log(f"{name} triggered database error disclosure in 200 response", "crit")
                    confirmed += 1
                elif name == "XSS" and "<script>vibe_xss_canary()</script>" in content:
                    self.log(f"{name} payload reflected UNESCAPED in response — confirmed XSS", "crit")
                    confirmed += 1
                elif name == "SSTI" and "95529227" in content:
                    self.log(f"{name} expression {{9731*9817}} evaluated to 95529227 — confirmed SSTI", "crit")
                    confirmed += 1
                elif name == "Path Traversal" and (
                    "root:x:0:0" in content
                    or "OPENROUTER_API_KEY" in content
                    or "JWT_SECRET" in content
                ):
                    self.log(f"{name} returned sensitive file contents — confirmed LFI/Traversal", "crit")
                    confirmed += 1
                else:
                    self.log(f"{name} returned 200 OK with no execution/leakage (parameter ignored or sanitized)", "pass")
                    reflected_or_accepted += 1
            elif status == 404:
                self.log(f"{name} — endpoint not found ({status})", "info")
            else:
                self.log(f"{name} — response status {status}", "info")

        self.log("=" * 32)
        if confirmed > 0:
            self.log(f"{confirmed} confirmed injection/filter vulnerability(ies) detected", "crit")
        elif blocked > 0:
            self.log(f"Payloads actively blocked ({blocked}) and no execution observed", "pass")
        else:
            self.log("No injection execution or filter bypass confirmed on this URL", "pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="AuthDoc - WAF & Input Filter Auditor")
    parser.add_argument("--url", required=True, help="Target endpoint (e.g. http://localhost:3456/search)")
    parser.add_argument("--type", choices=["SQLi", "XSS", "SSTI", "Path Traversal"], help="Run a specific payload type only")
    parser.add_argument('-v', '--version', action='version', version='AuthDoc 1.0.0')
    args = parser.parse_args()

    AuthDoc().run(args.url, args.type)
