import sys
import os
import argparse
import ipaddress
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool, FRAMEWORK_VERSION


# Each header carries the severity of it being ABSENT. This is deliberately
# calibrated so the tool doesn't cry "CRITICAL" over defense-in-depth niceties
# or headers that don't even apply to the target's scheme.
#   crit  — a real, exploitable gap (clickjacking, injection surface)
#   warn  — defense-in-depth; worth adding, not an emergency
#   info  — deprecated or context-dependent; often correct to omit
SECURITY_HEADERS = {
    "Content-Security-Policy":   ("Mitigates XSS and data injection", "crit"),
    "X-Frame-Options":           ("Prevents clickjacking", "crit"),
    "X-Content-Type-Options":    ("Blocks MIME-sniffing", "warn"),
    "Strict-Transport-Security": ("Enforces HTTPS (HSTS)", "crit"),
    "Referrer-Policy":           ("Controls Referer leakage", "warn"),
    "Permissions-Policy":        ("Restricts browser features (camera, mic)", "warn"),
    # Deprecated: modern guidance (OWASP, browser vendors) is to NOT set it.
    "X-XSS-Protection":          ("Deprecated legacy filter — omitting it is correct", "info"),
}


def _is_loopback_or_private(host):
    if host in {"localhost", "::1"}:
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_private or ip.is_link_local
    except ValueError:
        return host.endswith(".local") or host.endswith(".localhost")


class VibeHeaders(VibeTool):
    def __init__(self):
        super().__init__("Header Auditor", "HTTP Security Policy Auditor")

    def run(self, url):
        self.banner()
        self.log(f"Starting audit on: {url}")

        parsed = urllib.parse.urlparse(url)
        is_https = parsed.scheme == "https"

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

        present = 0
        applicable = 0
        real_gaps = 0  # crit/warn headers actually missing
        for header, (description, severity) in SECURITY_HEADERS.items():
            val = headers.get(header)

            # Context downgrades — a missing header that doesn't apply here is
            # informational, not a finding.
            if header == "Strict-Transport-Security" and not is_https:
                if not val:
                    self.log(f"N/A: {header} — only applies over HTTPS ({parsed.scheme}://). Info only.", "info")
                    continue
            if header == "X-XSS-Protection":
                if val:
                    self.log(f"{header}: {val} — set, but this header is deprecated; '0' or omit is preferred", "warn")
                else:
                    self.log(f"OK: {header} not set — deprecated header, omitting it is correct.", "pass")
                continue

            applicable += 1
            if val:
                display = val[:60] + "..." if len(val) > 60 else val
                self.log(f"{header}: {display}", "pass")
                present += 1
            else:
                self.log(f"MISSING: {header} — {description}", severity)
                if severity in ("crit", "warn"):
                    real_gaps += 1

        score = int((present / applicable) * 100) if applicable else 100
        self.log(f"Security Score: {score}% ({present}/{applicable} applicable headers present)", "info")

        crit_missing = not headers.get("Content-Security-Policy") or not headers.get("X-Frame-Options")
        if crit_missing:
            self.log("Missing a critical header (CSP or X-Frame-Options) — exploitable gap", "crit")
        elif real_gaps:
            self.log("Core headers present; some defense-in-depth headers absent — recommend hardening", "warn")
        else:
            self.log("All applicable security headers present — fully fortified", "pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vibe Headers - HTTP Security Policy Auditor")
    parser.add_argument("--url", required=True, help="Target URL (e.g. http://localhost:3456)")
    parser.add_argument('-v', '--version', action='version', version=f"Header Auditor {FRAMEWORK_VERSION}")
    args = parser.parse_args()

    VibeHeaders().run(args.url)
