import sys
import os
import argparse
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool


class CorScan(VibeTool):
    def __init__(self):
        super().__init__("CorScan", "CORS Misconfiguration Scanner")

    def _check_cors(self, url, origin):
        """Simple-request CORS check (GET with Origin header)."""
        headers = {'Origin': origin}
        status, _, res_headers = self.safe_request(url, headers=headers)
        acao = res_headers.get('Access-Control-Allow-Origin', '')
        acac = res_headers.get('Access-Control-Allow-Credentials', '').lower()
        return status, acao, acac

    def _check_preflight(self, url, origin):
        """
        FIX: added OPTIONS preflight check.
        CORS vulnerabilities often only appear on preflight — a server may reflect
        ACAO on OPTIONS with ACAC=true but not on GET, or vice versa.
        Without this, the scanner missed half the attack surface.
        """
        headers = {
            'Origin': origin,
            'Access-Control-Request-Method': 'POST',
            'Access-Control-Request-Headers': 'Authorization, Content-Type',
        }
        status, _, res_headers = self.safe_request(url, method='OPTIONS', headers=headers)
        acao = res_headers.get('Access-Control-Allow-Origin', '')
        acac = res_headers.get('Access-Control-Allow-Credentials', '').lower()
        acam = res_headers.get('Access-Control-Allow-Methods', '')
        vary = res_headers.get('Vary', '')
        return status, acao, acac, acam, vary

    def _evaluate(self, label, request_type, origin, acao, acac):
        """Shared severity logic for both simple and preflight results."""
        if not acao:
            self.log(f"{label} [{request_type}]: no CORS headers returned", "info")
            return 0

        reflected = (acao == origin or acao == '*')
        creds = (acac == 'true')

        if acao == '*' and creds:
            self.log(f"{label} [{request_type}]: wildcard + credentials=true — CRITICAL CORS bypass", "crit")
            return 1
        elif reflected and creds:
            self.log(f"{label} [{request_type}]: origin reflected ({acao}) + credentials=true — data theft possible", "crit")
            return 1
        elif reflected:
            self.log(f"{label} [{request_type}]: origin reflected ({acao}) — cross-origin reads allowed", "warn")
            return 1
        elif acao == '*':
            self.log(f"{label} [{request_type}]: wildcard (*) — public, no credentials risk", "warn")
        else:
            self.log(f"{label} [{request_type}]: CORS policy holds ({acao})", "pass")
        return 0

    def run(self, url):
        self.banner()
        self.log(f"Scanning CORS policy on: {url}")

        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or 'target.com'

        test_origins = {
            "Evil domain":              "https://evil.com",
            "null origin":              "null",
            "Subdomain of target":      f"https://evil.{host}",
            "Target as subdomain":      f"https://{host}.evil.com",
            "HTTP downgrade":           f"http://{host}",
            "Different port":           f"https://{host}:9999",
        }

        vulns = 0

        for label, origin in test_origins.items():
            # Simple-request check
            status, acao, acac = self._check_cors(url, origin)
            vulns += self._evaluate(label, "simple GET", origin, acao, acac)

            # FIX: preflight check — this is the half that was previously missing
            pf_status, pf_acao, pf_acac, pf_acam, pf_vary = self._check_preflight(url, origin)
            vulns += self._evaluate(label, "OPTIONS preflight", origin, pf_acao, pf_acac)

            # Warn if Vary: Origin is absent — required for correct CORS caching
            if pf_status == 200 and pf_acao and "origin" not in pf_vary.lower():
                self.log(
                    f"{label} [OPTIONS preflight]: missing 'Vary: Origin' header — CORS responses may be incorrectly cached",
                    "warn",
                )

        self.log("=" * 32)
        if vulns > 0:
            self.log(f"{vulns} CORS misconfiguration(s) found — cross-origin data theft is possible", "crit")
        else:
            self.log("CORS policy appears correctly configured on both simple and preflight requests", "pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CorScan - CORS Misconfiguration Scanner")
    parser.add_argument("--url", required=True, help="Target URL (e.g. http://localhost:3456/api/user)")
    parser.add_argument('-v', '--version', action='version', version='CorScan 1.0.0')
    args = parser.parse_args()

    CorScan().run(args.url)
