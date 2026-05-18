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
        headers = {'Origin': origin}
        status, _, res_headers = self.safe_request(url, headers=headers)
        acao = res_headers.get('Access-Control-Allow-Origin', '')
        acac = res_headers.get('Access-Control-Allow-Credentials', '').lower()
        return status, acao, acac

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
            status, acao, acac = self._check_cors(url, origin)

            if not acao:
                self.log(f"{label}: no CORS headers returned", "info")
                continue

            reflected = (acao == origin or acao == '*')
            creds = (acac == 'true')

            if acao == '*' and creds:
                self.log(f"{label}: wildcard + credentials=true — CRITICAL CORS bypass", "crit")
                vulns += 1
            elif reflected and creds:
                self.log(f"{label}: origin reflected ({acao}) + credentials=true — data theft possible", "crit")
                vulns += 1
            elif reflected:
                self.log(f"{label}: origin reflected ({acao}) — cross-origin reads allowed", "warn")
                vulns += 1
            elif acao == '*':
                self.log(f"{label}: wildcard (*) — public but no credentials", "warn")
            else:
                self.log(f"{label}: CORS policy holds ({acao})", "pass")

        self.log("=" * 32)
        if vulns > 0:
            self.log(f"{vulns} CORS misconfiguration(s) found — cross-origin data theft is possible", "crit")
        else:
            self.log("CORS policy appears correctly configured", "pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CorScan - CORS Misconfiguration Scanner")
    parser.add_argument("--url", required=True, help="Target URL (e.g. http://localhost:3456/api/user)")
    parser.add_argument('-v', '--version', action='version', version='CorScan 1.0.0')
    args = parser.parse_args()

    CorScan().run(args.url)
