import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool


class ApiFinder(VibeTool):
    def __init__(self):
        super().__init__("API Finder", "Hidden Endpoint Discovery")

    def run(self, base_url):
        self.banner()
        self.log(f"Scanning for endpoints at: {base_url}")
        self.calibrate_soft_404(base_url)

        endpoints = [
            'api.js', 'routes.js', 'server.js', 'controller.js',
            'api/', 'api/v1/', 'v1/api/', 'services/',
            'api/config', 'api/debug', 'api/env', 'api/user', 'api/admin',
            'api/health', 'api/status/full', 'graphql', 'openapi.json',
            'passwords/', 'vault/', 'auth/', 'db/'
        ]

        found = 0
        discovered = []

        for endpoint in endpoints:
            url = f"{base_url.rstrip('/')}/{endpoint}"
            self.log(f"Checking: {endpoint}")

            status, body, headers = self.safe_request(url, method='GET')

            if status == 200:
                if self.is_waf_challenge(status, body, headers) or self.is_soft_404(status, body):
                    continue
                self.log(f"FOUND — {url}", "hack")
                found += 1
                discovered.append(url)
            elif status == 403:
                self.log(f"Forbidden (exists but protected) — {endpoint}", "warn")
            elif status == 401:
                self.log(f"Auth required (exists) — {endpoint} (401)", "info")
                discovered.append(url)
            elif status == 404:
                pass
            elif status == 0:
                self.log(f"Connection issue on {endpoint}", "fail")
            else:
                self.log(f"Unusual response ({status}) on {endpoint}", "warn")

        if discovered:
            self.update_surface(endpoints=discovered)

        self.log("=" * 32)
        self.log(f"{found} endpoint(s) discovered" if found > 0 else "No exposed endpoints found",
                 "hack" if found > 0 else "pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="API Finder - Hidden Endpoint Discovery")
    parser.add_argument("--url", required=True, help="Target base URL (e.g. http://localhost:3456)")
    parser.add_argument('-v', '--version', action='version', version='API Finder 1.0.0')
    args = parser.parse_args()

    ApiFinder().run(args.url)
