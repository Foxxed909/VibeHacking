import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool


class ApiCheck(VibeTool):
    def __init__(self):
        super().__init__("API Check", "Single Endpoint Checker")

    def run(self, url):
        self.banner()
        self.log(f"Checking: {url}")

        status, body, headers = self.safe_request(url, method='GET')

        if status == 200:
            self.log(f"Endpoint is live (200 OK)", "pass")
            self.log(f"Content-Type: {headers.get('Content-Type', 'not disclosed')}", "info")
        elif status == 404:
            self.log(f"Endpoint not found (404)", "warn")
        elif status in (401, 403):
            self.log(f"Endpoint exists but requires auth ({status})", "warn")
        elif status == 0:
            self.log(f"Connection failed: {body}", "fail")
        else:
            self.log(f"Unexpected response ({status})", "warn")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="API Check - Single Endpoint Checker")
    parser.add_argument("--url", required=True, help="Endpoint to check (e.g. http://localhost:3456/api/health)")
    parser.add_argument('-v', '--version', action='version', version='API Check 1.0.0')
    args = parser.parse_args()

    ApiCheck().run(args.url)
