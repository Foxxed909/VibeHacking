import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool, baseline_probe, is_catch_all, looks_like_html_shell


class ApiFinder(VibeTool):
    def __init__(self):
        super().__init__("API Finder", "Hidden Endpoint Discovery")

    def run(self, base_url):
        self.banner()
        self.log(f"Scanning for endpoints at: {base_url}")

        root_status, root_body, ctrl_status, ctrl_body = baseline_probe(self, base_url)
        spa = looks_like_html_shell(root_body) and looks_like_html_shell(ctrl_body)
        if spa:
            self.log("SPA catch-all baseline active \u2014 identical HTML shells ignored", "warn")

        endpoints = [
            "api.js", "routes.js", "server.js", "controller.js",
            "api/", "api/v1/", "v1/api/", "services/",
            "passwords/", "vault/", "auth/", "db/",
        ]

        found = 0
        for endpoint in endpoints:
            url = f"{base_url.rstrip('/')}/{endpoint}"
            self.log(f"Checking: {endpoint}")
            status, content, _ = self.safe_request(url, method="GET")
            content = content or ""

            if status == 200:
                if is_catch_all(root_body, ctrl_body, content) or (
                    spa and looks_like_html_shell(content)
                    and " ".join(content.split())[:1500] == " ".join(root_body.split())[:1500]
                ):
                    continue
                self.log(f"FOUND \u2014 {url}", "hack")
                found += 1
            elif status == 403:
                self.log(f"Forbidden (exists but protected) \u2014 {endpoint}", "warn")
            elif status == 0:
                self.log(f"Connection issue on {endpoint}", "fail")
            elif status not in (404, 405):
                self.log(f"Unusual response ({status}) on {endpoint}", "warn")

        self.log("=" * 32)
        self.log(
            f"{found} endpoint(s) discovered" if found > 0 else "No exposed endpoints found",
            "hack" if found > 0 else "pass",
        )


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="API Finder - Hidden Endpoint Discovery")
    parser.add_argument("--url", required=True, help="Target base URL")
    parser.add_argument("-v", "--version", action="version", version="API Finder 1.1.0")
    args = parser.parse_args()
    ApiFinder().run(args.url)
