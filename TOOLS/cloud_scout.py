import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool


class CloudScout(VibeTool):
    def __init__(self):
        super().__init__("Cloud Scout", "Cloud Environment Prober")

    def run(self, base_url, targets):
        self.banner()
        self.log(f"Mapping environment at: {base_url}")

        active = 0

        for t in targets:
            full_url = f"{base_url.rstrip('/')}/{t.lstrip('/')}"
            self.log(f"Probing: {t}")

            status, _, _ = self.safe_request(full_url, method='GET')

            if status == 200:
                self.log(f"ACTIVE — {t} is accessible (200 OK)", "hack")
                active += 1
            elif status in (401, 403):
                self.log(f"Protected — {t} requires auth ({status})", "pass")
            elif status == 404:
                self.log(f"Not found — {t} ({status})", "warn")
            elif status == 0:
                self.log(f"Offline or unreachable — {t}", "fail")
            else:
                self.log(f"Unusual response on {t} ({status})", "warn")

        self.log("=" * 32)
        self.log(f"Mapping complete — {active} active unprotected endpoint(s) found",
                 "crit" if active > 0 else "pass")


DEFAULT_TARGETS = [
    "login.html", "index.html", "files.html",
    "admin.html", "dashboard.html", "vault.html"
]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cloud Scout - Cloud Environment Prober")
    parser.add_argument("--url", required=True, help="Target base URL (e.g. http://localhost:3456)")
    parser.add_argument("--targets", nargs='+', default=DEFAULT_TARGETS, help="Paths to probe")
    parser.add_argument('-v', '--version', action='version', version='Cloud Scout 1.0.0')
    args = parser.parse_args()

    CloudScout().run(args.url, args.targets)
