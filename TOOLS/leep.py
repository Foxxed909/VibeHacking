import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool


class Leep(VibeTool):
    def __init__(self):
        super().__init__("Leep", "Logic Flow / Auth Bypass Auditor")

    def run(self, url, paths):
        self.banner()
        self.log(f"Testing unauthorized access on: {url}")
        self.log(f"Probing {len(paths)} protected path(s)")

        flaws = 0

        for path in paths:
            target = f"{url.rstrip('/')}/{path.lstrip('/')}"
            self.log(f"Attempting leap to: /{path}")

            status, content, _ = self.safe_request(target, method='GET')

            if status == 200:
                if "login" in content.lower() or "sign in" in content.lower():
                    self.log(f"200 but redirected to login — protected", "pass")
                else:
                    self.log(f"LOGIC FLAW — /{path} accessible without auth (200 OK)", "crit")
                    flaws += 1
            elif status in (401, 403):
                self.log(f"Blocked ({status}) — /{path} is protected", "pass")
            elif status == 404:
                self.log(f"Not found ({status}) — /{path} doesn't exist", "warn")
            elif status == 0:
                self.log(f"Connection issue: {content}", "fail")
            else:
                self.log(f"Unusual response ({status}) on /{path}", "warn")

        self.log("=" * 32)
        if flaws > 0:
            self.log(f"{flaws} logic flaw(s) found — auth boundary is broken", "crit")
        else:
            self.log("No unauthorized leaps succeeded — auth boundary holds", "pass")


DEFAULT_PATHS = [
    "dashboard", "dashboard.html",
    "billing", "billing.html",
    "settings", "settings.html",
    "admin", "admin.html",
    "profile", "account"
]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Leep - Logic Flow / Auth Bypass Auditor")
    parser.add_argument("--url", required=True, help="Target base URL (e.g. http://localhost:3456)")
    parser.add_argument("--paths", nargs='+', default=DEFAULT_PATHS, help="Protected paths to probe (default: common dashboard/billing/settings routes)")
    parser.add_argument('-v', '--version', action='version', version='Leep 1.0.0')
    args = parser.parse_args()

    Leep().run(args.url, args.paths)
