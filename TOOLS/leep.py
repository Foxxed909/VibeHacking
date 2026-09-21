import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool, FRAMEWORK_VERSION


class Leep(VibeTool):
    def __init__(self):
        super().__init__("Leep", "Logic Flow / Auth Bypass Auditor")

    def run(self, url, paths):
        self.banner()
        self.log(f"Testing unauthorized access on: {url}")
        self.log(f"Probing {len(paths)} protected path(s)")

        flaws = 0

        # Catch-all guard (SPA/dev servers answer 200 for everything).
        baseline = self.baseline_probe(url)
        if baseline.get("catch_all"):
            self.log("Target returns 200 for a nonexistent path — a 200 alone cannot prove "
                     "unauthenticated access; responses identical to that baseline are ignored.", "warn")

        for path in paths:
            target = f"{url.rstrip('/')}/{path.lstrip('/')}"
            self.log(f"Attempting leap to: /{path}")

            status, content, _ = self.safe_request(target, method='GET')

            if status == 200:
                if "login" in content.lower() or "sign in" in content.lower():
                    self.log("200 but redirected to login — protected", "pass")
                elif self.matches_baseline(content, baseline):
                    self.log(f"/{path}: 200 identical to the catch-all baseline — inconclusive")
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
    parser.add_argument('-v', '--version', action='version', version=f"Leep {FRAMEWORK_VERSION}")
    args = parser.parse_args()

    Leep().run(args.url, args.paths)
