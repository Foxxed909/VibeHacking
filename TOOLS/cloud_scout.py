import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool, FRAMEWORK_VERSION


# Paths that are SUPPOSED to be publicly reachable — a 200 here is expected,
# not a finding.
EXPECTED_PUBLIC = (
    "index", "home", "login", "signin", "sign-in", "register", "signup",
    "landing", "about", "contact", "favicon", "robots", "sitemap", "/", "",
)

# Substrings that mark a path as sensitive — a 200 on one of these is worth
# flagging because it should normally be gated or absent.
SENSITIVE_MARKERS = (
    "admin", "dashboard", "vault", "config", "secret", "backup", "internal",
    "private", "debug", ".env", ".git", "db", "database", "credential", "key",
)


def _classify(path):
    p = path.strip("/").lower()
    if any(m in p for m in SENSITIVE_MARKERS):
        return "sensitive"
    stem = p.rsplit("/", 1)[-1].split(".")[0]
    if stem in EXPECTED_PUBLIC or p in EXPECTED_PUBLIC:
        return "public"
    return "neutral"


class CloudScout(VibeTool):
    def __init__(self):
        super().__init__("Cloud Scout", "Cloud Environment Prober")

    def run(self, base_url, targets):
        self.banner()
        self.log(f"Mapping environment at: {base_url}")

        exposed = 0  # sensitive paths that answered 200 — the real signal

        for t in targets:
            full_url = f"{base_url.rstrip('/')}/{t.lstrip('/')}"
            kind = _classify(t)
            self.log(f"Probing: {t}")

            status, _, _ = self.safe_request(full_url, method='GET')

            if status == 200:
                if kind == "sensitive":
                    self.log(f"EXPOSED — sensitive path {t} is accessible (200 OK) — verify it isn't leaking data", "hack")
                    exposed += 1
                elif kind == "public":
                    self.log(f"Reachable — {t} (200) — expected-public page, not a finding", "pass")
                else:
                    self.log(f"Reachable — {t} (200) — map it, then judge by content", "info")
            elif status in (401, 403):
                self.log(f"Protected — {t} requires auth ({status})", "pass")
            elif status == 404:
                self.log(f"Not found — {t} ({status})", "info")
            elif status == 0:
                self.log(f"Offline or unreachable — {t}", "warn")
            else:
                self.log(f"Unusual response on {t} ({status})", "info")

        self.log("=" * 32)
        if exposed > 0:
            self.log(f"Mapping complete — {exposed} sensitive path(s) reachable without auth", "crit")
        else:
            self.log("Mapping complete — no sensitive paths exposed (public pages don't count)", "pass")


DEFAULT_TARGETS = [
    "login.html", "index.html", "files.html",
    "admin.html", "dashboard.html", "vault.html"
]

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cloud Scout - Cloud Environment Prober")
    parser.add_argument("--url", required=True, help="Target base URL (e.g. http://localhost:3456)")
    parser.add_argument("--targets", nargs='+', default=DEFAULT_TARGETS, help="Paths to probe")
    parser.add_argument('-v', '--version', action='version', version=f"Cloud Scout {FRAMEWORK_VERSION}")
    args = parser.parse_args()

    CloudScout().run(args.url, args.targets)
