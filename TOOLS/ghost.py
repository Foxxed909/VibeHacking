import sys
import os
import argparse
import re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool, FRAMEWORK_VERSION


CONFIG_MARKERS = ("DB_", "PASSWORD=", "SECRET", "TOKEN=", "API_KEY", "<?php",
                  "BEGIN RSA", "BEGIN OPENSSH", "aws_access_key_id")


def _looks_like_config(content):
    """True when the body really looks like a config/secret file.

    The old check counted a bare "{" or "[" as proof — i.e. every JSON API
    response was reported as an exposed file.
    """
    body = content or ""
    if any(marker in body for marker in CONFIG_MARKERS):
        return True
    return bool(re.search(r"(?m)^[A-Z][A-Z0-9_]{2,}=.{4,}$", body))


class Ghost(VibeTool):
    def __init__(self):
        super().__init__("Ghost", "Sensitive Asset Finder")

    def run(self, url):
        self.banner()
        self.log(f"Scanning for exposed assets at: {url}")

        wordlist = [
            ".env", ".env.local", ".env.dev", ".env.test",
            "config.js", "config.json", "settings.json",
            "package.json", "package-lock.json", "composer.json",
            ".git/config", ".git/index", ".git/HEAD",
            ".vscode/settings.json", ".idea/workspace.xml",
            "backup.sql", "db.sqlite", "database.sqlite3", "dump.sql",
            "admin/", "administrator/", "login/", "auth/", "api/", "v1/", "v2/",
            "server-status", "phpinfo.php", "info.php",
            "Dockerfile", "docker-compose.yml", ".gitignore", ".dockerignore",
            "README.md", "CONTRIBUTING.md", "LICENSE",
            "vibe.py", "vibe_session.json", "vibe_core.py", "vibe_headers.py",
            "logs/ghost_session.log", "scripts/deploy.sh"
        ]

        found_count = 0

        # A catch-all route answers 200 for every word on this list; anything
        # byte-identical to that baseline is not an exposure.
        baseline = self.baseline_probe(url)
        if baseline.get("catch_all"):
            self.log("Target returns 200 for a nonexistent path (catch-all). Reporting only "
                     "responses that differ from that baseline and look like real files.", "warn")

        for item in wordlist:
            target = f"{url.rstrip('/')}/{item}"
            status, content, headers = self.safe_request(target, method='GET')

            if status == 200:
                if self.matches_baseline(content, baseline):
                    self.log(f"{item}: 200 identical to the catch-all baseline — ignored")
                    continue

                is_real = False
                lowered = (content or "").lower()

                if item.endswith('/'):
                    if "Index of" in content or "Parent Directory" in content:
                        self.log(f"DIRECTORY INDEXING DETECTED: {item}", "crit")
                        is_real = True
                elif _looks_like_config(content):
                    is_real = True
                elif item.endswith((".js", ".json")) and any(
                        m in content for m in ("function", "export ", "require(", "module.exports", "=>")):
                    is_real = True
                elif "not found" in lowered or "404" in lowered:
                    is_real = False

                if is_real:
                    self.log(f"EXPOSED: {item}", "crit")
                    found_count += 1
                    if ".env" in item or "config" in item:
                        peek = content[:100] + ("..." if len(content) > 100 else "")
                        self.log(f"Peek: {peek}", "hack")

            elif status == 403:
                self.log(f"Forbidden — {item} exists but is protected", "pass")
            elif status == 401:
                self.log(f"Unauthorized — {item} requires authentication", "warn")

        self.log(f"Scan complete — {found_count} exposed asset(s) found", "info")
        if found_count > 0:
            self.log("Restrict access to these files or update .gitignore immediately", "crit")
        else:
            self.log("Target appears clean of common sensitive asset exposure", "pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ghost - Sensitive Asset Finder")
    parser.add_argument("--url", required=True, help="Target base URL (e.g. http://localhost:3456)")
    parser.add_argument('-v', '--version', action='version', version=f"Ghost {FRAMEWORK_VERSION}")
    args = parser.parse_args()

    Ghost().run(args.url)
