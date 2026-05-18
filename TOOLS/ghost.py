import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool


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

        for item in wordlist:
            target = f"{url.rstrip('/')}/{item}"
            status, content, headers = self.safe_request(target, method='GET')

            if status == 200:
                is_real = False

                if item.endswith('/'):
                    if "Index of" in content or "Parent Directory" in content:
                        self.log(f"DIRECTORY INDEXING DETECTED: {item}", "crit")
                        is_real = True
                elif any(marker in content for marker in ["{", "[", "<?php", "export ", "DB_", "PASSWORD"]):
                    is_real = True
                elif len(content) > 0 and "404" not in content.lower() and "not found" not in content.lower():
                    is_real = True

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
    parser.add_argument('-v', '--version', action='version', version='Ghost 1.0.0')
    args = parser.parse_args()

    Ghost().run(args.url)
