import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool, baseline_probe, is_catch_all, looks_like_html_shell


ENV_MARKERS = (
    "API_KEY=", "SECRET=", "PASSWORD=", "DATABASE_URL=", "DB_PASSWORD=",
    "AWS_SECRET", "PRIVATE_KEY", "BEGIN RSA", "BEGIN OPENSSH",
    "MONGO_URI=", "REDIS_URL=", "JWT_SECRET",
)

JSON_MARKERS = ('"dependencies"', '"devDependencies"', '"scripts"', '"name"')
GIT_MARKERS = ("[core]", "repositoryformatversion", "ref: refs/")


class Ghost(VibeTool):
    def __init__(self):
        super().__init__("Ghost", "Sensitive Asset Finder")

    def run(self, url):
        self.banner()
        self.log(f"Scanning for exposed assets at: {url}")

        root_status, root_body, ctrl_status, ctrl_body = baseline_probe(self, url)
        if is_catch_all(root_body, ctrl_body, root_body) or (
            looks_like_html_shell(root_body) and looks_like_html_shell(ctrl_body)
            and _norm_eq(root_body, ctrl_body)
        ):
            self.log(
                "SPA / catch-all detected (root \u2248 nonsense path). "
                "HTTP 200 alone will NOT count as exposure.",
                "warn",
            )

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
        ]

        found_count = 0

        for item in wordlist:
            target = f"{url.rstrip('/')}/{item}"
            status, content, headers = self.safe_request(target, method="GET")
            content = content or ""

            if status != 200:
                if status == 403:
                    self.log(f"Forbidden \u2014 {item} exists but is protected", "pass")
                elif status == 401:
                    self.log(f"Unauthorized \u2014 {item} requires authentication", "warn")
                continue

            if is_catch_all(root_body, ctrl_body, content) or (
                looks_like_html_shell(content) and looks_like_html_shell(root_body)
                and _norm_eq(content, root_body)
            ):
                continue

            is_real = False
            if item.endswith("/"):
                if "Index of" in content or "Parent Directory" in content:
                    self.log(f"DIRECTORY INDEXING DETECTED: {item}", "crit")
                    is_real = True
            elif any(m in content for m in ENV_MARKERS):
                is_real = True
            elif item.endswith(".json") and any(m in content for m in JSON_MARKERS):
                is_real = True
            elif ".git" in item and any(m in content for m in GIT_MARKERS):
                is_real = True
            elif item.endswith((".sql", ".sqlite", ".sqlite3")) and len(content) > 50:
                is_real = True
            elif "phpinfo()" in content or "PHP Version" in content:
                is_real = True
            elif item in ("Dockerfile", "docker-compose.yml") and (
                "FROM " in content or "services:" in content
            ):
                is_real = True

            if is_real:
                self.log(f"EXPOSED: {item}", "crit")
                found_count += 1
                peek = content[:100].replace("\n", " ") + ("..." if len(content) > 100 else "")
                self.log(f"Peek: {peek}", "hack")

        self.log(f"Scan complete \u2014 {found_count} exposed asset(s) found", "info")
        if found_count > 0:
            self.log("Restrict access to these files or update .gitignore immediately", "crit")
        else:
            self.log("Target appears clean of common sensitive asset exposure", "pass")


def _norm_eq(a: str, b: str) -> bool:
    return " ".join((a or "").split())[:2000] == " ".join((b or "").split())[:2000]


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ghost - Sensitive Asset Finder")
    parser.add_argument("--url", required=True, help="Target base URL")
    parser.add_argument("-v", "--version", action="version", version="Ghost 1.1.0")
    args = parser.parse_args()
    Ghost().run(args.url)
