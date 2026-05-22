import sys
import os
import argparse
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_core import LiveTool

__version__ = "1.0.0"


class LiveHeaders(LiveTool):
    def __init__(self, delay=0.7):
        super().__init__("LiveHeaders", "Remote HTTP Header Injection & Host Poisoning Suite", delay=delay)

    def run(self, url, path="/"):
        self.banner()
        base = url.rstrip("/")
        probe = base + ("" if path == "/" else "/" + path.lstrip("/"))
        hits = 0

        # 1. Host header poisoning
        self.log(f"Test 1 — Host header poisoning on {probe}")
        import urllib.parse
        parsed = urllib.parse.urlparse(url)
        host = parsed.hostname or "target.com"

        for poison in [
            "evil.com",
            f"{host}@evil.com",
            "127.0.0.1",
            f"{host}\r\nX-Injected: hacked",
        ]:
            try:
                req = urllib.request.Request(probe)
                req.add_unredirected_header("Host", poison)
                r = urllib.request.urlopen(req, timeout=8)
                resp = r.read(200).decode('utf-8', errors='ignore')
                self.log(f"[{r.status}] Host: {poison[:40]} → {resp[:60]}")
                if "evil.com" in resp or "hacked" in resp:
                    self.log(f"Host header reflected in response!", "crit")
                    hits += 1
            except Exception as ex:
                self.log(f"Host: {poison[:40]} → {str(ex)[:60]}")

        # 2. Forwarding / cache poisoning headers
        self.log(f"Test 2 — Cache poisoning headers on {probe}")
        for hdr, val in [
            ("X-Forwarded-Host", "evil.com"),
            ("X-Forwarded-Proto", "http"),
            ("X-Original-URL", "/admin"),
            ("X-Rewrite-URL", "/admin"),
            ("X-Custom-IP-Authorization", "127.0.0.1"),
            ("Forwarded", "host=evil.com"),
        ]:
            status, body, hdrs = self.safe_request(probe, headers={hdr: val})
            if "evil.com" in body or "admin" in body.lower():
                self.log(f"[{status}] {hdr}: {val} — reflected/routed!", "crit")
                hits += 1
            else:
                self.log(f"[{status}] {hdr}: {val} — no reflection", "info")

        # 3. CRLF injection in URL path
        self.log("Test 3 — CRLF injection via URL path")
        for path_suffix in [
            "%0d%0aX-Injected:hacked",
            "%0aSet-Cookie:session=hacked",
        ]:
            try:
                r = urllib.request.urlopen(probe + path_suffix, timeout=5)
                hdrs = dict(r.headers)
                if "X-Injected" in hdrs or "hacked" in str(hdrs):
                    self.log(f"CRLF injection confirmed via {path_suffix}", "crit")
                    hits += 1
                else:
                    self.log(f"CRLF blocked/safe: {path_suffix}", "pass")
            except Exception as ex:
                self.log(f"CRLF {path_suffix}: {str(ex)[:60]}")

        self.log("=" * 32)
        if hits:
            self.log(f"{hits} header injection issue(s) found", "crit")
        else:
            self.log("No header injection issues detected", "pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LiveHeaders - Remote HTTP Header Injection Suite")
    parser.add_argument("--url", required=True, help="Target base URL (e.g. https://example.com)")
    parser.add_argument("--path", default="/", help="Path to probe (default: /)")
    parser.add_argument("--delay", type=float, default=0.7, help="Seconds between requests (default: 0.7)")
    parser.add_argument("--no-verify", action="store_true", help="Skip SSL certificate verification")
    parser.add_argument("-v", "--version", action="version", version=f"LiveHeaders {__version__}")
    args = parser.parse_args()

    tool = LiveHeaders(delay=args.delay)
    tool.verify_ssl = not args.no_verify
    tool.run(args.url, args.path)
