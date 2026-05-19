import sys, os, argparse, urllib.request, json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool


class HeaderInject(VibeTool):
    def __init__(self):
        super().__init__("Header Inject", "HTTP Header Injection & Host Poisoning Suite")

    def run(self, url):
        self.banner()
        base = url.rstrip("/")
        hits = 0

        # 1. Host header poisoning
        self.log("Test 1 — Host header poisoning...")
        for host in ["evil.com", "localhost:3456@evil.com", "localhost:3456\r\nX-Injected:hacked", "127.0.0.1:9999"]:
            try:
                req = urllib.request.Request(base + "/api/health")
                req.add_unredirected_header("Host", host)
                r = urllib.request.urlopen(req, timeout=4)
                resp = r.read().decode()
                self.log(f"[{r.status}] Host: {host[:40]} => {resp[:80]}")
            except Exception as ex:
                self.log(f"[ERR] Host: {host[:40]}: {str(ex)[:50]}")

        # 2. X-Forwarded-Host / Proto for cache poisoning
        self.log("Test 2 — Cache poisoning headers...")
        for hdr, val in [
            ("X-Forwarded-Host", "evil.com"),
            ("X-Forwarded-Proto", "http"),
            ("X-Original-URL", "/api/key"),
            ("X-Rewrite-URL", "/api/key"),
            ("X-Custom-IP-Authorization", "127.0.0.1"),
            ("Forwarded", "host=evil.com"),
        ]:
            try:
                req = urllib.request.Request(base + "/api/config")
                req.add_header(hdr, val)
                r = urllib.request.urlopen(req, timeout=4)
                resp = r.read().decode()
                self.log(f"[{r.status}] {hdr}: {val} => resp_len={len(resp)}")
                if "evil.com" in resp:
                    self.log(f"[CACHE POISON HIT] {hdr} reflected in response!", "fail")
                    hits += 1
            except Exception as ex:
                self.log(f"[ERR] {hdr}: {str(ex)[:50]}")

        # 3. Content-Type confusion
        self.log("Test 3 — Content-Type confusion attacks...")
        body = b'{"model":"openai/gpt-oss-20b:free","messages":[{"role":"user","content":"hi"}],"persona":"default"}'
        for ct in ["text/plain", "application/xml", "text/html", "multipart/form-data"]:
            try:
                req = urllib.request.Request(base + "/api/chat", data=body, method="POST")
                req.add_header("Content-Type", ct)
                r = urllib.request.urlopen(req, timeout=8)
                self.log(f"[{r.status}] Content-Type: {ct} — accepted")
                hits += 1
            except urllib.error.HTTPError as e:
                self.log(f"[{e.code}] Content-Type: {ct} — rejected")
            except Exception as ex:
                self.log(f"[ERR] {ct}: {str(ex)[:50]}")

        # 4. CRLF injection in headers
        self.log("Test 4 — CRLF injection via URL path...")
        for path in [
            "/api/health%0d%0aX-Injected:hacked",
            "/api/health%0aSet-Cookie:session=hacked",
            "/api/health\r\nX-Injected:hacked",
        ]:
            try:
                r = urllib.request.urlopen(base + path, timeout=4)
                headers = dict(r.headers)
                if "X-Injected" in headers or "hacked" in str(headers):
                    self.log(f"[CRLF HIT] Header injection confirmed: {path}", "fail")
                    hits += 1
                else:
                    self.log(f"[{r.status}] CRLF path blocked/passed: {path[:50]}")
            except Exception as ex:
                self.log(f"[ERR] CRLF: {str(ex)[:60]}")

        self.log("================================")
        self.log(f"Header injection issues: {hits}", "fail" if hits else "pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    args = parser.parse_args()
    HeaderInject().run(args.url)
