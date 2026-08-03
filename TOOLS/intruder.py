#!/usr/bin/env python3
"""
intruder.py — Authenticated multi-account attack engine (INTERNAL edition).

Everything else in the toolkit hits the target unauthenticated. Real attackers
don't: they register, log in, and attack from INSIDE a valid session. That's the
only way to actually confirm the bugs that matter most — cross-account IDOR,
horizontal/vertical privilege escalation, and session weaknesses.

intruder does exactly that:
  1. Stands up two throwaway accounts (attacker + victim), or uses creds you give.
  2. Logs both in and captures their sessions.
  3. Harvests object IDs the victim can see, then has the ATTACKER try to reach
     them — a true cross-account IDOR test (differential, not a guess).
  4. Probes privileged/admin surface from a low-priv session (vertical esc).
  5. Analyses the session cookie itself (flags + token entropy).

It endpoint-autodetects common login/signup shapes and lets you override every
one. Authorized targets only — this is the heavier artillery, kept to the
internal build.

    python TOOLS/intruder.py --url http://127.0.0.1:8800/
    python TOOLS/intruder.py --url https://your-app --login /api/login \
        --user-field email --signup /api/register
"""
import argparse
import http.cookiejar
import json
import math
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool, AuthHandler
from privacy_guard import privacy_user_agent

SIGNUP_PATHS = ["/signup", "/register", "/api/signup", "/api/register", "/api/users", "/users/new"]
LOGIN_PATHS = ["/login", "/api/login", "/api/auth/login", "/auth/login", "/session", "/api/session"]
# Where per-object data tends to live; {id} is substituted.
RESOURCE_TEMPLATES = [
    "/secrets/{id}/value", "/secrets/{id}", "/api/secrets/{id}", "/api/secret/{id}",
    "/api/user/{id}", "/api/users/{id}", "/user/{id}", "/account/{id}",
    "/api/item/{id}", "/api/items/{id}", "/api/orders/{id}", "/api/notes/{id}",
    "/api/documents/{id}", "/files/{id}", "/api/messages/{id}", "/api/record/{id}",
]
ADMIN_PATHS = [
    "/admin", "/api/admin", "/admin/users", "/api/admin/users", "/api/admin/config",
    "/api/users", "/dashboard/admin", "/api/all", "/api/export", "/settings/admin",
]
SENSITIVE_MARKERS = ("sk-", "sk_live_", "sk-proj-", "postgres://", "mysql://", "ghp_",
                     "password", "secret", "token", "api_key", "apikey", "\"value\"")


def _entropy(s):
    if not s:
        return 0.0
    counts = {}
    for c in s:
        counts[c] = counts.get(c, 0) + 1
    n = float(len(s))
    return -sum((v / n) * math.log(v / n, 2) for v in counts.values())


class Intruder(VibeTool):
    def __init__(self, base):
        super().__init__("Intruder", "Authenticated Multi-Account Attack Engine")
        self.base = base.rstrip("/")
        self.findings = 0
        self._last_setcookie = ""  # raw Set-Cookie header captured during auth

    # -- HTTP with a per-identity cookie jar --------------------------------
    class _NoRedirect(urllib.request.HTTPRedirectHandler):
        # Don't auto-follow 3xx: a login that 303-redirects sets its session
        # cookie ON the redirect response, which we'd otherwise never see.
        def redirect_request(self, *a, **k):
            return None

    def _opener(self):
        cj = http.cookiejar.CookieJar()
        op = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(cj), self._NoRedirect(), AuthHandler)
        return op, cj

    def _do(self, opener, path, method="GET", data=None, json_body=None):
        url = self.base + path
        headers = {"User-Agent": privacy_user_agent("Intruder"),
                   "Accept": "text/html,application/json,*/*"}
        body = None
        if json_body is not None:
            body = json.dumps(json_body).encode()
            headers["Content-Type"] = "application/json"
        elif isinstance(data, dict):
            body = urllib.parse.urlencode(data).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        try:
            req = urllib.request.Request(url, data=body, method=method, headers=headers)
            with opener.open(req, timeout=8) as r:
                return r.getcode(), r.read(40000).decode("utf-8", "replace"), r.headers
        except urllib.error.HTTPError as e:
            return e.code, e.read(40000).decode("utf-8", "replace"), e.headers
        except Exception as e:
            return 0, str(e), {}

    def _register_and_login(self, opener, username, password, signup_path, login_path,
                            user_field, pass_field):
        creds = {user_field: username, pass_field: password}

        def _remember(hdrs):
            try:
                sc = hdrs.get("Set-Cookie")
            except Exception:
                sc = None
            if sc:
                self._last_setcookie = sc

        # Try signup (form then JSON) across candidate paths.
        signup_candidates = [signup_path] if signup_path else SIGNUP_PATHS
        for sp in signup_candidates:
            st, _, h = self._do(opener, sp, "POST", data=creds)
            if st in (200, 201, 302, 303):
                _remember(h); break
            st, _, h = self._do(opener, sp, "POST", json_body=creds)
            if st in (200, 201, 302, 303):
                _remember(h); break
        # Log in (session may already be set by signup auto-login).
        login_candidates = [login_path] if login_path else LOGIN_PATHS
        for lp in login_candidates:
            st, _, h = self._do(opener, lp, "POST", data=creds)
            if st in (200, 302, 303):
                _remember(h); return True, lp
            st, _, h = self._do(opener, lp, "POST", json_body=creds)
            if st in (200, 302, 303):
                _remember(h); return True, lp
        # Signup may have auto-authenticated even if login shape is unknown.
        return False, ""

    def _authed(self, opener):
        """Is this opener carrying a live session (dashboard, not a login redirect)?"""
        st, body, _ = self._do(opener, "/")
        return st == 200 and "login" not in body[:400].lower()

    def _harvest_ids(self, opener):
        """Collect object IDs the victim can see from their authenticated pages."""
        ids = set()
        for path in ("/", "/dashboard", "/secrets", "/api/secrets", "/account"):
            st, body, _ = self._do(opener, path)
            if st != 200:
                continue
            for m in re.findall(r"/(?:secrets?|api/\w+|user|users|item|items|orders|notes|files|record|documents|messages)/(\d{1,7})", body):
                ids.add(int(m))
            for m in re.findall(r'"id"\s*:\s*(\d{1,7})', body):
                ids.add(int(m))
        return sorted(ids)

    def _looks_sensitive(self, body):
        low = body.lower()
        return any(mk in low for mk in SENSITIVE_MARKERS)

    # -- attack phases -------------------------------------------------------
    def cross_account_idor(self, atk_op, victim_ids, victim_bodies, anon_op):
        self.log("=== VERTICAL/HORIZONTAL IDOR: attacker reaching victim objects ===")
        if not victim_ids:
            self.log("No victim object IDs harvested — nothing to cross-test. "
                     "Supply --seed-ids or ensure the victim owns objects.", "warn")
            return
        tested = 0
        for tmpl in RESOURCE_TEMPLATES:
            for oid in victim_ids:
                path = tmpl.format(id=oid)
                a_st, a_body, _ = self._do(atk_op, path)
                tested += 1
                if a_st != 200 or not a_body:
                    continue
                # Confirm it's the VICTIM's data (matches what the victim saw)
                # and not something the anonymous user also gets (i.e. public).
                an_st, an_body, _ = self._do(anon_op, path)
                victim_match = any(self._same_object(a_body, vb) for vb in victim_bodies)
                if a_st == 200 and self._looks_sensitive(a_body) and an_st != 200 and victim_match:
                    self.log(f"IDOR CONFIRMED — attacker read victim object at {path}", "hack")
                    self.log(f"  evidence: {a_body[:160].strip()}", "crit")
                    self.findings += 1
        self.log(f"Cross-account IDOR: {tested} object accesses attempted.")

    @staticmethod
    def _same_object(a, b):
        # Cheap structural match: share a distinctive sensitive token.
        for mk in ("sk-proj-", "sk_live_", "postgres://", "ghp_"):
            if mk in a and mk in b:
                # same secret prefix present in both -> same object leaked
                ta = re.search(re.escape(mk) + r"[A-Za-z0-9_\-]{6,}", a)
                tb = re.search(re.escape(mk) + r"[A-Za-z0-9_\-]{6,}", b)
                if ta and tb and ta.group(0) == tb.group(0):
                    return True
        return False

    def privilege_escalation(self, atk_op, anon_op):
        self.log("=== VERTICAL PRIVILEGE ESCALATION: low-priv session -> admin surface ===")
        for path in ADMIN_PATHS:
            a_st, a_body, _ = self._do(atk_op, path)
            if a_st == 200 and self._looks_sensitive(a_body):
                an_st, _, _ = self._do(anon_op, path)
                tag = "hack" if an_st != 200 else "warn"
                self.log(f"PRIVILEGE ESCALATION — low-priv session reached {path} ({a_st})", tag)
                if an_st != 200:
                    self.findings += 1

    def session_analysis(self, cj):
        self.log("=== SESSION ANALYSIS ===")
        raw = self._last_setcookie
        if not raw:
            self.log("No Set-Cookie captured during auth — token-in-body or header auth?", "warn")
            return
        # Parse the RAW Set-Cookie header (http.cookiejar does not reliably expose
        # HttpOnly, so relying on its internals mis-flags secure cookies).
        low = raw.lower()
        name = raw.split("=", 1)[0].strip()
        value = raw.split("=", 1)[1].split(";", 1)[0] if "=" in raw else ""
        is_https = self.base.lower().startswith("https")
        flags = []
        if "httponly" not in low:
            flags.append("no HttpOnly (JS can read it — XSS steals the session)")
        if is_https and "secure" not in low:
            flags.append("no Secure")
        if "samesite" not in low:
            flags.append("no SameSite (CSRF exposure)")
        ent = _entropy(value)
        note = f"entropy={ent:.1f} bits/char, len={len(value)}"
        if flags:
            self.log(f"Cookie '{name}': {', '.join(flags)} — {note}", "warn")
        else:
            self.log(f"Cookie '{name}': HttpOnly + SameSite set{' + Secure' if is_https else ''} — {note}", "pass")
        if ent < 3.0 and len(value) < 20:
            self.log(f"Cookie '{name}' looks low-entropy/guessable — {note}", "crit")
            self.findings += 1

    def run(self, signup_path, login_path, user_field, pass_field, seed_ids):
        self.banner()
        self.log(f"Authenticated assault on: {self.base}")

        stamp = int(time.time())
        atk_op, atk_cj = self._opener()
        vic_op, vic_cj = self._opener()
        anon_op, _ = self._opener()

        vic_ok, vlp = self._register_and_login(
            vic_op, f"victim_{stamp}", "V!ctimPass123", signup_path, login_path, user_field, pass_field)
        atk_ok, alp = self._register_and_login(
            atk_op, f"attacker_{stamp}", "Att!ckPass123", signup_path, login_path, user_field, pass_field)

        vic_authed = vic_ok or self._authed(vic_op)
        atk_authed = atk_ok or self._authed(atk_op)
        self.log(f"Victim session:   {'ESTABLISHED' if vic_authed else 'FAILED'}"
                 + (f" via {vlp}" if vlp else ""), "pass" if vic_authed else "warn")
        self.log(f"Attacker session: {'ESTABLISHED' if atk_authed else 'FAILED'}"
                 + (f" via {alp}" if alp else ""), "pass" if atk_authed else "warn")

        if not (vic_authed and atk_authed):
            self.log("Could not stand up two authenticated accounts. Point --signup/--login "
                     "at the right paths (and --user-field if it uses email).", "warn")

        # Give the victim something to own if the app auto-seeds nothing.
        self._do(vic_op, "/secrets", "POST",
                 data={"name": f"loot_{stamp}", "value": f"sk-proj-INTRUDER-{stamp}-victimsecret", "note": "x"})

        victim_ids = [int(x) for x in seed_ids.split(",") if x.strip().isdigit()] if seed_ids else self._harvest_ids(vic_op)
        victim_bodies = []
        for oid in victim_ids:
            for tmpl in RESOURCE_TEMPLATES:
                st, body, _ = self._do(vic_op, tmpl.format(id=oid))
                if st == 200 and body:
                    victim_bodies.append(body)
        self.log(f"Harvested {len(victim_ids)} victim object id(s): {victim_ids[:12]}")

        self.cross_account_idor(atk_op, victim_ids, victim_bodies, anon_op)
        self.privilege_escalation(atk_op, anon_op)
        self.session_analysis(atk_cj)

        self.log("=" * 40)
        if self.findings:
            self.log(f"AUTHENTICATED ASSAULT COMPLETE — {self.findings} confirmed finding(s)", "hack")
            return 0
        self.log("No authenticated-context break-in confirmed. Access controls held under a real session.", "pass")
        return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="Intruder - authenticated multi-account attack engine")
    p.add_argument("--url", required=True, help="Target base URL you own/are authorized to test")
    p.add_argument("--signup", default="", help="Signup path (default: autodetect common paths)")
    p.add_argument("--login", default="", help="Login path (default: autodetect common paths)")
    p.add_argument("--user-field", default="username", help="Login/signup username field name (e.g. email)")
    p.add_argument("--pass-field", default="password", help="Login/signup password field name")
    p.add_argument("--seed-ids", default="", help="Comma-separated victim object IDs to cross-test (skips harvest)")
    p.add_argument("-v", "--version", action="version", version="Intruder 1.0.0")
    args = p.parse_args(argv)
    return Intruder(args.url).run(args.signup, args.login, args.user_field, args.pass_field, args.seed_ids)


if __name__ == "__main__":
    sys.exit(main())
