import sys
import os
import argparse
import base64
import hashlib
import hmac
import json
import re
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool
from privacy_guard import privacy_user_agent

COMMON_JWT_SECRETS = (
    "secret",
    "jwt_secret",
    "password",
    "123456",
    "admin",
    "changeme",
    "development",
    "default",
    "supersecret",
    "key",
)


class Phantom(VibeTool):
    def __init__(self):
        super().__init__("Phantom", "Cookie & Session Token Analyzer")

    @staticmethod
    def _b64url_decode(segment):
        padding = "=" * (-len(segment) % 4)
        return base64.urlsafe_b64decode(segment + padding)

    @staticmethod
    def _b64url_encode(raw_bytes):
        return base64.urlsafe_b64encode(raw_bytes).rstrip(b"=").decode("ascii")

    def _decode_jwt(self, token):
        try:
            parts = token.strip().split('.')
            if len(parts) != 3:
                return None, None, None
            header = json.loads(self._b64url_decode(parts[0]))
            payload = json.loads(self._b64url_decode(parts[1]))
            if not isinstance(header, dict) or not isinstance(payload, dict):
                return None, None, None
            return header, payload, parts[2]
        except Exception:
            return None, None, None

    def _crack_hs256(self, token):
        parts = token.strip().split('.')
        if len(parts) != 3:
            return None
        signing_input = f"{parts[0]}.{parts[1]}".encode("ascii", errors="ignore")
        sig = parts[2]
        for candidate in COMMON_JWT_SECRETS:
            digest = hmac.new(candidate.encode("utf-8"), signing_input, hashlib.sha256).digest()
            if hmac.compare_digest(self._b64url_encode(digest), sig):
                return candidate
        return None

    def _audit_jwt(self, token, source_label="cookie"):
        issues = []
        jwt_header, jwt_payload, jwt_sig = self._decode_jwt(token)
        if not jwt_header or not jwt_payload:
            return issues

        alg = str(jwt_header.get("alg", "")).strip()
        issues.append((f"JWT detected in {source_label} (alg={alg or 'none'}) — payload: {str(jwt_payload)[:120]}", "hack"))

        if alg.lower() == "none" or not jwt_sig:
            issues.append(("JWT uses alg:none or empty signature — CRITICAL authentication bypass possible", "crit"))
        elif alg.upper() == "HS256":
            weak_secret = self._crack_hs256(token)
            if weak_secret:
                issues.append((f"JWT signed with weak/default secret ('{weak_secret}') — full token forgery possible", "crit"))

        if "exp" not in jwt_payload:
            issues.append(("JWT has no expiry (exp claim missing) — token lives forever", "crit"))
        if "kid" in jwt_header and ("/" in str(jwt_header["kid"]) or ".." in str(jwt_header["kid"])):
            issues.append(("JWT header 'kid' contains path characters — potential kid traversal/injection", "warn"))

        self.update_surface(jwt_tokens=[token])
        return issues

    def _analyze_cookie(self, raw, is_https=True):
        parts = [p.strip() for p in raw.split(';')]
        name_val = parts[0]
        name = name_val.split('=')[0] if '=' in name_val else name_val
        value = name_val.split('=', 1)[1] if '=' in name_val else ''
        attrs = [p.lower() for p in parts[1:]]

        issues = []

        if 'httponly' not in attrs:
            issues.append(("Missing HttpOnly — JS can read this cookie (XSS session theft risk)", "crit"))
        if 'secure' not in attrs:
            sev = "crit" if is_https else "warn"
            issues.append(("Missing Secure flag — cookie can be transmitted over plain HTTP", sev))

        samesite = next((a for a in attrs if a.startswith('samesite')), None)
        if not samesite:
            issues.append(("Missing SameSite attribute — CSRF risk", "warn"))
        elif 'samesite=none' in samesite and 'secure' not in attrs:
            issues.append(("SameSite=None without Secure flag — rejected or unsafe cross-site cookie", "crit"))
        elif 'samesite=none' in samesite:
            issues.append(("SameSite=None — cross-site requests include this cookie", "warn"))

        issues.extend(self._audit_jwt(value, source_label=f"cookie '{name}'"))

        if 0 < len(value) < 16 and not issues:
            issues.append((f"Cookie value is suspiciously short ({len(value)} chars) — low entropy / predictable", "warn"))

        return name, issues

    def run(self, url, raw_token=""):
        self.banner()
        self.log(f"Analyzing cookies & session tokens from: {url}")

        total_issues = 0

        if raw_token:
            self.log("Auditing explicitly supplied token...")
            for msg, level in self._audit_jwt(raw_token, source_label="--token"):
                self.log(f"  {msg}", level)
                if level in ("crit", "warn", "hack"):
                    total_issues += 1

        headers = {
            'User-Agent': privacy_user_agent("Phantom"),
            'DNT': '1',
            'Sec-GPC': '1',
        }
        is_https = url.lower().startswith("https://")

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as res:
                all_cookies = res.info().get_all('Set-Cookie') or []
                status = res.getcode()
                body = res.read(65536).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as e:
            all_cookies = e.headers.get_all('Set-Cookie') or []
            status = e.code
            try:
                body = e.read(65536).decode("utf-8", errors="replace")
            except Exception:
                body = ""
        except Exception as e:
            self.log(f"Connection failed: {e}", "fail")
            return

        self.log(f"Server responded {status} — {len(all_cookies)} Set-Cookie header(s) found")

        for raw in all_cookies:
            name, issues = self._analyze_cookie(raw, is_https=is_https)
            self.log(f"Cookie: {name}", "info")
            if not issues:
                self.log("  All cookie security flags set correctly", "pass")
            for msg, level in issues:
                self.log(f"  {msg}", level)
                if level in ("crit", "warn"):
                    total_issues += 1

        # Also inspect response body for embedded JWTs (e.g., JSON token responses)
        jwt_matches = re.findall(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]*", body or "")
        for tok in list(dict.fromkeys(jwt_matches))[:5]:
            for msg, level in self._audit_jwt(tok, source_label="response body"):
                self.log(f"  {msg}", level)
                if level in ("crit", "warn"):
                    total_issues += 1

        if not all_cookies and not jwt_matches and not raw_token:
            self.log("No Set-Cookie headers or JWT tokens found on this endpoint", "info")
            self.log("Tip: point Phantom at /login, /api/login, or pass --token <jwt>", "info")
            return

        self.log("=" * 32)
        if total_issues > 0:
            self.log(f"{total_issues} cookie/token security issue(s) found", "crit")
        else:
            self.log("All cookies and tokens properly configured", "pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phantom - Cookie & Session Token Analyzer")
    parser.add_argument("--url", required=True, help="Target URL (e.g. http://localhost:3456/api/login)")
    parser.add_argument("--token", default="", help="Optional JWT token string to audit directly")
    parser.add_argument('-v', '--version', action='version', version='Phantom 1.0.0')
    args = parser.parse_args()

    Phantom().run(args.url, raw_token=args.token)
