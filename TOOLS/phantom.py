import sys
import os
import argparse
import base64
import json
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool, FRAMEWORK_VERSION
from privacy_guard import privacy_user_agent


class Phantom(VibeTool):
    def __init__(self):
        super().__init__("Phantom", "Cookie & Session Token Analyzer")

    @staticmethod
    def _b64_json(segment):
        padding = 4 - len(segment) % 4
        return json.loads(base64.urlsafe_b64decode(segment + '=' * padding))

    def _decode_jwt(self, token):
        """Return the JWT payload, or None when the value is not a JWT."""
        return self._decode_jwt_parts(token)[1]

    def _decode_jwt_parts(self, token):
        """Return (header, payload) for a JWT, or (None, None).

        `alg` lives in the header, not the payload — reading it from the payload
        made the alg:none check unreachable.
        """
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None, None
            return self._b64_json(parts[0]), self._b64_json(parts[1])
        except Exception:
            return None, None

    def _analyze_cookie(self, raw):
        parts = [p.strip() for p in raw.split(';')]
        name_val = parts[0]
        name = name_val.split('=')[0] if '=' in name_val else name_val
        value = name_val.split('=', 1)[1] if '=' in name_val else ''
        attrs = [p.lower() for p in parts[1:]]

        issues = []

        if 'httponly' not in attrs:
            issues.append(("Missing HttpOnly — JS can read this cookie (XSS risk)", "crit"))
        if 'secure' not in attrs:
            issues.append(("Missing Secure flag — cookie sent over plain HTTP", "crit"))

        samesite = next((a for a in attrs if a.startswith('samesite')), None)
        if not samesite:
            issues.append(("Missing SameSite — CSRF risk", "warn"))
        elif 'samesite=none' in samesite:
            issues.append(("SameSite=None — cross-site requests include this cookie", "warn"))

        jwt_header, jwt_payload = self._decode_jwt_parts(value)
        if jwt_payload:
            issues.append((f"JWT detected — payload: {str(jwt_payload)[:120]}", "hack"))
            if 'exp' not in jwt_payload:
                issues.append(("JWT has no expiry (exp claim missing) — token lives forever", "crit"))
            alg = str((jwt_header or {}).get('alg', '')).lower()
            if alg == 'none':
                issues.append(("JWT uses alg:none — CRITICAL auth bypass possible", "crit"))
            elif alg in ('hs256', 'hs384', 'hs512'):
                issues.append((f"JWT is signed with a symmetric algorithm ({alg.upper()}); "
                               f"verify the secret is not guessable", "warn"))

        if len(value) > 0 and len(value) < 16:
            issues.append((f"Cookie value is suspiciously short ({len(value)} chars) — may be predictable", "warn"))

        return name, issues

    def run(self, url):
        self.banner()
        self.log(f"Analyzing cookies from: {url}")

        headers = {
            'User-Agent': privacy_user_agent("Phantom"),
            'DNT': '1',
            'Sec-GPC': '1',
        }

        try:
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as res:
                all_cookies = res.info().get_all('Set-Cookie') or []
                status = res.getcode()
        except urllib.error.HTTPError as e:
            all_cookies = e.headers.get_all('Set-Cookie') or []
            status = e.code
        except Exception as e:
            self.log(f"Connection failed: {e}", "fail")
            return

        self.log(f"Server responded {status} — {len(all_cookies)} cookie(s) found")

        if not all_cookies:
            self.log("No Set-Cookie headers in response", "warn")
            self.log("Try a URL that triggers a session (e.g. /login or /api/auth)", "info")
            return

        total_issues = 0

        for raw in all_cookies:
            name, issues = self._analyze_cookie(raw)
            self.log(f"Cookie: {name}", "info")
            if not issues:
                self.log("  All flags set correctly", "pass")
            for msg, level in issues:
                self.log(f"  {msg}", level)
                total_issues += 1

        self.log("=" * 32)
        if total_issues > 0:
            self.log(f"{total_issues} cookie issue(s) found", "crit")
        else:
            self.log("All cookies properly configured", "pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phantom - Cookie & Session Token Analyzer")
    parser.add_argument("--url", required=True, help="Target URL (e.g. http://localhost:3456/api/login)")
    parser.add_argument('-v', '--version', action='version', version=f"Phantom {FRAMEWORK_VERSION}")
    args = parser.parse_args()

    Phantom().run(args.url)
