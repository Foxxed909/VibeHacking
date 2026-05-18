import sys
import os
import argparse
import base64
import json
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool


class Phantom(VibeTool):
    def __init__(self):
        super().__init__("Phantom", "Cookie & Session Token Analyzer")

    def _decode_jwt(self, token):
        try:
            parts = token.split('.')
            if len(parts) != 3:
                return None
            padding = 4 - len(parts[1]) % 4
            payload = base64.urlsafe_b64decode(parts[1] + '=' * padding)
            return json.loads(payload)
        except Exception:
            return None

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

        jwt_payload = self._decode_jwt(value)
        if jwt_payload:
            issues.append((f"JWT detected — payload: {str(jwt_payload)[:120]}", "hack"))
            if 'exp' not in jwt_payload:
                issues.append(("JWT has no expiry (exp claim missing) — token lives forever", "crit"))
            if jwt_payload.get('alg', '').lower() == 'none':
                issues.append(("JWT uses alg:none — CRITICAL auth bypass possible", "crit"))

        if len(value) > 0 and len(value) < 16:
            issues.append((f"Cookie value is suspiciously short ({len(value)} chars) — may be predictable", "warn"))

        return name, issues

    def run(self, url):
        self.banner()
        self.log(f"Analyzing cookies from: {url}")

        headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 Chrome/120.0.0.0 Safari/537.36'
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
                self.log(f"  All flags set correctly", "pass")
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
    parser.add_argument('-v', '--version', action='version', version='Phantom 1.0.0')
    args = parser.parse_args()

    Phantom().run(args.url)
