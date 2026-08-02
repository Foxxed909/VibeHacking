#!/usr/bin/env python3
"""
credstuff.py — Credential stuffing / login brute-force auditor (INTERNAL).

random_roll checks the password *policy*; this checks whether the login endpoint
actually resists an attacker throwing credentials at it. It learns the failure
response, sprays a wordlist (or provided creds), and reports:
  * any credentials that WORK,
  * whether the endpoint locks out / rate-limits after N attempts, or has NO
    throttle at all (freely brute-forceable),
  * whether a correct password triggers a second factor (2FA).

    python TOOLS/credstuff.py --url http://127.0.0.1:8800/ --login /login --user demo
    python TOOLS/credstuff.py --url http://host --login /api/login --user-field email \
        --users users.txt --passwords rockyou-top.txt
"""
import argparse
import difflib
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool
from privacy_guard import privacy_user_agent

COMMON_PASSWORDS = [
    "123456", "password", "123456789", "12345678", "12345", "qwerty", "admin",
    "abc123", "letmein", "welcome", "monkey", "111111", "iloveyou", "admin123",
    "password1", "1234567", "sunshine", "princess", "dragon", "passw0rd",
    "demo1234", "test1234", "root", "toor", "changeme", "secret", "default",
]
TWO_FACTOR_HINTS = ("otp", "2fa", "two-factor", "two factor", "verification code",
                    "verify your", "authenticator", "one-time", "mfa", "totp", "sms code")
LOCK_HINTS = ("locked", "too many", "try again later", "rate limit", "temporarily disabled",
              "account has been locked", "blocked")


class CredStuff(VibeTool):
    def __init__(self, base):
        super().__init__("CredStuff", "Credential Stuffing / Brute-Force Auditor")
        self.base = base.rstrip("/")
        self.found = []

    def _attempt(self, login_path, user, password, user_field, pass_field, extra):
        data = dict(extra)
        data[user_field] = user
        data[pass_field] = password
        body = urllib.parse.urlencode(data).encode()
        headers = {"User-Agent": privacy_user_agent("CredStuff"),
                   "Content-Type": "application/x-www-form-urlencoded",
                   "Accept": "text/html,application/json,*/*"}
        start = time.perf_counter()
        try:
            # Don't follow redirects — a 302/303 to a dashboard is a strong
            # success signal we want to see directly.
            class _NR(urllib.request.HTTPRedirectHandler):
                def redirect_request(self, *a, **k): return None
            op = urllib.request.build_opener(_NR())
            req = urllib.request.Request(self.base + login_path, data=body, method="POST", headers=headers)
            with op.open(req, timeout=8) as r:
                return r.getcode(), r.read(20000).decode("utf-8", "replace"), r.headers, time.perf_counter() - start
        except urllib.error.HTTPError as e:
            return e.code, e.read(20000).decode("utf-8", "replace"), e.headers, time.perf_counter() - start
        except Exception as e:
            return 0, str(e), {}, time.perf_counter() - start

    @staticmethod
    def _sets_session(headers):
        try:
            return "set-cookie" in {k.lower() for k in headers.keys()}
        except Exception:
            return False

    def run(self, login_path, users, passwords, user_field, pass_field, extra, delay):
        self.banner()
        self.log(f"Target login: {self.base}{login_path}  field={user_field!r}")

        # Learn the FAILURE signature with a definitely-wrong password.
        f_st, f_body, f_hdr, _ = self._attempt(login_path, users[0], "wrong_" + str(int(time.time())),
                                               user_field, pass_field, extra)
        if f_st == 0:
            self.log(f"Login request failed: {f_body}", "fail")
            return 2
        fail_sig = (f_st, self._sets_session(f_hdr))
        self.log(f"Failure signature: status={f_st}, sets-session={fail_sig[1]}, len={len(f_body)}")

        attempts = 0
        lockout_at = None
        throttled = False
        combos = [(u, p) for u in users for p in passwords]
        self.log(f"Spraying {len(combos)} credential pair(s)...")

        for user, password in combos:
            attempts += 1
            st, body, hdr, lat = self._attempt(login_path, user, password, user_field, pass_field, extra)
            low = body.lower()

            if any(h in low for h in LOCK_HINTS) or st == 429:
                lockout_at = lockout_at or attempts
                throttled = True
                self.log(f"THROTTLE/LOCKOUT detected after {attempts} attempt(s) (status {st})", "pass")
                break

            sess = self._sets_session(hdr)
            # Success = differs from the failure signature: a new session cookie,
            # a redirect the failure didn't produce, or a clearly different body.
            success = (
                (sess and not fail_sig[1]) or
                (st in (301, 302, 303) and f_st not in (301, 302, 303)) or
                (st == 200 and f_st in (401, 403)) or
                (difflib.SequenceMatcher(None, f_body, body).ratio() < 0.6 and st < 400)
            )
            if success:
                two_fa = any(h in low for h in TWO_FACTOR_HINTS)
                if two_fa:
                    self.log(f"VALID PASSWORD (2FA gate) — {user} : <redacted> (second factor required)", "warn")
                else:
                    self.log(f"CREDENTIALS ACCEPTED — {user} : <redacted> (no second factor)", "hack")
                self.found.append((user, password, two_fa))
            if delay:
                time.sleep(delay)

        self.log("=" * 40)
        # Posture verdict.
        if lockout_at:
            self.log(f"Lockout/rate-limit kicked in after {lockout_at} attempt(s) — brute-force resisted.", "pass")
        elif attempts >= 15 and not throttled:
            self.log(f"NO lockout or rate-limit after {attempts} attempts — endpoint is freely brute-forceable.", "crit")
        if self.found:
            weak = [f for f in self.found if not f[2]]
            self.log(f"{len(self.found)} valid credential(s) found"
                     + (f", {len(weak)} with NO 2FA" if weak else "") + ".", "hack")
            return 0
        self.log("No credentials cracked from the wordlist.", "pass")
        return 0


def _load_list(path_or_val, fallback):
    if not path_or_val:
        return fallback
    if os.path.isfile(path_or_val):
        with open(path_or_val, encoding="utf-8", errors="replace") as fh:
            return [ln.strip() for ln in fh if ln.strip()]
    return [path_or_val]


def main(argv=None):
    p = argparse.ArgumentParser(description="CredStuff - credential stuffing / brute-force auditor")
    p.add_argument("--url", required=True, help="Target base URL you own/are authorized to test")
    p.add_argument("--login", default="/login", help="Login path (default: /login)")
    p.add_argument("--user", default="", help="A single username/email to target")
    p.add_argument("--users", default="", help="File of usernames (one per line)")
    p.add_argument("--passwords", default="", help="File of passwords (default: built-in common list)")
    p.add_argument("--user-field", default="username", help="Username field name (e.g. email)")
    p.add_argument("--pass-field", default="password", help="Password field name")
    p.add_argument("--data", default="", help="Extra fixed fields, e.g. 'csrf=abc'")
    p.add_argument("--delay", type=float, default=0.0, help="Seconds between attempts")
    p.add_argument("-v", "--version", action="version", version="CredStuff 1.0.0")
    args = p.parse_args(argv)

    users = _load_list(args.users, None) or ([args.user] if args.user else ["admin"])
    passwords = _load_list(args.passwords, COMMON_PASSWORDS)
    extra = dict(urllib.parse.parse_qsl(args.data)) if args.data else {}
    return CredStuff(args.url).run(args.login, users, passwords, args.user_field,
                                   args.pass_field, extra, args.delay)


if __name__ == "__main__":
    sys.exit(main())
