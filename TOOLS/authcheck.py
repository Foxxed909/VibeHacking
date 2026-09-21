#!/usr/bin/env python3
"""
authcheck.py — verify the browser-assisted session the toolkit will use.

Loads your session (VIBE_AUTH_FILE / VIBE_COOKIE / VIBE_UA / VIBE_HEADERS, or
--cookie/--auth-file here), fetches a URL, and tells you honestly which state
you're in:

  * CHALLENGED  — still hitting a Cloudflare/anti-bot interstitial (session
                  missing/expired, or UA doesn't match the cf_clearance cookie)
  * ANONYMOUS   — reached the app but you look logged-out (login page/redirect)
  * AUTHENTICATED — reached real, logged-in content; the tools are good to go

Run this right after capturing a session, before any real testing.

    export VIBE_AUTH_FILE=$PWD/session_auth.json
    python TOOLS/authcheck.py --url https://app.bridgemind.ai/dashboard
    python TOOLS/authcheck.py --url https://app.example/me --cookie "cf_clearance=..; sid=.."
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool, FRAMEWORK_VERSION, auth_context

CHALLENGE_MARKERS = (
    "just a moment", "verifying you are human", "attention required",
    "cf-mitigated", "challenge-platform", "cf_chl", "__cf_chl", "enable javascript and cookies",
)
LOGIN_MARKERS = (
    "sign in", "log in", "login", "type=\"password\"", "type='password'",
    "forgot password", "create an account", "continue with google",
)
AUTHED_MARKERS = (
    "log out", "logout", "sign out", "dashboard", "my account", "settings",
    "profile", "billing", "api key", "welcome back",
)


class AuthCheck(VibeTool):
    def __init__(self):
        super().__init__("AuthCheck", "Browser-Assisted Session Verifier")

    def run(self, url):
        self.banner()
        cookie, ua, extra = auth_context()
        srcs = []
        if cookie:
            n = cookie.count("=")
            srcs.append(f"cookie ({n} value{'s' if n != 1 else ''}"
                        + (", incl. cf_clearance" if "cf_clearance" in cookie else "") + ")")
        if ua:
            srcs.append("user-agent")
        if extra:
            srcs.append(f"{len(extra)} extra header(s)")
        if not srcs:
            self.log("No session configured. Set VIBE_AUTH_FILE / VIBE_COOKIE (or pass "
                     "--cookie/--auth-file), or run helpers/browser/grab_session.js first.", "warn")
        else:
            self.log("Session loaded: " + ", ".join(srcs))

        self.log(f"Fetching {url} …")
        status, body, headers = self.safe_request(url)
        low = body.lower() if isinstance(body, str) else ""
        loc = headers.get("Location", "") if hasattr(headers, "get") else ""

        challenged = any(m in low for m in CHALLENGE_MARKERS)
        login_redirect = "/login" in loc.lower() or "/signin" in loc.lower() or "/auth" in loc.lower()
        looks_login = login_redirect or (sum(m in low for m in LOGIN_MARKERS) >= 2 and
                                         not any(m in low for m in AUTHED_MARKERS))
        looks_authed = any(m in low for m in AUTHED_MARKERS)

        self.log(f"HTTP {status}" + (f" -> {loc}" if loc else ""))
        if status == 0:
            self.log(f"Request failed: {body[:160]}", "fail")
            return 1
        if challenged:
            self.log("CHALLENGED — still behind the anti-bot wall. Re-capture the session in a "
                     "real browser (and make sure VIBE_UA matches the browser that solved it).", "crit")
            return 2
        if looks_login and not looks_authed:
            self.log("ANONYMOUS — reached the app but you look logged-out. Log in in the browser, "
                     "re-run grab_session.js, and try again.", "warn")
            return 3
        if looks_authed:
            self.log("AUTHENTICATED — logged-in content reached. The toolkit will reuse this "
                     "session; go test the authenticated surface.", "hack")
            return 0
        self.log("REACHED — no challenge and no clear login wall, but I couldn't positively confirm "
                 "a logged-in marker. Eyeball the response; the session is likely working.", "pass")
        return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="AuthCheck - verify the browser-assisted session")
    p.add_argument("--url", required=True, help="A URL that should return logged-in content")
    p.add_argument("--cookie", help="Raw Cookie header (sets VIBE_COOKIE for this run)")
    p.add_argument("--auth-file", help="Session JSON file (sets VIBE_AUTH_FILE for this run)")
    p.add_argument("--ua", help="User-Agent to match the session (sets VIBE_UA)")
    p.add_argument("-v", "--version", action="version", version=f"AuthCheck {FRAMEWORK_VERSION}")
    args = p.parse_args(argv)
    if args.cookie:
        os.environ["VIBE_COOKIE"] = args.cookie
    if args.auth_file:
        os.environ["VIBE_AUTH_FILE"] = args.auth_file
    if args.ua:
        os.environ["VIBE_UA"] = args.ua
    return AuthCheck().run(args.url)


if __name__ == "__main__":
    raise SystemExit(main())
