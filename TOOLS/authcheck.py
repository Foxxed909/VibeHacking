#!/usr/bin/env python3
"""authcheck.py — verify the browser-assisted session the toolkit will use.

Loads session (VIBE_AUTH_FILE / VIBE_COOKIE / VIBE_UA / VIBE_HEADERS),
fetches a URL, and reports CHALLENGED / ANONYMOUS / AUTHENTICATED / REACHED.

    export VIBE_AUTH_FILE=$PWD/session_auth.json
    python TOOLS/authcheck.py --url https://app.example/dashboard
    python TOOLS/authcheck.py --url https://app.example/me --cookie "sid=abc"
"""
import argparse
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool, auth_context

CHALLENGE_MARKERS = ("just a moment", "verifying you are human", "attention required",
                     "cf-mitigated", "challenge-platform", "cf_chl", "__cf_chl",
                     "enable javascript and cookies")
LOGIN_MARKERS = ("sign in", "log in", "login", 'type="password"', "type='password'",
                 "forgot password", "create an account", "continue with google")
AUTHED_MARKERS = ("log out", "logout", "sign out", "dashboard", "my account",
                  "settings", "profile", "billing", "api key", "welcome back")


class AuthCheck(VibeTool):
    def __init__(self):
        super().__init__("AuthCheck", "Browser-Assisted Session Verifier")

    def run(self, url):
        self.banner()
        cookie, ua, extra = auth_context()
        srcs = []
        if cookie:
            srcs.append(f"cookie" + (" (incl. cf_clearance)" if "cf_clearance" in cookie else ""))
        if ua:
            srcs.append("user-agent")
        if extra:
            srcs.append(f"{len(extra)} extra header(s)")
        if not srcs:
            self.log("No session configured. Set VIBE_AUTH_FILE / VIBE_COOKIE.", "warn")
        else:
            self.log("Session loaded: " + ", ".join(srcs))
        self.log(f"Fetching {url} …")
        status, body, headers = self.safe_request(url)
        low = body.lower() if isinstance(body, str) else ""
        loc = headers.get("Location", "") if hasattr(headers, "get") else ""
        challenged = any(m in low for m in CHALLENGE_MARKERS)
        login_redirect = any(p in loc.lower() for p in ("/login", "/signin", "/auth"))
        looks_login = login_redirect or (
            sum(m in low for m in LOGIN_MARKERS) >= 2 and
            not any(m in low for m in AUTHED_MARKERS))
        looks_authed = any(m in low for m in AUTHED_MARKERS)
        self.log(f"HTTP {status}" + (f" -> {loc}" if loc else ""))
        if status == 0:
            self.log(f"Request failed: {body[:160]}", "fail")
            return 1
        if challenged:
            self.log("CHALLENGED — still behind anti-bot wall. Re-capture session in browser.", "crit")
            return 2
        if looks_login and not looks_authed:
            self.log("ANONYMOUS — reached app but looks logged-out. Log in and re-capture session.", "warn")
            return 3
        if looks_authed:
            self.log("AUTHENTICATED — logged-in content reached. Toolkit session is good to go.", "hack")
            return 0
        self.log("REACHED — no challenge/login wall, but no positive authed marker. Session likely working.", "pass")
        return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="AuthCheck - verify browser-assisted session")
    p.add_argument("--url", required=True)
    p.add_argument("--cookie", help="Raw Cookie header (sets VIBE_COOKIE)")
    p.add_argument("--auth-file", help="Session JSON file (sets VIBE_AUTH_FILE)")
    p.add_argument("--ua", help="User-Agent (sets VIBE_UA)")
    p.add_argument("-v", "--version", action="version", version="AuthCheck 1.0.0")
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
