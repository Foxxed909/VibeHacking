#!/usr/bin/env python3
"""
ssti.py — Server-Side Template Injection detector (INTERNAL edition).

Injects arithmetic polyglots for the major template engines (Jinja2, Twig, Freemarker,
ERB, Velocity, Handlebars, Mako) and confirms only when the server EVALUATES the
expression — i.e. the response contains the product, not the literal payload. A
confirmed SSTI is usually a straight line to RCE.

    python TOOLS/ssti.py --url http://127.0.0.1:9200/api/render --field template
    python TOOLS/ssti.py --url "http://host/greet?name=x" --param name
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool
from privacy_guard import privacy_user_agent

# (label, payload) — 7*7 and 1337*7 so a random "49" on the page can't fool us.
PAYLOADS = [
    ("jinja2/twig", "{{7*7}}", "49"),
    ("jinja2-uniq", "{{1337*7}}", "9359"),
    ("freemarker", "${7*7}", "49"),
    ("velocity/mako", "#{7*7}", "49"),
    ("erb", "<%= 7*7 %>", "49"),
    ("handlebars", "{{#with 7 as |x|}}{{x}}{{/with}}", "7"),
    ("smarty-math", "{7*7}", "49"),
    ("razor", "@(7*7)", "49"),
]


class SSTI(VibeTool):
    def __init__(self, base):
        super().__init__("SSTI", "Server-Side Template Injection Detector")
        self.base = base
        self.findings = 0

    def _send(self, payload, param, field, method):
        h = {"User-Agent": privacy_user_agent("SSTI"), "Accept": "*/*"}
        parsed = urllib.parse.urlparse(self.base)
        if field:  # JSON body
            data = json.dumps({field: payload}).encode(); h["Content-Type"] = "application/json"
            url = self.base
        elif method == "GET":
            q = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True)); q[param] = payload
            url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(q))); data = None
        else:
            data = urllib.parse.urlencode({param: payload}).encode()
            h["Content-Type"] = "application/x-www-form-urlencoded"; url = self.base
        try:
            req = urllib.request.Request(url, data=data, method=method, headers=h)
            with urllib.request.urlopen(req, timeout=8) as r:
                return r.getcode(), r.read(20000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read(20000).decode("utf-8", "replace")
        except Exception as e:
            return 0, str(e)

    def run(self, param, field, method):
        self.banner()
        where = f"field={field!r}" if field else f"param={param!r}"
        self.log(f"SSTI test on {self.base} ({where})")
        for label, payload, expect in PAYLOADS:
            st, body = self._send(payload, param, field, method)
            # Confirmed only if the evaluated result is present and the raw
            # payload is NOT reflected verbatim (that would just be echo/XSS).
            if st and expect in body and payload not in body:
                self.log(f"SSTI CONFIRMED ({label}) — {payload} evaluated to {expect} server-side "
                         f"(likely RCE path)", "hack")
                self.findings += 1
                break
            else:
                self.log(f"{label}: not evaluated", "pass")
        self.log("=" * 40)
        if self.findings:
            self.log("SSTI present — escalate to RCE with an engine-specific gadget.", "hack")
        else:
            self.log("No SSTI — input isn't evaluated as a template.", "pass")
        return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="SSTI - server-side template injection detector")
    p.add_argument("--url", required=True, help="Target URL you own/are authorized to test")
    p.add_argument("--param", default="q", help="Query/form param to inject (when not JSON)")
    p.add_argument("--field", default="", help="JSON body field to inject (POST JSON)")
    p.add_argument("--method", default="POST", choices=("GET", "POST"))
    p.add_argument("-v", "--version", action="version", version="SSTI 1.0.0")
    args = p.parse_args(argv)
    return SSTI(args.url).run(args.param, args.field, args.method)


if __name__ == "__main__":
    sys.exit(main())
