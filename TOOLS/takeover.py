#!/usr/bin/env python3
"""
takeover.py — Subdomain takeover detection (INTERNAL edition).

Finds dangling DNS records: a subdomain of yours that still CNAMEs to a
third-party service (S3, GitHub Pages, Heroku, Azure, Fastly, Shopify,
Netlify, …) whose resource has been deleted, so anyone can re-register it and
serve content on your name.

It resolves the CNAME chain over DNS-over-HTTPS (no dig required, works behind
a proxy) and only calls a takeover when BOTH hold: the CNAME points at a known
takeover-prone service AND the live HTTP response shows that service's
"unclaimed resource" fingerprint (or the CNAME target itself is NXDOMAIN). A
subdomain that merely uses a service and serves real content is reported as
safe — pointing at S3 is not a bug; pointing at a *deleted* bucket is.

    python TOOLS/takeover.py --host assets.your-app.example
    python TOOLS/takeover.py --list subdomains.txt
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

# service -> (CNAME suffixes that route to it, unclaimed-response fingerprints)
SERVICES = {
    "AWS S3":        ((".s3.amazonaws.com", ".s3-website", ".amazonaws.com"),
                      ("NoSuchBucket", "The specified bucket does not exist")),
    "GitHub Pages":  ((".github.io",),
                      ("There isn't a GitHub Pages site here", "For root URLs (like http://example.com/) you must provide an index")),
    "Heroku":        ((".herokuapp.com", ".herokudns.com"),
                      ("No such app", "herokucdn.com/error-pages/no-such-app.html")),
    "Azure":         ((".azurewebsites.net", ".cloudapp.net", ".cloudapp.azure.com",
                       ".trafficmanager.net", ".blob.core.windows.net", ".azureedge.net"),
                      ("404 Web Site not found", "The resource you are looking for has been removed")),
    "Fastly":        ((".fastly.net", ".fastlylb.net"),
                      ("Fastly error: unknown domain",)),
    "Shopify":       ((".myshopify.com",),
                      ("Sorry, this shop is currently unavailable", "Only one step left")),
    "Netlify":       ((".netlify.app", ".netlify.com"),
                      ("Not Found - Request ID", "no such site")),
    "Surge.sh":      ((".surge.sh",),
                      ("project not found",)),
    "Bitbucket":     ((".bitbucket.io",),
                      ("Repository not found",)),
    "Zendesk":       ((".zendesk.com",),
                      ("Help Center Closed", "this help center no longer exists")),
    "Pantheon":      ((".pantheonsite.io",),
                      ("The gods are wise", "404 error unknown site")),
    "Tumblr":        ((".domains.tumblr.com",),
                      ("Whatever you were looking for doesn't currently exist",)),
    "Wordpress":     ((".wordpress.com",),
                      ("Do you want to register",)),
    "Ghost":         ((".ghost.io",),
                      ("The thing you were looking for is no longer here",)),
    "Cargo":         ((".cargocollective.com",),
                      ("404 Not Found",)),
    "Readme.io":     ((".readme.io",),
                      ("Project doesnt exist",)),
}

DOH_ENDPOINTS = ("https://dns.google/resolve", "https://cloudflare-dns.com/dns-query")


class Takeover(VibeTool):
    def __init__(self):
        super().__init__("Takeover", "Subdomain Takeover Detection")
        self.findings = 0

    def _doh(self, name, rrtype):
        for base in DOH_ENDPOINTS:
            q = base + "?" + urllib.parse.urlencode({"name": name, "type": rrtype})
            try:
                req = urllib.request.Request(q, headers={
                    "Accept": "application/dns-json",
                    "User-Agent": privacy_user_agent("Takeover")})
                with urllib.request.urlopen(req, timeout=8) as r:
                    return json.loads(r.read().decode("utf-8", "replace"))
            except Exception:
                continue
        return None

    def _cname_chain(self, host):
        """Return (chain, final_status) — CNAME targets and the DNS rcode name."""
        chain, seen, status = [], set(), "NOERROR"
        name = host
        for _ in range(8):
            data = self._doh(name, "CNAME")
            if data is None:
                return chain, "DNS_ERROR"
            status = {0: "NOERROR", 3: "NXDOMAIN"}.get(data.get("Status"), str(data.get("Status")))
            answers = [a for a in data.get("Answer", []) if a.get("type") == 5]
            if not answers:
                break
            target = answers[0]["data"].rstrip(".")
            if target in seen:
                break
            seen.add(target)
            chain.append(target)
            name = target
        return chain, status

    def _fetch(self, host):
        for scheme in ("https", "http"):
            try:
                req = urllib.request.Request(f"{scheme}://{host}/",
                                             headers={"User-Agent": privacy_user_agent("Takeover")})
                with urllib.request.urlopen(req, timeout=8) as r:
                    return r.getcode(), r.read(20000).decode("utf-8", "replace")
            except urllib.error.HTTPError as e:
                return e.code, e.read(20000).decode("utf-8", "replace")
            except Exception:
                continue
        return 0, ""

    def _match_service(self, chain):
        for target in chain:
            low = target.lower()
            for svc, (suffixes, fps) in SERVICES.items():
                if any(low.endswith(sfx) or sfx in low for sfx in suffixes):
                    return svc, target, fps
        return None, None, None

    def check(self, host):
        host = host.strip().rstrip(".")
        if not host:
            return
        chain, status = self._cname_chain(host)
        if not chain:
            self.log(f"{host}: no CNAME (A/AAAA record or apex) — not a CNAME-takeover candidate.", "info")
            return
        svc, target, fps = self._match_service(chain)
        arrow = " -> ".join([host] + chain)
        if not svc:
            self.log(f"{host}: CNAME {arrow} — not a known takeover-prone service.", "info")
            return

        # Signal 1: the CNAME target itself does not resolve (dangling pointer).
        tgt_a = self._doh(target, "A")
        tgt_dangling = tgt_a is not None and tgt_a.get("Status") == 3  # NXDOMAIN

        # Signal 2: live response shows the service's unclaimed fingerprint.
        code, body = self._fetch(host)
        fp_hit = next((fp for fp in fps if fp.lower() in body.lower()), None)

        if fp_hit:
            self.log(f"TAKEOVER CONFIRMED — {host} -> {svc} ({target}); unclaimed-resource "
                     f"fingerprint present: {fp_hit!r}", "hack")
            self.findings += 1
        elif tgt_dangling:
            self.log(f"TAKEOVER LIKELY — {host} CNAMEs to {svc} target {target} which is "
                     f"NXDOMAIN (dangling). Claim it on {svc} to confirm.", "crit")
            self.findings += 1
        else:
            self.log(f"{host}: points to {svc} ({target}) and serves live content — claimed, "
                     f"not vulnerable. ({arrow})", "pass")

    def run(self, hosts):
        self.banner()
        self.log(f"Checking {len(hosts)} host(s) for dangling third-party CNAMEs.")
        for h in hosts:
            self.check(h)
        self.log("=" * 40)
        if self.findings:
            self.log(f"TAKEOVER SWEEP COMPLETE — {self.findings} takeover risk(s). "
                     "Confirm ownership before claiming any resource.", "hack")
        else:
            self.log("No subdomain takeover risk found — no dangling third-party CNAMEs.", "pass")
        return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="Takeover - subdomain takeover detection")
    p.add_argument("--host", help="Single subdomain to check, e.g. assets.your-app.example")
    p.add_argument("--list", help="File with one subdomain per line")
    p.add_argument("-v", "--version", action="version", version="Takeover 1.0.0")
    args = p.parse_args(argv)
    hosts = []
    if args.host:
        hosts.append(args.host)
    if args.list:
        with open(args.list, encoding="utf-8") as f:
            hosts += [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    if not hosts:
        p.error("provide --host or --list")
    return Takeover().run(hosts)


if __name__ == "__main__":
    raise SystemExit(main())
