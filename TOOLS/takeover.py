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

With --enum it first *discovers* subdomains for a domain: a built-in wordlist
(plus your --wordlist), resolved over DoH into a live map — which hosts exist
(A/AAAA), which are CNAMEs and to what, which are absent — optionally enriched
from Certificate Transparency logs (--ct, best-effort). Then it runs the
takeover check on every CNAME it found. This closes the old gap where the tool
could only *check* names you already knew, never *find* them.

    python TOOLS/takeover.py --host assets.your-app.example   # check one
    python TOOLS/takeover.py --list subdomains.txt            # check a list
    python TOOLS/takeover.py --enum your-app.example          # discover + map + check
    python TOOLS/takeover.py --enum your-app.example --ct --wordlist big.txt
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

# Common subdomain labels for brute enumeration (DoH-resolved, no target traffic).
SUBDOMAIN_WORDLIST = (
    "www", "app", "api", "api2", "apis", "admin", "dashboard", "portal", "account",
    "accounts", "auth", "login", "sso", "id", "identity", "docs", "doc", "developer",
    "developers", "dev", "staging", "stage", "test", "testing", "qa", "uat", "sandbox",
    "demo", "beta", "alpha", "preview", "next", "new", "old", "legacy", "blog", "news",
    "cdn", "cdn2", "assets", "asset", "static", "media", "img", "images", "files",
    "file", "download", "downloads", "dl", "updates", "update", "release", "releases",
    "status", "health", "metrics", "grafana", "kibana", "prometheus", "monitor",
    "mail", "smtp", "imap", "pop", "webmail", "email", "mx", "ns", "ns1", "ns2",
    "vpn", "remote", "gateway", "gw", "proxy", "edge", "lb", "origin", "internal",
    "intranet", "corp", "git", "gitlab", "github", "ci", "cd", "jenkins", "build",
    "registry", "docker", "k8s", "kube", "cluster", "db", "database", "sql", "redis",
    "cache", "queue", "mq", "storage", "s3", "bucket", "backup", "backups", "vault",
    "billing", "pay", "payment", "payments", "checkout", "store", "shop", "cart",
    "support", "help", "helpdesk", "ticket", "tickets", "chat", "community", "forum",
    "ws", "wss", "socket", "stream", "live", "voice", "video", "call", "meet",
    "m", "mobile", "web", "app2", "console", "manage", "control", "panel", "cpanel",
    "webhook", "webhooks", "hooks", "callback", "events", "notify", "push",
    "search", "analytics", "track", "tracking", "pixel", "ads", "ad", "go", "link",
    "bridgespace", "bridgeagent", "bridgevoice", "bridgemcp", "bridgeswarm",
    "bridgeboard", "bridgememory", "bridge", "space", "agent", "swarm", "mcp",
)

CT_ENDPOINTS = ("https://crt.sh/?q=%25.{d}&output=json",)


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

    def _resolve(self, name):
        """Classify a name via DoH: ('cname', target) | ('addr', ip) | None (absent)."""
        cn = self._doh(name, "CNAME")
        if cn is not None:
            ans = [a for a in cn.get("Answer", []) if a.get("type") == 5]
            if ans:
                return ("cname", ans[0]["data"].rstrip("."))
            if cn.get("Status") == 3:  # NXDOMAIN — definitively absent
                return None
        a = self._doh(name, "A")
        if a is not None and a.get("Status") == 0:
            addrs = [r["data"] for r in a.get("Answer", []) if r.get("type") == 1]
            if addrs:
                return ("addr", addrs[0])
        return None

    def _ct_names(self, domain):
        """Best-effort Certificate Transparency lookup — silent if unreachable."""
        names = set()
        for tmpl in CT_ENDPOINTS:
            url = tmpl.format(d=urllib.parse.quote(domain))
            try:
                req = urllib.request.Request(url, headers={"User-Agent": privacy_user_agent("Takeover")})
                with urllib.request.urlopen(req, timeout=15) as r:
                    for row in json.loads(r.read().decode("utf-8", "replace")):
                        for field in ("common_name", "name_value"):
                            for nm in str(row.get(field, "")).split("\n"):
                                nm = nm.strip().lstrip("*.").lower()
                                if nm.endswith(domain) and "@" not in nm:
                                    names.add(nm)
            except Exception:
                continue
        return names

    def enumerate(self, domain, wordlist, use_ct):
        self.banner()
        domain = domain.strip().rstrip(".").lower()
        candidates = {f"{w}.{domain}" for w in wordlist} | {domain}
        ct_hits = self._ct_names(domain) if use_ct else set()
        if use_ct:
            self.log(f"CT logs: {len(ct_hits) or 'none reachable'} name(s) found." if ct_hits
                     else "CT logs unreachable from here — continuing with wordlist only.")
        candidates |= ct_hits
        self.log(f"Resolving {len(candidates)} candidate name(s) over DoH…")

        live_addr, live_cname, absent = [], [], 0
        for name in sorted(candidates):
            res = self._resolve(name)
            if res is None:
                absent += 1
            elif res[0] == "addr":
                live_addr.append((name, res[1]))
            else:
                live_cname.append((name, res[1]))

        self.log("=" * 40)
        self.log(f"LIVE SUBDOMAIN MAP for {domain} — "
                 f"{len(live_addr) + len(live_cname)} live, {absent} absent", "hack")
        for name, ip in live_addr:
            self.log(f"  A     {name} -> {ip}", "info")
        for name, tgt in live_cname:
            self.log(f"  CNAME {name} -> {tgt}", "warn")

        if live_cname:
            self.log("-" * 40)
            self.log(f"Running takeover check on {len(live_cname)} CNAME host(s)…")
            for name, _ in live_cname:
                self.check(name)
        else:
            self.log("No CNAME subdomains found — nothing to takeover-check.", "pass")

        self.log("=" * 40)
        if self.findings:
            self.log(f"ENUM COMPLETE — {self.findings} takeover risk(s) across "
                     f"{len(live_cname) + len(live_addr)} live host(s).", "hack")
        else:
            self.log(f"ENUM COMPLETE — {len(live_addr) + len(live_cname)} live host(s) mapped, "
                     "no takeover risk.", "pass")
        return 0

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
    p = argparse.ArgumentParser(description="Takeover - subdomain enumeration + takeover detection")
    p.add_argument("--host", help="Single subdomain to check, e.g. assets.your-app.example")
    p.add_argument("--list", help="File with one subdomain per line")
    p.add_argument("--enum", metavar="DOMAIN",
                   help="Discover subdomains for a domain (DoH wordlist), map them, then takeover-check")
    p.add_argument("--wordlist", help="Extra subdomain labels/names, one per line, added to --enum")
    p.add_argument("--ct", action="store_true",
                   help="Also query Certificate Transparency logs during --enum (best-effort)")
    p.add_argument("-v", "--version", action="version", version="Takeover 2.0.0")
    args = p.parse_args(argv)

    if args.enum:
        words = list(SUBDOMAIN_WORDLIST)
        if args.wordlist:
            with open(args.wordlist, encoding="utf-8") as f:
                words += [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
        return Takeover().enumerate(args.enum, words, args.ct)

    hosts = []
    if args.host:
        hosts.append(args.host)
    if args.list:
        with open(args.list, encoding="utf-8") as f:
            hosts += [ln.strip() for ln in f if ln.strip() and not ln.startswith("#")]
    if not hosts:
        p.error("provide --host, --list, or --enum")
    return Takeover().run(hosts)


if __name__ == "__main__":
    raise SystemExit(main())
