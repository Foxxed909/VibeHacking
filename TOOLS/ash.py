import sys
import os
import ssl
import socket
import argparse
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool, baseline_probe, is_catch_all, looks_like_html_shell
from privacy_guard import dns_probes_allowed, privacy_enabled

WAF_SIGNATURES = {
    "Cloudflare":   ["cf-ray", "cf-cache-status", "__cfduid"],
    "AWS WAF":      ["x-amzn-requestid", "x-amz-cf-id", "x-amz-apigw-id"],
    "Akamai":       ["akamai-grn", "x-check-cacheable", "x-akamai-transformed"],
    "Fastly":       ["x-fastly-request-id", "x-served-by", "x-cache"],
    "Sucuri":       ["x-sucuri-id", "x-sucuri-cache"],
    "Imperva":      ["x-iinfo", "x-cdn"],
    "Vercel":       ["x-vercel-id", "x-vercel-cache"],
}

TECH_HEADERS = [
    "server", "x-powered-by", "x-generator", "x-framework",
    "x-aspnet-version", "x-aspnetmvc-version",
]

PROBE_PATHS = [
    "robots.txt", "sitemap.xml", "humans.txt",
    "security.txt", ".well-known/security.txt",
    "favicon.ico",
]


class Ash(VibeTool):
    def __init__(self):
        super().__init__("Ash", "Domain Reconnaissance Agent")

    def run(self, url):
        self.banner()
        parsed = urlparse(url)
        host = parsed.hostname
        scheme = parsed.scheme or "https"

        self.log(f"Target: {url}")
        self.log(f"Host:   {host}")

        if privacy_enabled() and not dns_probes_allowed():
            self.log("DNS Resolution: skipped by privacy guard (set VIBE_ALLOW_DNS_PROBES=1 to run explicit DNS recon)", "warn")
        else:
            self._dns_probe(host)
        self._ssl_probe(host, scheme)
        self._http_fingerprint(url, host)
        self._path_probe(url)

    def _dns_probe(self, host):
        self.log("── DNS Resolution ──────────────────────")
        try:
            results = socket.getaddrinfo(host, None)
            ips = sorted({r[4][0] for r in results})
            for ip in ips:
                self.log(f"Resolved: {ip}", "pass")
        except socket.gaierror as e:
            self.log(f"DNS failed: {e}", "fail")

    def _ssl_probe(self, host, scheme):
        if scheme != "https":
            self.log("Skipping SSL probe — target is HTTP only", "warn")
            return

        self.log("── SSL / TLS ────────────────────────────")
        try:
            ctx = ssl.create_default_context()
            with socket.create_connection((host, 443), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    subject = dict(x[0] for x in cert.get("subject", ()))
                    issuer = dict(x[0] for x in cert.get("issuer", ()))
                    self.log(f"Common name : {subject.get('commonName', '?')}", "pass")
                    self.log(f"Issued by   : {issuer.get('organizationName', issuer.get('commonName', '?'))}")
                    self.log(f"Valid until : {cert.get('notAfter', '?')}")
                    sans = cert.get("subjectAltName") or ()
                    alts = [v for t, v in sans if t == "DNS"]
                    if alts:
                        self.log(f"Alt names   : {', '.join(alts[:8])}")
        except Exception as e:
            self.log(f"SSL probe failed: {e}", "fail")

    def _http_fingerprint(self, url, host):
        self.log("── Tech Fingerprint ─────────────────────")
        status, body, headers = self.safe_request(url)
        body = body or ""
        if status:
            self.log(f"HTTP status : {status}", "pass" if status < 400 else "warn")
        for h in TECH_HEADERS:
            val = headers.get(h) if headers else None
            if val:
                self.log(f"{h}: {val}", "warn")

        self.log("── WAF Detection ────────────────────────")
        found_waf = []
        hdr_keys = {k.lower(): v for k, v in (headers.items() if headers else [])}
        for waf, sigs in WAF_SIGNATURES.items():
            if any(s.lower() in hdr_keys for s in sigs):
                found_waf.append(waf)
        if found_waf:
            for w in found_waf:
                self.log(f"WAF detected: {w}", "warn")
        else:
            self.log("No common WAF signatures in headers", "info")

    def _path_probe(self, url):
        self.log("── Public Resource Probe ────────────────")
        base = url.rstrip("/")
        _, root_body, _, ctrl_body = baseline_probe(self, url)
        spa = looks_like_html_shell(root_body) and looks_like_html_shell(ctrl_body)
        if spa:
            self.log("SPA catch-all baseline active — shell clones ignored", "warn")

        for path in PROBE_PATHS:
            target = f"{base}/{path}"
            status, content, _ = self.safe_request(target)
            content = content or ""

            if status == 200:
                if is_catch_all(root_body, ctrl_body, content):
                    continue
                preview = content[:120].replace("\n", " ").strip()
                self.log(f"FOUND {path} ({len(content)} bytes) — {preview}", "hack")
            elif status == 403:
                self.log(f"Exists but blocked: {path} (403)", "warn")
            elif status == 401:
                self.log(f"Auth required: {path} (401)", "warn")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ash - Domain Reconnaissance Agent")
    parser.add_argument("--url", required=True, help="Target URL (e.g. https://example.com)")
    parser.add_argument("-v", "--version", action="version", version="Ash 2.0.0")
    args = parser.parse_args()

    Ash().run(args.url)
