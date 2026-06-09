import sys
import os
import ssl
import socket
import argparse
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool

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

        self._dns_probe(host)
        self._ssl_probe(host, scheme)
        self._http_fingerprint(url, host)
        self._path_probe(url)

    # ── DNS ──────────────────────────────────────────────────────────────────

    def _dns_probe(self, host):
        self.log("── DNS Resolution ──────────────────────")
        try:
            results = socket.getaddrinfo(host, None)
            ips = sorted({r[4][0] for r in results})
            for ip in ips:
                self.log(f"Resolved: {ip}", "pass")
        except socket.gaierror as e:
            self.log(f"DNS failed: {e}", "fail")

    # ── SSL ──────────────────────────────────────────────────────────────────

    def _ssl_probe(self, host, scheme):
        if scheme != "https":
            self.log("Skipping SSL probe — target is HTTP only", "warn")
            return

        self.log("── SSL / TLS ────────────────────────────")
        try:
            ctx = ssl.create_default_context()
            with ctx.wrap_socket(socket.create_connection((host, 443), timeout=8), server_hostname=host) as s:
                cert = s.getpeercert()
                subject = dict(x[0] for x in cert.get("subject", []))
                issuer  = dict(x[0] for x in cert.get("issuer", []))
                san     = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]

                self.log(f"Common name : {subject.get('commonName', 'N/A')}", "pass")
                self.log(f"Issued by   : {issuer.get('organizationName', 'N/A')}", "info")
                self.log(f"Valid until : {cert.get('notAfter', 'N/A')}", "info")
                if san:
                    self.log(f"Alt names   : {', '.join(san[:8])}" + (" …" if len(san) > 8 else ""), "info")
        except ssl.SSLCertVerificationError as e:
            self.log(f"SSL cert invalid: {e}", "crit")
        except Exception as e:
            self.log(f"SSL probe failed: {e}", "fail")

    # ── HTTP fingerprint ─────────────────────────────────────────────────────

    def _http_fingerprint(self, url, host):
        self.log("── Tech Fingerprint ─────────────────────")
        status, body, headers = self.safe_request(url)

        if status == 0:
            self.log(f"Connection failed: {body}", "fail")
            return

        self.log(f"HTTP status : {status}", "pass" if status < 400 else "warn")

        for h in TECH_HEADERS:
            val = headers.get(h) or headers.get(h.title())
            if val:
                self.log(f"{h}: {val}", "warn")

        self._detect_waf(headers)
        self._detect_tech_in_body(body)

    def _detect_waf(self, headers):
        self.log("── WAF Detection ────────────────────────")
        detected = []
        lower_headers = {k.lower(): v for k, v in headers.items()}
        for waf, sigs in WAF_SIGNATURES.items():
            if any(sig in lower_headers for sig in sigs):
                detected.append(waf)

        if detected:
            for w in detected:
                self.log(f"WAF detected: {w}", "warn")
        else:
            self.log("No known WAF signatures found", "info")

    def _detect_tech_in_body(self, body):
        markers = {
            "React":      ["react.development.js", "react.production.min.js", "_reactRootContainer", "__NEXT_DATA__"],
            "Next.js":    ["__NEXT_DATA__", "/_next/static/"],
            "Vue":        ["vue.min.js", "__vue__", "v-app"],
            "Angular":    ["ng-version=", "angular.min.js"],
            "jQuery":     ["jquery.min.js", "jquery-"],
            "Bootstrap":  ["bootstrap.min.css", "bootstrap.bundle"],
            "Tailwind":   ["tailwind.min.css", "cdn.tailwindcss"],
            "WordPress":  ["wp-content/", "wp-includes/", "xmlrpc.php"],
            "Shopify":    ["cdn.shopify.com", "Shopify.theme"],
            "Laravel":    ["laravel_session", "XSRF-TOKEN"],
        }

        found = []
        for tech, sigs in markers.items():
            if any(sig in body for sig in sigs):
                found.append(tech)

        if found:
            self.log("── Front-End Stack ──────────────────────")
            for t in found:
                self.log(f"Detected: {t}", "info")

    # ── Path probe ───────────────────────────────────────────────────────────

    def _path_probe(self, url):
        self.log("── Public Resource Probe ────────────────")
        base = url.rstrip("/")

        for path in PROBE_PATHS:
            target = f"{base}/{path}"
            status, content, _ = self.safe_request(target)

            if status == 200:
                preview = content[:120].replace("\n", " ").strip()
                self.log(f"FOUND {path} ({len(content)} bytes) — {preview}", "hack")
            elif status == 403:
                self.log(f"Exists but blocked: {path} (403)", "warn")
            elif status == 401:
                self.log(f"Auth required: {path} (401)", "warn")
            # 404 / others are expected noise — skip


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ash - Domain Reconnaissance Agent")
    parser.add_argument("--url", required=True, help="Target URL (e.g. https://example.com)")
    parser.add_argument("-v", "--version", action="version", version="Ash 2.0.0")
    args = parser.parse_args()

    Ash().run(args.url)
