#!/usr/bin/env python3
"""
cloud_scout.py v2.0 — Cloudflare, AWS & Vercel (.vercel.app) Edge & Environment Prober.

Fingerprints and audits applications running on or backed by:
  - Cloudflare (Edge CDN, WAF, Workers/Pages, `/cdn-cgi/trace`, `CF-Ray`, `CF-Cache-Status`)
  - Vercel / `.vercel.app` (Edge Network, Serverless Functions, Next.js `/_next`, `x-vercel-id`, `x-vercel-cache`)
  - AWS (CloudFront `x-amz-cf-pop`, ALB/API Gateway `x-amzn-RequestId`, Lambda URLs, S3 `<ListBucketResult>`)
  - Sensitive cloud/config/admin paths (`--targets`)
"""
import argparse
import os
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool

EXPECTED_PUBLIC = (
    "index", "home", "login", "signin", "sign-in", "register", "signup",
    "landing", "about", "contact", "favicon", "robots", "sitemap", "/", "",
)

SENSITIVE_MARKERS = (
    "admin", "dashboard", "vault", "config", "secret", "backup", "internal",
    "private", "debug", ".env", ".git", "db", "database", "credential", "key",
)

DEFAULT_TARGETS = [
    "login.html", "index.html", "files.html",
    "admin.html", "dashboard.html", "vault.html",
]


def _classify(path):
    p = path.strip("/").lower()
    if any(m in p for m in SENSITIVE_MARKERS):
        return "sensitive"
    stem = p.rsplit("/", 1)[-1].split(".")[0]
    if stem in EXPECTED_PUBLIC or p in EXPECTED_PUBLIC:
        return "public"
    return "neutral"


def detect_cloud_stack(url, headers_dict):
    """Return a structured summary of detected Cloudflare, Vercel, and AWS edge layers."""
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    hdrs = {str(k).lower(): str(v) for k, v in (headers_dict or {}).items()}
    server = hdrs.get("server", "").lower()

    providers = []
    details = {}

    # 1. Cloudflare
    if (
        "cf-ray" in hdrs
        or "cf-cache-status" in hdrs
        or "cloudflare" in server
        or host.endswith((".workers.dev", ".pages.dev", ".cloudflare.com"))
    ):
        providers.append("Cloudflare")
        details["cf_ray"] = hdrs.get("cf-ray", "detected")
        details["cf_cache_status"] = hdrs.get("cf-cache-status", "n/a")

    # 2. Vercel (.vercel.app)
    if (
        "x-vercel-id" in hdrs
        or "x-vercel-cache" in hdrs
        or "vercel" in server
        or host.endswith((".vercel.app", ".now.sh"))
    ):
        providers.append("Vercel")
        details["vercel_id"] = hdrs.get("x-vercel-id", "detected")
        details["vercel_cache"] = hdrs.get("x-vercel-cache", "n/a")
        if "x-matched-path" in hdrs:
            details["vercel_matched_path"] = hdrs["x-matched-path"]

    # 3. AWS (CloudFront / ALB / API Gateway / S3 / Lambda URL)
    if (
        "x-amz-cf-id" in hdrs
        or "x-amz-cf-pop" in hdrs
        or "cloudfront" in hdrs.get("via", "").lower()
        or "cloudfront" in hdrs.get("x-cache", "").lower()
        or host.endswith(".cloudfront.net")
    ):
        providers.append("AWS-CloudFront")
        details["aws_cf_pop"] = hdrs.get("x-amz-cf-pop", "detected")
        details["aws_x_cache"] = hdrs.get("x-cache", "n/a")

    if (
        "x-amzn-requestid" in hdrs
        or "x-amzn-trace-id" in hdrs
        or "x-amz-apigw-id" in hdrs
        or "awselb" in hdrs.get("set-cookie", "").lower()
        or host.endswith((".amazonaws.com", ".awsapprunner.com", ".on.aws"))
    ):
        providers.append("AWS-ALB/APIGW")
        details["aws_request_id"] = hdrs.get("x-amzn-requestid", hdrs.get("x-amzn-trace-id", "detected"))

    if "x-amz-bucket-region" in hdrs or "amazons3" in server:
        providers.append("AWS-S3")
        details["aws_s3_region"] = hdrs.get("x-amz-bucket-region", "detected")

    return providers, details


class CloudScout(VibeTool):
    def __init__(self):
        super().__init__("Cloud Scout", "Cloudflare, AWS & Vercel (.vercel.app) Edge & Environment Prober")

    def _probe_cloudflare(self, base_url):
        trace_url = f"{base_url.rstrip('/')}/cdn-cgi/trace"
        status, body, _ = self.safe_request(trace_url, method="GET")
        if status == 200 and body and "colo=" in body and "fl=" in body:
            kv = {}
            for line in body.splitlines():
                if "=" in line:
                    k, v = line.split("=", 1)
                    kv[k.strip()] = v.strip()
            self.log(
                f"Cloudflare Edge Trace active: colo={kv.get('colo', '?')} "
                f"http={kv.get('http', '?')} tls={kv.get('tls', '?')} sni={kv.get('sni', '?')}",
                "info",
            )

        # Check if sensitive API endpoints are inadvertently cached at the Cloudflare edge
        cfg_url = f"{base_url.rstrip('/')}/api/config"
        c_status, _, c_hdrs = self.safe_request(cfg_url, method="GET")
        if c_status == 200 and c_hdrs:
            cf_cache = (c_hdrs.get("CF-Cache-Status") or "").upper()
            cc = (c_hdrs.get("Cache-Control") or "").lower()
            if cf_cache in ("HIT", "STALE", "EXPIRED") and "private" not in cc and "no-store" not in cc:
                self.log(
                    f"Cloudflare Edge Cache Risk: {cfg_url} returned CF-Cache-Status={cf_cache} without Cache-Control: private/no-store",
                    "warn",
                )
                self.record_finding(
                    title="Cloudflare Edge Caching Sensitive API Response",
                    severity="medium",
                    location=cfg_url,
                    evidence=f"CF-Cache-Status: {cf_cache}, Cache-Control: {cc or '(missing)'}",
                    recommendation="Set 'Cache-Control: private, no-store' on authenticated or configuration API endpoints behind Cloudflare.",
                    cwe="CWE-525",
                    owasp="A05:2021 - Security Misconfiguration",
                )

    def _probe_vercel(self, base_url):
        # Probe Vercel / Next.js environment & build exposure paths
        vercel_probes = [
            (".env.local", "critical"),
            (".env.production", "critical"),
            ("_next/static/chunks/pages/_app.js.map", "medium"),
        ]
        for subpath, sev in vercel_probes:
            u = f"{base_url.rstrip('/')}/{subpath}"
            status, body, hdrs = self.safe_request(u, method="GET")
            if status == 200 and body:
                if subpath.startswith(".env") and "=" in body and "<html" not in body.lower():
                    self.log(f"EXPOSED Vercel env file: {u} (200 OK)", "crit")
                    self.record_finding(
                        title=f"Exposed Vercel Environment File ({subpath})",
                        severity=sev,
                        location=u,
                        evidence=body[:140],
                        recommendation="Never deploy .env.local or .env.production in static public/ directories on Vercel.",
                        cwe="CWE-200",
                        owasp="A05:2021 - Security Misconfiguration",
                    )
                elif subpath.endswith(".map") and '"mappings"' in body:
                    self.log(f"Exposed Next.js client source map on Vercel: {u}", "warn")
                    self.record_finding(
                        title="Exposed Next.js Source Map in Production",
                        severity="low",
                        location=u,
                        evidence="Source map JSON with 'mappings' key accessible publicly",
                        recommendation="Disable productionBrowserSourceMaps in next.config.js unless intentionally public.",
                        cwe="CWE-540",
                        owasp="A05:2021 - Security Misconfiguration",
                    )
            elif status in (401, 403) and hdrs and ("x-vercel-mitigated" in {k.lower() for k in hdrs.keys()}):
                self.log("Vercel Firewall / Deployment Protection active on target.", "pass")

    def _probe_aws(self, base_url, root_body):
        if root_body and "<ListBucketResult" in root_body:
            self.log(f"CRITICAL: Open AWS S3 Bucket Listing at {base_url}", "crit")
            self.record_finding(
                title="Publicly Listable AWS S3 Bucket",
                severity="high",
                location=base_url,
                evidence="<ListBucketResult> XML returned at root URL",
                recommendation="Enable S3 Block Public Access and restrict s3:ListBucket in the bucket policy.",
                cwe="CWE-284",
                owasp="A01:2021 - Broken Access Control",
            )
        cred_url = f"{base_url.rstrip('/')}/.aws/credentials"
        st, body, _ = self.safe_request(cred_url, method="GET")
        if st == 200 and body and "aws_access_key_id" in body.lower():
            self.log(f"CRITICAL: Exposed AWS credentials file at {cred_url}", "crit")
            self.record_finding(
                title="Exposed .aws/credentials File",
                severity="critical",
                location=cred_url,
                evidence="aws_access_key_id present in response",
                recommendation="Remove .aws/credentials from web root and rotate affected IAM keys immediately.",
                cwe="CWE-798",
                owasp="A07:2021 - Identification and Authentication Failures",
            )

    def run(self, base_url, targets):
        self.banner()
        if "://" not in base_url:
            base_url = f"https://{base_url}"
        self.log(f"Mapping cloud/edge environment at: {base_url}")

        # Phase 1: Fingerprint Cloud / Edge Provider (Cloudflare, Vercel, AWS)
        root_status, root_body, root_headers = self.safe_request(base_url, method="GET")
        hdr_dict = dict(root_headers.items()) if root_headers else {}
        providers, details = detect_cloud_stack(base_url, hdr_dict)
        if providers:
            detail_str = ", ".join(f"{k}={v}" for k, v in details.items())
            self.log(f"Detected Cloud/Edge Stack: {', '.join(providers)} ({detail_str})", "pass")
        else:
            self.log("Detected Stack: Direct Origin / Custom Server (no Cloudflare/Vercel/AWS edge headers found)", "info")

        # Phase 2: Provider-specific edge & security checks
        if "Cloudflare" in providers:
            self._probe_cloudflare(base_url)
        if "Vercel" in providers:
            self._probe_vercel(base_url)
        if any(p.startswith("AWS") for p in providers):
            self._probe_aws(base_url, root_body)

        # Phase 3: Probe target paths
        exposed = 0
        for t in targets:
            full_url = f"{base_url.rstrip('/')}/{t.lstrip('/')}"
            kind = _classify(t)
            self.log(f"Probing: {t}")

            status, body, _ = self.safe_request(full_url, method="GET")

            if status == 200:
                if kind == "sensitive":
                    self.log(f"EXPOSED — sensitive path {t} is accessible (200 OK) — verify it isn't leaking data", "hack")
                    self.record_finding(
                        title=f"Unauthenticated Sensitive Cloud Path Reachable ({t})",
                        severity="medium",
                        location=full_url,
                        evidence=f"HTTP 200 OK ({len(body or '')} bytes)",
                        recommendation=f"Restrict access to /{t.lstrip('/')} via authentication or edge WAF rules.",
                        cwe="CWE-284",
                        owasp="A01:2021 - Broken Access Control",
                    )
                    exposed += 1
                elif kind == "public":
                    self.log(f"Reachable — {t} (200) — expected-public page, not a finding", "pass")
                else:
                    self.log(f"Reachable — {t} (200) — map it, then judge by content", "info")
            elif status in (401, 403):
                self.log(f"Protected — {t} requires auth ({status})", "pass")
            elif status == 404:
                self.log(f"Not found — {t} ({status})", "info")
            elif status == 0:
                self.log(f"Offline or unreachable — {t}", "warn")
            else:
                self.log(f"Unusual response on {t} ({status})", "info")

        self.log("=" * 32)
        if exposed > 0:
            self.log(f"Mapping complete — {exposed} sensitive path(s) reachable without auth", "crit")
        else:
            self.log("Mapping complete — no sensitive paths exposed (public pages don't count)", "pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Cloud Scout v2.0 - Cloudflare, AWS & Vercel (.vercel.app) Edge Prober")
    parser.add_argument("--url", required=True, help="Target base URL (e.g. https://my-app.vercel.app or http://localhost:3456)")
    parser.add_argument("--targets", nargs="+", default=DEFAULT_TARGETS, help="Paths to probe")
    parser.add_argument("-v", "--version", action="version", version="Cloud Scout 2.0.0")
    args = parser.parse_args()

    CloudScout().run(args.url, args.targets)
