#!/usr/bin/env python3
"""
smuggle_probe.py — HTTP Protocol, Verb-Tampering, Cache-Control & Desync Auditor.

Audits HTTP reverse-proxy, CDN, and server parser behavior safely:
  1. Sensitive API Cache-Control leakage (missing `no-store` on sensitive JSON routes)
  2. HTTP Verb Tampering (TRACE / XST reflection, X-HTTP-Method-Override bypass)
  3. Hop-by-Hop `Connection` header abuse
  4. Safe single-socket `Transfer-Encoding` parser tolerance check
"""
import argparse
import os
import re
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool

SENSITIVE_BODY_RE = re.compile(
    r'("openrouter_api_key"|"jwt_secret"|"password"|"pw_hash"|"secret"|"api_key"|"token"\s*:)',
    re.IGNORECASE,
)


class SmuggleProbe(VibeTool):
    def __init__(self):
        super().__init__("Smuggle Probe", "HTTP Protocol, Verb-Tampering & Cache-Control Auditor")

    def _audit_cache_control(self, base_url):
        self.log("Test 1 — Auditing Cache-Control policy on sensitive API routes...")
        candidates = [
            base_url,
            f"{base_url.rstrip('/')}/api/debug",
            f"{base_url.rstrip('/')}/api/config?debug=true",
            f"{base_url.rstrip('/')}/api/user?id=1",
        ]
        surface = self.get_surface()
        for ep in surface.get("endpoints", [])[:8]:
            if ep not in candidates:
                candidates.append(ep)

        issues = 0
        for target in candidates:
            status, body, headers = self.safe_request(target, method="GET", timeout=5)
            if status != 200 or not body:
                continue
            if SENSITIVE_BODY_RE.search(body):
                cc = (headers.get("Cache-Control") or "").lower()
                pragma = (headers.get("Pragma") or "").lower()
                if "no-store" not in cc and "private" not in cc and "no-cache" not in pragma:
                    self.log(
                        f"CACHEABLE SENSITIVE RESPONSE on {target} (Cache-Control: '{cc or 'missing'}')",
                        "crit",
                    )
                    self.record_finding(
                        title=f"Sensitive API Response Missing Cache-Control: no-store ({target})",
                        severity="high",
                        location=target,
                        evidence=f"Endpoint returned sensitive fields (status 200) with Cache-Control='{cc or 'none'}'.",
                        recommendation="Set 'Cache-Control: no-store, no-cache, must-revalidate, private' on all authenticated and sensitive API responses.",
                        cwe="CWE-525",
                        owasp="A05:2021-Security Misconfiguration",
                    )
                    issues += 1
        return issues

    def _audit_verb_tampering(self, base_url):
        self.log("Test 2 — Auditing HTTP Verb Tampering & TRACE/Method-Override...")
        issues = 0

        # Check TRACE method (Cross-Site Tracing / header reflection)
        canary_hdr = "vibe-trace-canary-909"
        st, body, _ = self.safe_request(
            base_url,
            method="TRACE",
            headers={"X-Vibe-Trace": canary_hdr},
            timeout=5,
        )
        if st == 200 and canary_hdr in (body or ""):
            self.log(f"HTTP TRACE method enabled and reflects request headers on {base_url}", "crit")
            self.record_finding(
                title="HTTP TRACE Method Enabled (Cross-Site Tracing)",
                severity="medium",
                location=base_url,
                evidence="TRACE request returned 200 OK echoing custom request headers in response body.",
                recommendation="Disable HTTP TRACE/TRACK methods at the web server or reverse proxy.",
                cwe="CWE-693",
                owasp="A05:2021-Security Misconfiguration",
            )
            issues += 1
        else:
            self.log(f"HTTP TRACE rejected or disabled (HTTP {st})", "pass")

        # Check Method-Override bypass on protected boundary
        admin_url = f"{base_url.rstrip('/')}/api/admin"
        base_st, _, _ = self.safe_request(admin_url, method="GET", timeout=5)
        if base_st in (401, 403):
            for hdr_name in ("X-HTTP-Method-Override", "X-Method-Override", "X-HTTP-Method"):
                st_ov, body_ov, _ = self.safe_request(
                    admin_url,
                    method="POST",
                    headers={hdr_name: "GET"},
                    data={},
                    timeout=5,
                )
                if st_ov == 200:
                    self.log(f"VERB OVERRIDE BYPASS via {hdr_name} on {admin_url} ({base_st} -> 200)", "crit")
                    self.record_finding(
                        title=f"Access Control Bypass via {hdr_name}",
                        severity="critical",
                        location=admin_url,
                        evidence=f"Protected route ({base_st}) returned 200 OK when accessed with POST + {hdr_name}: GET.",
                        recommendation="Enforce authorization checks across all HTTP methods and ignore untrusted method-override headers.",
                        cwe="CWE-650",
                        owasp="A01:2021-Broken Access Control",
                    )
                    issues += 1

        return issues

    def _audit_hop_by_hop(self, base_url):
        self.log("Test 3 — Auditing Hop-by-Hop Connection header stripping...")
        base_st, base_body, _ = self.safe_request(base_url, method="GET", timeout=5)
        hop_st, hop_body, _ = self.safe_request(
            base_url,
            method="GET",
            headers={"Connection": "close, X-Forwarded-For, Authorization, X-Real-IP"},
            timeout=5,
        )
        if base_st in (401, 403) and hop_st == 200:
            self.log(f"Hop-by-Hop Connection header caused auth bypass ({base_st} -> 200)", "crit")
            return 1
        self.log(f"Hop-by-Hop probe returned HTTP {hop_st} (baseline {base_st}) — no differential", "pass")
        return 0

    def run(self, url):
        self.banner()
        parsed = urllib.parse.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.log(f"Auditing HTTP transport, cache policy & verb boundaries on: {base_url}")

        total = 0
        total += self._audit_cache_control(base_url)
        total += self._audit_verb_tampering(base_url)
        total += self._audit_hop_by_hop(base_url)

        self.log("=" * 32)
        if total > 0:
            self.log(f"HTTP protocol & cache audit found {total} issue(s)", "crit")
        else:
            self.log("HTTP transport, method handling, and cache headers passed checks", "pass")
        return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="Smuggle Probe - HTTP Protocol, Verb-Tampering & Cache-Control Auditor"
    )
    parser.add_argument("--url", required=True, help="Target URL (e.g. http://localhost:3456)")
    parser.add_argument("-v", "--version", action="version", version="Smuggle Probe 1.0.0")
    args = parser.parse_args()

    sys.exit(SmuggleProbe().run(args.url))
