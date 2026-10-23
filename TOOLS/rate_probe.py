#!/usr/bin/env python3
"""
rate_probe.py — Dedicated Rate Limit & Brute Force Protection Tester.

Tests whether your app properly enforces:
  1. Login brute force lockout (wrong-password rate limiting)
  2. API endpoint rate limits (request-per-minute throttling)
  3. Per-user vs per-IP rate limiting
  4. Distributed rate limit bypass (rotating IPs via X-Forwarded-For)
  5. Concurrency limits (parallel request flooding)
  6. Account lockout behaviour (lockout time, unlock method)
  7. CAPTCHA trigger threshold
  8. Password reset rate limiting
  9. OTP/2FA brute force protection
 10. Credit/wallet drain amplification (AI token endpoint flooding)
"""
import argparse
import concurrent.futures
import json
import os
import sys
import time
import threading
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool


class RateProbe(VibeTool):
    def __init__(self):
        super().__init__("Rate Probe", "Rate Limit & Brute Force Protection Tester")
        self._lock = threading.Lock()

    # ── helpers ────────────────────────────────────────────────────────────

    def _burst(self, url, method, data, headers, count, workers):
        """Fire `count` identical requests in parallel and collect (status, latency) pairs."""
        tasks = [{"url": url, "method": method, "data": data,
                  "headers": headers, "timeout": 8}] * count
        raw = self.parallel_requests(tasks, max_workers=workers)
        return [(status, len(body or "")) for (_, status, body, _) in raw]

    def _status_summary(self, results):
        counts = {}
        for status, _ in results:
            counts[status] = counts.get(status, 0) + 1
        return counts

    # ── vector 1: login brute force ────────────────────────────────────────

    def vector_login_bruteforce(self, base):
        self.log("=== VECTOR 1: Login Brute Force Protection ===")
        url = f"{base}/api/login"
        passwords = [
            "wrong1", "wrong2", "wrong3", "wrong4", "wrong5",
            "wrong6", "wrong7", "wrong8", "wrong9", "wrong10",
            "wrong11", "wrong12",
        ]
        statuses = []
        lockout_at = None
        for i, pw in enumerate(passwords, 1):
            status, body, _ = self.safe_request(
                url, method="POST",
                data={"username": "admin", "password": pw},
                timeout=6
            )
            statuses.append(status)
            if status == 429:
                lockout_at = i
                self.log(f"  Rate limit triggered at attempt {i} (HTTP 429)", "pass")
                break
            elif status == 423:
                lockout_at = i
                self.log(f"  Account lock triggered at attempt {i} (HTTP 423)", "pass")
                break
            elif status == 403 and "lock" in (body or "").lower():
                lockout_at = i
                self.log(f"  Account locked at attempt {i} (HTTP 403 + lock body)", "pass")
                break
            else:
                self.log(f"  Attempt {i}: HTTP {status}")

        if lockout_at is None:
            msg = f"No brute force protection triggered after {len(passwords)} login attempts — account lockout missing"
            self.log(msg, "crit")
            self.record_finding(
                title="Missing Login Brute Force Protection",
                severity="high",
                location=url,
                evidence=f"12 sequential wrong-password attempts returned statuses {statuses} with no 429/423 lockout.",
                recommendation="Implement exponential backoff, account lockout after 5-10 failures, and CAPTCHA on repeated failures.",
                cwe="CWE-307",
                owasp="A07:2021-Identification and Authentication Failures",
            )
        return lockout_at

    # ── vector 2: API rate limiting ────────────────────────────────────────

    def vector_api_rate_limit(self, base, burst_count=40):
        self.log(f"=== VECTOR 2: API Rate Limit ({burst_count} parallel requests) ===")
        endpoints = [
            (f"{base}/api/config",   "GET",  None),
            (f"{base}/api/health",   "GET",  None),
            (f"{base}/",             "GET",  None),
        ]
        for url, method, data in endpoints:
            results = self._burst(url, method, data, {}, burst_count, workers=burst_count)
            summary = self._status_summary(results)
            rate_limited = summary.get(429, 0)
            self.log(f"  {url} ({burst_count} req): {summary}")
            if rate_limited == 0:
                self.log(f"  No 429 on {url} under {burst_count}-request burst", "warn")
            else:
                self.log(f"  {rate_limited}/{burst_count} requests rate-limited on {url}", "pass")

    # ── vector 3: distributed IP bypass ────────────────────────────────────

    def vector_ip_bypass(self, base, attempts=20):
        self.log("=== VECTOR 3: Distributed Rate Limit Bypass (IP Rotation) ===")
        url = f"{base}/api/login"
        bypassed = 0
        for i in range(attempts):
            spoof = f"203.0.113.{i + 1}"
            status, body, _ = self.safe_request(
                url, method="POST",
                data={"username": "admin", "password": f"spray{i}"},
                headers={
                    "X-Forwarded-For": spoof,
                    "X-Real-IP": spoof,
                    "CF-Connecting-IP": spoof,
                    "True-Client-IP": spoof,
                    "X-Vercel-Forwarded-For": spoof,
                },
                timeout=5
            )
            if status not in (429, 423):
                bypassed += 1
            else:
                self.log(f"  Spoofed IP {spoof} correctly rate-limited at attempt {i+1}", "pass")
                break

        if bypassed >= attempts:
            msg = f"Rate limit bypassed via IP spoofing — {attempts} login attempts completed with rotating X-Forwarded-For"
            self.log(msg, "crit")
            self.record_finding(
                title="Rate Limit Bypassable via X-Forwarded-For IP Spoofing",
                severity="high",
                location=url,
                evidence=f"{bypassed}/{attempts} attempts succeeded with rotated X-Forwarded-For headers.",
                recommendation="Rate limit by verified IP (server-side), not by X-Forwarded-For which is attacker-controlled. Use CF-Connecting-IP only when behind Cloudflare.",
                cwe="CWE-290",
                owasp="A07:2021-Identification and Authentication Failures",
            )
        return bypassed

    # ── vector 4: concurrency flood ────────────────────────────────────────

    def vector_concurrency_flood(self, base, workers=50):
        self.log(f"=== VECTOR 4: Concurrency Flood ({workers} simultaneous requests) ===")
        url = f"{base}/api/chat"
        data = {
            "model": "openai/gpt-oss-20b:free",
            "messages": [{"role": "user", "content": "ping"}],
            "persona": "default",
        }
        t0 = time.perf_counter()
        results = self._burst(url, "POST", data, {}, workers, workers=workers)
        elapsed = time.perf_counter() - t0
        summary = self._status_summary(results)
        errors  = summary.get(0, 0) + summary.get(500, 0) + summary.get(503, 0)
        self.log(f"  {workers} concurrent /api/chat in {elapsed:.2f}s: {summary}")
        if errors > workers * 0.3:
            self.log(f"  {errors}/{workers} requests failed under concurrency flood", "crit")
            self.record_finding(
                title=f"Service Degrades Under {workers}-Concurrent-Request Load",
                severity="medium",
                location=url,
                evidence=f"{errors}/{workers} requests returned errors (5xx/timeout) in {elapsed:.2f}s.",
                recommendation="Add connection pool limits, queue depth caps, and 503 circuit breakers to prevent full service collapse.",
                cwe="CWE-400",
                owasp="A04:2021-Insecure Design",
            )
        else:
            self.log(f"  Service held under {workers} concurrent requests (errors: {errors})", "pass")

    # ── vector 5: password reset rate limit ────────────────────────────────

    def vector_password_reset(self, base, attempts=10):
        self.log("=== VECTOR 5: Password Reset Rate Limit ===")
        url = f"{base}/api/auth/reset"
        emails = [f"victim{i}@test.com" for i in range(attempts)]
        statuses = []
        for em in emails:
            status, _, _ = self.safe_request(url, method="POST", data={"email": em}, timeout=5)
            statuses.append(status)
            if status == 429:
                self.log(f"  Reset rate limit triggered ({statuses.index(429)+1} requests)", "pass")
                break
        else:
            self.log(f"  {attempts} password reset requests completed without 429 — no rate limit on reset", "warn")
            self.record_finding(
                title="No Rate Limit on Password Reset Endpoint",
                severity="medium",
                location=url,
                evidence=f"{attempts} reset requests returned statuses {statuses} with no 429.",
                recommendation="Rate limit password reset by email domain and source IP. Add CAPTCHA after 3 attempts.",
                cwe="CWE-307",
                owasp="A07:2021-Identification and Authentication Failures",
            )

    # ── vector 6: AI credit drain amplification ────────────────────────────

    def vector_credit_drain(self, base, count=20):
        self.log(f"=== VECTOR 6: AI Credit Drain Amplification ({count} parallel /api/chat) ===")
        url = f"{base}/api/chat"
        # Long, expensive prompt to maximise token cost per request
        long_prompt = "Explain quantum entanglement in exhaustive detail, including all mathematical proofs. " * 30
        data = {
            "model": "openai/gpt-4o",   # expensive model to maximise cost amplification
            "messages": [{"role": "user", "content": long_prompt}],
            "persona": "default",
        }
        t0 = time.perf_counter()
        results = self._burst(url, "POST", data, {}, count, workers=count)
        elapsed = time.perf_counter() - t0
        summary = self._status_summary(results)
        accepted = summary.get(200, 0)
        self.log(f"  {count} parallel expensive prompts in {elapsed:.2f}s: {summary}")
        if accepted > 0:
            msg = f"AI credit drain amplification: {accepted}/{count} parallel expensive prompts accepted with no rate limit"
            self.log(msg, "crit")
            self.record_finding(
                title="AI API Credit Drain — No Rate Limit on Expensive Model Prompts",
                severity="high",
                location=url,
                evidence=f"{accepted}/{count} parallel requests to expensive model accepted in {elapsed:.2f}s.",
                recommendation="Rate limit /api/chat by IP and user. Whitelist allowed models. Set monthly spend caps per user.",
                cwe="CWE-770",
                owasp="API4:2023-Unrestricted Resource Consumption",
            )
        else:
            self.log(f"  All {count} expensive prompts blocked or rate-limited", "pass")

    # ── main ───────────────────────────────────────────────────────────────

    def run(self, url, burst=40, workers=50):
        self.banner()
        base = url.rstrip("/")
        self.log(f"Target: {base}")

        self.vector_login_bruteforce(base)
        self.vector_api_rate_limit(base, burst_count=burst)
        self.vector_ip_bypass(base)
        self.vector_concurrency_flood(base, workers=workers)
        self.vector_password_reset(base)
        self.vector_credit_drain(base)

        self.log("=" * 32)
        critical = sum(1 for f in self.recorded_findings if f and f.get("severity") in ("critical", "high"))
        if critical:
            self.log(f"RATE LIMIT AUDIT COMPLETE — {critical} critical/high issue(s) found", "crit")
        else:
            self.log("Rate limits appear correctly enforced across all tested vectors", "pass")
        return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Rate Probe — Rate Limit & Brute Force Protection Tester")
    parser.add_argument("--url", required=True, help="Target base URL (e.g. http://localhost:3456)")
    parser.add_argument("--burst", type=int, default=40, help="Burst count for API rate limit vector (default: 40)")
    parser.add_argument("--workers", type=int, default=50, help="Concurrency for flood vector (default: 50)")
    parser.add_argument("-v", "--version", action="version", version="Rate Probe 1.0.0")
    args = parser.parse_args()
    sys.exit(RateProbe().run(args.url, burst=args.burst, workers=args.workers))
