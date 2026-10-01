#!/usr/bin/env python3
"""
asymmetric_probe.py v1.0 — Asymmetric 'Origin-Killer & Wallet-Drainer' Amplification Auditor.

Think like a zero-credential attacker: instead of needing 1,000,000 RPS, an attacker
looks for 1-request-equals-50x-CPU/DB/LLM-cost bottlenecks that bypass Cloudflare/Vercel/AWS
edge caches and exhaust serverless concurrency or cloud billing at low request rates:
  1. Next.js / Vercel `/_next/image` On-the-Fly Image Resize CPU Amplification
  2. GraphQL Array Batching (`[query x 20]`) & Deep-Alias (`a1..a25`) Amplification
  3. Cache-Miss + Wildcard/Regex/Sort DB Table-Scan Amplification (`?q=%25%25&limit=10000&_cb=...`)
  4. Unauthenticated AI / LLM Inference & Token Wallet-Drain (`/api/chat`, `/api/completions`)
"""
import argparse
import json
import os
import sys
import time
import urllib.parse
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool


class AsymmetricProbe(VibeTool):
    def __init__(self):
        super().__init__(
            "Asymmetric Probe",
            "Zero-Credential 'Origin-Killer & Wallet-Drainer' CPU/DB/LLM Amplification Auditor",
        )

    def _timed_request(self, url, method="GET", data=None, headers=None):
        t0 = time.perf_counter()
        st, body, hdrs = self.safe_request(url, method=method, data=data, headers=headers, timeout=12)
        lat_ms = (time.perf_counter() - t0) * 1000.0
        return st, lat_ms, len(body or ""), body or "", hdrs

    def run(self, url):
        self.banner()
        if "://" not in url:
            first_host = url.split("/")[0].split(":")[0].lower()
            url = f"{'http' if first_host in ('localhost', '127.0.0.1', '::1') else 'https'}://{url}"
        base = url.rstrip("/")
        self.log(f"Profiling asymmetric amplification bottlenecks on {base} (Zero-Key Attacker Mode)")

        # 1. Measure baseline latency on root
        base_st, base_ms, base_bytes, _, _ = self._timed_request(f"{base}/")
        if base_st == 0:
            self.log("Target unreachable during baseline probe.", "warn")
            return 0
        base_ms = max(0.5, base_ms)
        self.log(f"Baseline GET / : HTTP {base_st} | {base_ms:.2f}ms | {base_bytes} bytes")

        results = []
        bypass_hdrs = {
            "Cache-Control": "no-cache, no-store, must-revalidate",
            "Pragma": "no-cache",
        }

        # Vector 1: Next.js / Vercel Image Optimizer CPU Amplification
        img_path = f"/_next/image?url=%2Ffavicon.ico&w=3840&q=100&_cb={uuid.uuid4().hex[:8]}"
        st, ms, nbytes, _, _ = self._timed_request(f"{base}{img_path}", headers=bypass_hdrs)
        if st in (200, 400, 500):
            amp = ms / base_ms
            results.append({"vector": "nextjs_image_optimizer", "path": img_path, "status": st, "ms": round(ms, 2), "amplification_x": round(amp, 2)})
            if st == 200 and amp >= 4.0:
                self.log(
                    f"High CPU Amplification on /_next/image: {ms:.2f}ms ({amp:.1f}x slower than baseline)",
                    "warn",
                )

        # Vector 2: GraphQL Array Batching & Alias Amplification
        aliases = " ".join(f"a{i}: __typename" for i in range(1, 26))
        batched_gql = [{"query": f"query {{ {aliases} }}"} for _ in range(15)]
        for gql_sub in ("/graphql", "/api/graphql"):
            st, ms, nbytes, body, _ = self._timed_request(
                f"{base}{gql_sub}",
                method="POST",
                data=batched_gql,
                headers={**bypass_hdrs, "Content-Type": "application/json"},
            )
            if st == 200 and ("__typename" in body or "data" in body):
                amp = ms / base_ms
                results.append({"vector": "graphql_batch_amplification", "path": gql_sub, "status": st, "ms": round(ms, 2), "amplification_x": round(amp, 2)})
                self.log(
                    f"CRITICAL: Unauthenticated GraphQL Batching + 25x Alias accepted on {gql_sub} ({ms:.2f}ms, {amp:.1f}x)",
                    "hack",
                )
                self.record_finding(
                    title=f"Unauthenticated GraphQL Query Batching & Alias Amplification ({gql_sub})",
                    severity="high",
                    location=f"{base}{gql_sub}",
                    evidence=f"15-query batch with 25 aliases each executed in 1 HTTP POST ({ms:.2f}ms, {amp:.1f}x baseline)",
                    recommendation="Disable unauthenticated GraphQL array batching and enforce query depth/cost/alias limits.",
                    cwe="CWE-400",
                    owasp="API4:2023 - Unrestricted Resource Consumption",
                )

        # Vector 3: Cache-Miss + Wildcard/Sort/Limit DB Scan Amplification
        db_paths = ["/api/guestbook", "/api/config", "/api/search", "/api/users", "/openapi.json"]
        surface = self.get_surface()
        for ep in (surface.get("endpoints") or [])[:6]:
            p = urllib.parse.urlparse(ep).path
            if p and p not in db_paths:
                db_paths.append(p)

        for p in db_paths:
            heavy_q = f"{p}{'&' if '?' in p else '?'}q=%25%25%25&search=a&sort=-created_at&limit=5000&_cb={uuid.uuid4().hex[:8]}"
            st, ms, nbytes, _, _ = self._timed_request(f"{base}{heavy_q}", headers=bypass_hdrs)
            if 200 <= st < 300:
                amp = ms / base_ms
                results.append({"vector": "cache_miss_db_scan", "path": heavy_q, "status": st, "ms": round(ms, 2), "amplification_x": round(amp, 2)})
                if amp >= 5.0 or nbytes > max(base_bytes * 10, 32768):
                    self.log(
                        f"Asymmetric DB/SSR endpoint: {p} took {ms:.2f}ms ({amp:.1f}x baseline, {nbytes} bytes)",
                        "warn",
                    )

        # Vector 4: Unauthenticated AI / LLM Inference Wallet-Drainer
        llm_payload = {
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "Write a detailed 500-word analysis of cloud security."}],
        }
        for chat_path in ("/api/chat", "/api/completions", "/api/generate"):
            st, ms, nbytes, body, _ = self._timed_request(
                f"{base}{chat_path}",
                method="POST",
                data=llm_payload,
                headers={**bypass_hdrs, "Content-Type": "application/json"},
            )
            if st == 200 and any(k in body.lower() for k in ("reply", "choices", "content", "assistant")):
                amp = ms / base_ms
                results.append({"vector": "unauthenticated_llm_wallet_drain", "path": chat_path, "status": st, "ms": round(ms, 2), "amplification_x": round(amp, 2)})
                self.log(
                    f"WALLET-DRAIN RISK: Unauthenticated AI/LLM endpoint {chat_path} executed without API key or auth ({ms:.2f}ms)!",
                    "hack",
                )
                self.record_finding(
                    title=f"Unauthenticated AI/LLM Inference Endpoint Exposed to Wallet-Drain ({chat_path})",
                    severity="high",
                    location=f"{base}{chat_path}",
                    evidence=f"POST {chat_path} with zero credentials triggered LLM response ({nbytes} bytes, {ms:.2f}ms)",
                    recommendation="Require session authentication, per-user token quotas, and strict rate limiting on LLM inference routes.",
                    cwe="CWE-770",
                    owasp="LLM10:2025 - Unbounded Consumption",
                )

        # Rank by amplification factor and save to vibe_session.json for Hyperion
        results.sort(key=lambda r: r["amplification_x"], reverse=True)
        sess = self.load_session()
        if isinstance(sess, dict):
            surf = sess.get("surface", {}) if isinstance(sess.get("surface"), dict) else {}
            surf["asymmetric_targets"] = results[:10]
            sess["surface"] = surf
            try:
                with open(self.session_file, "w", encoding="utf-8") as fh:
                    json.dump(sess, fh, indent=2)
            except OSError:
                pass

        if results:
            top = results[0]
            self.log(
                f"Top asymmetric target: {top['path']} ({top['vector']}) -> {top['ms']:.2f}ms ({top['amplification_x']:.1f}x baseline)",
                "pass",
            )
        return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Asymmetric Probe v1.0 - Zero-Credential 'Origin-Killer & Wallet-Drainer' Amplification Auditor"
    )
    parser.add_argument("--url", "-t", "--target", dest="url", required=True, help="Target URL (e.g. https://my-app.vercel.app)")
    parser.add_argument("-v", "--version", action="version", version="Asymmetric Probe 1.0.0")
    args = parser.parse_args(argv)
    return AsymmetricProbe().run(args.url)


if __name__ == "__main__":
    sys.exit(main())
