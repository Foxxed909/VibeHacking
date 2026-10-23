#!/usr/bin/env python3
"""
asymmetric_probe.py v2.0 — Asymmetric 'Origin-Killer & Wallet-Drainer' Amplification Auditor.

IMPROVEMENTS over v1.0:
  - Multi-sample median (5 samples per vector) replaces single-request ratio —
    single-sample amplification from network jitter was indistinguishable from
    real server-side cost, producing noise-driven findings.
  - Cache-busted baseline — baseline is now measured with a cache-bust token so
    edge CDN hits don't produce an unrealistically fast reference.
  - GraphQL detection now accepts any HTTP 200 JSON response, not just bodies
    containing "__typename" or "data" — catches custom field names.
  - LLM wallet drain detection handles SSE streaming responses (text/event-stream)
    in addition to JSON, and tries /api/completions + /api/generate.
  - 3 new vectors: cold-start amplification, search regex DB scan, webhook fanout.
  - Amplification table printed at end ranked by ratio.
"""
import argparse
import json
import os
import statistics
import sys
import time
import urllib.parse
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool

_SAMPLES = 5  # samples per vector for reliable median


class AsymmetricProbe(VibeTool):
    def __init__(self):
        super().__init__(
            "Asymmetric Probe",
            "Zero-Credential 'Origin-Killer & Wallet-Drainer' CPU/DB/LLM Amplification Auditor v2.0",
        )

    def _sample(self, url, method="GET", data=None, headers=None, n=_SAMPLES):
        """
        IMPROVEMENT: take n samples and return median latency.
        Single-sample timing from v1.0 was indistinguishable from network jitter.
        """
        samples = []
        for _ in range(n):
            t0 = time.perf_counter()
            st, body, hdrs = self.safe_request(url, method=method, data=data, headers=headers, timeout=15)
            lat_ms = (time.perf_counter() - t0) * 1000.0
            samples.append((st, lat_ms, len(body or ""), body or "", hdrs))
            time.sleep(0.05)  # brief pause between samples to avoid self-induced rate limiting
        # Return the median-latency sample
        samples.sort(key=lambda x: x[1])
        return samples[len(samples) // 2]

    def _baseline(self, base):
        """
        IMPROVEMENT: cache-busted baseline so edge CDN hits don't produce an
        unrealistically fast reference that makes everything look amplified.
        """
        cb = f"/?_cb={uuid.uuid4().hex[:8]}"
        bypass_hdrs = {"Cache-Control": "no-cache, no-store", "Pragma": "no-cache"}
        st, ms, nbytes, _, _ = self._sample(f"{base}{cb}", headers=bypass_hdrs)
        return max(0.5, ms), st

    def run(self, url):
        self.banner()
        if "://" not in url:
            first_host = url.split("/")[0].split(":")[0].lower()
            url = f"{'http' if first_host in ('localhost', '127.0.0.1', '::1') else 'https'}://{url}"
        base = url.rstrip("/")
        self.log(f"Profiling asymmetric amplification on {base} (Zero-Key Attacker Mode)")
        self.log(f"Using {_SAMPLES}-sample median per vector for reliable ratio estimation")

        # Cache-busted baseline
        base_ms, base_st = self._baseline(base)
        if base_st == 0:
            self.log("Target unreachable during baseline probe.", "warn")
            return 0
        self.log(f"Baseline GET / (cache-busted, {_SAMPLES}-sample median): {base_ms:.2f}ms HTTP {base_st}")

        results = []
        bypass_hdrs = {"Cache-Control": "no-cache, no-store, must-revalidate", "Pragma": "no-cache"}

        # ── Vector 1: Next.js / Vercel Image Optimizer CPU Amplification ──
        img_path = f"/_next/image?url=%2Ffavicon.ico&w=3840&q=100&_cb={uuid.uuid4().hex[:8]}"
        st, ms, nbytes, _, _ = self._sample(f"{base}{img_path}", headers=bypass_hdrs)
        if st in (200, 400, 500):
            amp = ms / base_ms
            results.append({"vector": "nextjs_image_optimizer", "path": img_path, "status": st, "ms": round(ms, 2), "amplification_x": round(amp, 2)})
            if st == 200 and amp >= 3.0:
                self.log(f"CPU Amplification on /_next/image: {ms:.2f}ms ({amp:.1f}x baseline median)", "warn")
                self.record_finding(
                    title="Next.js /_next/image CPU Amplification (uncapped image resize)",
                    severity="medium",
                    location=f"{base}{img_path}",
                    evidence=f"Unauthenticated 3840px resize: {ms:.2f}ms median ({amp:.1f}x baseline)",
                    recommendation="Set --images.minimumCacheTTL and add size allowlist in next.config.js.",
                    cwe="CWE-400", owasp="API4:2023-Unrestricted Resource Consumption",
                )

        # ── Vector 2: GraphQL Batch + Alias Amplification ──
        aliases = " ".join(f"a{i}: __typename" for i in range(1, 26))
        batched_gql = [{"query": f"query {{ {aliases} }}"} for _ in range(15)]
        for gql_sub in ("/graphql", "/api/graphql"):
            st, ms, nbytes, body, _ = self._sample(
                f"{base}{gql_sub}", method="POST", data=batched_gql,
                headers={**bypass_hdrs, "Content-Type": "application/json"},
            )
            # IMPROVEMENT: accept any HTTP 200 JSON — v1.0 required "__typename"/"data" in body
            # which failed on custom field names and error responses with HTTP 200.
            if st == 200 and nbytes > 20:
                try:
                    json.loads(body)  # confirm it's JSON
                    is_json = True
                except Exception:
                    is_json = False
                if is_json:
                    amp = ms / base_ms
                    results.append({"vector": "graphql_batch_amplification", "path": gql_sub, "status": st, "ms": round(ms, 2), "amplification_x": round(amp, 2)})
                    self.log(f"GRAPHQL BATCH ACCEPTED: {gql_sub} ({ms:.2f}ms, {amp:.1f}x baseline)", "hack")
                    self.record_finding(
                        title=f"Unauthenticated GraphQL Batching + 25x Alias ({gql_sub})",
                        severity="high",
                        location=f"{base}{gql_sub}",
                        evidence=f"15-query batch with 25 aliases each executed in 1 POST ({ms:.2f}ms, {amp:.1f}x)",
                        recommendation="Disable unauthenticated array batching; enforce query depth/cost/alias limits.",
                        cwe="CWE-400", owasp="API4:2023-Unrestricted Resource Consumption",
                    )

        # ── Vector 3: Cache-Miss + Wildcard DB Scan ──
        db_paths = ["/api/guestbook", "/api/config", "/api/search", "/api/users", "/openapi.json"]
        surface = self.get_surface()
        for ep in (surface.get("endpoints") or [])[:8]:
            p = urllib.parse.urlparse(ep).path
            if p and p not in db_paths:
                db_paths.append(p)

        for p in db_paths:
            heavy_q = f"{p}{'&' if '?' in p else '?'}q=%25%25%25&search=a&sort=-created_at&limit=5000&_cb={uuid.uuid4().hex[:8]}"
            st, ms, nbytes, _, _ = self._sample(f"{base}{heavy_q}", headers=bypass_hdrs)
            if 200 <= st < 300:
                amp = ms / base_ms
                results.append({"vector": "cache_miss_db_scan", "path": heavy_q, "status": st, "ms": round(ms, 2), "amplification_x": round(amp, 2)})
                if amp >= 4.0 or nbytes > max(base_ms * 100, 32768):
                    self.log(f"DB/SSR hotspot: {p} {ms:.2f}ms ({amp:.1f}x, {nbytes}b)", "warn")
                    self.record_finding(
                        title=f"Asymmetric DB/SSR Scan Hotspot ({p})",
                        severity="medium",
                        location=f"{base}{p}",
                        evidence=f"Wildcard query: {ms:.2f}ms ({amp:.1f}x baseline) returning {nbytes}b",
                        recommendation="Paginate results, index search columns, and reject unbounded ?limit= params.",
                        cwe="CWE-400", owasp="API4:2023-Unrestricted Resource Consumption",
                    )

        # ── Vector 4: Unauthenticated LLM Wallet Drain ──
        llm_payload = {
            "model": "gpt-4o-mini",
            "messages": [{"role": "user", "content": "Write a detailed 500-word analysis of cloud security."}],
        }
        for chat_path in ("/api/chat", "/api/completions", "/api/generate", "/v1/chat/completions"):
            st, ms, nbytes, body, hdrs = self._sample(
                f"{base}{chat_path}", method="POST", data=llm_payload,
                headers={**bypass_hdrs, "Content-Type": "application/json"},
            )
            ct = hdrs.get("Content-Type", "") if hdrs else ""
            # IMPROVEMENT: detect both JSON responses AND SSE streaming (text/event-stream)
            is_llm_response = (
                st == 200 and (
                    any(k in body.lower() for k in ("reply", "choices", "content", "assistant", "message"))
                    or "text/event-stream" in ct.lower()
                    or (nbytes > 100 and st == 200)
                )
            )
            if is_llm_response:
                amp = ms / base_ms
                results.append({"vector": "llm_wallet_drain", "path": chat_path, "status": st, "ms": round(ms, 2), "amplification_x": round(amp, 2)})
                self.log(f"WALLET-DRAIN: Unauthenticated LLM {chat_path} executed zero-credential ({ms:.2f}ms)", "hack")
                self.record_finding(
                    title=f"Unauthenticated LLM Inference Wallet-Drain ({chat_path})",
                    severity="high",
                    location=f"{base}{chat_path}",
                    evidence=f"POST with zero credentials: HTTP {st}, {nbytes}b, {ms:.2f}ms, ct={ct[:60]}",
                    recommendation="Require session auth, per-user token quotas, and rate limiting on LLM routes.",
                    cwe="CWE-770", owasp="LLM10:2025-Unbounded Consumption",
                )

        # ── Vector 5 (NEW): Serverless Cold-Start Amplification ──
        # Send a burst of 5 requests immediately after an idle period to measure
        # cold-start latency variance — a cold-start costs 10-50x more than warm.
        self.log("=== COLD-START: Idle + burst to measure cold-start amplification ===")
        time.sleep(3)  # let connection pool drain
        cold_samples = []
        for _ in range(5):
            t0 = time.perf_counter()
            st, body, hdrs = self.safe_request(
                f"{base}/?_cold={uuid.uuid4().hex[:8]}",
                headers=bypass_hdrs, timeout=15,
            )
            cold_samples.append((time.perf_counter() - t0) * 1000)
            time.sleep(0.1)
        if cold_samples:
            cold_first = cold_samples[0]
            cold_warm  = statistics.median(cold_samples[2:]) if len(cold_samples) > 2 else cold_samples[-1]
            cold_amp   = cold_first / max(cold_warm, 0.5)
            results.append({"vector": "cold_start", "path": "/", "status": 200, "ms": round(cold_first, 2), "amplification_x": round(cold_amp, 2)})
            if cold_amp >= 3.0:
                self.log(f"COLD-START amplification: first={cold_first:.1f}ms warm={cold_warm:.1f}ms ({cold_amp:.1f}x)", "warn")
                self.record_finding(
                    title="Serverless Cold-Start Amplification",
                    severity="low",
                    location=f"{base}/",
                    evidence=f"First request: {cold_first:.1f}ms, warm median: {cold_warm:.1f}ms, ratio: {cold_amp:.1f}x",
                    recommendation="Use warm-up pings, min-instances=1, or edge functions to reduce cold-start gaps.",
                    cwe="CWE-400", owasp="API4:2023-Unrestricted Resource Consumption",
                )
            else:
                self.log(f"Cold-start ratio {cold_amp:.1f}x — within acceptable range", "pass")

        # ── Vector 6 (NEW): Regex/LIKE Search DB Scan ──
        self.log("=== REGEX SEARCH: High-cost LIKE/regex DB scan ===")
        for search_path in ("/api/search", "/api/guestbook", "/api/users"):
            regex_q = f"{search_path}?q=.*.*.*.*.*&_cb={uuid.uuid4().hex[:8]}"
            st, ms, nbytes, _, _ = self._sample(f"{base}{regex_q}", headers=bypass_hdrs, n=3)
            if 200 <= st < 300:
                amp = ms / base_ms
                results.append({"vector": "regex_search_scan", "path": regex_q, "status": st, "ms": round(ms, 2), "amplification_x": round(amp, 2)})
                if amp >= 3.0:
                    self.log(f"REGEX SCAN hotspot: {search_path} {ms:.2f}ms ({amp:.1f}x)", "warn")

        # ── Vector 7 (NEW): Webhook Fanout Amplification ──
        self.log("=== WEBHOOK FANOUT: Single request → N backend calls ===")
        for wh_path in ("/api/webhook", "/api/notify", "/api/broadcast", "/api/fanout"):
            fanout_payload = {"event": "test", "data": {"message": "amplification_probe"}, "targets": ["a"] * 50}
            st, ms, nbytes, body, _ = self._sample(
                f"{base}{wh_path}", method="POST", data=fanout_payload,
                headers={**bypass_hdrs, "Content-Type": "application/json"}, n=3,
            )
            if st == 200:
                amp = ms / base_ms
                results.append({"vector": "webhook_fanout", "path": wh_path, "status": st, "ms": round(ms, 2), "amplification_x": round(amp, 2)})
                if amp >= 5.0:
                    self.log(f"WEBHOOK FANOUT: {wh_path} {ms:.2f}ms ({amp:.1f}x) — single req → 50 targets", "hack")

        # ── Ranked results table ──
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

        self.log("=" * 50)
        self.log(f"{'VECTOR':<30} {'PATH':<30} {'MS':>8} {'AMP':>6}")
        for r in results[:10]:
            flag = " ⚠" if r["amplification_x"] >= 3.0 else ""
            self.log(f"  {r['vector']:<28} {r['path'][:28]:<30} {r['ms']:>8.1f} {r['amplification_x']:>5.1f}x{flag}")

        high_amp = [r for r in results if r["amplification_x"] >= 3.0]
        if high_amp:
            self.log(f"TOP ASYMMETRIC TARGET: {results[0]['path']} → {results[0]['ms']:.1f}ms ({results[0]['amplification_x']:.1f}x baseline)", "hack")
        else:
            self.log("No high-amplification vectors found. Target appears cost-proportionate.", "pass")
        return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Asymmetric Probe v2.0 - Origin-Killer & Wallet-Drainer Amplification Auditor"
    )
    parser.add_argument("--url", "-t", "--target", dest="url", required=True)
    parser.add_argument("-v", "--version", action="version", version="Asymmetric Probe 2.0.0")
    args = parser.parse_args(argv)
    return AsymmetricProbe().run(args.url)


if __name__ == "__main__":
    sys.exit(main())
