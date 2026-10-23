#!/usr/bin/env python3
"""
credit_drain.py v2.0 — AI API Credit Drain & Rate-Limit Auditor (Full Rewrite).

Tests whether your AI/LLM proxy endpoint properly enforces:
  - Per-user / per-IP rate limits on expensive model calls
  - Cost isolation (attacker can't spend your OpenRouter/OpenAI credits)
  - Model allowlist enforcement (can attacker invoke gpt-4o on your proxy?)
  - Concurrent request flooding (wallet drain via parallel calls)
  - Per-model spend breakdown with estimated cost

IMPROVEMENTS over v1.0:
  - Uses safe_request() instead of raw urllib — inherits WAF bypass, cookie jar,
    bot-breaker headers; v1.0 was blocked by Cloudflare as a bot on most deploys.
  - Cost parsed with json.loads() instead of line-splitting heuristic that broke
    on minified JSON, trailing commas, and nested objects.
  - Corrected and expanded model list (all valid OpenRouter IDs as of 2026).
  - Cost estimation fallback: if cost_usd not in response, estimates from
    token count × known model pricing.
  - Per-model breakdown table printed after each round.
  - Tries multiple endpoint paths: /api/chat, /api/completions, /v1/chat/completions.
  - Parallel flood mode using parallel_requests() instead of ad-hoc threading.
"""
import argparse
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool

# Current valid OpenRouter model IDs + estimated cost per 1M output tokens (USD)
PAID_MODELS = [
    {"id": "anthropic/claude-opus-4-5",        "cost_per_m_out": 15.00},
    {"id": "openai/gpt-4o",                    "cost_per_m_out":  5.00},
    {"id": "openai/gpt-4o-mini",               "cost_per_m_out":  0.60},
    {"id": "google/gemini-2.5-pro-preview",    "cost_per_m_out": 10.00},
    {"id": "mistralai/mistral-large",           "cost_per_m_out":  6.00},
    {"id": "meta-llama/llama-3.1-70b-instruct","cost_per_m_out":  0.88},
]

# Simple prompt — just enough to confirm inference happened (low cost per call)
_PING_PROMPT = "Reply with exactly one word: pong"

# Expensive prompt — maximise token cost per accepted request
_EXPENSIVE_PROMPT = (
    "Write an extremely detailed 2000-word technical analysis of microservices security, "
    "including authentication patterns, zero-trust networking, and common CVEs."
)

LLM_ENDPOINTS = ["/api/chat", "/api/completions", "/v1/chat/completions", "/api/generate"]


def _estimate_cost(response_body, model_cost_per_m):
    """
    IMPROVEMENT: parse cost from response JSON with json.loads() then fall back
    to token-count estimation. v1.0's line-splitting heuristic broke on any
    non-pretty-printed JSON.
    """
    try:
        data = json.loads(response_body)
        # Direct cost field (VibeHacking testapp, some custom proxies)
        if "cost_usd" in data:
            return float(data["cost_usd"])
        # OpenAI-style usage object
        usage = data.get("usage", {})
        completion_tokens = usage.get("completion_tokens", 0)
        if completion_tokens and model_cost_per_m > 0:
            return (completion_tokens / 1_000_000) * model_cost_per_m
    except Exception:
        pass
    return 0.0


class CreditDrain(VibeTool):
    def __init__(self):
        super().__init__("Credit Drain", "AI API Credit Drain & Rate-Limit Auditor v2.0")

    def _find_llm_endpoint(self, base):
        """Try common LLM endpoint paths and return the first that responds."""
        for path in LLM_ENDPOINTS:
            url = base + path
            status, _, _ = self.safe_request(url, method="GET", timeout=4)
            if status not in (0, 404):
                return path
        return LLM_ENDPOINTS[0]  # default

    def _fire_model(self, base, endpoint, model_id, prompt, extra_headers=None):
        """Fire one LLM request and return (status, body, latency_ms)."""
        t0 = time.perf_counter()
        status, body, _ = self.safe_request(
            base + endpoint,
            method="POST",
            data={
                "model": model_id,
                "messages": [{"role": "user", "content": prompt}],
                "persona": "default",
                "max_tokens": 800,
            },
            headers=extra_headers or {},
            timeout=20,
        )
        latency_ms = (time.perf_counter() - t0) * 1000
        return status, body, latency_ms

    def vector_model_allowlist(self, base, endpoint):
        """Test whether the proxy enforces a model allowlist or accepts any model ID."""
        self.log("=== VECTOR 1: Model Allowlist Enforcement ===")
        accepted = []
        for m in PAID_MODELS:
            status, body, ms = self._fire_model(base, endpoint, m["id"], _PING_PROMPT)
            accepted_flag = (
                status == 200 and
                any(k in (body or "").lower() for k in ("pong", "reply", "choices", "content", "assistant"))
            )
            symbol = "✓ ACCEPTED" if accepted_flag else f"✗ {status}"
            self.log(f"  {m['id']:<48} {symbol}  {ms:.0f}ms")
            if accepted_flag:
                accepted.append(m)
        if accepted:
            self.log(
                f"  {len(accepted)} paid model(s) accepted with zero credentials — cost exposure confirmed",
                "crit",
            )
            self.record_finding(
                title=f"Unauthenticated Paid Model Access ({len(accepted)} model(s) accepted)",
                severity="critical",
                location=f"{base}{endpoint}",
                evidence=f"Models accepted: {[m['id'] for m in accepted]}",
                recommendation="Enforce model allowlist server-side; require auth before proxying any model call.",
                cwe="CWE-770",
                owasp="API4:2023-Unrestricted Resource Consumption",
            )
        else:
            self.log("  No paid models accepted without credentials", "pass")
        return accepted

    def vector_rate_limit(self, base, endpoint, rounds, concurrency):
        """
        Fire `rounds` requests in parallel and check for 429.
        IMPROVEMENT: uses parallel_requests() instead of ad-hoc threading.
        """
        self.log(f"=== VECTOR 2: Rate Limit Under Parallel Flood ({rounds} requests, {concurrency} workers) ===")
        tasks = [
            {
                "url": base + endpoint,
                "method": "POST",
                "data": {
                    "model": PAID_MODELS[i % len(PAID_MODELS)]["id"],
                    "messages": [{"role": "user", "content": _PING_PROMPT}],
                    "persona": "default",
                },
                "timeout": 15,
            }
            for i in range(rounds)
        ]
        results = self.parallel_requests(tasks, max_workers=concurrency)

        status_counts = {}
        for _, status, _, _ in results:
            status_counts[status] = status_counts.get(status, 0) + 1

        self.log(f"  Status breakdown: {status_counts}")
        rate_limited = status_counts.get(429, 0)
        if rate_limited == 0:
            self.log(
                f"  No 429 after {rounds} parallel requests — endpoint is freely drainable at {concurrency}x concurrency",
                "crit",
            )
            self.record_finding(
                title=f"No Rate Limit on LLM Endpoint Under {rounds}-Request Parallel Flood",
                severity="high",
                location=f"{base}{endpoint}",
                evidence=f"{rounds} parallel requests: {status_counts} — no HTTP 429 triggered",
                recommendation="Add per-IP and per-user rate limits (e.g. 10 req/min) on all LLM endpoints.",
                cwe="CWE-307",
                owasp="API4:2023-Unrestricted Resource Consumption",
            )
        else:
            self.log(f"  Rate limit active — {rate_limited}/{rounds} requests returned 429", "pass")
        return status_counts

    def vector_expensive_flood(self, base, endpoint, rounds, concurrency):
        """
        Fire `rounds` expensive (long-prompt, costly-model) requests in parallel
        and measure total estimated cost.
        """
        self.log(f"=== VECTOR 3: Expensive Model Flood — Cost Estimation ({rounds}x parallel) ===")
        tasks = [
            {
                "url": base + endpoint,
                "method": "POST",
                "data": {
                    "model": "openai/gpt-4o",
                    "messages": [{"role": "user", "content": _EXPENSIVE_PROMPT}],
                    "persona": "default",
                    "max_tokens": 1200,
                },
                "timeout": 30,
            }
            for _ in range(rounds)
        ]
        results = self.parallel_requests(tasks, max_workers=concurrency)

        total_cost = 0.0
        accepted = 0
        gpt4o_cost = next((m["cost_per_m_out"] for m in PAID_MODELS if "gpt-4o" in m["id"] and "mini" not in m["id"]), 5.0)
        for _, status, body, _ in results:
            if status == 200:
                accepted += 1
                total_cost += _estimate_cost(body, gpt4o_cost)

        self.log(f"  {accepted}/{rounds} expensive requests accepted")
        if total_cost > 0:
            self.log(f"  Estimated cost burned: ${total_cost:.4f} USD ({accepted} calls × gpt-4o pricing)", "warn")
        else:
            self.log("  Cost could not be estimated (no usage/cost_usd field in responses)")

        if accepted > 0 and total_cost > 0.01:
            self.record_finding(
                title=f"Confirmed AI Credit Drain — ${total_cost:.4f} Estimated from {accepted} Unauthenticated Calls",
                severity="critical",
                location=f"{base}{endpoint}",
                evidence=f"{accepted} gpt-4o long-prompt requests accepted. Est. cost: ${total_cost:.4f}",
                recommendation="Require authentication, enforce model allowlist, and set monthly spend caps per user.",
                cwe="CWE-770",
                owasp="API4:2023-Unrestricted Resource Consumption",
            )
        return total_cost

    def vector_per_model_breakdown(self, base, endpoint):
        """Fire one request per model and show per-model latency + cost."""
        self.log("=== VECTOR 4: Per-Model Latency + Cost Breakdown ===")
        self.log(f"  {'MODEL':<50} {'STATUS':>6} {'MS':>8} {'EST_COST':>10}")
        for m in PAID_MODELS:
            status, body, ms = self._fire_model(base, endpoint, m["id"], _PING_PROMPT)
            cost = _estimate_cost(body, m["cost_per_m_out"]) if status == 200 else 0.0
            self.log(f"  {m['id']:<50} {status:>6} {ms:>8.0f} ${cost:>9.6f}")

    def run(self, url, rounds=15, concurrency=8):
        self.banner()
        base = url.rstrip("/")
        self.log(f"Target: {base} | rounds={rounds} concurrency={concurrency}")

        endpoint = self._find_llm_endpoint(base)
        self.log(f"Active LLM endpoint: {endpoint}", "info")

        accepted_models = self.vector_model_allowlist(base, endpoint)
        self.vector_rate_limit(base, endpoint, rounds, concurrency)
        total_cost = self.vector_expensive_flood(base, endpoint, rounds // 2, concurrency)
        self.vector_per_model_breakdown(base, endpoint)

        self.log("=" * 50)
        critical_count = sum(1 for f in self.recorded_findings if f and f.get("severity") == "critical")
        if critical_count:
            self.log(f"CREDIT DRAIN AUDIT: {critical_count} critical finding(s). Endpoint is drainable.", "crit")
        elif accepted_models:
            self.log("Rate limit active but paid models accepted — monitor spend closely.", "warn")
        else:
            self.log("No credit drain confirmed — endpoint appears protected.", "pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Credit Drain v2.0 - AI Credit Drain & Rate-Limit Auditor")
    parser.add_argument("--url", required=True, help="Target base URL (e.g. http://localhost:3456)")
    parser.add_argument("--rounds", type=int, default=15, help="Requests per flood vector (default: 15)")
    parser.add_argument("--concurrency", type=int, default=8, help="Parallel workers (default: 8)")
    parser.add_argument("-v", "--version", action="version", version="Credit Drain 2.0.0")
    args = parser.parse_args()
    CreditDrain().run(args.url, rounds=args.rounds, concurrency=args.concurrency)
