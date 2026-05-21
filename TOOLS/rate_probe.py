import sys
import os
import argparse
import threading
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool

__version__ = "1.0.0"


class RateProbe(VibeTool):
    def __init__(self):
        super().__init__("RateProbe", "Rate Limit Auditor")

    def run(self, url, rounds=20, concurrency=10):
        self.banner()
        self.log(f"Target: {url}  rounds={rounds}  concurrency={concurrency}")

        results = []
        lock = threading.Lock()

        def fire(i):
            t0 = time.time()
            status, body, headers = self.safe_request(url)
            elapsed = time.time() - t0
            rate_headers = {
                k: v for k, v in headers.items()
                if any(x in k.lower() for x in ("ratelimit", "retry-after", "x-rate"))
            }
            with lock:
                results.append((i, status, elapsed, rate_headers, body[:80]))

        threads = [threading.Thread(target=fire, args=(i,)) for i in range(rounds)]
        for i in range(0, len(threads), concurrency):
            batch = threads[i:i + concurrency]
            for t in batch:
                t.start()
            for t in batch:
                t.join()

        codes = {}
        rate_limited = 0
        all_headers_seen = {}
        latencies = []

        for _, status, elapsed, rate_hdrs, _ in sorted(results):
            codes[status] = codes.get(status, 0) + 1
            latencies.append(elapsed)
            all_headers_seen.update(rate_hdrs)
            if status == 429:
                rate_limited += 1

        avg_lat = sum(latencies) / len(latencies) if latencies else 0
        max_lat = max(latencies) if latencies else 0

        self.log(f"Status codes: {codes}")
        self.log(f"Latency — avg: {avg_lat:.3f}s  max: {max_lat:.3f}s")

        if all_headers_seen:
            self.log(f"Rate-limit headers observed: {all_headers_seen}", "warn")

        if rate_limited > 0:
            self.log(f"Rate limited on {rate_limited}/{rounds} requests (429) — protection is active", "pass")
        else:
            self.log("No 429 responses detected — rate limiting may be absent", "crit")

        retry_after = all_headers_seen.get("Retry-After", all_headers_seen.get("retry-after"))
        if retry_after:
            self.log(f"Retry-After header: {retry_after}", "warn")

        remaining = all_headers_seen.get(
            "X-RateLimit-Remaining",
            all_headers_seen.get("x-ratelimit-remaining")
        )
        if remaining is not None:
            self.log(f"X-RateLimit-Remaining: {remaining}", "info")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="RateProbe - Rate Limit Auditor")
    parser.add_argument("--url", required=True, help="Target URL to probe (e.g. http://localhost:3456/api/chat)")
    parser.add_argument("--rounds", type=int, default=20, help="Number of requests to fire (default: 20)")
    parser.add_argument("--concurrency", type=int, default=10, help="Concurrent requests per batch (default: 10)")
    parser.add_argument("-v", "--version", action="version", version=f"RateProbe {__version__}")
    args = parser.parse_args()
    RateProbe().run(args.url, args.rounds, args.concurrency)
