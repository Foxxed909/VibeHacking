import sys, os, argparse, urllib.request, json, time, threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool

# Model ids are OpenRouter-style because the bundled practice target is an
# OpenRouter front-end. Override with --models for a different gateway.
PAID_MODELS = [
    "anthropic/claude-sonnet-4.5",
    "openai/gpt-4o",
    "google/gemini-2.5-pro",
    "mistralai/mistral-large",
]


class CreditDrain(VibeTool):
    def __init__(self):
        super().__init__("CreditDrain", "API Credit Drain / Rate-Limit Auditor")

    def run(self, url, rounds=10, concurrency=5, models=None):
        self.banner()
        self.log(f"Target: {url}  rounds={rounds}  concurrency={concurrency}")
        models = models or PAID_MODELS

        endpoint = url.rstrip("/") + "/api/chat"
        results = []
        lock = threading.Lock()
        total_cost = 0.0

        def fire(i, model):
            body = json.dumps({
                "model": model,
                "messages": [{"role": "user", "content": "ping"}],
                "persona": "default",
            }).encode()
            req = urllib.request.Request(endpoint, data=body, method="POST")
            req.add_header("Content-Type", "application/json")
            t0 = time.time()
            try:
                r = urllib.request.urlopen(req, timeout=10)
                raw = r.read().decode()
                # Extract cost from usage line
                cost = 0.0
                for line in raw.splitlines():
                    if '"cost_usd"' in line:
                        try:
                            cost = float(line.split('"cost_usd":')[1].split("}")[0].strip())
                        except Exception:
                            pass
                with lock:
                    results.append((i, r.status, time.time() - t0, cost, model))
            except urllib.error.HTTPError as e:
                with lock:
                    results.append((i, e.code, time.time() - t0, 0.0, model))
            except Exception:
                with lock:
                    results.append((i, 0, time.time() - t0, 0.0, model))

        self.log(f"Firing {rounds} requests across {len(models)} paid models (concurrency={concurrency})")
        all_threads = []
        for i in range(rounds):
            model = models[i % len(models)]
            t = threading.Thread(target=fire, args=(i, model))
            all_threads.append(t)

        for i in range(0, len(all_threads), concurrency):
            batch = all_threads[i:i+concurrency]
            [t.start() for t in batch]
            [t.join() for t in batch]

        codes = {}
        for _, code, dur, cost, model in sorted(results):
            codes[code] = codes.get(code, 0) + 1
            total_cost += cost

        succeeded = sum(count for code, count in codes.items() if 200 <= code < 300)
        self.log(f"Status code breakdown: {codes}")
        self.log(f"Rate limited (429)? {'YES' if 429 in codes else 'NO'}")
        if total_cost > 0:
            self.log(f"Estimated cost burned: ${total_cost:.6f} USD", "warn")
        else:
            self.log("Cost could not be extracted from responses")

        if 429 in codes:
            self.log("Rate limit is active — endpoint has some protection.", "pass")
        elif 429 not in codes and succeeded == 0:
            # Nothing succeeded, so absence of a 429 proves nothing: a 404/401
            # endpoint has no rate limit because it has no functionality.
            self.log(f"No request succeeded ({succeeded}/{len(results)}), so the absence of "
                     f"rate limiting is inconclusive. Check the endpoint path/payload.", "warn")
        elif 429 not in codes and succeeded >= len(results):
            self.log(f"CRITICAL — {succeeded} paid-model request(s) succeeded with no 429. "
                     f"The endpoint accepted every request and is drainable.", "fail")
        else:
            self.log(f"PARTIAL — {succeeded}/{len(results)} requests succeeded without a 429; "
                     f"rate limiting looks weak but the endpoint is partly rejecting traffic.", "warn")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--rounds", type=int, default=10)
    parser.add_argument("--concurrency", type=int, default=5)
    parser.add_argument("--models", default="", help="Comma-separated model ids to request")
    args = parser.parse_args()
    model_list = [m.strip() for m in args.models.split(",") if m.strip()] or None
    CreditDrain().run(args.url, args.rounds, args.concurrency, models=model_list)
