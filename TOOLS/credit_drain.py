import sys, os, argparse, urllib.request, json, time, threading

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool

PAID_MODELS = [
    "anthropic/claude-opus-4-7",
    "openai/gpt-4o",
    "google/gemini-2.5-pro",
    "mistralai/mistral-large",
]


class CreditDrain(VibeTool):
    def __init__(self):
        super().__init__("CreditDrain", "API Credit Drain / Rate-Limit Auditor")

    def run(self, url, rounds=10, concurrency=5):
        self.banner()
        self.log(f"Target: {url}  rounds={rounds}  concurrency={concurrency}")

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
            except Exception as ex:
                with lock:
                    results.append((i, 0, time.time() - t0, 0.0, model))

        self.log(f"Firing {rounds} requests across {len(PAID_MODELS)} paid models (concurrency={concurrency})")
        all_threads = []
        for i in range(rounds):
            model = PAID_MODELS[i % len(PAID_MODELS)]
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

        self.log(f"Status code breakdown: {codes}")
        self.log(f"Rate limited (429)? {'YES' if 429 in codes else 'NO'}")
        if total_cost > 0:
            self.log(f"Estimated cost burned: ${total_cost:.6f} USD", "warn")
        else:
            self.log("Cost could not be extracted from responses")

        if 429 not in codes:
            self.log("CRITICAL — No rate limiting detected. Endpoint is fully drainable.", "fail")
        else:
            self.log("Rate limit is active — endpoint has some protection.", "pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--url", required=True)
    parser.add_argument("--rounds", type=int, default=10)
    parser.add_argument("--concurrency", type=int, default=5)
    args = parser.parse_args()
    CreditDrain().run(args.url, args.rounds, args.concurrency)
