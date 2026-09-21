#!/usr/bin/env python3
"""
racer.py — Race-condition / limit-overrun tester (INTERNAL edition).

Business-logic limits (redeem-once, one-vote, withdraw-balance) are usually
enforced with a read-then-write that isn't atomic. Fire many requests at the
exact same instant and the check passes for all of them before any write lands —
so a "one use" coupon gets redeemed 20 times, a balance goes negative, etc.

racer aligns N requests on a barrier so they hit together, then counts how many
SUCCEEDED. More than the intended limit == exploitable race.

    python TOOLS/racer.py --url http://127.0.0.1:9200/ --endpoint /api/coupon/redeem \
        --data '{"code":"SAVE50"}' --count 20 --success granted
"""
import argparse
import concurrent.futures
import os
import sys
import threading
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool, FRAMEWORK_VERSION
from privacy_guard import privacy_user_agent


class Racer(VibeTool):
    def __init__(self, base):
        super().__init__("Racer", "Race-Condition / Limit-Overrun Tester")
        self.base = base.rstrip("/")

    def _fire(self, endpoint, method, body, headers, barrier):
        data = None
        h = {"User-Agent": privacy_user_agent("Racer"), "Accept": "*/*"}
        h.update(headers)
        if body:
            data = body.encode()
            h.setdefault("Content-Type", "application/json")
        req = urllib.request.Request(self.base + endpoint, data=data, method=method, headers=h)
        barrier.wait()  # align all threads to fire together
        try:
            with urllib.request.urlopen(req, timeout=15) as r:
                return r.getcode(), r.read(4000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read(4000).decode("utf-8", "replace")
        except Exception as e:
            return 0, str(e)

    def run(self, endpoint, method, body, count, success_marker, cookie):
        self.banner()
        self.log(f"Racing {method} {self.base}{endpoint}  x{count} concurrent")
        headers = {"Cookie": cookie} if cookie else {}
        barrier = threading.Barrier(count)

        results = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=count) as pool:
            futs = [pool.submit(self._fire, endpoint, method, body, headers, barrier) for _ in range(count)]
            for f in concurrent.futures.as_completed(futs):
                results.append(f.result())

        def ok(st, bd):
            if success_marker:
                return success_marker.lower() in bd.lower() and ('"%s": true' % success_marker.lower() in bd.lower()
                                                                  or success_marker.lower() in bd.lower())
            return 200 <= st < 300
        successes = [(st, bd) for st, bd in results if ok(st, bd)]
        statuses = {}
        for st, _ in results:
            statuses[st] = statuses.get(st, 0) + 1

        self.log(f"Status spread: {statuses}")
        self.log(f"Successful responses: {len(successes)} / {count}")

        # If a limit is meant to allow ONE success but several landed, that's a race.
        if len(successes) > 1:
            self.log(f"RACE CONDITION CONFIRMED — {len(successes)} requests succeeded past a "
                     f"single-use limit (expected 1). Read-then-write is not atomic.", "hack")
            self.log(f"  sample winner: {successes[0][1][:160]}", "crit")
        elif len(successes) == 1:
            self.log("Only one request succeeded — limit held under concurrency.", "pass")
        else:
            self.log("No successful responses — endpoint/marker may be off, or nothing was grantable.", "warn")
        return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="Racer - race-condition / limit-overrun tester")
    p.add_argument("--url", required=True, help="Target base URL you own/are authorized to test")
    p.add_argument("--endpoint", required=True, help="State-changing endpoint, e.g. /api/coupon/redeem")
    p.add_argument("--method", default="POST")
    p.add_argument("--data", default="", help="Request body (JSON string)")
    p.add_argument("--count", type=int, default=20, help="Concurrent requests to fire (default 20)")
    p.add_argument("--success", dest="success_marker", default="",
                   help="Substring/field marking success (e.g. 'granted'); default: any 2xx")
    p.add_argument("--cookie", default="", help="Session cookie if the action needs auth")
    p.add_argument("-v", "--version", action="version", version=f"Racer {FRAMEWORK_VERSION}")
    args = p.parse_args(argv)
    return Racer(args.url).run(args.endpoint, args.method, args.data, max(2, args.count),
                               args.success_marker, args.cookie)


if __name__ == "__main__":
    sys.exit(main())
