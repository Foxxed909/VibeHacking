#!/usr/bin/env python3
"""racer.py — Race-condition / limit-overrun tester (INTERNAL).

Fires N requests at the same instant on a barrier and counts how many succeed.
More than the intended limit = exploitable race (read-then-write not atomic).

    python TOOLS/racer.py --url http://127.0.0.1:9200/ --endpoint /api/coupon/redeem \
        --data '{"code":"SAVE50"}' --count 20 --success granted
"""
import argparse
import concurrent.futures
import json
import os
import sys
import threading
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool
from privacy_guard import privacy_user_agent


class Racer(VibeTool):
    def __init__(self, base):
        super().__init__("Racer", "Race-Condition / Limit-Overrun Tester")
        self.base = base.rstrip("/")

    def _fire(self, endpoint, method, body, headers, barrier):
        h = {"User-Agent": privacy_user_agent("Racer"), "Accept": "*/*"}
        h.update(headers)
        data = None
        if body:
            data = body.encode()
            h.setdefault("Content-Type", "application/json")
        req = urllib.request.Request(self.base + endpoint, data=data, method=method, headers=h)
        barrier.wait()
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
            futs = [pool.submit(self._fire, endpoint, method, body, headers, barrier)
                    for _ in range(count)]
            for f in concurrent.futures.as_completed(futs):
                results.append(f.result())
        def ok(st, bd):
            if success_marker:
                return success_marker.lower() in bd.lower()
            return 200 <= st < 300
        successes = [(st, bd) for st, bd in results if ok(st, bd)]
        statuses = {}
        for st, _ in results:
            statuses[st] = statuses.get(st, 0) + 1
        self.log(f"Status spread: {statuses}")
        self.log(f"Successful responses: {len(successes)} / {count}")
        if len(successes) > 1:
            self.log(f"RACE CONDITION CONFIRMED — {len(successes)} requests succeeded past a "
                     "single-use limit. Read-then-write is not atomic.", "hack")
            self.log(f"  sample: {successes[0][1][:160]}", "crit")
        elif len(successes) == 1:
            self.log("Only one request succeeded — limit held under concurrency.", "pass")
        else:
            self.log("No successful responses — endpoint/marker may be off.", "warn")
        return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="Racer - race-condition / limit-overrun tester")
    p.add_argument("--url", required=True)
    p.add_argument("--endpoint", required=True)
    p.add_argument("--method", default="POST")
    p.add_argument("--data", default="")
    p.add_argument("--count", type=int, default=20)
    p.add_argument("--success", dest="success_marker", default="")
    p.add_argument("--cookie", default="")
    p.add_argument("-v", "--version", action="version", version="Racer 1.0.0")
    args = p.parse_args(argv)
    return Racer(args.url).run(args.endpoint, args.method, args.data,
                               max(2, args.count), args.success_marker, args.cookie)


if __name__ == "__main__":
    sys.exit(main())
