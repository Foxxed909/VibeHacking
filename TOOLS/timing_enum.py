#!/usr/bin/env python3
"""
timing_enum.py — Login timing user-enumeration detector.

If "user exists but wrong password" takes longer than "user unknown"
(e.g. hash verify only on existing users), usernames are enumerable.

    python TOOLS/timing_enum.py --url https://target \
        --login /api/login --known alice --samples 15
"""
import argparse
import json
import statistics
import sys
import time
import urllib.error
import urllib.request


def _login(url, user_field, pass_field, username, password):
    body = json.dumps({user_field: username, pass_field: password}).encode()
    req = urllib.request.Request(
        url, data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    t0 = time.perf_counter()
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            r.read()
            code = r.status
    except urllib.error.HTTPError as e:
        e.read()
        code = e.code
    except Exception:
        code = 0
    return code, (time.perf_counter() - t0) * 1000


def main():
    p = argparse.ArgumentParser(description="Timing-based username enumeration probe")
    p.add_argument("--url", required=True)
    p.add_argument("--login", default="/api/login")
    p.add_argument("--user-field", default="username")
    p.add_argument("--pass-field", default="password")
    p.add_argument("--known", required=True, help="A username you know exists")
    p.add_argument("--unknown", default="__no_such_user_zz_999__")
    p.add_argument("--samples", type=int, default=12)
    args = p.parse_args()
    login_url = args.url.rstrip("/") + args.login
    wrong = "DefinitelyWrongPass!999"

    print("=" * 48)
    print(" TIMING ENUM — login response timing")
    print("=" * 48)

    known_ms, unknown_ms = [], []
    for _ in range(args.samples):
        _, ms = _login(login_url, args.user_field, args.pass_field, args.known, wrong)
        known_ms.append(ms)
        _, ms = _login(login_url, args.user_field, args.pass_field, args.unknown, wrong)
        unknown_ms.append(ms)

    k = statistics.mean(known_ms)
    u = statistics.mean(unknown_ms)
    delta = k - u
    print(f"[*] known user wrong-password:   mean={k:.1f}ms p50={statistics.median(known_ms):.1f}ms")
    print(f"[*] unknown user wrong-password: mean={u:.1f}ms p50={statistics.median(unknown_ms):.1f}ms")
    print(f"[*] delta (known - unknown):     {delta:.1f}ms")

    # Heuristic: >50ms stable gap is a practical side channel on WAN
    if delta > 50:
        print("[🔥 HACK] Likely timing-based username enumeration")
        return 0
    if abs(delta) < 15:
        print("[🟢 PASS] No meaningful timing gap observed")
        return 0
    print("[🟡 WARN] Small timing gap — re-run with more samples / closer network")
    return 0


if __name__ == "__main__":
    sys.exit(main())
