import argparse
import concurrent.futures
import json
import os
import re
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool


LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def _is_local_target(url):
    parsed = urllib.parse.urlparse(url)
    return parsed.hostname in LOCAL_HOSTS


def _join_url(base_url, path):
    return urllib.parse.urljoin(base_url.rstrip("/") + "/", path.lstrip("/"))


def _request(target_url, method="GET", body=None, timeout=5):
    headers = {
        "User-Agent": "VibeStorm/1.0 local-stress",
        "Accept": "text/html,application/json,*/*",
    }
    data = None
    if body is not None:
        headers["Content-Type"] = "application/json"
        data = body if isinstance(body, bytes) else json.dumps(body).encode("utf-8")

    started = time.perf_counter()
    try:
        req = urllib.request.Request(target_url, method=method, data=data, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as response:
            response.read(512)
            return response.getcode(), time.perf_counter() - started, ""
    except urllib.error.HTTPError as exc:
        exc.read(512)
        return exc.code, time.perf_counter() - started, ""
    except Exception as exc:
        return 0, time.perf_counter() - started, str(exc)


def _check_url(target_url, timeout=8):
    headers = {
        "User-Agent": "VibeStorm/1.0 url-check",
        "Accept": "text/html,application/json,*/*",
    }
    started = time.perf_counter()
    try:
        req = urllib.request.Request(target_url, method="GET", headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as response:
            content = response.read(120_000).decode("utf-8", errors="ignore")
            title_match = re.search(r"<title[^>]*>(.*?)</title>", content, re.I | re.S)
            title = re.sub(r"\s+", " ", title_match.group(1)).strip() if title_match else ""
            return {
                "url": target_url,
                "status": response.getcode(),
                "latency_ms": (time.perf_counter() - started) * 1000,
                "bytes_sampled": len(content),
                "title": title[:120],
                "server": response.headers.get("Server", ""),
                "content_type": response.headers.get("Content-Type", ""),
                "error": "",
            }
    except urllib.error.HTTPError as exc:
        exc.read(512)
        return {
            "url": target_url,
            "status": exc.code,
            "latency_ms": (time.perf_counter() - started) * 1000,
            "bytes_sampled": 0,
            "title": "",
            "server": exc.headers.get("Server", ""),
            "content_type": exc.headers.get("Content-Type", ""),
            "error": "",
        }
    except Exception as exc:
        return {
            "url": target_url,
            "status": 0,
            "latency_ms": (time.perf_counter() - started) * 1000,
            "bytes_sampled": 0,
            "title": "",
            "server": "",
            "content_type": "",
            "error": str(exc),
        }


def _load_urls(single_url, urls_file):
    urls = []
    if single_url:
        urls.append(single_url)
    if urls_file:
        with open(urls_file, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line and not line.startswith("#"):
                    urls.append(line)
    return urls


def run_url_check(urls, timeout):
    tool = VibeTool("Storm", "URL Availability Tester")
    tool.banner()

    if not urls:
        tool.log("No URLs provided. Pass a URL or --urls-file.", "fail")
        return 2

    bad_schemes = [url for url in urls if urllib.parse.urlparse(url).scheme not in {"http", "https"}]
    if bad_schemes:
        tool.log(f"Refusing unsupported URL schemes: {bad_schemes[:3]}", "fail")
        return 2

    tool.log(f"Checking {len(urls)} URL(s). No traffic storm will run in URL-check mode.")
    failures = 0
    for url in urls:
        result = _check_url(url, timeout=timeout)
        status = result["status"]
        if status == 0 or status >= 500:
            failures += 1
            level = "crit"
        elif status >= 400:
            level = "warn"
        else:
            level = "pass"
        title = f" title='{result['title']}'" if result["title"] else ""
        server = f" server='{result['server']}'" if result["server"] else ""
        error = f" error='{result['error']}'" if result["error"] else ""
        tool.log(
            f"{url} -> status={status} latency={result['latency_ms']:.1f}ms "
            f"type='{result['content_type']}'{server}{title}{error}",
            level,
        )

    if failures:
        tool.log(f"URL check completed with {failures} hard failure(s).", "crit")
        return 1
    tool.log("URL check completed without hard failures.", "pass")
    return 0


def _build_plan(base_url, include_chat=False):
    plan = [
        ("GET", _join_url(base_url, "/"), None),
        ("GET", _join_url(base_url, "/index.html"), None),
        ("GET", _join_url(base_url, "/dashboard.html"), None),
        ("GET", _join_url(base_url, "/landing.html"), None),
        ("GET", _join_url(base_url, "/api/config"), None),
        ("POST", _join_url(base_url, "/api/chat"), b"{bad-json"),
    ]

    if include_chat:
        plan.append(
            (
                "POST",
                _join_url(base_url, "/api/chat"),
                {
                    "messages": [{"role": "user", "content": "VibeStorm ping"}],
                    "model": "nvidia/nemotron-3-super-120b-a12b:free",
                    "persona": "default",
                    "stream": False,
                },
            )
        )

    return plan


def run_storm(base_url, duration, entries_per_min, concurrency, include_chat, timeout, full_send):
    tool = VibeTool("Storm", "Localhost Traffic Stressor")
    tool.banner()

    if not _is_local_target(base_url):
        tool.log("Refusing to run: Storm is localhost-only.", "fail")
        return 2

    duration = max(1, int(duration))
    entries_per_min = max(1, int(entries_per_min))
    concurrency = max(1, int(concurrency))
    interval = 0 if full_send else 60.0 / entries_per_min
    total_budget = max(1, int(entries_per_min * (duration / 60.0)))
    plan = _build_plan(base_url, include_chat=include_chat)

    tool.log(
        f"Target={base_url} duration={duration}s entries/min={entries_per_min} "
        f"budget={'unbounded' if full_send else total_budget} concurrency={concurrency}"
    )
    if full_send:
        tool.log("Full-send mode enabled. Storm will submit as fast as workers free up.", "warn")
    if include_chat:
        tool.log("Chat profile enabled. This may exercise upstream AI calls if the app has a key.", "warn")
    else:
        tool.log("Default profile avoids valid chat payloads to reduce API-credit risk.", "info")

    pre_status, pre_latency, pre_error = _request(base_url, timeout=timeout)
    if pre_status == 0:
        tool.log(f"Preflight failed before stress: {pre_error}", "fail")
        return 1
    tool.log(f"Preflight OK: status={pre_status} latency={pre_latency * 1000:.1f}ms", "pass")

    results = []
    errors = {}

    def record_done(futures):
        pending = []
        for future in futures:
            if future.done():
                status, latency, error = future.result()
                results.append((status, latency))
                if error:
                    errors[error] = errors.get(error, 0) + 1
            else:
                pending.append(future)
        return pending

    next_at = time.perf_counter()
    started = time.perf_counter()
    submitted = 0

    with concurrent.futures.ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = []
        while (full_send or submitted < total_budget) and time.perf_counter() - started < duration:
            futures = record_done(futures)
            while len(futures) >= concurrency:
                done, _ = concurrent.futures.wait(
                    futures, timeout=0.05, return_when=concurrent.futures.FIRST_COMPLETED
                )
                for future in done:
                    status, latency, error = future.result()
                    results.append((status, latency))
                    if error:
                        errors[error] = errors.get(error, 0) + 1
                futures = [f for f in futures if not f.done()]

            method, url, body = plan[submitted % len(plan)]
            futures.append(pool.submit(_request, url, method, body, timeout))
            submitted += 1
            if not full_send:
                next_at += interval
                delay = next_at - time.perf_counter()
                if delay > 0:
                    time.sleep(delay)

        for future in concurrent.futures.as_completed(futures):
            status, latency, error = future.result()
            results.append((status, latency))
            if error:
                errors[error] = errors.get(error, 0) + 1

    elapsed = max(0.001, time.perf_counter() - started)
    post_status, post_latency, post_error = _request(base_url, timeout=timeout)

    statuses = {}
    latencies = []
    for status, latency in results:
        statuses[status] = statuses.get(status, 0) + 1
        latencies.append(latency * 1000)

    rate = len(results) / elapsed
    p50 = statistics.median(latencies) if latencies else 0
    p95 = sorted(latencies)[int(len(latencies) * 0.95) - 1] if latencies else 0
    max_latency = max(latencies) if latencies else 0

    tool.log(f"Completed {len(results)} requests in {elapsed:.1f}s ({rate:.1f} req/s)")
    tool.log(f"Status counts: {statuses}")
    tool.log(f"Latency ms: p50={p50:.1f} p95={p95:.1f} max={max_latency:.1f}")

    if errors:
        top_errors = sorted(errors.items(), key=lambda item: item[1], reverse=True)[:5]
        tool.log(f"Transport errors: {top_errors}", "warn")

    if post_status == 0:
        tool.log(f"Post-stress health check failed: {post_error}", "crit")
        return 1

    slowdown = post_latency / pre_latency if pre_latency > 0 else 0
    tool.log(f"Post-stress health: status={post_status} latency={post_latency * 1000:.1f}ms")
    if post_status >= 500 or slowdown >= 5:
        tool.log(f"Target degraded after storm. Slowdown={slowdown:.1f}x", "crit")
    else:
        tool.log(f"Target survived storm. Slowdown={slowdown:.1f}x", "pass")

    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Storm - Localhost Traffic Stressor")
    parser.add_argument("--url", default="", help="Target URL. Stress mode defaults to http://localhost:3456/")
    parser.add_argument("--urls-file", default="", help="File containing one URL per line for --url-check")
    parser.add_argument(
        "--url-check",
        action="store_true",
        help="Run safe one-request-per-URL checks. Required for external URLs.",
    )
    parser.add_argument("--duration", type=int, default=15, help="Stress duration in seconds")
    parser.add_argument("--entries-per-min", type=int, default=600, help="Request entries per minute")
    parser.add_argument("--concurrency", type=int, default=20, help="Maximum concurrent requests")
    parser.add_argument("--timeout", type=float, default=5, help="Per-request timeout in seconds")
    parser.add_argument(
        "--full-send",
        action="store_true",
        help="Ignore entries/min pacing and submit as fast as local workers free up.",
    )
    parser.add_argument(
        "--include-chat",
        action="store_true",
        help="Also send valid /api/chat payloads. May consume API credits if a key is loaded.",
    )
    parser.add_argument("-v", "--version", action="version", version="Storm 1.0.0")
    args = parser.parse_args()

    if args.url_check or args.urls_file:
        raise SystemExit(run_url_check(_load_urls(args.url, args.urls_file), args.timeout))

    raise SystemExit(
        run_storm(
            args.url or "http://localhost:3456/",
            args.duration,
            args.entries_per_min,
            args.concurrency,
            args.include_chat,
            args.timeout,
            args.full_send,
        )
    )
