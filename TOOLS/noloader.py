import argparse
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from privacy_guard import privacy_user_agent, sanitize_data
from vibe_core import VibeTool


MIN_INTERVAL = 0.5
MAX_EXTRA_CONFIRMATIONS = 25
MAX_FORCE = 50


def _parse_seconds(raw):
    value = str(raw).strip().lower()
    if not value:
        raise ValueError("empty duration")

    multiplier = 1.0
    for suffix, scale in (("seconds", 1), ("second", 1), ("secs", 1), ("sec", 1), ("s", 1), ("m", 60), ("h", 3600)):
        if value.endswith(suffix):
            multiplier = scale
            value = value[: -len(suffix)]
            break

    return max(0.1, float(value) * multiplier)


def _duration_from_token(token):
    value = token.strip().lower()
    if value.startswith("t-"):
        return _parse_seconds(value[2:])
    if value.startswith("t=") or value.startswith("t:"):
        return _parse_seconds(value[2:])
    if value.startswith("t") and len(value) > 1 and value[1].isdigit():
        return _parse_seconds(value[1:])
    return None


def _normalize_url(raw, auto_scheme=False):
    url = (raw or "").strip()
    if auto_scheme and "://" not in url:
        url = "https://" + url
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        raise ValueError("expected an http(s) URL, e.g. https://example.com")
    return url


def _state_from_result(status, treat_4xx_down, fail_status, text_ok=True):
    if status == 0:
        return "NO-LOAD"
    if treat_4xx_down and status >= 400:
        return "NO-LOAD"
    if status >= fail_status:
        return "NO-LOAD"
    if not text_ok:
        # Reachable but the expected health string was absent — treat as down
        # for monitoring purposes (a 200 that isn't actually serving your app).
        return "NO-LOAD"
    return "LOADED"


def _percentile(values, pct):
    if not values:
        return 0.0
    ordered = sorted(values)
    import math
    idx = min(len(ordered) - 1, max(0, math.ceil(pct / 100 * len(ordered)) - 1))
    return ordered[idx]


def _text_ok(body_bytes, expect_text):
    if not expect_text:
        return True
    try:
        return expect_text.lower() in body_bytes.decode("utf-8", "replace").lower()
    except Exception:
        return False


def _probe(url, method, timeout, max_bytes, expect_text=""):
    headers = {
        "User-Agent": privacy_user_agent("NoLoader"),
        "Accept": "text/html,application/json,*/*",
        "DNT": "1",
        "Sec-GPC": "1",
    }
    # A health-string check needs a body, so force a GET with enough bytes.
    if expect_text and method == "HEAD":
        method = "GET"
    read_bytes = max(max_bytes, 65536) if expect_text else max_bytes
    started = time.perf_counter()
    try:
        req = urllib.request.Request(url, method=method, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as response:
            body = response.read(read_bytes) if method != "HEAD" else b""
            return {
                "status": response.getcode(),
                "latency_ms": (time.perf_counter() - started) * 1000,
                "content_type": response.headers.get("Content-Type", ""),
                "server": response.headers.get("Server", ""),
                "text_ok": _text_ok(body, expect_text),
                "error": "",
            }
    except urllib.error.HTTPError as exc:
        try:
            body = exc.read(read_bytes)
        except Exception:
            body = b""
        return {
            "status": exc.code,
            "latency_ms": (time.perf_counter() - started) * 1000,
            "content_type": exc.headers.get("Content-Type", ""),
            "server": exc.headers.get("Server", ""),
            "text_ok": _text_ok(body, expect_text),
            "error": "",
        }
    except (TimeoutError, socket.timeout) as exc:
        return {
            "status": 0,
            "latency_ms": (time.perf_counter() - started) * 1000,
            "content_type": "",
            "server": "",
            "text_ok": False,
            "error": f"timeout: {exc}",
        }
    except Exception as exc:
        return {
            "status": 0,
            "latency_ms": (time.perf_counter() - started) * 1000,
            "content_type": "",
            "server": "",
            "text_ok": False,
            "error": str(exc),
        }


class NoLoader(VibeTool):
    def __init__(self):
        super().__init__("NoLoader", "App Availability & No-Load Window Monitor")

    def _log_probe(self, index, result, state, expected_state):
        level = "pass" if state == expected_state else "fail"
        error = f" error='{result['error']}'" if result["error"] else ""
        content_type = f" type='{result['content_type']}'" if result["content_type"] else ""
        self.log(
            f"probe={index} state={state} status={result['status']} "
            f"latency={result['latency_ms']:.1f}ms{content_type}{error}",
            level,
        )

    def run(
        self,
        url,
        duration,
        interval,
        request_timeout,
        force,
        force_x,
        method,
        expect_up,
        treat_4xx_down,
        fail_status,
        max_bytes,
        keep_watching,
        json_output,
        expect_text="",
    ):
        self.banner()

        interval = max(MIN_INTERVAL, float(interval))
        request_timeout = max(0.1, float(request_timeout))
        force = min(MAX_FORCE, max(1, int(force)))
        force_x = min(MAX_EXTRA_CONFIRMATIONS, max(0, int(force_x)))
        max_bytes = max(0, int(max_bytes))
        expected_state = "LOADED" if expect_up else "NO-LOAD"

        self.log(
            f"Watching {url} for {duration:.1f}s; expected={expected_state}; "
            f"interval={interval:.1f}s timeout={request_timeout:.1f}s force={force} fx={force_x}"
        )
        self.log("Safe mode: serial probes only; no parallel workers and no traffic flood.")

        started = time.perf_counter()
        deadline = started + duration
        samples = []
        expected_streak = 0
        unexpected_seen = False
        first_unexpected = None
        probe_index = 0

        if expect_text:
            self.log(f"Health check: a LOADED probe must contain '{expect_text}' in the body.")

        def do_probe():
            nonlocal expected_streak, unexpected_seen, first_unexpected, probe_index
            probe_index += 1
            result = _probe(url, method, request_timeout, max_bytes, expect_text)
            state = _state_from_result(result["status"], treat_4xx_down, fail_status,
                                       result.get("text_ok", True))
            result["state"] = state
            result["probe"] = probe_index
            samples.append(result)

            if state == expected_state:
                expected_streak += 1
            else:
                expected_streak = 0
                unexpected_seen = True
                if first_unexpected is None:
                    first_unexpected = dict(result)

            self._log_probe(probe_index, result, state, expected_state)
            return state

        while True:
            do_probe()
            if not expect_up and unexpected_seen and not keep_watching:
                break
            # In health/monitor mode (keep_watching) keep sampling the whole
            # window so uptime %, latency, and flap stats are meaningful instead
            # of stopping the instant the app answers once.
            if expect_up and expected_streak >= force and not keep_watching:
                break

            now = time.perf_counter()
            if now >= deadline:
                break
            time.sleep(min(interval, max(0, deadline - now)))

        if expected_streak >= force and force_x:
            self.log(f"Running {force_x} extra confirmation probe(s).")
            for _ in range(force_x):
                time.sleep(interval)
                state = do_probe()
                if state != expected_state:
                    break

        elapsed = time.perf_counter() - started
        success = expected_streak >= force and (expect_up or not unexpected_seen)

        # Availability & latency stats — the useful part for watching your own app.
        up_samples = sum(1 for s in samples if s["state"] == "LOADED")
        down_samples = len(samples) - up_samples
        uptime_pct = round(100.0 * up_samples / len(samples), 1) if samples else 0.0
        transitions = sum(
            1 for a, b in zip(samples, samples[1:]) if a["state"] != b["state"]
        )
        up_latencies = [s["latency_ms"] for s in samples if s["state"] == "LOADED"]
        latency = {
            "avg_ms": round(sum(up_latencies) / len(up_latencies), 1) if up_latencies else 0.0,
            "p50_ms": round(_percentile(up_latencies, 50), 1),
            "p95_ms": round(_percentile(up_latencies, 95), 1),
            "max_ms": round(max(up_latencies), 1) if up_latencies else 0.0,
        }
        if uptime_pct >= 99.5 and transitions == 0:
            health = "HEALTHY"
        elif uptime_pct >= 80.0:
            health = "DEGRADED"
        else:
            health = "DOWN"

        summary = {
            "url": url,
            "expected": expected_state,
            "success": success,
            "samples": len(samples),
            "elapsed_seconds": round(elapsed, 3),
            "required_streak": force,
            "final_streak": expected_streak,
            "unexpected_seen": unexpected_seen,
            "first_unexpected": first_unexpected,
            "uptime_pct": uptime_pct,
            "up_samples": up_samples,
            "down_samples": down_samples,
            "state_transitions": transitions,
            "latency": latency,
            "health": health,
        }

        # Availability report — always shown; this is what makes it useful for
        # keeping an eye on your own local/personal apps.
        icon = {"HEALTHY": "🟢", "DEGRADED": "🟡", "DOWN": "🔴"}[health]
        self.log("── availability ──────────────────────────────")
        self.log(
            f"{icon} {health}  uptime={uptime_pct}%  up={up_samples}/{len(samples)}  "
            f"flaps={transitions}",
            "pass" if health == "HEALTHY" else ("warn" if health == "DEGRADED" else "fail"),
        )
        if up_latencies:
            self.log(
                f"latency ms: avg={latency['avg_ms']} p50={latency['p50_ms']} "
                f"p95={latency['p95_ms']} max={latency['max_ms']}"
            )

        if success:
            self.log(
                f"Result: {expected_state} condition confirmed "
                f"({expected_streak} consecutive expected probe(s), {len(samples)} sample(s)).",
                "pass",
            )
        else:
            self.log(
                f"Result: {expected_state} condition not confirmed "
                f"(final streak={expected_streak}, samples={len(samples)}).",
                "fail",
            )

        if json_output:
            print(json.dumps(sanitize_data(summary), indent=2, sort_keys=True))

        return 0 if success else 1


def _parse_args(argv):
    parser = argparse.ArgumentParser(
        description="NoLoader - watch your own app's availability with safe, serial (no-load) probes. "
                    "Use --health to monitor uptime %/latency/flapping for an app you expect UP, or "
                    "the default mode to confirm a URL stays DOWN for a window."
    )
    parser.add_argument("tokens", nargs="*", help="Optional URL and shorthand duration tokens such as t-60")
    parser.add_argument("--url", "--urlx", "-urlx", dest="url", default="", help="Target URL")
    parser.add_argument("-t", "--time", "--seconds", dest="duration", default="30s", help="Observation window, e.g. 60, 60s, 2m")
    parser.add_argument("-f", "--force", type=int, default=1, help="Consecutive expected-state probes required")
    parser.add_argument("-fx", "--fx", "--force-x", dest="force_x", type=int, default=0, help="Extra serial confirmation probes")
    parser.add_argument("--interval", type=float, default=2.0, help="Seconds between serial probes (min 0.5)")
    parser.add_argument("--request-timeout", "--timeout", dest="request_timeout", type=float, default=5.0, help="Per-probe timeout seconds")
    parser.add_argument("--method", choices=("GET", "HEAD"), default="GET", help="HTTP method to probe with")
    parser.add_argument("--expect-up", action="store_true", help="Invert the check: succeed when the URL loads")
    parser.add_argument("--treat-4xx-down", action="store_true", help="Count HTTP 4xx responses as no-load")
    parser.add_argument("--fail-status", type=int, default=500, help="HTTP status at or above this counts as no-load")
    parser.add_argument("--max-bytes", type=int, default=2048, help="Maximum response bytes to read per GET probe")
    parser.add_argument("--keep-watching", action="store_true", help="Keep sampling until the time window ends after an unexpected state")
    parser.add_argument(
        "--health", action="store_true",
        help="Health-monitor mode for your own app: expect it UP, watch the whole window, "
             "and report uptime %%, latency, and flapping.",
    )
    parser.add_argument("--expect-text", default="", help="Substring that must appear in the body for a probe to count as healthy (e.g. 'ok' or 'healthy')")
    parser.add_argument("--auto-scheme", action="store_true", help="Prefix https:// when the URL has no scheme")
    parser.add_argument("--json", action="store_true", help="Print a machine-readable summary")
    parser.add_argument("-v", "--version", action="version", version="NoLoader 1.0.0")
    args = parser.parse_args(argv)

    duration = _parse_seconds(args.duration)
    url = args.url
    for token in args.tokens:
        token_duration = _duration_from_token(token)
        if token_duration is not None:
            duration = token_duration
        elif not url and token.startswith(("http://", "https://")):
            url = token
        elif not url and args.auto_scheme and "://" not in token:
            url = token
        else:
            parser.error(f"unrecognized token: {token}")

    if not url:
        parser.error("missing URL. Use --url, -urlx, or pass the URL as the first token.")

    try:
        url = _normalize_url(url, auto_scheme=args.auto_scheme)
    except ValueError as exc:
        parser.error(str(exc))

    if args.fail_status < 400 or args.fail_status > 599:
        parser.error("--fail-status must be between 400 and 599")

    return args, url, duration


def main(argv=None):
    args, url, duration = _parse_args(sys.argv[1:] if argv is None else argv)
    # --health is the "watch my own app" preset: expect it up and sample the
    # whole window so uptime %% / latency / flap stats are meaningful.
    expect_up = args.expect_up or args.health
    keep_watching = args.keep_watching or args.health
    return NoLoader().run(
        url=url,
        duration=duration,
        interval=args.interval,
        request_timeout=args.request_timeout,
        force=args.force,
        force_x=args.force_x,
        method=args.method,
        expect_up=expect_up,
        treat_4xx_down=args.treat_4xx_down,
        fail_status=args.fail_status,
        max_bytes=args.max_bytes,
        keep_watching=keep_watching,
        json_output=args.json,
        expect_text=args.expect_text,
    )


if __name__ == "__main__":
    raise SystemExit(main())
