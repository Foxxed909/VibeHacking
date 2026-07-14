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


def _state_from_result(status, treat_4xx_down, fail_status):
    if status == 0:
        return "NO-LOAD"
    if treat_4xx_down and status >= 400:
        return "NO-LOAD"
    if status >= fail_status:
        return "NO-LOAD"
    return "LOADED"


def _probe(url, method, timeout, max_bytes):
    headers = {
        "User-Agent": privacy_user_agent("NoLoader"),
        "Accept": "text/html,application/json,*/*",
        "DNT": "1",
        "Sec-GPC": "1",
    }
    started = time.perf_counter()
    try:
        req = urllib.request.Request(url, method=method, headers=headers)
        with urllib.request.urlopen(req, timeout=timeout) as response:
            if method != "HEAD":
                response.read(max_bytes)
            return {
                "status": response.getcode(),
                "latency_ms": (time.perf_counter() - started) * 1000,
                "content_type": response.headers.get("Content-Type", ""),
                "server": response.headers.get("Server", ""),
                "error": "",
            }
    except urllib.error.HTTPError as exc:
        try:
            exc.read(max_bytes)
        except Exception:
            pass
        return {
            "status": exc.code,
            "latency_ms": (time.perf_counter() - started) * 1000,
            "content_type": exc.headers.get("Content-Type", ""),
            "server": exc.headers.get("Server", ""),
            "error": "",
        }
    except (TimeoutError, socket.timeout) as exc:
        return {
            "status": 0,
            "latency_ms": (time.perf_counter() - started) * 1000,
            "content_type": "",
            "server": "",
            "error": f"timeout: {exc}",
        }
    except Exception as exc:
        return {
            "status": 0,
            "latency_ms": (time.perf_counter() - started) * 1000,
            "content_type": "",
            "server": "",
            "error": str(exc),
        }


class NoLoader(VibeTool):
    def __init__(self):
        super().__init__("NoLoader", "URL No-Load Window Verifier")

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

        def do_probe():
            nonlocal expected_streak, unexpected_seen, first_unexpected, probe_index
            probe_index += 1
            result = _probe(url, method, request_timeout, max_bytes)
            state = _state_from_result(result["status"], treat_4xx_down, fail_status)
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
            if expect_up and expected_streak >= force:
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
        }

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
        description="NoLoader - verify that a URL stays unavailable for a time window without generating load."
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
    return NoLoader().run(
        url=url,
        duration=duration,
        interval=args.interval,
        request_timeout=args.request_timeout,
        force=args.force,
        force_x=args.force_x,
        method=args.method,
        expect_up=args.expect_up,
        treat_4xx_down=args.treat_4xx_down,
        fail_status=args.fail_status,
        max_bytes=args.max_bytes,
        keep_watching=args.keep_watching,
        json_output=args.json,
    )


if __name__ == "__main__":
    raise SystemExit(main())
