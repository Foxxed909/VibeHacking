#!/usr/bin/env python3
"""
hyperion.py — Next-Gen Guarded Resilience, Multi-Profile & SLO Load Engine.

Hyperion is VibeHacking's next-generation competitor to Maelstrom:
  - Protected by mandatory authorization guard code (`XXLMILLEAMEAN`) + audit log
  - Enforces strict localhost/private IP or `authorized_targets.txt` allowlist
  - Dual Engine: delegates to Go HTTP/2 engine (`TOOLS/hyperion/main.go`) when Go
    is installed, or runs natively via Python's `http.client` persistent keep-alive
    connection pool (zero external dependencies)
  - Supports `constant`, `ramp`, `step`, and `spike` load profiles
  - Supports multi-endpoint scenario rotation (`--endpoints "/,/api/config"`)
  - Tracks Reservoir-sampled p50 / p90 / p95 / p99 / p99.9 latency + jitter (stdev)
  - Includes Smart Circuit Breaker + CI/CD SLO pass/fail gates (`--slo-p95`, `--slo-err-pct`)
"""
import argparse
import concurrent.futures
import hmac
import http.client
import ipaddress
import json
import math
import os
import random
import shutil
import ssl
import subprocess
import sys
import threading
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from privacy_guard import privacy_user_agent, sanitize_text
from vibe_core import VibeTool

_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

GUARD_CODE = "XXLMILLEAMEAN"
MAX_EXTERNAL_RPS = 9999.99
MAX_EXTERNAL_WORKERS = 256
MAX_PRIVATE_RPS = 250000.0
RESERVOIR_CAP = 250_000
LOCAL_LITERALS = {"localhost", "127.0.0.1", "::1"}


def _log_guard_attempt(allowed, detail, target=""):
    log_dir = os.environ.get("VIBE_LOG_DIR") or os.path.join(_root, "logs")
    os.makedirs(log_dir, exist_ok=True)
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    safe_target = sanitize_text(target) if target else "-"
    line = f"{stamp}\ttool=hyperion\tallowed={str(allowed).lower()}\tdetail={detail}\ttarget={safe_target}\n"
    try:
        with open(os.path.join(log_dir, "locked_cli_access.log"), "a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError:
        pass


def verify_guard_code(supplied_code, target="", interactive=True):
    candidate = (
        (supplied_code or "").strip()
        or os.environ.get("VIBE_HYPERION_GUARD", "").strip()
        or os.environ.get("VIBE_GUARD_CODE", "").strip()
    )
    if candidate and hmac.compare_digest(candidate, GUARD_CODE):
        _log_guard_attempt(True, "guard_code_verified", target)
        return True

    if not candidate and interactive and sys.stdin.isatty():
        try:
            prompted = input("  [🔒 HYPERION GUARD] Enter authorization guard code to unlock: ").strip()
        except EOFError:
            prompted = ""
        if prompted and hmac.compare_digest(prompted, GUARD_CODE):
            _log_guard_attempt(True, "interactive_guard_verified", target)
            return True

    _log_guard_attempt(False, "invalid_or_missing_guard_code", target)
    return False


def _parse_duration(raw):
    s = str(raw or "15s").strip().lower()
    mult = 1.0
    for suffix, scale in (("ms", 0.001), ("s", 1.0), ("m", 60.0), ("h", 3600.0)):
        if s.endswith(suffix):
            mult = scale
            s = s[: -len(suffix)]
            break
    return max(0.1, float(s.strip()) * mult)


def _parse_rate(raw):
    s = str(raw if raw is not None else "1000").strip().lower()
    if s in {"0", "full", "full-send", "max"}:
        return 0.0
    per_min = False
    for suffix in ("/min", "rpm", "permin", "per-minute"):
        if s.endswith(suffix):
            per_min = True
            s = s[: -len(suffix)]
            break
    for suffix in ("/s", "rps", "persec", "per-second"):
        if s.endswith(suffix):
            s = s[: -len(suffix)]
            break
    mult = 1.0
    if s.endswith("k"):
        mult = 1_000.0
        s = s[:-1]
    elif s.endswith("m"):
        mult = 1_000_000.0
        s = s[:-1]
    elif s.endswith("g"):
        mult = 1_000_000_000.0
        s = s[:-1]
    val = float(s.strip()) * mult
    if val < 0:
        raise ValueError("rate cannot be negative")
    return val / 60.0 if per_min else val


def _is_local_or_private(host):
    h = (host or "").strip().lower()
    if h in LOCAL_LITERALS:
        return True
    try:
        ip = ipaddress.ip_address(h)
        return ip.is_loopback or ip.is_private or ip.is_link_local
    except ValueError:
        return False


def _load_authorized_hosts():
    hosts = set()
    here = os.path.dirname(os.path.abspath(__file__))
    for _ in range(6):
        candidate = os.path.join(here, "authorized_targets.txt")
        if os.path.isfile(candidate):
            try:
                with open(candidate, "r", encoding="utf-8") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line or line.startswith("#") or "*" in line or "?" in line:
                            continue
                        host = line
                        if "://" in host:
                            host = urllib.parse.urlparse(host).hostname or host
                        host = host.split("/")[0].strip().lower()
                        if "@" in host:
                            host = host.split("@")[-1]
                        if host.count(":") == 1:
                            host = host.split(":")[0]
                        if host:
                            hosts.add(host)
            except OSError:
                pass
            break
        parent = os.path.dirname(here)
        if parent == here:
            break
        here = parent
    return hosts


def _effective_rate(base_rate, profile, progress):
    if base_rate <= 0:
        return 0.0
    p = max(0.0, min(1.0, progress))
    if profile == "ramp":
        return base_rate * (0.10 + 0.90 * p)
    if profile == "step":
        if p < 0.25:
            return base_rate * 0.25
        if p < 0.50:
            return base_rate * 0.50
        if p < 0.75:
            return base_rate * 0.75
        return base_rate
    if profile == "spike":
        return base_rate if 0.40 <= p <= 0.65 else base_rate * 0.25
    return base_rate


def _percentile(sorted_vals, pct):
    if not sorted_vals:
        return 0.0
    idx = min(len(sorted_vals) - 1, max(0, int(math.ceil((pct / 100.0) * len(sorted_vals))) - 1))
    return sorted_vals[idx]


class Hyperion(VibeTool):
    def __init__(self):
        super().__init__("Hyperion", "Next-Gen Guarded Resilience, Multi-Profile & SLO Load Engine")
        self._tls_ctx = ssl.create_default_context()
        self._thread_local = threading.local()

    def _build_scenario_paths(self, base_url, endpoints_csv):
        parsed = urllib.parse.urlsplit(base_url)
        base_path = parsed.path or "/"
        if parsed.query:
            base_path = f"{base_path}?{parsed.query}"
        if not endpoints_csv:
            return [base_path]

        paths = []
        for raw in endpoints_csv.split(","):
            sub = raw.strip()
            if not sub:
                continue
            if "://" in sub:
                u = urllib.parse.urlsplit(sub)
                if u.netloc.lower() != parsed.netloc.lower():
                    continue
                p = u.path or "/"
                if u.query:
                    p = f"{p}?{u.query}"
                paths.append(p)
            else:
                if not sub.startswith("/"):
                    sub = "/" + sub
                paths.append(sub)
        return paths or [base_path]

    def _get_connection(self, scheme, host, port, timeout):
        conn = getattr(self._thread_local, "conn", None)
        conn_key = getattr(self._thread_local, "conn_key", None)
        target_key = (scheme, host, port, timeout)
        if conn is not None and conn_key == target_key:
            return conn
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        if scheme == "https":
            conn = http.client.HTTPSConnection(host, port or 443, timeout=timeout, context=self._tls_ctx)
        else:
            conn = http.client.HTTPConnection(host, port or 80, timeout=timeout)
        self._thread_local.conn = conn
        self._thread_local.conn_key = target_key
        return conn

    def _reset_connection(self):
        conn = getattr(self._thread_local, "conn", None)
        if conn is not None:
            try:
                conn.close()
            except Exception:
                pass
        self._thread_local.conn = None

    def _fire_once(self, scheme, host, port, path, method, body_bytes, req_headers, timeout):
        t0 = time.perf_counter()
        for attempt in range(2):
            conn = self._get_connection(scheme, host, port, timeout)
            try:
                conn.request(method, path, body=body_bytes, headers=req_headers)
                resp = conn.getresponse()
                data = resp.read()
                status = resp.status
                return status, (time.perf_counter() - t0) * 1000.0, len(data), ""
            except Exception as exc:
                self._reset_connection()
                if attempt == 1:
                    return 0, (time.perf_counter() - t0) * 1000.0, 0, str(exc)
        return 0, (time.perf_counter() - t0) * 1000.0, 0, "request_failed"

    def run_python_engine(
        self,
        target,
        endpoints_csv="",
        profile="constant",
        method="GET",
        rate_raw="1000",
        duration_raw="15s",
        workers=32,
        payload_path="",
        custom_headers=None,
        timeout_raw="5s",
        slo_p95=0.0,
        slo_err_pct=0.0,
        circuit_breaker=True,
        report_file="",
        json_out="",
    ):
        self.banner()
        duration = _parse_duration(duration_raw)
        timeout = _parse_duration(timeout_raw)
        rate = _parse_rate(rate_raw)
        workers = max(1, int(workers))

        parsed = urllib.parse.urlsplit(target)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower()
        port = parsed.port

        scenario_paths = self._build_scenario_paths(target, endpoints_csv)
        body_bytes = None
        if payload_path:
            with open(payload_path, "rb") as fh:
                body_bytes = fh.read()

        req_headers = {
            "User-Agent": privacy_user_agent("Hyperion"),
            "Accept": "*/*",
            "Connection": "keep-alive",
        }
        if body_bytes is not None:
            req_headers["Content-Type"] = "application/json"
        for raw_hdr in custom_headers or []:
            if ":" in raw_hdr:
                k, v = raw_hdr.split(":", 1)
                req_headers[k.strip()] = v.strip()

        self.log(
            f"Engine=Python-KeepAlive target={target} endpoints={len(scenario_paths)} "
            f"profile={profile} method={method} duration={duration:.1f}s workers={workers} rate={rate_raw}"
        )

        lock = threading.Lock()
        stop_event = threading.Event()
        tripped = False

        total = 0
        s2xx = s3xx = s4xx = s5xx = sother = errors = 0
        total_bytes = 0
        sum_ms = 0.0
        sum_sq_ms = 0.0
        min_ms = 0.0
        max_ms = 0.0
        latencies = []
        seq_counter = 0

        started = time.perf_counter()
        deadline = started + duration

        def worker_loop():
            nonlocal total, s2xx, s3xx, s4xx, s5xx, sother, errors, total_bytes
            nonlocal sum_ms, sum_sq_ms, min_ms, max_ms, tripped, seq_counter

            next_slot = time.perf_counter()
            while not stop_event.is_set():
                now = time.perf_counter()
                if now >= deadline:
                    break

                progress = (now - started) / max(duration, 0.001)
                eff_rate = _effective_rate(rate, profile, progress)
                if eff_rate > 0:
                    worker_rate = max(0.5, eff_rate / max(1, workers))
                    interval = 1.0 / worker_rate
                    if now < next_slot:
                        sleep_for = min(next_slot - now, max(0.0, deadline - now))
                        if sleep_for > 0:
                            time.sleep(sleep_for)
                    next_slot = max(time.perf_counter(), next_slot + interval)

                with lock:
                    idx = seq_counter
                    seq_counter += 1
                path = scenario_paths[idx % len(scenario_paths)]

                st, lat_ms, nbytes, err = self._fire_once(
                    scheme, host, port, path, method, body_bytes, req_headers, timeout
                )

                with lock:
                    total += 1
                    total_bytes += nbytes
                    if err or st == 0:
                        errors += 1
                    elif 200 <= st < 300:
                        s2xx += 1
                    elif 300 <= st < 400:
                        s3xx += 1
                    elif 400 <= st < 500:
                        s4xx += 1
                    elif 500 <= st < 600:
                        s5xx += 1
                    else:
                        sother += 1

                    sum_ms += lat_ms
                    sum_sq_ms += lat_ms * lat_ms
                    if total == 1 or lat_ms < min_ms:
                        min_ms = lat_ms
                    if lat_ms > max_ms:
                        max_ms = lat_ms

                    if len(latencies) < RESERVOIR_CAP:
                        latencies.append(lat_ms)
                    else:
                        j = random.randint(0, total - 1)
                        if j < RESERVOIR_CAP:
                            latencies[j] = lat_ms

                    if circuit_breaker and total >= 50 and not tripped:
                        if (s5xx + errors) / float(total) >= 0.80:
                            tripped = True
                            stop_event.set()
            self._reset_connection()

        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
            futures = [pool.submit(worker_loop) for _ in range(workers)]
            for fut in concurrent.futures.as_completed(futures):
                fut.result()

        elapsed = max(0.001, time.perf_counter() - started)
        sorted_lat = sorted(latencies)
        p50 = _percentile(sorted_lat, 50)
        p90 = _percentile(sorted_lat, 90)
        p95 = _percentile(sorted_lat, 95)
        p99 = _percentile(sorted_lat, 99)
        p999 = _percentile(sorted_lat, 99.9)
        avg_ms = (sum_ms / total) if total > 0 else 0.0
        variance = ((sum_sq_ms / total) - (avg_ms * avg_ms)) if total > 0 else 0.0
        jitter_ms = math.sqrt(variance) if variance > 0 else 0.0
        rps = total / elapsed
        err_count = s5xx + errors
        err_pct = (err_count * 100.0 / total) if total > 0 else 0.0

        if tripped:
            self.log(
                "CIRCUIT BREAKER TRIPPED: >=80% error/5xx rate detected. Load halted automatically.",
                "crit",
            )

        slo_failed = False
        slo_notes = []
        if slo_p95 and slo_p95 > 0:
            if p95 > slo_p95:
                slo_failed = True
                slo_notes.append(f"FAIL: p95 {p95:.1f}ms > SLO {slo_p95:.1f}ms")
            else:
                slo_notes.append(f"PASS: p95 {p95:.1f}ms <= SLO {slo_p95:.1f}ms")
        if slo_err_pct and slo_err_pct > 0:
            if err_pct > slo_err_pct:
                slo_failed = True
                slo_notes.append(f"FAIL: err/5xx {err_pct:.2f}% > SLO {slo_err_pct:.2f}%")
            else:
                slo_notes.append(f"PASS: err/5xx {err_pct:.2f}% <= SLO {slo_err_pct:.2f}%")

        self.log(
            f"Completed {total} req in {elapsed:.2f}s ({rps:.1f} RPS) | "
            f"2xx={s2xx} 3xx={s3xx} 4xx={s4xx} 5xx={s5xx} err={errors} ({err_pct:.2f}%)",
            "pass" if not (tripped or slo_failed) else "crit",
        )
        self.log(
            f"Latency ms: min={min_ms:.1f} avg={avg_ms:.1f} jitter(σ)={jitter_ms:.1f} "
            f"p50={p50:.1f} p90={p90:.1f} p95={p95:.1f} p99={p99:.1f} p99.9={p999:.1f} max={max_ms:.1f}"
        )
        if slo_notes:
            self.log("SLO Evaluation: " + " | ".join(slo_notes), "crit" if slo_failed else "pass")

        md_report = (
            "\n## Hyperion Resilience & SLO Report\n\n"
            f"- Target: `{sanitize_text(target)}` ({len(scenario_paths)} scenario endpoint(s))\n"
            f"- Profile / Method: `{profile}` / `{method}`\n"
            f"- Duration / Workers: `{elapsed:.2f}s` / `{workers}`\n"
            f"- Total requests: `{total}` (`{rps:.1f} RPS`)\n"
            f"- 2xx / 3xx / 4xx / 5xx / errors: `{s2xx} / {s3xx} / {s4xx} / {s5xx} / {errors}` (error/5xx rate: `{err_pct:.2f}%`)\n"
            f"- Latency min / avg / jitter(σ) / max: `{min_ms:.1f}ms / {avg_ms:.1f}ms / {jitter_ms:.1f}ms / {max_ms:.1f}ms`\n"
            f"- Percentiles p50 / p90 / p95 / p99 / p99.9: `{p50:.1f}ms / {p90:.1f}ms / {p95:.1f}ms / {p99:.1f}ms / {p999:.1f}ms`\n"
        )
        if slo_notes:
            md_report += f"- SLO Gate: `{' | '.join(slo_notes)}`\n"

        if report_file:
            os.makedirs(os.path.dirname(os.path.abspath(report_file)), exist_ok=True)
            with open(report_file, "w", encoding="utf-8") as fh:
                fh.write(md_report)
            self.log(f"Markdown report written: {report_file}", "pass")

        if json_out:
            os.makedirs(os.path.dirname(os.path.abspath(json_out)), exist_ok=True)
            metrics_doc = {
                "engine": "hyperion-python-keepalive",
                "target": sanitize_text(target),
                "scenario_paths": scenario_paths,
                "profile": profile,
                "method": method,
                "duration_seconds": round(elapsed, 3),
                "workers": workers,
                "total_requests": total,
                "average_rps": round(rps, 2),
                "status_2xx": s2xx,
                "status_3xx": s3xx,
                "status_4xx": s4xx,
                "status_5xx": s5xx,
                "transport_errors": errors,
                "error_rate_pct": round(err_pct, 3),
                "circuit_tripped": tripped,
                "slo_failed": slo_failed,
                "latency_ms": {
                    "min": round(min_ms, 2),
                    "avg": round(avg_ms, 2),
                    "stdev": round(jitter_ms, 2),
                    "p50": round(p50, 2),
                    "p90": round(p90, 2),
                    "p95": round(p95, 2),
                    "p99": round(p99, 2),
                    "p999": round(p999, 2),
                    "max": round(max_ms, 2),
                },
            }
            with open(json_out, "w", encoding="utf-8") as fh:
                json.dump(metrics_doc, fh, indent=2)
            self.log(f"JSON telemetry written: {json_out}", "pass")

        return 1 if (tripped or slo_failed) else 0


def _confirm_external(host, rate_desc, assume_yes=False):
    bar = "=" * 64
    print(bar)
    print("  ⚠  HYPERION EXTERNAL TARGET — ACTIVE LOAD TEST")
    print(bar)
    print(f"  Host : {sanitize_text(host)}")
    print(f"  Rate : {rate_desc}")
    print("  Proceed ONLY if you own this host or hold written permission.")
    print(bar)
    if assume_yes:
        return True
    try:
        ans = input(f"  Type the hostname ({host}) to proceed: ").strip().lower()
    except EOFError:
        return False
    return ans == host.lower()


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Hyperion - Next-Gen Guarded Resilience, Multi-Profile & SLO Load Engine (requires --guard XXLMILLEAMEAN)"
    )
    parser.add_argument("-t", "--target", "--url", dest="target", default="http://localhost:3456/", help="Target URL endpoint")
    parser.add_argument("--endpoints", default="", help="Comma-separated subpaths on the same host (e.g. '/,/api/config,/api/guestbook')")
    parser.add_argument("-P", "--profile", choices=["constant", "ramp", "step", "spike"], default="constant", help="Load profile (default: constant)")
    parser.add_argument("-m", "--method", default="GET", help="HTTP method (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)")
    parser.add_argument("-r", "--rate", default="1000", help="Target rate in RPS (e.g. 1000, 25k, 60000rpm, or 0 for local full-send)")
    parser.add_argument("-d", "--duration", default="10s", help="Test duration (e.g. 10s, 1m)")
    parser.add_argument("-w", "--workers", type=int, default=32, help="Concurrent workers")
    parser.add_argument("-p", "--payload", default="", help="Optional payload file path for POST/PUT/PATCH")
    parser.add_argument("-H", "--header", "--headers", dest="headers", action="append", default=[], help="Custom header 'Name: value' (repeatable)")
    parser.add_argument("--timeout", default="5s", help="Per-request timeout (default: 5s)")
    parser.add_argument("-g", "--guard", "--code", dest="guard", default="", help="Required authorization guard code")
    parser.add_argument("--slo-p95", type=float, default=0.0, help="SLO gate: fail if p95 latency (ms) exceeds threshold")
    parser.add_argument("--slo-err-pct", type=float, default=0.0, help="SLO gate: fail if 5xx/error percentage exceeds threshold")
    parser.add_argument("--no-circuit-breaker", action="store_true", help="Disable the 80%% 5xx/error auto-abort circuit breaker")
    parser.add_argument("--engine", choices=["auto", "python", "go"], default="auto", help="Execution engine (default: auto)")
    parser.add_argument("--report-file", default="", help="Optional Markdown report path")
    parser.add_argument("--json-out", default="", help="Optional JSON metrics output path")
    parser.add_argument("-y", "--yes", action="store_true", help="Skip interactive hostname prompt for trusted external hosts")
    parser.add_argument("-v", "--version", action="version", version="Hyperion 1.0.0")
    args = parser.parse_args(argv)

    # 1. Enforce mandatory guard code XXLMILLEAMEAN
    if not verify_guard_code(args.guard, target=args.target, interactive=not args.yes):
        print("[-] Hyperion guard lock active: authorization code required (--guard <code> or VIBE_HYPERION_GUARD).")
        print("    Access denied and logged to logs/locked_cli_access.log.")
        return 2

    # 2. Validate URL & target scope
    parsed = urllib.parse.urlparse(args.target)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        print(f"[-] Invalid target URL: {sanitize_text(args.target)}")
        return 2

    host = parsed.hostname.lower()
    try:
        parsed_rate = _parse_rate(args.rate)
    except ValueError as exc:
        print(f"[-] Invalid rate '{args.rate}': {exc}")
        return 2

    if not _is_local_or_private(host):
        if host not in _load_authorized_hosts():
            print(f"[-] Refusing external target '{sanitize_text(host)}': not in authorized_targets.txt.")
            print(f"    Authorize a host you own first: python vibe.py trust add {host}")
            return 2
        if parsed_rate <= 0 or parsed_rate > MAX_EXTERNAL_RPS:
            print(f"[-] Refusing unsafe public-host rate: {args.rate} ({parsed_rate:.2f} RPS).")
            print(f"    External Hyperion runs are capped at {MAX_EXTERNAL_RPS:g} RPS; full-send is local-only.")
            return 2
        if args.workers > MAX_EXTERNAL_WORKERS:
            print(f"[-] Public-host workers ({args.workers}) exceed the {MAX_EXTERNAL_WORKERS} worker cap.")
            return 2
        if not _confirm_external(host, rate_desc=f"{args.rate} ({args.profile})", assume_yes=args.yes):
            print("[-] Aborted — external target confirmation did not match.")
            return 2
    else:
        if parsed_rate > MAX_PRIVATE_RPS:
            print(f"[-] Rate {parsed_rate:.0f} RPS exceeds local safety cap ({MAX_PRIVATE_RPS:.0f} RPS).")
            return 2

    # 3. Choose Go engine if available and requested, else Python keep-alive engine
    go_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), "hyperion")
    has_go = bool(shutil.which("go")) and os.path.isfile(os.path.join(go_dir, "main.go"))

    if args.engine == "go" and not has_go:
        print("[-] Go toolchain not found; use --engine auto or --engine python.")
        return 2

    if args.engine in ("auto", "go") and has_go:
        cmd = [
            "go", "run", ".",
            "--guard", GUARD_CODE,
            "-t", args.target,
            "-P", args.profile,
            "-m", args.method,
            "-r", str(args.rate),
            "-d", str(args.duration),
            "-w", str(args.workers),
            "--timeout", str(args.timeout),
            f"--circuit-breaker={'false' if args.no_circuit_breaker else 'true'}",
        ]
        if args.endpoints:
            cmd += ["--endpoints", args.endpoints]
        if args.payload:
            cmd += ["-p", args.payload]
        if args.slo_p95 > 0:
            cmd += ["--slo-p95", str(args.slo_p95)]
        if args.slo_err_pct > 0:
            cmd += ["--slo-err-pct", str(args.slo_err_pct)]
        if args.report_file:
            cmd += ["--report-file", os.path.abspath(args.report_file)]
        if args.json_out:
            cmd += ["--json-out", os.path.abspath(args.json_out)]
        for h in args.headers or []:
            cmd += ["-H", h]
        return subprocess.run(cmd, cwd=go_dir).returncode

    return Hyperion().run_python_engine(
        target=args.target,
        endpoints_csv=args.endpoints,
        profile=args.profile,
        method=args.method.upper(),
        rate_raw=args.rate,
        duration_raw=args.duration,
        workers=args.workers,
        payload_path=args.payload,
        custom_headers=args.headers,
        timeout_raw=args.timeout,
        slo_p95=args.slo_p95,
        slo_err_pct=args.slo_err_pct,
        circuit_breaker=not args.no_circuit_breaker,
        report_file=args.report_file,
        json_out=args.json_out,
    )


if __name__ == "__main__":
    sys.exit(main())
