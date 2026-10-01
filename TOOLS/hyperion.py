#!/usr/bin/env python3
"""
hyperion.py v2.0 — 14x Sharded Resilience, HDR Histogram & SLO Load Engine.

Hyperion v2.0 is VibeHacking's next-generation competitor to Maelstrom:
  1. Mandatory `XXLMILLEAMEAN` constant-time cryptographic guard + audit log
  2. Tamper-evident HMAC-SHA256 signed run receipt (`receipt_hmac`)
  3. 14x Private-Lab Ceiling (3,500,000 RPS max private cap vs Maelstrom's 250k)
     while strictly enforcing 9999.99 RPS / 256 workers + `authorized_targets.txt`
     on external targets
  4. Dual Sharded Engine: Lock-free Go HTTP/2 engine (`TOOLS/hyperion/main.go`) +
     Lock-free Python `asyncio` raw HTTP/1.1 Keep-Alive socket-pool engine
  5. 6 Load Profiles: `constant`, `ramp`, `step`, `spike`, `sawtooth`, `stress-knee`
  6. Automatic Saturation Knee Detector (identifies exact RPS where latency spikes)
  7. Weighted Multi-Endpoint Scenario Ring (`--endpoints "/:50,/api/config:30,/api/guestbook:20"`)
  8. Dynamic Request Mutation Macros (`--cache-bust`, `{{seq}}`, `{{timestamp}}`, `{{uuid}}`)
  9. O(1) Fixed-Memory HDR Histogram (100us resolution: p50, p75, p90, p95, p99, p99.9, p99.99 + ASCII chart)
  10. Apdex (Application Performance Index) Score (`--apdex-t`) & Jitter (σ)
  11. 4-Stage Progression Telemetry Table (`Q1`–`Q4` RPS, avg latency, error %)
  12. Pre-Flight Baseline & Post-Load Recovery Slowdown Factor (`pre_ms -> post_ms`)
  13. Rate-Limiter (`HTTP 429`) & Response Integrity Assertions (`--expect-status`, `--expect-text`)
  14. Multi-Threshold Circuit Breaker + 5-Metric CI/CD SLO Gate (`--slo-p95`, `--slo-p99`, `--slo-err-pct`, `--slo-apdex`, `--slo-min-rps`)
"""
import argparse
import asyncio
import hashlib
import hmac
import http.client
import ipaddress
import json
import math
import os
import shutil
import socket
import ssl
import subprocess
import sys
import time
import urllib.parse
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from privacy_guard import privacy_user_agent, sanitize_text
from vibe_core import VibeTool

_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

GUARD_CODE = "XXLMILLEAMEAN"
MAX_EXTERNAL_RPS = 9999.99
MAX_EXTERNAL_WORKERS = 256
# 14x Maelstrom's 250,000 RPS private lab cap (3,500,000 RPS)
MAX_PRIVATE_RPS = 3_500_000.0
HIST_BUCKETS = 60_000
HIST_STEP_MS = 0.1  # 100 microsecond (0.1ms) bucket resolution up to 6,000ms
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
    if profile in ("step", "stress-knee"):
        if p < 0.25:
            return base_rate * 0.25
        if p < 0.50:
            return base_rate * 0.50
        if p < 0.75:
            return base_rate * 0.75
        return base_rate
    if profile == "spike":
        return base_rate if 0.40 <= p <= 0.65 else base_rate * 0.20
    if profile == "sawtooth":
        wave = (p * 4.0) % 1.0
        return base_rate * (0.20 + 0.80 * wave)
    return base_rate


class _WorkerShard:
    """Lock-free per-worker metrics shard — zero lock contention during the hot loop."""

    __slots__ = (
        "hist",
        "overflow",
        "count",
        "s2xx",
        "s3xx",
        "s4xx",
        "s429",
        "s5xx",
        "sother",
        "errors",
        "assert_fails",
        "bytes_read",
        "sum_ms",
        "sum_sq_ms",
        "min_ms",
        "max_ms",
        "apdex_sat",
        "apdex_tol",
        "stage_counts",
        "stage_sum_ms",
        "stage_5xx_err",
    )

    def __init__(self):
        self.hist = {}
        self.overflow = 0
        self.count = 0
        self.s2xx = 0
        self.s3xx = 0
        self.s4xx = 0
        self.s429 = 0
        self.s5xx = 0
        self.sother = 0
        self.errors = 0
        self.assert_fails = 0
        self.bytes_read = 0
        self.sum_ms = 0.0
        self.sum_sq_ms = 0.0
        self.min_ms = 0.0
        self.max_ms = 0.0
        self.apdex_sat = 0
        self.apdex_tol = 0
        self.stage_counts = [0, 0, 0, 0]
        self.stage_sum_ms = [0.0, 0.0, 0.0, 0.0]
        self.stage_5xx_err = [0, 0, 0, 0]

    def record(self, status, lat_ms, nbytes, err_flag, assert_ok, stage_idx, apdex_t):
        self.count += 1
        self.bytes_read += nbytes
        self.sum_ms += lat_ms
        self.sum_sq_ms += lat_ms * lat_ms
        if self.count == 1 or lat_ms < self.min_ms:
            self.min_ms = lat_ms
        if lat_ms > self.max_ms:
            self.max_ms = lat_ms

        b = int(lat_ms / HIST_STEP_MS)
        if b < 0:
            b = 0
        if b < HIST_BUCKETS:
            self.hist[b] = self.hist.get(b, 0) + 1
        else:
            self.overflow += 1

        self.stage_counts[stage_idx] += 1
        self.stage_sum_ms[stage_idx] += lat_ms

        if not assert_ok:
            self.assert_fails += 1

        if err_flag or status == 0:
            self.errors += 1
            self.stage_5xx_err[stage_idx] += 1
        elif 200 <= status < 300:
            self.s2xx += 1
            if lat_ms <= apdex_t:
                self.apdex_sat += 1
            elif lat_ms <= apdex_t * 4.0:
                self.apdex_tol += 1
        elif 300 <= status < 400:
            self.s3xx += 1
            if lat_ms <= apdex_t:
                self.apdex_sat += 1
            elif lat_ms <= apdex_t * 4.0:
                self.apdex_tol += 1
        elif status == 429:
            self.s4xx += 1
            self.s429 += 1
        elif 400 <= status < 500:
            self.s4xx += 1
        elif 500 <= status < 600:
            self.s5xx += 1
            self.stage_5xx_err[stage_idx] += 1
        else:
            self.sother += 1


class Hyperion(VibeTool):
    def __init__(self):
        super().__init__("Hyperion", "14x Sharded Resilience, HDR Histogram & SLO Load Engine")
        self._tls_ctx = ssl.create_default_context()

    @staticmethod
    def _build_weighted_ring(base_url, endpoints_csv):
        parsed = urllib.parse.urlsplit(base_url)
        base_path = parsed.path or "/"
        if parsed.query:
            base_path = f"{base_path}?{parsed.query}"
        if not endpoints_csv:
            return [base_path], [{"path": base_path, "weight": 1}]

        ring = []
        specs = []
        for item in endpoints_csv.split(","):
            raw = item.strip()
            if not raw:
                continue
            weight = 1
            sub = raw
            if ":" in raw and not raw.startswith(("http://", "https://")):
                prefix, maybe_w = raw.rsplit(":", 1)
                if maybe_w.isdigit() and 1 <= int(maybe_w) <= 100:
                    weight = int(maybe_w)
                    sub = prefix
            if "://" in sub:
                u = urllib.parse.urlsplit(sub)
                if u.netloc.lower() != parsed.netloc.lower():
                    continue
                p = u.path or "/"
                if u.query:
                    p = f"{p}?{u.query}"
                sub = p
            elif not sub.startswith("/"):
                sub = "/" + sub
            specs.append({"path": sub, "weight": weight})
            ring.extend([sub] * weight)

        if not ring:
            ring = [base_path]
            specs = [{"path": base_path, "weight": 1}]
        return ring, specs

    def _probe_single_sync(self, scheme, host, port, path, method, headers_dict, timeout):
        t0 = time.perf_counter()
        conn = None
        try:
            if scheme == "https":
                conn = http.client.HTTPSConnection(host, port or 443, timeout=timeout, context=self._tls_ctx)
            else:
                conn = http.client.HTTPConnection(host, port or 80, timeout=timeout)
            conn.request(method, path, headers=headers_dict)
            resp = conn.getresponse()
            resp.read()
            return resp.status, (time.perf_counter() - t0) * 1000.0
        except Exception:
            return 0, (time.perf_counter() - t0) * 1000.0
        finally:
            if conn is not None:
                try:
                    conn.close()
                except Exception:
                    pass

    async def _run_async_coro(
        self,
        scheme,
        host,
        port,
        ring_paths,
        profile,
        method,
        rate,
        duration,
        workers,
        payload_template,
        req_headers,
        timeout,
        cache_bust,
        expect_status,
        expect_text,
        apdex_t,
        circuit_breaker,
        abort_5xx_pct,
    ):
        shards = [_WorkerShard() for _ in range(workers)]
        stop_flag = False
        tripped = False
        has_macros = payload_template is not None and (b"{{" in payload_template)
        expect_bytes = expect_text.encode("utf-8") if expect_text else b""
        host_header = f"{host}:{port}" if port else host

        # Pre-build raw HTTP/1.1 request frames for the fast path (when no dynamic macros/cache-bust)
        extra_hdr_lines = "".join(
            f"{k}: {v}\r\n"
            for k, v in req_headers.items()
            if k.lower() not in ("host", "connection", "content-length")
        )
        body_len = len(payload_template) if payload_template else 0
        static_frames = {}
        for p in set(ring_paths):
            head = (
                f"{method} {p} HTTP/1.1\r\n"
                f"Host: {host_header}\r\n"
                f"Connection: keep-alive\r\n"
                f"{extra_hdr_lines}"
            )
            if body_len > 0:
                head += f"Content-Length: {body_len}\r\n\r\n"
                static_frames[p] = head.encode("latin-1", errors="ignore") + payload_template
            else:
                head += "\r\n"
                static_frames[p] = head.encode("latin-1", errors="ignore")

        started = time.perf_counter()
        deadline = started + duration
        worker_base_rate = (rate / float(workers)) if rate > 0 else 0.0
        global_seq = 0

        async def open_stream():
            r, w = await asyncio.wait_for(
                asyncio.open_connection(
                    host,
                    port or (443 if scheme == "https" else 80),
                    ssl=self._tls_ctx if scheme == "https" else None,
                ),
                timeout=timeout,
            )
            sock = w.get_extra_info("socket")
            if sock is not None:
                try:
                    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                except Exception:
                    pass
            return r, w

        async def read_http_response(reader):
            status_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
            if not status_line:
                raise ConnectionError("eof")
            parts = status_line.split(b" ", 2)
            status_code = int(parts[1]) if len(parts) >= 2 and parts[1].isdigit() else 0
            content_length = None
            chunked = False
            conn_close = b"HTTP/1.0" in status_line

            while True:
                hline = await asyncio.wait_for(reader.readline(), timeout=timeout)
                if not hline or hline in (b"\r\n", b"\n"):
                    break
                lower_h = hline.lower()
                if lower_h.startswith(b"content-length:"):
                    try:
                        content_length = int(lower_h.split(b":", 1)[1].strip())
                    except ValueError:
                        content_length = 0
                elif lower_h.startswith(b"transfer-encoding:") and b"chunked" in lower_h:
                    chunked = True
                elif lower_h.startswith(b"connection:") and b"close" in lower_h:
                    conn_close = True

            body_sample = b""
            nbytes = 0
            if method == "HEAD" or status_code in (204, 304) or (100 <= status_code < 200):
                pass
            elif content_length is not None:
                if content_length > 0:
                    data = await asyncio.wait_for(reader.readexactly(content_length), timeout=timeout)
                    nbytes = len(data)
                    if expect_bytes:
                        body_sample = data
            elif chunked:
                chunks = []
                while True:
                    sz_line = await asyncio.wait_for(reader.readline(), timeout=timeout)
                    if not sz_line:
                        break
                    sz_str = sz_line.split(b";", 1)[0].strip()
                    sz = int(sz_str, 16) if sz_str else 0
                    if sz == 0:
                        await asyncio.wait_for(reader.readline(), timeout=timeout)
                        break
                    chunk_data = await asyncio.wait_for(reader.readexactly(sz + 2), timeout=timeout)
                    nbytes += sz
                    if expect_bytes and len(chunks) < 4:
                        chunks.append(chunk_data[:-2])
                if expect_bytes:
                    body_sample = b"".join(chunks)
            else:
                data = await asyncio.wait_for(reader.read(65536), timeout=timeout)
                nbytes = len(data)
                if expect_bytes:
                    body_sample = data
                conn_close = True

            return status_code, nbytes, body_sample, conn_close

        async def worker_task(w_id, shard):
            nonlocal stop_flag, tripped, global_seq
            reader = writer = None
            local_seq = w_id
            next_slot = time.perf_counter()

            try:
                while not stop_flag:
                    now = time.perf_counter()
                    if now >= deadline:
                        break
                    progress = (now - started) / max(duration, 0.001)
                    stage_idx = min(3, max(0, int(progress * 4.0)))

                    if worker_base_rate > 0:
                        eff_w_rate = _effective_rate(worker_base_rate, profile, progress)
                        if eff_w_rate > 0.1:
                            interval = 1.0 / eff_w_rate
                            if now < next_slot:
                                sleep_for = min(next_slot - now, max(0.0, deadline - now))
                                if sleep_for > 0.0005:
                                    await asyncio.sleep(sleep_for)
                            next_slot = max(time.perf_counter() - 0.02, next_slot + interval)

                    global_seq += 1
                    seq = global_seq
                    path = ring_paths[local_seq % len(ring_paths)]
                    local_seq += workers

                    if not cache_bust and not has_macros:
                        frame = static_frames[path]
                    else:
                        req_path = f"{path}{'&' if '?' in path else '?'}_cb={seq}" if cache_bust else path
                        body_b = payload_template or b""
                        if has_macros and body_b:
                            text_b = body_b.decode("utf-8", errors="ignore")
                            text_b = (
                                text_b.replace("{{seq}}", str(seq))
                                .replace("{{timestamp}}", str(int(time.time() * 1000)))
                                .replace("{{uuid}}", uuid.uuid4().hex[:12])
                            )
                            body_b = text_b.encode("utf-8")
                        head = (
                            f"{method} {req_path} HTTP/1.1\r\n"
                            f"Host: {host_header}\r\n"
                            f"Connection: keep-alive\r\n"
                            f"{extra_hdr_lines}"
                        )
                        if cache_bust:
                            head += f"X-Request-Sequence: {seq}\r\n"
                        if body_b:
                            head += f"Content-Length: {len(body_b)}\r\n\r\n"
                            frame = head.encode("latin-1", errors="ignore") + body_b
                        else:
                            head += "\r\n"
                            frame = head.encode("latin-1", errors="ignore")

                    t0 = time.perf_counter()
                    status_code = 0
                    nbytes = 0
                    err_flag = False
                    assert_ok = True

                    for attempt in range(2):
                        try:
                            if writer is None:
                                reader, writer = await open_stream()
                            writer.write(frame)
                            await writer.drain()
                            status_code, nbytes, body_sample, conn_close = await read_http_response(reader)
                            if conn_close:
                                writer.close()
                                reader = writer = None
                            if expect_status > 0 and status_code != expect_status:
                                assert_ok = False
                            if expect_bytes and expect_bytes not in body_sample:
                                assert_ok = False
                            err_flag = False
                            break
                        except Exception:
                            if writer is not None:
                                try:
                                    writer.close()
                                except Exception:
                                    pass
                            reader = writer = None
                            err_flag = True

                    lat_ms = (time.perf_counter() - t0) * 1000.0
                    shard.record(status_code, lat_ms, nbytes, err_flag, assert_ok, stage_idx, apdex_t)

                    if circuit_breaker and shard.count >= 20 and (seq % 16 == 0):
                        tot_req = sum(s.count for s in shards)
                        if tot_req >= 50:
                            bad_req = sum(s.s5xx + s.errors for s in shards)
                            if (bad_req * 100.0 / tot_req) >= abort_5xx_pct:
                                tripped = True
                                stop_flag = True
                                break
            finally:
                if writer is not None:
                    try:
                        writer.close()
                    except Exception:
                        pass

        tasks = [asyncio.create_task(worker_task(i, shards[i])) for i in range(workers)]
        await asyncio.gather(*tasks, return_exceptions=True)
        return shards, time.perf_counter() - started, tripped

    @staticmethod
    def _ascii_histogram(merged_hist, total_count):
        if total_count == 0:
            return ""
        bands = [
            ("< 1ms", 0, 10),
            ("1 - 5ms", 10, 50),
            ("5 - 20ms", 50, 200),
            ("20 - 100ms", 200, 1000),
            ("100 - 500ms", 1000, 5000),
            (">= 500ms", 5000, HIST_BUCKETS + 1),
        ]
        lines = []
        for label, lo, hi in bands:
            cnt = sum(v for b, v in merged_hist.items() if lo <= b < hi)
            pct = (cnt * 100.0) / total_count
            bar_len = int(round(pct / 4.0))
            bar = "█" * bar_len + "░" * (25 - bar_len)
            lines.append(f"  {label:<12} | {bar} | {pct:5.1f}% ({cnt})")
        return "\n".join(lines)

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
        cache_bust=False,
        expect_status=0,
        expect_text="",
        apdex_t=100.0,
        slo_p95=0.0,
        slo_p99=0.0,
        slo_err_pct=0.0,
        slo_apdex=0.0,
        slo_min_rps=0.0,
        circuit_breaker=True,
        abort_5xx_pct=80.0,
        report_file="",
        json_out="",
    ):
        self.banner()
        duration = _parse_duration(duration_raw)
        timeout = _parse_duration(timeout_raw)
        rate = _parse_rate(rate_raw)
        workers = max(1, int(workers))
        apdex_t = max(1.0, float(apdex_t or 100.0))

        parsed = urllib.parse.urlsplit(target)
        scheme = parsed.scheme.lower()
        host = (parsed.hostname or "").lower()
        port = parsed.port

        ring_paths, specs = self._build_weighted_ring(target, endpoints_csv)
        payload_template = None
        if payload_path:
            with open(payload_path, "rb") as fh:
                payload_template = fh.read()

        req_headers = {
            "User-Agent": privacy_user_agent("Hyperion/2.0"),
            "Accept": "*/*",
        }
        if payload_template is not None:
            req_headers["Content-Type"] = "application/json"
        for raw_hdr in custom_headers or []:
            if ":" in raw_hdr:
                k, v = raw_hdr.split(":", 1)
                req_headers[k.strip()] = v.strip()

        pre_status, pre_lat_ms = self._probe_single_sync(
            scheme, host, port, ring_paths[0], method, req_headers, timeout
        )
        self.log(
            f"Engine=Async-Sharded-HDR v2.0 | target={target} endpoints={len(specs)} "
            f"profile={profile} method={method} duration={duration:.1f}s workers={workers} rate={rate_raw}"
        )
        self.log(f"Preflight baseline: HTTP {pre_status} ({pre_lat_ms:.2f}ms) | Guard=VERIFIED")

        shards, elapsed, tripped = asyncio.run(
            self._run_async_coro(
                scheme=scheme,
                host=host,
                port=port,
                ring_paths=ring_paths,
                profile=profile,
                method=method,
                rate=rate,
                duration=duration,
                workers=workers,
                payload_template=payload_template,
                req_headers=req_headers,
                timeout=timeout,
                cache_bust=cache_bust,
                expect_status=expect_status,
                expect_text=expect_text,
                apdex_t=apdex_t,
                circuit_breaker=circuit_breaker,
                abort_5xx_pct=abort_5xx_pct,
            )
        )
        elapsed = max(0.001, elapsed)
        post_status, post_lat_ms = self._probe_single_sync(
            scheme, host, port, ring_paths[0], method, req_headers, timeout
        )

        # Merge lock-free worker shards
        merged_hist = {}
        total = overflow = s2xx = s3xx = s4xx = s429 = s5xx = sother = errors = assert_fails = 0
        sum_ms = sum_sq_ms = min_ms = max_ms = 0.0
        apdex_sat = apdex_tol = 0
        stage_counts = [0, 0, 0, 0]
        stage_sum_ms = [0.0, 0.0, 0.0, 0.0]
        stage_5xx_err = [0, 0, 0, 0]

        for s in shards:
            if s.count == 0:
                continue
            if total == 0 or s.min_ms < min_ms:
                min_ms = s.min_ms
            if s.max_ms > max_ms:
                max_ms = s.max_ms
            total += s.count
            overflow += s.overflow
            s2xx += s.s2xx
            s3xx += s.s3xx
            s4xx += s.s4xx
            s429 += s.s429
            s5xx += s.s5xx
            sother += s.sother
            errors += s.errors
            assert_fails += s.assert_fails
            sum_ms += s.sum_ms
            sum_sq_ms += s.sum_sq_ms
            apdex_sat += s.apdex_sat
            apdex_tol += s.apdex_tol
            for i in range(4):
                stage_counts[i] += s.stage_counts[i]
                stage_sum_ms[i] += s.stage_sum_ms[i]
                stage_5xx_err[i] += s.stage_5xx_err[i]
            for b, cnt in s.hist.items():
                merged_hist[b] = merged_hist.get(b, 0) + cnt

        sorted_buckets = sorted(merged_hist.items())

        def hist_quantile(q):
            if total == 0:
                return 0.0
            target_rank = max(1, int(math.ceil((q / 100.0) * total)))
            cum = 0
            for b, cnt in sorted_buckets:
                cum += cnt
                if cum >= target_rank:
                    return round((b + 0.5) * HIST_STEP_MS, 2)
            return round(max_ms, 2)

        p50 = hist_quantile(50.0)
        p75 = hist_quantile(75.0)
        p90 = hist_quantile(90.0)
        p95 = hist_quantile(95.0)
        p99 = hist_quantile(99.0)
        p999 = hist_quantile(99.9)
        p9999 = hist_quantile(99.99)

        avg_ms = (sum_ms / total) if total > 0 else 0.0
        variance = ((sum_sq_ms / total) - (avg_ms * avg_ms)) if total > 0 else 0.0
        jitter_ms = math.sqrt(variance) if variance > 0 else 0.0
        apdex = ((apdex_sat + 0.5 * apdex_tol) / float(total)) if total > 0 else 0.0
        rps = total / elapsed
        err_pct = ((s5xx + errors) * 100.0 / total) if total > 0 else 0.0
        slowdown = (post_lat_ms / pre_lat_ms) if pre_lat_ms > 0 and post_lat_ms > 0 else 1.0

        # 4-Stage breakdown & saturation knee detection
        stage_dur = max(elapsed / 4.0, 0.001)
        stage_labels = ["Q1 (0-25%)", "Q2 (25-50%)", "Q3 (50-75%)", "Q4 (75-100%)"]
        stages = []
        knee_rps = 0.0
        q1_avg = 0.0
        for i in range(4):
            c = stage_counts[i]
            s_avg = (stage_sum_ms[i] / c) if c > 0 else 0.0
            s_err = (stage_5xx_err[i] * 100.0 / c) if c > 0 else 0.0
            s_rps = c / stage_dur
            if i == 0:
                q1_avg = s_avg
            elif knee_rps == 0.0 and ((q1_avg > 0 and s_avg > q1_avg * 2.5) or s_err >= 5.0):
                knee_rps = round(s_rps, 1)
            stages.append({
                "stage": i + 1,
                "label": stage_labels[i],
                "requests": c,
                "rps": round(s_rps, 2),
                "avg_ms": round(s_avg, 2),
                "error_rate_pct": round(s_err, 2),
            })

        if tripped:
            self.log(
                f"CIRCUIT BREAKER TRIPPED: >= {abort_5xx_pct:.1f}% error/5xx rate detected. Load halted.",
                "crit",
            )

        slo_failed = False
        slo_notes = []
        if slo_p95 and slo_p95 > 0:
            ok = p95 <= slo_p95
            slo_failed = slo_failed or (not ok)
            slo_notes.append(f"{'PASS' if ok else 'FAIL'}: p95 {p95:.2f}ms <= {slo_p95:.2f}ms")
        if slo_p99 and slo_p99 > 0:
            ok = p99 <= slo_p99
            slo_failed = slo_failed or (not ok)
            slo_notes.append(f"{'PASS' if ok else 'FAIL'}: p99 {p99:.2f}ms <= {slo_p99:.2f}ms")
        if slo_err_pct and slo_err_pct > 0:
            ok = err_pct <= slo_err_pct
            slo_failed = slo_failed or (not ok)
            slo_notes.append(f"{'PASS' if ok else 'FAIL'}: err/5xx {err_pct:.2f}% <= {slo_err_pct:.2f}%")
        if slo_apdex and slo_apdex > 0:
            ok = apdex >= slo_apdex
            slo_failed = slo_failed or (not ok)
            slo_notes.append(f"{'PASS' if ok else 'FAIL'}: Apdex {apdex:.3f} >= {slo_apdex:.3f}")
        if slo_min_rps and slo_min_rps > 0:
            ok = rps >= slo_min_rps
            slo_failed = slo_failed or (not ok)
            slo_notes.append(f"{'PASS' if ok else 'FAIL'}: RPS {rps:.1f} >= {slo_min_rps:.1f}")

        sig_input = f"hyperion|{target}|{total}|{rps:.2f}|{p95:.2f}|{slo_failed}".encode("utf-8")
        receipt_hmac = hmac.new(GUARD_CODE.encode("utf-8"), sig_input, hashlib.sha256).hexdigest()[:24]

        self.log(
            f"Completed {total} req in {elapsed:.2f}s ({rps:.1f} RPS) | Apdex={apdex:.3f} | "
            f"2xx={s2xx} 3xx={s3xx} 4xx={s4xx}(429:{s429}) 5xx={s5xx} err={errors} ({err_pct:.2f}%)",
            "pass" if not (tripped or slo_failed) else "crit",
        )
        self.log(
            f"HDR Latency ms: min={min_ms:.2f} avg={avg_ms:.2f} jitter(σ)={jitter_ms:.2f} "
            f"p50={p50:.2f} p75={p75:.2f} p90={p90:.2f} p95={p95:.2f} p99={p99:.2f} p99.9={p999:.2f} p99.99={p9999:.2f} max={max_ms:.2f}"
        )
        self.log(
            f"Recovery check: pre={pre_lat_ms:.2f}ms -> post={post_lat_ms:.2f}ms (slowdown={slowdown:.2f}x) | Receipt={receipt_hmac}"
        )
        if slo_notes:
            self.log("SLO Evaluation: " + " | ".join(slo_notes), "crit" if slo_failed else "pass")

        hist_chart = self._ascii_histogram(merged_hist, total)
        stage_table = "\n".join(
            f"  - {st['label']}: `{st['requests']} req` | `{st['rps']:.1f} RPS` | `avg={st['avg_ms']:.2f}ms` | `err={st['error_rate_pct']:.2f}%`"
            for st in stages
        )
        knee_desc = f"{knee_rps:.1f} RPS" if knee_rps > 0 else "none (linear scaling maintained)"

        md_report = (
            "\n## ⚡ Hyperion v2.0 Resilience, HDR & SLO Report\n\n"
            f"- Target: `{sanitize_text(target)}` ({len(specs)} weighted endpoint(s))\n"
            f"- Profile / Method / Workers: `{profile}` / `{method}` / `{workers}`\n"
            f"- Total Requests / Throughput: `{total}` (`{rps:.1f} RPS` over `{elapsed:.2f}s`)\n"
            f"- Apdex Score (T={apdex_t:.0f}ms): `{apdex:.3f}` | Saturation Knee: `{knee_desc}`\n"
            f"- HTTP Status (2xx / 3xx / 4xx / 429-RL / 5xx / err): `{s2xx} / {s3xx} / {s4xx} / {s429} / {s5xx} / {errors}` (error/5xx rate: `{err_pct:.2f}%`)\n"
            f"- Latency min / avg / jitter(σ) / max: `{min_ms:.2f}ms / {avg_ms:.2f}ms / {jitter_ms:.2f}ms / {max_ms:.2f}ms`\n"
            f"- HDR Percentiles p50 / p75 / p90 / p95 / p99 / p99.9 / p99.99: `{p50:.2f}ms / {p75:.2f}ms / {p90:.2f}ms / {p95:.2f}ms / {p99:.2f}ms / {p999:.2f}ms / {p9999:.2f}ms`\n"
            f"- Pre/Post Recovery: `pre={pre_lat_ms:.2f}ms (HTTP {pre_status}) -> post={post_lat_ms:.2f}ms (HTTP {post_status}) [slowdown={slowdown:.2f}x]`\n"
            f"- Guard Receipt HMAC: `{receipt_hmac}`\n"
        )
        if slo_notes:
            md_report += f"- SLO Gate: `{' | '.join(slo_notes)}`\n"
        md_report += f"\n### Stage Progression\n{stage_table}\n"
        if hist_chart:
            md_report += f"\n### Latency Distribution (HDR 100us Buckets)\n```text\n{hist_chart}\n```\n"

        if report_file:
            os.makedirs(os.path.dirname(os.path.abspath(report_file)), exist_ok=True)
            with open(report_file, "w", encoding="utf-8") as fh:
                fh.write(md_report)
            self.log(f"Markdown report written: {report_file}", "pass")

        if json_out:
            os.makedirs(os.path.dirname(os.path.abspath(json_out)), exist_ok=True)
            metrics_doc = {
                "engine": "hyperion-async-sharded-hdr",
                "version": "2.0.0",
                "guard_verified": True,
                "receipt_hmac": receipt_hmac,
                "target": sanitize_text(target),
                "endpoints": specs,
                "profile": profile,
                "method": method,
                "duration_seconds": round(elapsed, 3),
                "workers": workers,
                "total_requests": total,
                "average_rps": round(rps, 2),
                "saturation_knee_rps": knee_rps,
                "apdex_score": round(apdex, 4),
                "status_2xx": s2xx,
                "status_3xx": s3xx,
                "status_4xx": s4xx,
                "status_429_ratelim": s429,
                "status_5xx": s5xx,
                "transport_errors": errors,
                "assertion_failures": assert_fails,
                "error_rate_pct": round(err_pct, 3),
                "circuit_tripped": tripped,
                "slo_failed": slo_failed,
                "preflight_ms": round(pre_lat_ms, 2),
                "postflight_ms": round(post_lat_ms, 2),
                "recovery_slowdown": round(slowdown, 2),
                "stages": stages,
                "latency_ms": {
                    "min": round(min_ms, 2),
                    "avg": round(avg_ms, 2),
                    "stdev": round(jitter_ms, 2),
                    "p50": p50,
                    "p75": p75,
                    "p90": p90,
                    "p95": p95,
                    "p99": p99,
                    "p999": p999,
                    "p9999": p9999,
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
    print("  ⚠  HYPERION v2.0 EXTERNAL TARGET — ACTIVE LOAD TEST")
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
        description="Hyperion v2.0 - 14x Sharded Resilience, HDR Histogram & SLO Load Engine (requires --guard XXLMILLEAMEAN)"
    )
    parser.add_argument("-t", "--target", "--url", dest="target", default="http://localhost:3456/", help="Target URL endpoint")
    parser.add_argument(
        "--endpoints",
        default="",
        help="Weighted subpaths on the same host (e.g. '/:50,/api/config:30,/api/guestbook:20')",
    )
    parser.add_argument(
        "-P",
        "--profile",
        choices=["constant", "ramp", "step", "spike", "sawtooth", "stress-knee"],
        default="constant",
        help="Load profile (default: constant)",
    )
    parser.add_argument("-m", "--method", default="GET", help="HTTP method (GET, POST, PUT, DELETE, PATCH, HEAD, OPTIONS)")
    parser.add_argument("-r", "--rate", default="1000", help="Target rate in RPS (up to 3.5m on local/private labs; 9999.99 RPS cap on trusted external)")
    parser.add_argument("-d", "--duration", default="10s", help="Test duration (e.g. 10s, 1m)")
    parser.add_argument("-w", "--workers", type=int, default=32, help="Concurrent workers/coroutines")
    parser.add_argument("-p", "--payload", default="", help="Optional payload file path (supports {{seq}}, {{timestamp}}, {{uuid}})")
    parser.add_argument("-H", "--header", "--headers", dest="headers", action="append", default=[], help="Custom header 'Name: value' (repeatable)")
    parser.add_argument("--timeout", default="5s", help="Per-request timeout (default: 5s)")
    parser.add_argument("-g", "--guard", "--code", dest="guard", default="", help="Required authorization guard code")
    parser.add_argument("--cache-bust", action="store_true", help="Append per-request cache-busting query and sequence header")
    parser.add_argument("--expect-status", type=int, default=0, help="Expected HTTP status code assertion")
    parser.add_argument("--expect-text", default="", help="Substring assertion required in response body")
    parser.add_argument("--apdex-t", type=float, default=100.0, help="Apdex satisfactory latency threshold T in ms (default: 100)")
    parser.add_argument("--slo-p95", type=float, default=0.0, help="SLO gate: fail if p95 latency (ms) exceeds threshold")
    parser.add_argument("--slo-p99", type=float, default=0.0, help="SLO gate: fail if p99 latency (ms) exceeds threshold")
    parser.add_argument("--slo-err-pct", type=float, default=0.0, help="SLO gate: fail if 5xx/error percentage exceeds threshold")
    parser.add_argument("--slo-apdex", type=float, default=0.0, help="SLO gate: fail if Apdex score (0.0-1.0) is below threshold")
    parser.add_argument("--slo-min-rps", type=float, default=0.0, help="SLO gate: fail if achieved RPS is below threshold")
    parser.add_argument("--no-circuit-breaker", action="store_true", help="Disable the auto-abort circuit breaker")
    parser.add_argument("--abort-5xx-pct", type=float, default=80.0, help="Circuit-breaker 5xx/error percentage threshold (default: 80)")
    parser.add_argument("--engine", choices=["auto", "python", "go"], default="auto", help="Execution engine (default: auto)")
    parser.add_argument("--report-file", default="", help="Optional Markdown report path")
    parser.add_argument("--json-out", default="", help="Optional JSON metrics output path")
    parser.add_argument("-y", "--yes", action="store_true", help="Skip interactive hostname prompt for trusted external hosts")
    parser.add_argument("-v", "--version", action="version", version="Hyperion 2.0.0")
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

    # 3. Choose Go engine if available and requested, else Python sharded async HDR engine
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
            "--apdex-t", str(args.apdex_t),
            "--abort-5xx-pct", str(args.abort_5xx_pct),
            f"--circuit-breaker={'false' if args.no_circuit_breaker else 'true'}",
        ]
        if args.endpoints:
            cmd += ["--endpoints", args.endpoints]
        if args.payload:
            cmd += ["-p", args.payload]
        if args.cache_bust:
            cmd.append("--cache-bust")
        if args.expect_status > 0:
            cmd += ["--expect-status", str(args.expect_status)]
        if args.expect_text:
            cmd += ["--expect-text", args.expect_text]
        if args.slo_p95 > 0:
            cmd += ["--slo-p95", str(args.slo_p95)]
        if args.slo_p99 > 0:
            cmd += ["--slo-p99", str(args.slo_p99)]
        if args.slo_err_pct > 0:
            cmd += ["--slo-err-pct", str(args.slo_err_pct)]
        if args.slo_apdex > 0:
            cmd += ["--slo-apdex", str(args.slo_apdex)]
        if args.slo_min_rps > 0:
            cmd += ["--slo-min-rps", str(args.slo_min_rps)]
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
        cache_bust=args.cache_bust,
        expect_status=args.expect_status,
        expect_text=args.expect_text,
        apdex_t=args.apdex_t,
        slo_p95=args.slo_p95,
        slo_p99=args.slo_p99,
        slo_err_pct=args.slo_err_pct,
        slo_apdex=args.slo_apdex,
        slo_min_rps=args.slo_min_rps,
        circuit_breaker=not args.no_circuit_breaker,
        abort_5xx_pct=args.abort_5xx_pct,
        report_file=args.report_file,
        json_out=args.json_out,
    )


if __name__ == "__main__":
    sys.exit(main())
