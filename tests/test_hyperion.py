"""Hyperion correctness checks; all HTTP fixtures are loopback and low rate."""
import contextlib
import io
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "TOOLS"))
import hyperion
from vibe_core import VibeTool


class HyperionTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.directory = Path(self.temp.name)
        self.session = self.directory / "session.json"
        self.env = patch.dict(os.environ, {
            "VIBE_LOG_DIR": str(self.directory / "logs"),
            "VIBE_SESSION_FILE": str(self.session),
            "VIBE_COOKIE": "", "VIBE_AUTH_FILE": "", "VIBE_HEADERS": "{}",
            "VIBE_UA": "",
        })
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_surface_reader_tolerates_missing_and_invalid_sessions(self):
        tool = VibeTool("test", "test")
        self.assertEqual(tool.get_surface(), {})
        for value in ([], None, {"surface": []}, {"surface": None}):
            with self.subTest(value=value):
                self.session.write_text(json.dumps(value))
                self.assertEqual(tool.get_surface(), {})
        self.session.write_text('{"surface":{"endpoints":["/health"]}}')
        self.assertEqual(tool.get_surface()["endpoints"], ["/health"])

    def test_nonfinite_rates_and_durations_are_rejected(self):
        for rate in ("nan", "inf", "-inf", "1e309", "-1"):
            with self.subTest(rate=rate), self.assertRaises(ValueError):
                hyperion._parse_rate(rate)
        for duration in ("nan", "inf", "0s", "-1s"):
            with self.subTest(duration=duration), self.assertRaises(ValueError):
                hyperion._parse_duration(duration)

    def test_auto_engine_requires_an_actual_go_toolchain(self):
        go_dir = str(ROOT / "TOOLS/hyperion")
        with patch.object(hyperion.shutil, "which", return_value=None):
            self.assertFalse(hyperion._go_toolchain_available(go_dir))
        with patch.object(hyperion.shutil, "which", return_value="/synthetic/go"):
            for code, output, expected in ((1, "Go: Unknown option", False),
                                           (0, "another program", False),
                                           (0, "go version go1.20 linux/amd64", True)):
                with self.subTest(output=output), patch.object(hyperion.subprocess, "run",
                        return_value=subprocess.CompletedProcess([], code, output, "")):
                    self.assertEqual(hyperion._go_toolchain_available(go_dir), expected)

    def test_profile_credentials_require_the_same_origin(self):
        self.assertTrue(hyperion._same_origin("https://APP.example/", "https://app.example:443/x"))
        for other in ("http://app.example", "https://app.example:8443", "https://other.example", "", None):
            with self.subTest(other=other):
                self.assertFalse(hyperion._same_origin("https://app.example", other))

    def test_cli_rejects_nonfinite_slo_thresholds(self):
        for flag in ("--slo-min-rps", "--slo-p95", "--slo-apdex", "--slo-err-pct", "--abort-5xx-pct"):
            with self.subTest(flag=flag), contextlib.redirect_stderr(io.StringIO()):
                with self.assertRaises(SystemExit) as raised:
                    hyperion.main([flag, "nan"])
                self.assertEqual(raised.exception.code, 2)

    def test_failed_requests_are_counted_once_and_do_not_earn_apdex(self):
        cases = [(200, False, True, False, 0), (302, False, True, False, 0),
                 (403, False, True, False, 1), (429, False, True, False, 1),
                 (503, False, False, True, 1), (0, True, True, False, 1),
                 (200, False, False, False, 1), (200, False, True, True, 1)]
        for status, error, asserted, challenged, failed in cases:
            with self.subTest(status=status, error=error, asserted=asserted, challenged=challenged):
                shard = hyperion._WorkerShard()
                shard.record(status, 1, 2, error, asserted, 0, 100, waf_challenged=challenged)
                self.assertEqual(shard.failed, failed)
                self.assertEqual(shard.successful, 1 - failed)
                self.assertEqual(shard.stage_failures[0], failed)
                self.assertEqual(shard.apdex_sat, 1 - failed)

    def fixture(self):
        observed = []
        class Handler(BaseHTTPRequestHandler):
            protocol_version = "HTTP/1.1"
            def log_message(self, *args):
                pass
            def do_GET(self):
                observed.append(self.headers.get("Cookie"))
                status = int(self.path.strip("/") or "200")
                body = b"healthy"
                self.send_response(200 if status == 299 else status)
                if status == 299:
                    self.send_header("cf-mitigated", "challenge")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        def close():
            server.shutdown()
            server.server_close()
        self.addCleanup(close)
        return f"http://127.0.0.1:{server.server_port}", observed

    def run_engine(self, url, **options):
        output = self.directory / "nested" / "metrics.json"
        params = dict(target=url, rate_raw="10", duration_raw="0.15s", workers=1,
                      timeout_raw="1s", json_out=str(output), report_file=str(output.with_suffix(".md")))
        params.update(options)
        with contextlib.redirect_stdout(io.StringIO()):
            code = hyperion.Hyperion().run_python_engine(**params)
        return code, json.loads(output.read_text())

    def test_loopback_success_produces_successful_throughput(self):
        url, _ = self.fixture()
        code, metrics = self.run_engine(url)
        self.assertEqual(code, 0)
        self.assertGreater(metrics["successful_requests"], 0)
        self.assertEqual(metrics["failed_requests"], 0)
        self.assertEqual(metrics["successful_rps"], metrics["average_rps"])
        self.assertEqual(metrics["requested_rps"], 10)

    def test_blocked_and_challenged_responses_fail_the_run(self):
        url, _ = self.fixture()
        for status in (403, 429, 299):
            with self.subTest(status=status):
                code, metrics = self.run_engine(f"{url}/{status}")
                self.assertEqual(code, 1)
                self.assertEqual(metrics["successful_requests"], 0)
                self.assertEqual(metrics["successful_rps"], 0)
                self.assertEqual(metrics["error_rate_pct"], 100)
                self.assertTrue(metrics["slo_failed"])

    def test_assertion_failure_fails_even_with_a_permissive_error_budget(self):
        url, _ = self.fixture()
        code, metrics = self.run_engine(url, expect_text="absent", slo_err_pct=100)
        self.assertEqual(code, 1)
        self.assertGreater(metrics["assertion_failures"], 0)

    def test_other_origin_profile_cookies_are_not_replayed(self):
        url, observed = self.fixture()
        self.session.write_text(json.dumps({"surface": {"agent_profile": {
            "target": "https://other.example", "cookies": {"session": "synthetic"}}}}))
        code, _ = self.run_engine(url)
        self.assertEqual(code, 0)
        self.assertTrue(observed)
        self.assertFalse(any(observed))

    def test_preflight_does_not_forward_credentials_across_ports_or_schemes(self):
        tool = hyperion.Hyperion()
        for location in ("http://127.0.0.1:3457/", "https://127.0.0.1:3456/"):
            with self.subTest(location=location), patch.object(hyperion.http.client, "HTTPConnection") as factory:
                response = factory.return_value.getresponse.return_value
                response.status = 302
                response.getheaders.return_value = [("Location", location)]
                result = tool._probe_single_sync("http", "127.0.0.1", 3456, "127.0.0.1",
                    "/", "GET", {"Cookie": "synthetic"}, 1, follow_redirects=True)
                self.assertEqual(result[0], 302)
                self.assertEqual(factory.call_count, 1)
                self.assertEqual(factory.return_value.request.call_count, 1)

    def test_no_samples_cannot_pass(self):
        async def no_samples(**kwargs):
            return [], 0.1, False
        baseline = (200, 1.0, {}, "http", 80, "/")
        with patch.object(hyperion.Hyperion, "_run_async_coro", side_effect=no_samples), \
             patch.object(hyperion.Hyperion, "_probe_single_sync", return_value=baseline):
            code, metrics = self.run_engine("http://127.0.0.1/")
        self.assertEqual(code, 1)
        self.assertEqual(metrics["total_requests"], 0)
        self.assertTrue(metrics["slo_failed"])

    def test_minimum_rps_uses_successful_responses(self):
        shard = hyperion._WorkerShard()
        shard.record(200, 1, 2, False, True, 0, 100)
        for _ in range(9):
            shard.record(429, 1, 2, False, True, 0, 100)
        async def samples(**kwargs):
            return [shard], 1.0, False
        with patch.object(hyperion.Hyperion, "_run_async_coro", side_effect=samples), \
             patch.object(hyperion.Hyperion, "_probe_single_sync", return_value=(200, 1, {}, "http", 80, "/")):
            code, metrics = self.run_engine("http://127.0.0.1/", slo_min_rps=5, slo_err_pct=95)
        self.assertEqual(code, 1)
        self.assertEqual(metrics["average_rps"], 10)
        self.assertEqual(metrics["successful_rps"], 1)

    def test_cli_still_requires_guard_and_public_authorization(self):
        output = io.StringIO()
        with contextlib.redirect_stdout(output), patch.object(hyperion.Hyperion, "run_python_engine") as engine:
            self.assertEqual(hyperion.main(["--guard", "WRONG", "--yes"]), 2)
            with patch.object(hyperion, "_load_authorized_hosts", return_value=set()):
                self.assertEqual(hyperion.main(["--guard", hyperion.GUARD_CODE,
                    "--engine", "python", "-t", "https://unapproved.example", "--yes"]), 2)
            engine.assert_not_called()

    def test_cli_runs_the_python_engine_against_loopback(self):
        url, _ = self.fixture()
        result = subprocess.run([sys.executable, str(ROOT / "TOOLS/hyperion.py"),
            "--guard", hyperion.GUARD_CODE, "--engine", "python", "-t", url,
            "-r", "5", "-d", "0.1s", "-w", "1"],
            cwd=ROOT, capture_output=True, text=True, timeout=10)
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        self.assertIn("successful RPS", result.stdout)


if __name__ == "__main__":
    unittest.main()
