"""stdlib-only MAEL regression suite: python -m unittest MAEL.tests -v"""
import email.message
import json
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from MAEL.cli import assess_headers, audit_ad, validate_target, web_probe


class WebPolicyTests(unittest.TestCase):
    def test_public_requires_explicit_scope(self):
        with self.assertRaises(ValueError):
            validate_target("https://example.com")
        validate_target("https://example.com", allow_public=True)

    def test_credentials_rejected(self):
        with self.assertRaises(ValueError):
            validate_target("http://user:pass@127.0.0.1/")

    def test_cookie_reports_attributes_without_values(self):
        headers = email.message.Message()
        headers.add_header("Set-Cookie", "sid=SUPER_SECRET; Path=/")
        reports = assess_headers(headers, "http", "127.0.0.1")
        self.assertTrue(any(x["id"] == "WEB_COOKIE_HTTPONLY" for x in reports))
        self.assertNotIn("SUPER_SECRET", json.dumps(reports))

    def test_get_is_local_and_does_not_follow_redirect(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(302)
                self.send_header("Location", "https://example.com/not-followed")
                self.end_headers()
            def log_message(self, *args):
                pass
        server = HTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            result = web_probe("http://127.0.0.1:%d/" % server.server_port)
            self.assertEqual(302, result["status"])
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=3)


class DomainOpsTests(unittest.TestCase):
    def test_synthetic_snapshot_findings(self):
        sample = Path(__file__).resolve().parent / "examples" / "ad_snapshot.json"
        with sample.open(encoding="utf-8") as fh:
            report = audit_ad(json.load(fh))
        codes = {x["id"] for x in report["findings"]}
        self.assertIn("AD_PREAUTH_DISABLED", codes)
        self.assertIn("AD_UNCONSTRAINED_DELEGATION", codes)
        self.assertIn("AD_NO_LOCKOUT", codes)
        self.assertIn("AD_PASSWORD_NOT_REQUIRED", codes)

    def test_bad_schema_rejected(self):
        with self.assertRaises(ValueError):
            audit_ad({"users": {}})


class ExploitLabTests(unittest.TestCase):
    def test_bundled_local_demo_exists(self):
        source = Path(__file__).resolve().parent / "crash_demo.c"
        self.assertTrue(source.is_file())
        self.assertIn("strcpy", source.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
