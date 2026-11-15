"""Regression tests for the VibeHacking expanded lab modules."""
import tempfile
import unittest
from email.message import Message
from pathlib import Path

from vibe_ext.ad import analyze_edges
from vibe_ext.exploit import generate_corpus, triage_log
from vibe_ext.scope import require_scope
from vibe_ext.web import analyze_headers


class ExtensionTests(unittest.TestCase):
    def test_scope_local(self):
        self.assertEqual(require_scope("http://127.0.0.1:3456/"),
                         "http://127.0.0.1:3456")

    def test_scope_external_rejected(self):
        with self.assertRaises(ValueError):
            require_scope("https://not-authorized.example/")

    def test_scope_explicit(self):
        with tempfile.TemporaryDirectory() as directory:
            manifest = Path(directory) / "scope.json"
            manifest.write_text('{"authorized_origins":["https://owned.example"]}')
            self.assertEqual(require_scope("https://owned.example/test", str(manifest)),
                             "https://owned.example:443")
            with self.assertRaises(ValueError):
                require_scope("https://other.example", str(manifest))

    def test_ad_paths(self):
        with tempfile.TemporaryDirectory() as directory:
            csv = Path(directory) / "edges.csv"
            csv.write_text("source,target,relationship\n"
                           "alice,Helpdesk,member_of\n"
                           "Helpdesk,Domain Admins,generic_all\n")
            result = analyze_edges(str(csv), "alice")
            self.assertEqual(result["paths"][0]["classification"],
                             "potential_acl_escalation")

    def test_crash_triage(self):
        with tempfile.TemporaryDirectory() as directory:
            log = Path(directory) / "asan.txt"
            log.write_text("==123==ERROR: AddressSanitizer: stack-buffer-overflow\n"
                           "    #0 0x1234 in main crashme.c:12:3\n")
            result = triage_log(str(log))
            self.assertEqual(result["sanitizer_type"], "stack-buffer-overflow")
            self.assertEqual(result["classification"], "memory-safety")

    def test_corpus(self):
        with tempfile.TemporaryDirectory() as directory:
            result = generate_corpus(str(Path(directory) / "cases"), 3)
            self.assertEqual(len(result["cases"]), 3)
            self.assertEqual((Path(directory) / "cases/case_000.bin").read_bytes(), b"")

    def test_headers(self):
        headers = Message()
        headers.add_header("Set-Cookie", "id=secret; Path=/")
        result = analyze_headers(200, headers, "https")
        kinds = {finding["check"] for finding in result["findings"]}
        self.assertIn("cookie_flags", kinds)
        self.assertIn("missing_hsts", kinds)
        self.assertNotIn("secret", str(result))


if __name__ == "__main__":
    unittest.main()

