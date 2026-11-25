"""Offline regression tests for internal reporting."""
import json
import os
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "TOOLS"))
import sarif_export


class InternalReportingTests(unittest.TestCase):
    def setUp(self):
        self.exporter = sarif_export.SarifExporter.__new__(sarif_export.SarifExporter)

    def test_classification_preserved(self):
        finding = {"tool": "Example", "title": "Synthetic finding",
                   "cwe": "CWE-798", "owasp": "A02:2021"}
        run = self.exporter.build_sarif([finding])["runs"][0]
        self.assertEqual(run["results"][0]["properties"]["cwe"], "CWE-798")

    def test_unknown_classification(self):
        run = self.exporter.build_sarif([{"tool": "Example"}])["runs"][0]
        self.assertEqual(run["results"][0]["properties"]["cwe"], "unclassified")
        self.assertNotIn("precision", run["tool"]["driver"]["rules"][0]["properties"])

    def test_structured_input_redacted_and_non_objects_ignored(self):
        with tempfile.TemporaryDirectory() as tmp:
            logs = Path(tmp) / "logs"
            logs.mkdir()
            row = {"tool": "Example", "title": "Synthetic finding",
                   "location": "https://example.invalid/", "evidence": "token=fake-value"}
            (logs / "findings.jsonl").write_text(
                "null\n[]\n" + json.dumps(row) + "\n", encoding="utf-8")
            with patch.dict(os.environ, {"VIBE_PRIVACY_MODE": "on"}), patch.object(
                sarif_export, "_root", tmp
            ):
                findings = self.exporter._collect_findings(str(logs))
            self.assertEqual(len(findings), 1)
            self.assertNotIn("fake-value", findings[0]["evidence"])
            self.assertNotIn("example.invalid", findings[0]["location"])

    def test_junit_export(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "report.xml"
            self.exporter.write_junit_xml([], str(path))
            self.assertIn("NoSecurityFindings", path.read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
