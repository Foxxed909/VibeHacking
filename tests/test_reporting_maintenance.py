"""Offline tests for report integrity and release metadata."""
import json
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "TOOLS"))
import sarif_export


class ReportingMaintenanceTests(unittest.TestCase):
    def setUp(self):
        self.exporter = sarif_export.SarifExporter.__new__(sarif_export.SarifExporter)

    def test_release_metadata_matches(self):
        version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
        metadata = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
        project = metadata.split("[project]", 1)[1].split("\n[", 1)[0]
        match = re.search(r'^version\s*=\s*"([^"]+)"\s*$', project, re.MULTILINE)
        self.assertIsNotNone(match)
        self.assertEqual(match.group(1), version)

    def test_structured_classification_is_preserved(self):
        findings = [{"tool": "Example", "title": "Synthetic finding",
                     "severity": "medium", "cwe": "CWE-798", "owasp": "A02:2021"}]
        run = self.exporter.build_sarif(findings)["runs"][0]
        result = run["results"][0]
        self.assertEqual(result["properties"]["cwe"], "CWE-798")
        self.assertEqual(result["properties"]["owasp"], "A02:2021")

    def test_missing_classification_is_not_invented(self):
        run = self.exporter.build_sarif([{"tool": "Example", "title": "Synthetic finding"}])["runs"][0]
        result = run["results"][0]
        self.assertEqual(result["properties"]["cwe"], "unclassified")
        self.assertEqual(result["properties"]["owasp"], "unclassified")
        rule = run["tool"]["driver"]["rules"][0]
        self.assertNotIn("precision", rule["properties"])
        self.assertNotIn("unclassified", rule["properties"]["tags"])

    def test_legacy_log_fallback_remains_unclassified(self):
        with tempfile.TemporaryDirectory() as tmp:
            log_dir = Path(tmp) / "logs"
            log_dir.mkdir()
            (log_dir / "example_session.log").write_text(
                "[🔴 CRITICAL] Synthetic finding\n", encoding="utf-8"
            )
            with patch.object(sarif_export, "_root", tmp), patch.object(
                self.exporter, "load_session", return_value={"target": "local-fixture"}
            ):
                findings = self.exporter._collect_findings(str(log_dir))
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]["cwe"], "unclassified")
        self.assertEqual(findings[0]["owasp"], "unclassified")


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


if __name__ == "__main__":
    unittest.main()
