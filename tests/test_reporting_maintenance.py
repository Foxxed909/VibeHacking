"""Offline tests for report integrity and release metadata."""
import json
import os
import re
import sys
import tempfile
import unittest
from datetime import datetime, timezone
from pathlib import Path
from subprocess import CompletedProcess
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "TOOLS"))
import sarif_export
sys.path.insert(0, str(ROOT))
import vibe


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


    def test_session_metadata_has_utc_timestamp_and_redacted_target(self):
        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp) / "session.json"
            with patch.dict(os.environ, {"VIBE_PRIVACY_MODE": "on",
                                         "VIBE_SESSION_FILE": str(session)}):
                vibe._write_session("https://example.invalid/?token=fake-value")
            metadata = json.loads(session.read_text(encoding="utf-8"))
        self.assertNotIn("example.invalid", metadata["target"])
        self.assertNotIn("fake-value", metadata["target"])
        self.assertEqual(datetime.fromisoformat(metadata["last_scan"]).tzinfo, timezone.utc)

    def test_private_artifact_name_contains_no_target_details(self):
        with patch.dict(os.environ, {"VIBE_PRIVACY_MODE": "on"}):
            self.assertEqual(vibe._target_slug(3, "https://example.invalid/private"), "target-03")

    def test_reporting_returns_failure_without_running_subprocesses(self):
        for codes, expected in [([0, 2], 2), ([1, 0], 1), ([130], 130)]:
            with self.subTest(codes=codes), patch.object(sys, "argv", ["vibe", "report"]), patch.object(
                vibe, "run_tool", side_effect=[CompletedProcess([], code) for code in codes]
            ) as run:
                self.assertEqual(vibe.run_vibe(), expected)
                self.assertEqual(run.call_count, len(codes))



    def test_surface_summary_does_not_retain_reusable_data(self):
        from vibe_core import VibeTool

        for privacy_mode in ("on", "off"):
            with self.subTest(privacy_mode=privacy_mode), tempfile.TemporaryDirectory() as tmp:
                session = Path(tmp) / "session.json"
                session.write_text(json.dumps({
                    "marker": "preserve-me",
                    "surface": {
                        "jwt_tokens": ["legacy-fixture-token"],
                        "endpoints": ["https://example.invalid/private"],
                        "agent_profile": {"cookies": "legacy-fixture-cookie"},
                    },
                    "surface_summary": {"jwt_count": 4, "jwt_tokens": ["invalid"]},
                }), encoding="utf-8")
                with patch.dict(os.environ, {
                    "VIBE_PRIVACY_MODE": privacy_mode,
                    "VIBE_SESSION_FILE": str(session),
                    "VIBE_LOG_DIR": str(Path(tmp) / "logs"),
                }):
                    tool = VibeTool("fixture", "offline regression")
                    self.assertEqual(tool.get_surface(), {"jwt_count": 4})
                    tool.update_surface(endpoints=["fixture-route"], forms=["fixture-form"],
                                        jwt_tokens=["new-fixture-token"])
                    tool.update_surface(tech=["fixture-tech"])
                    self.assertEqual(tool.get_surface(), {
                        "endpoint_count": 1, "form_count": 1, "jwt_count": 1, "tech_count": 1,
                    })
                persisted = session.read_text(encoding="utf-8")
                self.assertEqual(json.loads(persisted)["marker"], "preserve-me")
                self.assertNotIn("surface", json.loads(persisted))
                for value in ("legacy-fixture-token", "legacy-fixture-cookie", "new-fixture-token",
                              "fixture-route", "fixture-form", "fixture-tech", "example.invalid"):
                    self.assertNotIn(value, persisted)

    def test_surface_summary_handles_non_object_sessions(self):
        from vibe_core import VibeTool

        with tempfile.TemporaryDirectory() as tmp:
            session = Path(tmp) / "session.json"
            session.write_text("[]", encoding="utf-8")
            with patch.dict(os.environ, {"VIBE_SESSION_FILE": str(session),
                                         "VIBE_LOG_DIR": str(Path(tmp) / "logs")}):
                tool = VibeTool("fixture", "offline regression")
                self.assertEqual(tool.get_surface(), {})
                tool.update_surface(tech=["fixture"])
                self.assertEqual(tool.get_surface(), {"tech_count": 1})


if __name__ == "__main__":
    unittest.main()
