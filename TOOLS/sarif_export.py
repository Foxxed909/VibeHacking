#!/usr/bin/env python3
"""
sarif_export.py — Enterprise SARIF 2.1.0, JUnit XML & JSON Findings Exporter.

Aggregates VibeHacking findings from logs/findings.jsonl (and session logs) into:
  - SARIF 2.1.0 (reports/vibe.sarif) for GitHub Advanced Security / Code Scanning
  - JUnit XML (reports/vibe-junit.xml) for GitLab CI / Jenkins / Azure DevOps
  - JSON Summary (reports/findings_summary.json) for SIEM / DefectDojo ingestion

Supports `--fail-on {critical,high,medium,low}` to act as a CI/CD pipeline gate.
"""
import argparse
import datetime
import glob
import json
import os
import re
import sys
import xml.etree.ElementTree as ET

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from privacy_guard import sanitize_text
from vibe_core import DEFAULT_TOOL_TAXONOMY, FRAMEWORK_VERSION, VibeTool

_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

SEVERITY_RANK = {
    "critical": 4,
    "high": 3,
    "medium": 2,
    "low": 1,
    "info": 0,
}

SARIF_LEVEL = {
    "critical": "error",
    "high": "error",
    "medium": "warning",
    "low": "note",
    "info": "note",
}


class SarifExporter(VibeTool):
    def __init__(self):
        super().__init__("SARIF Exporter", "Enterprise SARIF 2.1.0 & JUnit XML Compliance Exporter")

    def _collect_findings(self, log_dir):
        findings = []
        seen = set()

        # 1. Primary source: structured logs/findings.jsonl
        jsonl_path = os.path.join(log_dir, "findings.jsonl")
        if os.path.isfile(jsonl_path):
            try:
                with open(jsonl_path, "r", encoding="utf-8", errors="replace") as fh:
                    for line in fh:
                        line = line.strip()
                        if not line:
                            continue
                        try:
                            item = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if item.get("tool", "").lower() == "sarif exporter":
                            continue
                        key = (item.get("tool", ""), item.get("title", ""), item.get("location", ""))
                        if key not in seen:
                            seen.add(key)
                            findings.append(item)
            except OSError:
                pass

        # 2. Secondary source: reports/senoria_findings.json
        senoria_json = os.path.join(_root, "reports", "senoria_findings.json")
        if os.path.isfile(senoria_json):
            try:
                with open(senoria_json, "r", encoding="utf-8", errors="replace") as fh:
                    data = json.load(fh)
                for f in data.get("findings", []):
                    title = f"Senoria: {f.get('kind', 'Secret')} at line {f.get('line', 1)}"
                    loc = f.get("url", data.get("target", ""))
                    key = ("Senoria", title, loc)
                    if key not in seen:
                        seen.add(key)
                        findings.append({
                            "timestamp": data.get("generated_at", ""),
                            "tool": "Senoria",
                            "title": sanitize_text(title),
                            "severity": f.get("severity", "high").lower(),
                            "location": sanitize_text(loc),
                            "evidence": sanitize_text(f.get("evidence", "")),
                            "recommendation": "Rotate the exposed credential immediately and remove it from public bundles.",
                            "cwe": "CWE-798",
                            "owasp": "A02:2021-Cryptographic Failures",
                        })
            except (OSError, json.JSONDecodeError):
                pass

        # 3. Fallback: parse session logs if no structured findings were recorded yet
        if not findings:
            session_target = self.load_session().get("target", "http://localhost/")
            for log_file in sorted(glob.glob(os.path.join(log_dir, "*_session.log"))):
                base = os.path.basename(log_file)
                tool_stem = base.replace("_session.log", "")
                if tool_stem in ("lmx", "sarif_exporter", "sarif exporter"):
                    continue
                tax = DEFAULT_TOOL_TAXONOMY.get(tool_stem.replace("_", " "), {"cwe": "CWE-200", "owasp": "A05:2021"})
                try:
                    with open(log_file, "r", encoding="utf-8", errors="replace") as fh:
                        for line in fh:
                            m = re.search(r"\[(🔴 CRITICAL|🔥 HACK)\]\s*(.+)$", line.strip())
                            if not m:
                                continue
                            tag, msg = m.group(1), m.group(2).strip()
                            sev = "critical" if "CRITICAL" in tag else "high"
                            title = f"{tool_stem.upper()}: {msg[:100]}"
                            key = (tool_stem, title, session_target)
                            if key not in seen:
                                seen.add(key)
                                findings.append({
                                    "timestamp": "",
                                    "tool": tool_stem,
                                    "title": sanitize_text(title),
                                    "severity": sev,
                                    "location": sanitize_text(session_target),
                                    "evidence": sanitize_text(msg),
                                    "recommendation": "Review the affected endpoint and apply defense-in-depth controls.",
                                    "cwe": tax.get("cwe", "CWE-200"),
                                    "owasp": tax.get("owasp", "A05:2021"),
                                })
                except OSError:
                    pass

        return findings

    @staticmethod
    def _rule_id(finding):
        tool_slug = re.sub(r"[^A-Za-z0-9]+", "-", str(finding.get("tool", "vibe"))).strip("-").upper()
        cwe = str(finding.get("cwe", "CWE-200")).upper()
        return f"VIBE-{tool_slug}-{cwe}"

    def build_sarif(self, findings):
        rules_map = {}
        results = []

        for f in findings:
            rule_id = self._rule_id(f)
            sev = str(f.get("severity", "medium")).lower()
            cwe = str(f.get("cwe", "CWE-200"))
            owasp = str(f.get("owasp", "A05:2021"))

            if rule_id not in rules_map:
                rules_map[rule_id] = {
                    "id": rule_id,
                    "name": f"{f.get('tool', 'VibeHacking')}SecurityCheck",
                    "shortDescription": {"text": f"{f.get('tool', 'VibeTool')} Security Audit ({cwe})"},
                    "fullDescription": {
                        "text": f"Automated black-box security check by {f.get('tool', 'VibeTool')} mapped to {cwe} / {owasp}."
                    },
                    "properties": {
                        "tags": ["security", "black-box", cwe, owasp],
                        "precision": "high",
                    },
                }

            loc_uri = str(f.get("location") or "http://localhost/")
            results.append({
                "ruleId": rule_id,
                "level": SARIF_LEVEL.get(sev, "warning"),
                "message": {
                    "text": f"[{sev.upper()}] {f.get('title', '')} — Evidence: {f.get('evidence', '')}"
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": loc_uri,
                            }
                        }
                    }
                ],
                "properties": {
                    "severity": sev,
                    "tool": f.get("tool", ""),
                    "cwe": cwe,
                    "owasp": owasp,
                    "recommendation": f.get("recommendation", ""),
                },
            })

        return {
            "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
            "version": "2.1.0",
            "runs": [
                {
                    "tool": {
                        "driver": {
                            "name": "VibeHacking",
                            "version": FRAMEWORK_VERSION,
                            "informationUri": "https://github.com/Foxxed909/VibeHacking",
                            "rules": list(rules_map.values()),
                        }
                    },
                    "results": results,
                }
            ],
        }

    @staticmethod
    def write_junit_xml(findings, junit_path):
        suites = ET.Element("testsuites", name="VibeHacking Security Audit", tests=str(max(1, len(findings))))
        suite = ET.SubElement(
            suites,
            "testsuite",
            name="VibeHacking",
            tests=str(max(1, len(findings))),
            failures=str(len(findings)),
        )

        if not findings:
            ET.SubElement(suite, "testcase", classname="VibeHacking.Baseline", name="NoSecurityFindings")
        else:
            for f in findings:
                tc = ET.SubElement(
                    suite,
                    "testcase",
                    classname=f"VibeHacking.{f.get('tool', 'Tool')}",
                    name=f"[{f.get('severity', 'medium').upper()}] {f.get('title', 'Finding')[:120]}",
                )
                fail = ET.SubElement(
                    tc,
                    "failure",
                    type=f"{f.get('cwe', 'CWE-200')} ({f.get('owasp', 'OWASP')})",
                    message=str(f.get("title", "")),
                )
                fail.text = (
                    f"Severity: {f.get('severity', '').upper()}\n"
                    f"Tool: {f.get('tool', '')}\n"
                    f"Location: {f.get('location', '')}\n"
                    f"CWE: {f.get('cwe', '')} | OWASP: {f.get('owasp', '')}\n"
                    f"Evidence: {f.get('evidence', '')}\n"
                    f"Recommendation: {f.get('recommendation', '')}"
                )

        tree = ET.ElementTree(suites)
        os.makedirs(os.path.dirname(os.path.abspath(junit_path)), exist_ok=True)
        tree.write(junit_path, encoding="utf-8", xml_declaration=True)

    def run(self, log_dir=None, sarif_out=None, junit_out=None, json_out=None, fail_on="none"):
        self.banner()
        log_dir = log_dir or self.log_dir
        reports_dir = os.path.join(_root, "reports")
        os.makedirs(reports_dir, exist_ok=True)

        sarif_path = sarif_out or os.path.join(reports_dir, "vibe.sarif")
        junit_path = junit_out or os.path.join(reports_dir, "vibe-junit.xml")
        summary_path = json_out or os.path.join(reports_dir, "findings_summary.json")

        findings = self._collect_findings(log_dir)
        counts = {sev: 0 for sev in SEVERITY_RANK}
        for f in findings:
            s = str(f.get("severity", "medium")).lower()
            counts[s] = counts.get(s, 0) + 1

        sarif_doc = self.build_sarif(findings)
        os.makedirs(os.path.dirname(os.path.abspath(sarif_path)), exist_ok=True)
        with open(sarif_path, "w", encoding="utf-8") as fh:
            json.dump(sarif_doc, fh, indent=2)

        self.write_junit_xml(findings, junit_path)

        summary_doc = {
            "generated_at": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "version": FRAMEWORK_VERSION,
            "total_findings": len(findings),
            "counts_by_severity": counts,
            "findings": findings,
        }
        os.makedirs(os.path.dirname(os.path.abspath(summary_path)), exist_ok=True)
        with open(summary_path, "w", encoding="utf-8") as fh:
            json.dump(summary_doc, fh, indent=2)

        self.log(f"Compiled {len(findings)} structured finding(s): {counts}", "info")
        self.log(f"SARIF 2.1.0 report : {sarif_path}", "pass")
        self.log(f"JUnit XML report   : {junit_path}", "pass")
        self.log(f"JSON summary report: {summary_path}", "pass")

        if fail_on and fail_on != "none":
            threshold = SEVERITY_RANK.get(fail_on.lower(), 99)
            breaches = [f for f in findings if SEVERITY_RANK.get(str(f.get("severity", "")).lower(), 0) >= threshold]
            if breaches:
                self.log(
                    f"CI/CD Gate FAILED: {len(breaches)} finding(s) at or above '{fail_on.upper()}' severity.",
                    "fail",
                )
                return 1
            self.log(f"CI/CD Gate PASSED: 0 findings at or above '{fail_on.upper()}'.", "pass")

        return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="SARIF Exporter - Generate SARIF 2.1.0, JUnit XML, and JSON security reports for CI/CD"
    )
    parser.add_argument("--log-dir", default=None, help="Source log directory (default: logs/)")
    parser.add_argument("--sarif-out", default=None, help="Output path for SARIF 2.1.0 file (default: reports/vibe.sarif)")
    parser.add_argument("--junit-out", default=None, help="Output path for JUnit XML file (default: reports/vibe-junit.xml)")
    parser.add_argument("--json-out", default=None, help="Output path for JSON summary (default: reports/findings_summary.json)")
    parser.add_argument(
        "--fail-on",
        choices=["critical", "high", "medium", "low", "none"],
        default="none",
        help="Exit non-zero (1) if any finding meets or exceeds this severity",
    )
    parser.add_argument("-v", "--version", action="version", version="SARIF Exporter 1.0.0")
    args = parser.parse_args()

    sys.exit(
        SarifExporter().run(
            log_dir=args.log_dir,
            sarif_out=args.sarif_out,
            junit_out=args.junit_out,
            json_out=args.json_out,
            fail_on=args.fail_on,
        )
    )
