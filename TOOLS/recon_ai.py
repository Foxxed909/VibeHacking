#!/usr/bin/env python3
"""
recon_ai.py — AI-Powered Attack Surface Intelligence Synthesis Engine.

Reads logs/findings.jsonl and sends the full finding set to an OpenRouter
free model, which produces:
  1. Executive summary (1 paragraph, non-technical)
  2. Kill-chain narrative: how a zero-credential attacker moves from entry
     point to full compromise using the confirmed findings
  3. Top 5 prioritized remediation steps (ordered by attacker impact)
  4. Attack graph: which findings chain together and why

This is the "brain" layer that turns raw tool output into actionable intelligence.

Category: INTELLIGENCE
"""
import argparse
import json
import os
import sys
import urllib.request
import urllib.error
import textwrap

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

FREE_MODELS = [
    "poolside/laguna-s-2.1:free",
    "inclusionai/ling-3.0-flash-fin:free",
    "poolside/laguna-xs-2.1:free",
    "openrouter/free",
]

ANALYST_SYSTEM = """You are an expert offensive security analyst writing a pentest report.
You receive a list of confirmed vulnerability findings from automated security tools.
Your job is to synthesize them into actionable intelligence.

Always respond with ONLY a valid JSON object in exactly this schema:
{
  "executive_summary": "<1-paragraph non-technical summary of overall security posture>",
  "kill_chain": "<narrative of how an attacker chains these findings from entry to full compromise>",
  "attack_chains": [
    {"step": 1, "finding": "<finding title>", "leads_to": "<what it enables>"},
    ...
  ],
  "critical_paths": ["<path 1 as: Finding A → Finding B → Impact>", ...],
  "top_remediations": [
    {"priority": 1, "action": "<specific fix>", "impact": "<what it prevents>"},
    ...
  ],
  "attacker_dwell_time_estimate": "<estimated time from entry to full compromise>",
  "overall_risk": "critical|high|medium|low"
}"""


def _load_findings(path):
    findings = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try:
                        findings.append(json.loads(line))
                    except Exception:
                        pass
    except OSError:
        pass
    return findings


def _dedup(findings):
    seen = set()
    out  = []
    for f in findings:
        fp = f.get("fingerprint") or f.get("title", "")[:60]
        if fp not in seen:
            seen.add(fp)
            out.append(f)
    return out


def _summarize_for_prompt(findings):
    """Compact finding list for prompt — title, severity, location, cwe."""
    lines = []
    for i, f in enumerate(findings[:40], 1):
        lines.append(
            f"{i}. [{f.get('severity','?').upper()}] {f.get('title','')} "
            f"| Location: {f.get('location','?')} "
            f"| {f.get('cwe','')} / {f.get('owasp','')} "
            f"| Evidence: {f.get('evidence','')[:120]}"
        )
    return "\n".join(lines)


class ReconAI(VibeTool):
    def __init__(self):
        super().__init__("Recon AI", "AI-Powered Attack Surface Intelligence Synthesis Engine")

    def _call_llm(self, api_key, findings_prompt):
        """Call an OpenRouter free model and return the parsed intelligence report."""
        user_msg = (
            f"Analyze these {len(findings_prompt.splitlines())} security findings and produce "
            f"the intelligence report JSON:\n\n{findings_prompt}"
        )
        payload = json.dumps({
            "model": FREE_MODELS[0],
            "messages": [
                {"role": "system", "content": ANALYST_SYSTEM},
                {"role": "user",   "content": user_msg},
            ],
            "temperature": 0.15,
            "max_tokens": 1200,
        }).encode("utf-8")

        for model in FREE_MODELS:
            try:
                p = json.loads(payload)
                p["model"] = model
                req = urllib.request.Request(
                    "https://openrouter.ai/api/v1/chat/completions",
                    data=json.dumps(p).encode("utf-8"),
                    headers={
                        "Authorization": f"Bearer {api_key}",
                        "Content-Type":  "application/json",
                        "HTTP-Referer":  "https://vibehacking.local",
                        "X-Title":       "VibeHacking ReconAI",
                    },
                    method="POST",
                )
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = json.loads(resp.read().decode("utf-8", errors="ignore"))
                content = data["choices"][0]["message"]["content"].strip()
                # strip markdown fences
                import re
                content = re.sub(r"^```(?:json)?|```$", "", content, flags=re.MULTILINE).strip()
                m = re.search(r"\{.*\}", content, re.DOTALL)
                if m:
                    return json.loads(m.group(0)), model
            except Exception as e:
                self.log(f"  [{model}] failed: {e}", "warn")
                continue
        return None, None

    def _offline_synthesis(self, findings):
        """Deterministic synthesis when offline or no API key."""
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        sorted_f = sorted(findings, key=lambda f: sev_order.get(f.get("severity","info").lower(), 4))
        critical = [f for f in sorted_f if f.get("severity") in ("critical","high")]

        # Build attack chains from finding CWE/OWASP patterns
        chains = []
        if any("CWE-347" in f.get("cwe","") for f in findings):
            chains.append("JWT bypass → authenticated endpoint access → privilege escalation")
        if any("CWE-918" in f.get("cwe","") for f in findings):
            chains.append("SSRF → internal metadata → credential extraction")
        if any("CWE-22"  in f.get("cwe","") for f in findings):
            chains.append("Path traversal → .env read → API key exfiltration")
        if any("CWE-798" in f.get("cwe","") for f in findings):
            chains.append("Exposed API key → direct LLM access → unlimited spend")
        if any("CWE-942" in f.get("cwe","") for f in findings):
            chains.append("CORS misconfiguration → cross-origin credential read → session hijack")

        top_rem = []
        seen_cwe = set()
        for f in sorted_f[:5]:
            cwe = f.get("cwe","")
            if cwe not in seen_cwe:
                seen_cwe.add(cwe)
                top_rem.append({
                    "priority": len(top_rem) + 1,
                    "action": f.get("recommendation") or f"Fix: {f.get('title','')}",
                    "impact": f"Prevents {f.get('owasp','')} exploitation",
                })

        overall = sorted_f[0]["severity"] if sorted_f else "info"

        return {
            "executive_summary": (
                f"The target has {len(findings)} confirmed finding(s) including "
                f"{len(critical)} critical/high severity issue(s). "
                f"The most severe finding is: {sorted_f[0].get('title','') if sorted_f else 'none'}."
            ),
            "kill_chain": " → ".join(
                f.get("title","")[:40] for f in sorted_f[:4]
            ) + " → Full Compromise" if sorted_f else "No kill chain identified.",
            "attack_chains": [
                {"step": i+1, "finding": f.get("title",""), "leads_to": f.get("owasp","")}
                for i, f in enumerate(sorted_f[:5])
            ],
            "critical_paths": chains or ["No high-confidence chains identified from current findings."],
            "top_remediations": top_rem or [{"priority": 1, "action": "Review all findings.", "impact": "General hardening"}],
            "attacker_dwell_time_estimate": "< 30 minutes" if critical else "1–4 hours",
            "overall_risk": overall,
            "_source": "offline_synthesis"
        }

    def run(self, findings_path=None, api_key="", out_path=""):
        self.banner()

        # Load API key
        if not api_key:
            api_key = os.environ.get("OPENROUTER_API_KEY", "")
            if not api_key:
                env_file = os.path.join(_ROOT, ".env")
                if os.path.isfile(env_file):
                    try:
                        for line in open(env_file).readlines():
                            if line.strip().startswith("OPENROUTER_API_KEY="):
                                api_key = line.strip().split("=", 1)[1].strip().strip('"').strip("'")
                    except Exception:
                        pass

        # Load findings
        path = findings_path or os.path.join(_ROOT, "logs", "findings.jsonl")
        findings = _dedup(_load_findings(path))
        self.log(f"Loaded {len(findings)} deduplicated findings from {path}")

        if not findings:
            self.log("No findings to analyze. Run some VibeHacking tools first.", "warn")
            return 1

        sev_counts = {}
        for f in findings:
            sev = f.get("severity", "info").lower()
            sev_counts[sev] = sev_counts.get(sev, 0) + 1
        self.log(f"Severity breakdown: {sev_counts}")

        findings_prompt = _summarize_for_prompt(findings)

        report = None
        model_used = "offline"

        if api_key:
            self.log("Calling OpenRouter free model for AI synthesis...")
            report, model_used = self._call_llm(api_key, findings_prompt)
            if report:
                self.log(f"AI synthesis complete via {model_used}", "pass")
            else:
                self.log("All free models failed — falling back to offline synthesis", "warn")

        if not report:
            self.log("Running offline deterministic synthesis...")
            report = self._offline_synthesis(findings)
            model_used = "offline"

        # Print report
        print("\n" + "═" * 60)
        print(f" ⚡ RECON AI — Attack Surface Intelligence Report")
        print(f"   Source: {path} | Model: {model_used}")
        print("═" * 60)
        print(f"\n🎯 OVERALL RISK: {report.get('overall_risk','?').upper()}")
        print(f"\n📋 EXECUTIVE SUMMARY\n{textwrap.fill(report.get('executive_summary',''), width=72)}")
        print(f"\n⛓  KILL CHAIN\n{report.get('kill_chain','')}")

        chains = report.get("critical_paths", [])
        if chains:
            print("\n🔗 CRITICAL ATTACK PATHS")
            for c in chains:
                print(f"  → {c}")

        rems = report.get("top_remediations", [])
        if rems:
            print("\n🛠  TOP REMEDIATIONS (by attacker impact)")
            for r in rems:
                print(f"  [{r.get('priority','?')}] {r.get('action','')}")
                print(f"      Prevents: {r.get('impact','')}")

        print(f"\n⏱  Estimated dwell time to full compromise: {report.get('attacker_dwell_time_estimate','unknown')}")
        print("═" * 60 + "\n")

        # Save JSON report
        if not out_path:
            out_path = os.path.join(_ROOT, "logs", "recon_ai_report.json")
        os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
        report["_meta"] = {"findings_count": len(findings), "model": model_used, "source_path": path}
        with open(out_path, "w", encoding="utf-8") as fh:
            json.dump(report, fh, indent=2)
        self.log(f"Full JSON report saved: {out_path}", "pass")
        return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Recon AI — AI-Powered Attack Surface Intelligence Synthesis")
    parser.add_argument("--findings", default="", help="Path to findings.jsonl (default: logs/findings.jsonl)")
    parser.add_argument("--api-key", default="", help="OpenRouter API key (or set OPENROUTER_API_KEY env)")
    parser.add_argument("--out", default="", help="JSON report output path (default: logs/recon_ai_report.json)")
    parser.add_argument("-v", "--version", action="version", version="Recon AI 1.0.0")
    args = parser.parse_args()
    sys.exit(ReconAI().run(findings_path=args.findings, api_key=args.api_key, out_path=args.out))
