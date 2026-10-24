#!/usr/bin/env python3
"""
vuln_chain.py — Vulnerability Chaining Engine.
Category: INTELLIGENCE

Reads logs/findings.jsonl and identifies which findings combine into
multi-step attack chains. 10 CWE-pair rules covering CVSS 6.8–9.8.
Outputs: ranked chain list, Graphviz DOT attack graph, JSON report.
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

CHAIN_RULES = [
    {"name": "JWT Bypass → Privilege Escalation",         "cwe_a": "CWE-347", "cwe_b": "CWE-285", "impact": "critical", "cvss_est": 9.8, "narrative": "A forged or alg:none-stripped JWT passes authentication (CWE-347), then broken access control (CWE-285) fails to re-verify role server-side. Attacker gains admin with zero credentials.", "fix": "Enforce RS256 JWT + server-side role re-validation on every protected route."},
    {"name": "SSRF → Cloud Metadata Credential Theft",    "cwe_a": "CWE-918", "cwe_b": "CWE-522", "impact": "critical", "cvss_est": 9.3, "narrative": "SSRF (CWE-918) reaches AWS/GCP/Azure metadata endpoint which returns unprotected IAM credentials (CWE-522).", "fix": "Block RFC-1918/loopback on egress firewall. Enforce IMDSv2 on AWS."},
    {"name": "WAF Bypass → SQL Injection Data Dump",      "cwe_a": "CWE-693", "cwe_b": "CWE-89",  "impact": "critical", "cvss_est": 9.6, "narrative": "WAF evasion (CWE-693: 16KB padding, Unicode escapes) smuggles SQLi payload (CWE-89) past the firewall.", "fix": "Use parameterized queries — WAF bypass is irrelevant if SQLi doesn't exist."},
    {"name": "Path Traversal → API Key Exfiltration",     "cwe_a": "CWE-22",  "cwe_b": "CWE-798", "impact": "critical", "cvss_est": 9.1, "narrative": "Path traversal (CWE-22) reads .env containing hardcoded API keys (CWE-798). Attacker reads /../.env and extracts OPENROUTER_API_KEY.", "fix": "Jail static file serving. Load secrets from env vars only, never files on disk."},
    {"name": "Prompt Injection → SSRF via LLM",           "cwe_a": "CWE-1427","cwe_b": "CWE-918", "impact": "high",     "cvss_est": 8.5, "narrative": "Prompt injection (CWE-1427) overrides LLM instructions, then instructs the AI to fetch an internal URL (CWE-918). LLM navigates to 169.254.169.254 on attacker's behalf.", "fix": "Isolate LLM from network access. Use strict allowlist for external calls."},
    {"name": "Broken Access Control → IDOR Mass Exposure", "cwe_a": "CWE-285", "cwe_b": "CWE-639", "impact": "high",     "cvss_est": 8.2, "narrative": "Missing access control (CWE-285) + predictable object IDs (CWE-639/BOLA) lets any authenticated user enumerate all other users' data.", "fix": "Validate object ownership on every request. Use UUIDs instead of sequential IDs."},
    {"name": "CORS → Cross-Origin Session Theft",         "cwe_a": "CWE-942", "cwe_b": "CWE-614", "impact": "high",     "cvss_est": 8.1, "narrative": "CORS reflecting arbitrary origins (CWE-942) + missing Secure/SameSite cookies (CWE-614) allows attacker's page to read authenticated cross-origin responses.", "fix": "Strict CORS origin allowlist. Set SameSite=Strict and Secure on all session cookies."},
    {"name": "Rate Limit Bypass → Brute Force Takeover",  "cwe_a": "CWE-290", "cwe_b": "CWE-307", "impact": "high",     "cvss_est": 7.8, "narrative": "IP spoofing via X-Forwarded-For (CWE-290) resets rate limit counter. Missing lockout (CWE-307) allows unlimited login attempts.", "fix": "Rate limit by verified socket IP, not headers. Enforce lockout after 5-10 failures."},
    {"name": "XSS → Session Token Exfiltration",          "cwe_a": "CWE-79",  "cwe_b": "CWE-614", "impact": "high",     "cvss_est": 7.5, "narrative": "Stored/reflected XSS (CWE-79) injects a script. Cookie without HttpOnly (CWE-614) makes document.cookie readable — attacker exfiltrates session token.", "fix": "Output-encode all user content. Set HttpOnly=true on all session cookies."},
    {"name": "GraphQL Batching → AI Credit Drain",        "cwe_a": "CWE-400", "cwe_b": "CWE-770", "impact": "medium",   "cvss_est": 6.8, "narrative": "Unbounded GraphQL batching (CWE-400) sends 15 queries/request to unauthenticated LLM endpoint (CWE-770). Burns 15x token cost per HTTP request.", "fix": "Require auth on LLM endpoints. Enforce query depth and batch size limits."},
]


def _load_findings(path):
    out = []
    try:
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if line:
                    try: out.append(json.loads(line))
                    except Exception: pass
    except OSError:
        pass
    return out


def _dedup(findings):
    seen, out = set(), []
    for f in findings:
        fp = f.get("fingerprint") or (f.get("title", "") + f.get("location", ""))[:80]
        if fp not in seen:
            seen.add(fp)
            out.append(f)
    return out


class VulnChain(VibeTool):
    def __init__(self):
        super().__init__("Vuln Chain", "Vulnerability Chaining Engine — Multi-Step Attack Path Mapper")

    def _build_cwe_index(self, findings):
        idx = {}
        for f in findings:
            cwe = f.get("cwe", "").strip()
            if cwe:
                idx.setdefault(cwe, []).append(f)
        return idx

    def _emit_dot(self, chains, findings, out_path):
        COLOR = {"critical": "#ff4444", "high": "#ff8800", "medium": "#ffcc00", "low": "#44aaff", "info": "#aaaaaa"}
        lines = ['digraph AttackGraph {', '  rankdir=LR;', '  node [shape=box, style=filled, fontname="Courier", fontsize=10];', '  edge [fontsize=9];', '']
        node_ids = {}
        for i, f in enumerate(findings[:30]):
            nid = f"f{i}"
            node_ids[f.get("fingerprint", f.get("title","")[:30])] = nid
            col = COLOR.get(f.get("severity","info").lower(), "#aaaaaa")
            label = f.get("title","")[:40].replace('"', "'")
            lines.append(f'  {nid} [label="{label}\\n{f.get("cwe","")}",fillcolor="{col}",fontcolor="black"];')
        lines.append("")
        for chain in chains:
            nid_a = node_ids.get(chain["finding_a"].get("fingerprint", chain["finding_a"].get("title","")[:30]))
            nid_b = node_ids.get(chain["finding_b"].get("fingerprint", chain["finding_b"].get("title","")[:30]))
            if nid_a and nid_b:
                lines.append(f'  {nid_a} -> {nid_b} [label="{chain["name"].replace(chr(34), chr(39))}",color="red"];')
        lines.append("}")
        try:
            os.makedirs(os.path.dirname(os.path.abspath(out_path)), exist_ok=True)
            with open(out_path, "w", encoding="utf-8") as fh:
                fh.write("\n".join(lines))
        except OSError as e:
            self.log(f"Could not write DOT file: {e}", "warn")

    def run(self, findings_path=None, dot_out="", json_out=""):
        self.banner()
        path = findings_path or os.path.join(_ROOT, "logs", "findings.jsonl")
        findings = _dedup(_load_findings(path))
        self.log(f"Loaded {len(findings)} unique finding(s) from {path}")
        if not findings:
            self.log("No findings. Run VibeHacking tools first.", "warn")
            return 1
        cwe_idx = self._build_cwe_index(findings)
        self.log(f"CWE coverage: {sorted(cwe_idx.keys())}")
        confirmed_chains = []
        for rule in CHAIN_RULES:
            findings_a = cwe_idx.get(rule["cwe_a"], [])
            findings_b = cwe_idx.get(rule["cwe_b"], [])
            if findings_a and findings_b:
                confirmed_chains.append({**rule, "finding_a": findings_a[0], "finding_b": findings_b[0]})
        confirmed_chains.sort(key=lambda c: c["cvss_est"], reverse=True)
        print("\n" + "═" * 64)
        print(" ⛓  VULN CHAIN — Multi-Step Attack Path Report")
        print(f"   {len(confirmed_chains)} chain(s) confirmed from {len(findings)} finding(s)")
        print("═" * 64)
        if not confirmed_chains:
            self.log("No multi-step chains found.", "pass")
        else:
            for i, chain in enumerate(confirmed_chains, 1):
                icon = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🔵"}.get(chain["impact"],"⚪")
                print(f"\n{icon} CHAIN {i}: {chain['name']}")
                print(f"   CVSS: {chain['cvss_est']} | {chain['cwe_a']} → {chain['cwe_b']}")
                print(f"   Narrative: {chain['narrative']}")
                print(f"   Fix: {chain['fix']}")
                self.record_finding(
                    title=f"Attack Chain: {chain['name']}",
                    severity=chain["impact"],
                    location=chain["finding_a"].get("location",""),
                    evidence=f"{chain['finding_a'].get('title','')} ({chain['cwe_a']}) → {chain['finding_b'].get('title','')} ({chain['cwe_b']}). CVSS: {chain['cvss_est']}.",
                    recommendation=chain["fix"],
                    cwe=chain["cwe_a"],
                    owasp=chain["finding_a"].get("owasp",""),
                )
        print("\n" + "═" * 64 + "\n")
        dot_path = dot_out or os.path.join(_ROOT, "logs", "vuln_chain.dot")
        self._emit_dot(confirmed_chains, findings, dot_path)
        self.log(f"Attack graph: {dot_path} (render: dot -Tpng {dot_path} -o graph.png)", "pass")
        jp = json_out or os.path.join(_ROOT, "logs", "vuln_chain.json")
        try:
            out_data = [{k: v for k, v in c.items() if k not in ("finding_a","finding_b")} for c in confirmed_chains]
            with open(jp, "w", encoding="utf-8") as fh:
                json.dump({"chains": out_data, "total": len(out_data)}, fh, indent=2)
            self.log(f"JSON chains: {jp}", "pass")
        except OSError as e:
            self.log(f"Could not save JSON: {e}", "warn")
        return 0 if not confirmed_chains else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vuln Chain — Vulnerability Chaining Engine")
    parser.add_argument("--findings", default="")
    parser.add_argument("--dot-out", default="")
    parser.add_argument("--json-out", default="")
    parser.add_argument("-v", "--version", action="version", version="Vuln Chain 1.0.0")
    args = parser.parse_args()
    sys.exit(VulnChain().run(findings_path=args.findings, dot_out=args.dot_out, json_out=args.json_out))
