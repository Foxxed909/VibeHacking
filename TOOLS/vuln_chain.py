#!/usr/bin/env python3
"""
vuln_chain.py — Vulnerability Chaining Engine.

Reads logs/findings.jsonl and identifies which findings can be combined
into multi-step attack chains that individually look low-risk but together
produce critical-impact exploitation paths.

Category: INTELLIGENCE

Classic chains detected:
  CORS + JWT weak secret    → cross-origin credential theft + session forgery
  SSRF + Path Traversal     → cloud metadata + .env key extraction
  WAF bypass + SQLi         → data dump after evading detection layer
  Prompt injection + SSRF   → LLM navigates internal network on attacker's behalf
  Rate limit miss + Login   → brute force to account takeover
  JWT bypass + IDOR         → admin access + data of all users
  XSS + httpOnly-less cookie→ session hijack via DOM exfil

Output:
  - Ranked list of chaining paths with combined severity
  - For each chain: individual steps, combined CVSS estimate, remediation priority
  - Graphviz DOT file of the full attack graph (saved to logs/vuln_chain.dot)
"""
import argparse
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# ── Chain rule definitions ────────────────────────────────────────────────────
# Each rule: (name, description, node_a_cwe, node_b_cwe, combined_impact, chain_narrative)
# If both CWEs are present in findings, the chain fires.

CHAIN_RULES = [
    {
        "name":      "JWT Bypass → Privilege Escalation",
        "cwe_a":     "CWE-347",
        "cwe_b":     "CWE-285",
        "impact":    "critical",
        "cvss_est":  9.8,
        "narrative": (
            "A forged or alg:none-stripped JWT passes authentication (CWE-347), "
            "then the broken access control (CWE-285) fails to re-verify role server-side. "
            "An attacker gains admin access with zero credentials."
        ),
        "fix": "Enforce RS256 JWT + server-side role re-validation on every protected route.",
    },
    {
        "name":      "SSRF → Cloud Metadata Credential Theft",
        "cwe_a":     "CWE-918",
        "cwe_b":     "CWE-522",
        "impact":    "critical",
        "cvss_est":  9.3,
        "narrative": (
            "SSRF (CWE-918) reaches the AWS/GCP/Azure metadata endpoint "
            "which returns unprotected instance credentials (CWE-522). "
            "An attacker calls http://169.254.169.254/ to extract cloud IAM tokens."
        ),
        "fix": "Block RFC-1918/loopback on egress firewall. Enforce IMDSv2 on AWS.",
    },
    {
        "name":      "Path Traversal → API Key Exfiltration",
        "cwe_a":     "CWE-22",
        "cwe_b":     "CWE-798",
        "impact":    "critical",
        "cvss_est":  9.1,
        "narrative": (
            "Path traversal (CWE-22) reads the .env file containing hardcoded "
            "API keys (CWE-798). An attacker reads GET /../.env and extracts "
            "OPENROUTER_API_KEY, bypassing all authentication."
        ),
        "fix": "Jail static file serving. Load secrets from environment variables only, never files on disk.",
    },
    {
        "name":      "WAF Bypass → SQL Injection Data Dump",
        "cwe_a":     "CWE-693",
        "cwe_b":     "CWE-89",
        "impact":    "critical",
        "cvss_est":  9.6,
        "narrative": (
            "A WAF evasion technique (CWE-693, e.g. 16KB padding, Unicode escapes) "
            "smuggles a SQL injection payload (CWE-89) past the firewall. "
            "The underlying database executes the query and returns all user data."
        ),
        "fix": "Use parameterized queries at the DB layer — WAF bypass is irrelevant if SQLi doesn't exist.",
    },
    {
        "name":      "Prompt Injection → SSRF via LLM",
        "cwe_a":     "CWE-1427",
        "cwe_b":     "CWE-918",
        "impact":    "high",
        "cvss_est":  8.5,
        "narrative": (
            "A prompt injection (CWE-1427) overrides the LLM system instructions, "
            "then instructs the AI assistant to fetch an internal URL (CWE-918). "
            "The LLM navigates to http://169.254.169.254/ on the attacker's behalf "
            "and returns cloud credentials in its response."
        ),
        "fix": "Isolate LLM from network access. Use a separate agent with strict allowlist for external calls.",
    },
    {
        "name":      "CORS Misconfiguration → Cross-Origin Session Theft",
        "cwe_a":     "CWE-942",
        "cwe_b":     "CWE-614",
        "impact":    "high",
        "cvss_est":  8.1,
        "narrative": (
            "A CORS policy that reflects arbitrary origins (CWE-942) allows an attacker's "
            "malicious page to make credentialed cross-origin requests. "
            "Combined with missing Secure/SameSite on session cookies (CWE-614), "
            "the cookie is sent cross-origin and the attacker reads the authenticated response."
        ),
        "fix": "Strict CORS origin allowlist. Set SameSite=Strict and Secure on all session cookies.",
    },
    {
        "name":      "Rate Limit Bypass → Brute Force Account Takeover",
        "cwe_a":     "CWE-290",
        "cwe_b":     "CWE-307",
        "impact":    "high",
        "cvss_est":  7.8,
        "narrative": (
            "IP spoofing via X-Forwarded-For (CWE-290) resets the rate limit counter, "
            "then the missing lockout (CWE-307) allows unlimited login attempts. "
            "An attacker cycles through a password list until they hit a match."
        ),
        "fix": "Rate limit by verified IP (socket, not headers). Enforce lockout after 5-10 failures.",
    },
    {
        "name":      "XSS → Session Token Exfiltration",
        "cwe_a":     "CWE-79",
        "cwe_b":     "CWE-614",
        "impact":    "high",
        "cvss_est":  7.5,
        "narrative": (
            "A stored or reflected XSS (CWE-79) injects a script into a victim's browser. "
            "Because the session cookie lacks HttpOnly (CWE-614), "
            "document.cookie is readable and the attacker exfiltrates the session token."
        ),
        "fix": "Output-encode all user content. Set HttpOnly=true on all session cookies.",
    },
    {
        "name":      "Broken Access Control → IDOR Mass Data Exposure",
        "cwe_a":     "CWE-285",
        "cwe_b":     "CWE-639",
        "impact":    "high",
        "cvss_est":  8.2,
        "narrative": (
            "Missing function-level access control (CWE-285) combines with predictable "
            "object IDs (CWE-639, BOLA/IDOR) to allow any authenticated user to enumerate "
            "and read data belonging to all other users by incrementing the ID parameter."
        ),
        "fix": "Validate object ownership on every request. Use UUIDs instead of sequential IDs.",
    },
    {
        "name":      "GraphQL Batching → AI Credit Drain",
        "cwe_a":     "CWE-400",
        "cwe_b":     "CWE-770",
        "impact":    "medium",
        "cvss_est":  6.8,
        "narrative": (
            "Unbounded GraphQL batching (CWE-400) sends 15 queries in one HTTP request "
            "to the unauthenticated LLM inference endpoint (CWE-770, AI wallet drain). "
            "An attacker burns 15x the normal token cost per HTTP request, "
            "exhausting the application's API credit budget in minutes."
        ),
        "fix": "Require auth on LLM endpoints. Enforce GraphQL query depth and batch size limits.",
    },
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
    seen = set()
    out  = []
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
        """Map CWE → list of matching findings."""
        idx = {}
        for f in findings:
            cwe = f.get("cwe", "").strip()
            if cwe:
                idx.setdefault(cwe, []).append(f)
        return idx

    def _emit_dot(self, chains, findings, out_path):
        """Generate a Graphviz DOT file representing the full attack graph."""
        lines = [
            'digraph AttackGraph {',
            '  rankdir=LR;',
            '  node [shape=box, style=filled, fontname="Courier", fontsize=10];',
            '  edge [fontsize=9];',
            '',
        ]
        # Color by severity
        COLOR = {"critical": "#ff4444", "high": "#ff8800", "medium": "#ffcc00", "low": "#44aaff", "info": "#aaaaaa"}
        # Add finding nodes
        node_ids = {}
        for i, f in enumerate(findings[:30]):
            nid = f"f{i}"
            node_ids[f.get("fingerprint", f.get("title","")[:30])] = nid
            sev  = f.get("severity","info").lower()
            col  = COLOR.get(sev, "#aaaaaa")
            label = f.get("title","")[:40].replace('"', "'")
            lines.append(f'  {nid} [label="{label}\\n{f.get("cwe","")}",fillcolor="{col}",fontcolor="black"];')

        lines.append("")
        # Add chain edges
        for chain in chains:
            nid_a = node_ids.get(chain["finding_a"].get("fingerprint", chain["finding_a"].get("title","")[:30]))
            nid_b = node_ids.get(chain["finding_b"].get("fingerprint", chain["finding_b"].get("title","")[:30]))
            if nid_a and nid_b:
                label = chain["name"].replace('"', "'")
                lines.append(f'  {nid_a} -> {nid_b} [label="{label}",color="red"];')

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

        # Evaluate chain rules
        confirmed_chains = []
        for rule in CHAIN_RULES:
            findings_a = cwe_idx.get(rule["cwe_a"], [])
            findings_b = cwe_idx.get(rule["cwe_b"], [])
            if findings_a and findings_b:
                confirmed_chains.append({
                    "name":      rule["name"],
                    "impact":    rule["impact"],
                    "cvss_est":  rule["cvss_est"],
                    "narrative": rule["narrative"],
                    "fix":       rule["fix"],
                    "finding_a": findings_a[0],
                    "finding_b": findings_b[0],
                    "cwe_a":     rule["cwe_a"],
                    "cwe_b":     rule["cwe_b"],
                })

        # Sort by combined CVSS estimate
        confirmed_chains.sort(key=lambda c: c["cvss_est"], reverse=True)

        # Print
        print("\n" + "═" * 64)
        print(" ⛓  VULN CHAIN — Multi-Step Attack Path Report")
        print(f"   {len(confirmed_chains)} chain(s) confirmed from {len(findings)} finding(s)")
        print("═" * 64)

        if not confirmed_chains:
            self.log("No multi-step chains found. Either clean app or insufficient finding coverage.", "pass")
        else:
            for i, chain in enumerate(confirmed_chains, 1):
                sev_icon = {"critical":"🔴","high":"🟠","medium":"🟡","low":"🔵"}.get(chain["impact"],"⚪")
                print(f"\n{sev_icon} CHAIN {i}: {chain['name']}")
                print(f"   CVSS Estimate: {chain['cvss_est']}")
                print(f"   Step 1 ({chain['cwe_a']}): {chain['finding_a'].get('title','')}")
                print(f"   Step 2 ({chain['cwe_b']}): {chain['finding_b'].get('title','')}")
                print(f"   Narrative: {chain['narrative']}")
                print(f"   Fix: {chain['fix']}")

                # Record as a finding
                self.record_finding(
                    title=f"Attack Chain: {chain['name']}",
                    severity=chain["impact"],
                    location=chain["finding_a"].get("location",""),
                    evidence=(
                        f"{chain['finding_a'].get('title','')} ({chain['cwe_a']}) "
                        f"→ {chain['finding_b'].get('title','')} ({chain['cwe_b']}). "
                        f"CVSS estimate: {chain['cvss_est']}. {chain['narrative']}"
                    ),
                    recommendation=chain["fix"],
                    cwe=chain["cwe_a"],
                    owasp=chain["finding_a"].get("owasp",""),
                )

        print("\n" + "═" * 64 + "\n")

        # DOT graph
        dot_path = dot_out or os.path.join(_ROOT, "logs", "vuln_chain.dot")
        self._emit_dot(confirmed_chains, findings, dot_path)
        self.log(f"Attack graph saved: {dot_path} (render with: dot -Tpng {dot_path} -o attack_graph.png)", "pass")

        # JSON output
        jp = json_out or os.path.join(_ROOT, "logs", "vuln_chain.json")
        try:
            out_data = [
                {k: v for k, v in c.items() if k not in ("finding_a","finding_b")}
                for c in confirmed_chains
            ]
            with open(jp, "w", encoding="utf-8") as fh:
                json.dump({"chains": out_data, "total": len(out_data)}, fh, indent=2)
            self.log(f"JSON chains saved: {jp}", "pass")
        except OSError as e:
            self.log(f"Could not save JSON: {e}", "warn")

        return 0 if not confirmed_chains else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vuln Chain — Vulnerability Chaining Engine")
    parser.add_argument("--findings", default="", help="Path to findings.jsonl (default: logs/findings.jsonl)")
    parser.add_argument("--dot-out",  default="", help="Graphviz DOT output path")
    parser.add_argument("--json-out", default="", help="JSON chains output path")
    parser.add_argument("-v", "--version", action="version", version="Vuln Chain 1.0.0")
    args = parser.parse_args()
    sys.exit(VulnChain().run(findings_path=args.findings, dot_out=args.dot_out, json_out=args.json_out))
