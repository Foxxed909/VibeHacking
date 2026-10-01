import sys
import os
import glob
import re
import json
import html
import argparse
import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool
from privacy_guard import sanitize_text

_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class LMX(VibeTool):
    def __init__(self):
        super().__init__("LMX", "Executive Security Dashboard Generator")

    @staticmethod
    def _load_structured_findings(log_dir):
        findings_path = os.path.join(log_dir, "findings.jsonl")
        findings = []
        seen = set()
        if not os.path.isfile(findings_path):
            return findings
        try:
            with open(findings_path, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        item = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    key = (item.get("tool", ""), item.get("title", ""), item.get("location", ""))
                    if key not in seen:
                        seen.add(key)
                        findings.append(item)
        except OSError:
            pass
        return findings

    def run(self, log_dir=None, output_file=None):
        self.banner()

        if log_dir is None:
            log_dir = self.log_dir

        dashboard_file = output_file or os.path.join(_root, "VIBE_DASHBOARD.html")
        log_files = [
            f for f in (glob.glob(os.path.join(log_dir, "*.md")) + glob.glob(os.path.join(log_dir, "*.log")))
            if not os.path.basename(f).startswith("lmx_")
        ]

        self.log(f"Compiling intelligence from {len(log_files)} artifact(s)...")

        stats = {"Critical": 0, "High": 0, "Medium": 0, "Pass": 0}
        session_data = []

        for file in log_files:
            try:
                with open(file, "r", encoding="utf-8", errors="replace") as f:
                    content = f.read()
                    name = os.path.basename(file)
                    # Match exact VibeTool log prefixes rather than substring words in payloads
                    crit = len(re.findall(r"\[🔴 CRITICAL\]", content))
                    hack = len(re.findall(r"\[🔥 HACK\]", content))
                    med  = len(re.findall(r"\[🟡 WARN\]", content))
                    passed = len(re.findall(r"\[🟢 PASS\]", content))

                    stats["Critical"] += crit
                    stats["High"]     += hack
                    stats["Medium"]   += med
                    stats["Pass"]     += passed

                    session_data.append({
                        "name": name,
                        "crit": crit,
                        "hack": hack,
                        "med": med,
                        "pass": passed,
                        "type": "Log" if file.endswith(".log") else "Session",
                        "date": datetime.datetime.fromtimestamp(os.path.getmtime(file)).strftime('%Y-%m-%d %H:%M')
                    })
            except (OSError, UnicodeDecodeError) as e:
                self.log(f"Could not read {file}: {e}", "fail")

        session_data.sort(key=lambda x: x['date'], reverse=True)
        structured = self._load_structured_findings(log_dir)

        rows = ""
        for s in session_data:
            safe_name = html.escape(sanitize_text(s['name']))
            safe_type = html.escape(s['type'])
            safe_date = html.escape(s['date'])
            rows += f"""
                <tr>
                    <td>{safe_name}</td>
                    <td><span class="type-badge">{safe_type}</span></td>
                    <td>{safe_date}</td>
                    <td class="crit">{s['crit']}</td>
                    <td class="high">{s['hack']}</td>
                    <td class="med">{s['med']}</td>
                    <td class="low">{s['pass']}</td>
                </tr>"""

        finding_rows = ""
        for f in structured[:50]:
            sev = html.escape(str(f.get("severity", "info")).upper())
            sev_cls = "crit" if sev == "CRITICAL" else ("high" if sev == "HIGH" else ("med" if sev == "MEDIUM" else "info"))
            tool_name = html.escape(sanitize_text(str(f.get("tool", ""))))
            title = html.escape(sanitize_text(str(f.get("title", ""))))
            cwe = html.escape(str(f.get("cwe", "CWE-200")))
            owasp = html.escape(str(f.get("owasp", "A05:2021")))
            finding_rows += f"""
                <tr>
                    <td><span class="sev-pill {sev_cls}">{sev}</span></td>
                    <td>{tool_name}</td>
                    <td>{title}</td>
                    <td><span class="type-badge">{cwe}</span></td>
                    <td><span class="type-badge">{owasp}</span></td>
                </tr>"""

        structured_section = ""
        if finding_rows:
            structured_section = f"""
        <h2 style="margin-top:48px;font-size:1.3rem;color:#38bdf8;">Structured Compliance & Vulnerability Register (CWE / OWASP)</h2>
        <table>
            <thead>
                <tr><th>Severity</th><th>Tool</th><th>Finding</th><th>CWE</th><th>OWASP Category</th></tr>
            </thead>
            <tbody>{finding_rows}
            </tbody>
        </table>"""

        dashboard_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>VibeHacking Dashboard v{html.escape(str(self.version))}</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=JetBrains+Mono&display=swap');
        body {{ font-family: 'Outfit', sans-serif; background: #05070a; color: #cbd5e1; margin: 0; padding: 60px; }}
        .glass {{ background: rgba(30,41,59,0.7); backdrop-filter: blur(12px); border: 1px solid rgba(255,255,255,0.1); border-radius: 24px; padding: 40px; box-shadow: 0 20px 50px rgba(0,0,0,0.5); }}
        h1 {{ margin: 0; font-size: 2.5rem; font-weight: 800; background: linear-gradient(90deg, #38bdf8, #818cf8); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .header {{ display: flex; justify-content: space-between; align-items: flex-end; margin-bottom: 40px; }}
        .stat-grid {{ display: grid; grid-template-columns: repeat(5, 1fr); gap: 20px; margin-bottom: 50px; }}
        .stat-card {{ background: #0f172a; padding: 24px; border-radius: 20px; border: 1px solid #1e293b; transition: transform 0.3s; }}
        .stat-card:hover {{ transform: translateY(-5px); border-color: #38bdf8; }}
        .stat-label {{ text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.1em; color: #94a3b8; font-weight: 600; }}
        .stat-val {{ font-size: 3rem; font-weight: 800; display: block; }}
        .crit {{ color: #f43f5e; }} .high {{ color: #fb923c; }} .med {{ color: #f59e0b; }} .low {{ color: #10b981; }} .info {{ color: #6366f1; }}
        table {{ width: 100%; border-collapse: separate; border-spacing: 0; }}
        th {{ text-align: left; padding: 16px; color: #94a3b8; font-weight: 600; border-bottom: 2px solid #1e293b; }}
        td {{ padding: 16px; border-bottom: 1px solid #1e293b; font-family: 'JetBrains Mono', monospace; font-size: 0.88rem; }}
        tr:hover td {{ background: rgba(56,189,248,0.05); }}
        .type-badge {{ padding: 4px 10px; border-radius: 6px; font-size: 0.7rem; background: #1e293b; color: #38bdf8; font-weight: 700; }}
        .sev-pill {{ padding: 4px 10px; border-radius: 6px; font-size: 0.72rem; font-weight: 800; background: #0f172a; border: 1px solid currentColor; }}
    </style>
</head>
<body>
    <div class="glass">
        <div class="header">
            <div>
                <p style="color:#38bdf8;font-weight:700;margin-bottom:5px;">EXECUTIVE INTELLIGENCE</p>
                <h1>VIBEHACKING STATUS v{html.escape(str(self.version))}</h1>
            </div>
            <div style="text-align:right;">
                <p style="margin:0;font-size:0.8rem;color:#64748b;">VERSION: {html.escape(str(self.version))} [STABLE]</p>
                <p style="margin:0;font-weight:600;">GENERATED: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
            </div>
        </div>
        <div class="stat-grid">
            <div class="stat-card"><span class="stat-label">Critical Findings</span><span class="stat-val crit">{stats['Critical']}</span></div>
            <div class="stat-card"><span class="stat-label">Exploit Signals</span><span class="stat-val high">{stats['High']}</span></div>
            <div class="stat-card"><span class="stat-label">Moderate Warnings</span><span class="stat-val med">{stats['Medium']}</span></div>
            <div class="stat-card"><span class="stat-label">Passed Checks</span><span class="stat-val low">{stats['Pass']}</span></div>
            <div class="stat-card"><span class="stat-label">Total Artifacts</span><span class="stat-val info">{len(session_data)}</span></div>
        </div>
        <table>
            <thead>
                <tr><th>Component / Artifact</th><th>Type</th><th>Timestamp</th><th class="crit">Crit</th><th class="high">Hack</th><th class="med">Warn</th><th class="low">Pass</th></tr>
            </thead>
            <tbody>{rows}
            </tbody>
        </table>{structured_section}
    </div>
</body>
</html>"""

        with open(dashboard_file, "w", encoding="utf-8") as f:
            f.write(dashboard_html)

        self.log(f"Dashboard rendered: {dashboard_file}", "pass")
        self.log("Audit pipeline fully synchronized", "pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LMX - Executive Security Dashboard Generator")
    parser.add_argument("--log-dir", default=None, help="Directory containing session logs (default: logs/)")
    parser.add_argument("--out", default=None, help="Output HTML file path (default: VIBE_DASHBOARD.html)")
    parser.add_argument("-v", "--version", action="version", version="LMX 1.0.0")
    args = parser.parse_args()
    LMX().run(log_dir=args.log_dir, output_file=args.out)
