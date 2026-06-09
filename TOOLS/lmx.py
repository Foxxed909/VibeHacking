import sys
import os
import glob
import re
import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool
from privacy_guard import sanitize_text

_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class LMX(VibeTool):
    def __init__(self):
        super().__init__("LMX", "Executive Security Dashboard Generator")

    def run(self, log_dir=None):
        self.banner()

        if log_dir is None:
            log_dir = os.path.join(_root, "logs")

        dashboard_file = os.path.join(_root, "VIBE_DASHBOARD.html")
        log_files = glob.glob(os.path.join(log_dir, "*.md")) + glob.glob(os.path.join(log_dir, "*.log"))

        self.log(f"Compiling intelligence from {len(log_files)} artifact(s)...")

        stats = {"Critical": 0, "Medium": 0, "Low": 0, "Info": 0}
        session_data = []

        for file in log_files:
            try:
                with open(file, "r", encoding="utf-8") as f:
                    content = f.read()
                    name = os.path.basename(file)
                    crit = len(re.findall(r'🔴|CRITICAL|crit', content, re.IGNORECASE))
                    med  = len(re.findall(r'🟡|MEDIUM|warn', content, re.IGNORECASE))
                    low  = len(re.findall(r'🟢|LOW|pass', content, re.IGNORECASE))
                    info = len(re.findall(r'🔵|INFO|hack', content, re.IGNORECASE))

                    stats["Critical"] += crit
                    stats["Medium"]   += med
                    stats["Low"]      += low
                    stats["Info"]     += info

                    session_data.append({
                        "name": name,
                        "crit": crit, "med": med, "low": low, "info": info,
                        "type": "Log" if file.endswith(".log") else "Session",
                        "date": datetime.datetime.fromtimestamp(os.path.getmtime(file)).strftime('%Y-%m-%d %H:%M')
                    })
            except (OSError, UnicodeDecodeError) as e:
                self.log(f"Could not read {file}: {e}", "fail")

        session_data.sort(key=lambda x: x['date'], reverse=True)

        rows = ""
        for s in session_data:
            rows += f"""
                <tr>
                    <td>{sanitize_text(s['name'])}</td>
                    <td><span class="type-badge">{s['type']}</span></td>
                    <td>{s['date']}</td>
                    <td class="crit">{s['crit']}</td>
                    <td class="med">{s['med']}</td>
                    <td class="low">{s['low']}</td>
                </tr>"""

        html = f"""<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <title>VibeHacking Dashboard v{self.version}</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;600;800&family=JetBrains+Mono&display=swap');
        body {{ font-family: 'Outfit', sans-serif; background: #05070a; color: #cbd5e1; margin: 0; padding: 60px; }}
        .glass {{ background: rgba(30,41,59,0.7); backdrop-filter: blur(12px); border: 1px solid rgba(255,255,255,0.1); border-radius: 24px; padding: 40px; box-shadow: 0 20px 50px rgba(0,0,0,0.5); }}
        h1 {{ margin: 0; font-size: 2.5rem; font-weight: 800; background: linear-gradient(90deg, #38bdf8, #818cf8); -webkit-background-clip: text; -webkit-text-fill-color: transparent; }}
        .header {{ display: flex; justify-content: space-between; align-items: flex-end; margin-bottom: 40px; }}
        .stat-grid {{ display: grid; grid-template-columns: repeat(4, 1fr); gap: 24px; margin-bottom: 60px; }}
        .stat-card {{ background: #0f172a; padding: 30px; border-radius: 20px; border: 1px solid #1e293b; transition: transform 0.3s; }}
        .stat-card:hover {{ transform: translateY(-5px); border-color: #38bdf8; }}
        .stat-label {{ text-transform: uppercase; font-size: 0.75rem; letter-spacing: 0.1em; color: #94a3b8; font-weight: 600; }}
        .stat-val {{ font-size: 3.5rem; font-weight: 800; display: block; }}
        .crit {{ color: #f43f5e; }} .med {{ color: #f59e0b; }} .low {{ color: #10b981; }} .info {{ color: #6366f1; }}
        table {{ width: 100%; border-collapse: separate; border-spacing: 0; }}
        th {{ text-align: left; padding: 20px; color: #94a3b8; font-weight: 600; border-bottom: 2px solid #1e293b; }}
        td {{ padding: 20px; border-bottom: 1px solid #1e293b; font-family: 'JetBrains Mono', monospace; font-size: 0.9rem; }}
        tr:hover td {{ background: rgba(56,189,248,0.05); }}
        .type-badge {{ padding: 4px 10px; border-radius: 6px; font-size: 0.7rem; background: #1e293b; color: #38bdf8; font-weight: 700; }}
    </style>
</head>
<body>
    <div class="glass">
        <div class="header">
            <div>
                <p style="color:#38bdf8;font-weight:700;margin-bottom:5px;">EXECUTIVE INTELLIGENCE</p>
                <h1>VIBEHACKING STATUS v{self.version}</h1>
            </div>
            <div style="text-align:right;">
                <p style="margin:0;font-size:0.8rem;color:#64748b;">VERSION: {self.version} [STABLE]</p>
                <p style="margin:0;font-weight:600;">GENERATED: {datetime.datetime.now().strftime('%Y-%m-%d %H:%M')}</p>
            </div>
        </div>
        <div class="stat-grid">
            <div class="stat-card"><span class="stat-label">Critical Findings</span><span class="stat-val crit">{stats['Critical']}</span></div>
            <div class="stat-card"><span class="stat-label">Moderate Risks</span><span class="stat-val med">{stats['Medium']}</span></div>
            <div class="stat-card"><span class="stat-label">Passed Checks</span><span class="stat-val low">{stats['Low']}</span></div>
            <div class="stat-card"><span class="stat-label">Total Artifacts</span><span class="stat-val info">{len(session_data)}</span></div>
        </div>
        <table>
            <thead>
                <tr><th>Component / Artifact</th><th>Type</th><th>Timestamp</th><th class="crit">Crit</th><th class="med">Med</th><th class="low">Low</th></tr>
            </thead>
            <tbody>{rows}
            </tbody>
        </table>
    </div>
</body>
</html>"""

        with open(dashboard_file, "w", encoding="utf-8") as f:
            f.write(html)

        self.log(f"Dashboard rendered: {dashboard_file}", "pass")
        self.log("Audit pipeline fully synchronized", "pass")


if __name__ == "__main__":
    LMX().run()
