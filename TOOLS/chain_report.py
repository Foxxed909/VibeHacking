#!/usr/bin/env python3
"""
chain_report.py — VibeHacking HTML Pentest Report Generator.

Reads logs/findings.jsonl and generates a self-contained, styled HTML report
with severity breakdown, OWASP/CWE mapping, evidence, and recommendations.
No external dependencies — pure stdlib + inline CSS/JS.

Usage:
  python TOOLS/chain_report.py                       # reads logs/findings.jsonl
  python TOOLS/chain_report.py --out my_report.html  # custom output path
  python TOOLS/chain_report.py --open                # open in browser after generating
"""
import argparse
import datetime
import json
import os
import sys
import webbrowser

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
DEFAULT_FINDINGS = os.path.join(_ROOT, "logs", "findings.jsonl")
DEFAULT_OUT      = os.path.join(_ROOT, "reports", "vibe_report.html")

SEV_ORDER  = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
SEV_COLOR  = {
    "critical": "#ff4444",
    "high":     "#ff8800",
    "medium":   "#ffcc00",
    "low":      "#44aaff",
    "info":     "#aaaaaa",
}
SEV_BADGE  = {
    "critical": "🔴",
    "high":     "🟠",
    "medium":   "🟡",
    "low":      "🔵",
    "info":     "⚪",
}


def _esc(s):
    return (str(s)
            .replace("&", "&amp;")
            .replace("<", "&lt;")
            .replace(">", "&gt;")
            .replace('"', "&quot;")
            .replace("'", "&#39;"))


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
    except OSError as e:
        print(f"[-] Could not read {path}: {e}", file=sys.stderr)
    return findings


def _severity_counts(findings):
    counts = {k: 0 for k in SEV_ORDER}
    for f in findings:
        sev = str(f.get("severity", "info")).lower()
        counts[sev] = counts.get(sev, 0) + 1
    return counts


def _owasp_breakdown(findings):
    breakdown = {}
    for f in findings:
        tag = str(f.get("owasp", "Unknown"))
        breakdown[tag] = breakdown.get(tag, 0) + 1
    return sorted(breakdown.items(), key=lambda x: -x[1])


def _tool_breakdown(findings):
    tools = {}
    for f in findings:
        t = str(f.get("tool", "unknown"))
        tools[t] = tools.get(t, 0) + 1
    return sorted(tools.items(), key=lambda x: -x[1])


def _build_html(findings, source_path):
    counts   = _severity_counts(findings)
    total    = len(findings)
    owasp_bk = _owasp_breakdown(findings)
    tool_bk  = _tool_breakdown(findings)
    generated = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S UTC")

    sorted_findings = sorted(
        findings,
        key=lambda f: (SEV_ORDER.get(str(f.get("severity", "info")).lower(), 99),
                       str(f.get("timestamp", "")))
    )

    # Deduplicate by fingerprint for display (keep first occurrence)
    seen_fps = set()
    display_findings = []
    for f in sorted_findings:
        fp = f.get("fingerprint", "")
        if fp and fp in seen_fps:
            continue
        if fp:
            seen_fps.add(fp)
        display_findings.append(f)

    score = 100
    for f in display_findings:
        sev = str(f.get("severity", "info")).lower()
        score -= {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}.get(sev, 0)
    score = max(0, score)

    score_color = "#44cc44" if score >= 70 else ("#ffaa00" if score >= 40 else "#ff4444")

    rows_html = ""
    for i, f in enumerate(display_findings):
        sev  = str(f.get("severity", "info")).lower()
        color = SEV_COLOR.get(sev, "#aaaaaa")
        badge = SEV_BADGE.get(sev, "⚪")
        rows_html += f"""
        <tr class="finding-row" data-sev="{_esc(sev)}" data-tool="{_esc(f.get('tool',''))}">
          <td><span class="badge" style="background:{color}">{badge} {_esc(sev.upper())}</span></td>
          <td class="title-cell" onclick="toggle({i})">{_esc(f.get('title',''))}</td>
          <td><code>{_esc(f.get('tool',''))}</code></td>
          <td><code>{_esc(f.get('cwe',''))}</code></td>
          <td class="loc"><a href="{_esc(f.get('location',''))}" target="_blank">{_esc(f.get('location','')[:60])}</a></td>
          <td>{_esc(f.get('timestamp','')[:10])}</td>
        </tr>
        <tr id="detail-{i}" class="detail-row" style="display:none">
          <td colspan="6">
            <div class="detail-box">
              <div class="detail-section"><b>Evidence</b><pre>{_esc(f.get('evidence',''))}</pre></div>
              <div class="detail-section"><b>Recommendation</b><p>{_esc(f.get('recommendation','') or 'See OWASP guidance for ' + f.get('owasp',''))}</p></div>
              <div class="detail-section meta">
                <span>OWASP: {_esc(f.get('owasp',''))}</span>
                <span>CWE: {_esc(f.get('cwe',''))}</span>
                <span>Auto-captured: {'yes' if f.get('auto_captured') else 'no'}</span>
                <span>Fingerprint: <code>{_esc(f.get('fingerprint',''))}</code></span>
              </div>
            </div>
          </td>
        </tr>"""

    owasp_rows = "".join(
        f"<tr><td>{_esc(tag)}</td><td>{cnt}</td></tr>"
        for tag, cnt in owasp_bk
    )
    tool_rows = "".join(
        f"<tr><td><code>{_esc(t)}</code></td><td>{cnt}</td></tr>"
        for t, cnt in tool_bk
    )

    sev_bars = ""
    for sev, cnt in counts.items():
        pct = (cnt / max(total, 1)) * 100
        sev_bars += f"""
        <div class="bar-row">
          <span class="bar-label" style="color:{SEV_COLOR[sev]}">{SEV_BADGE[sev]} {sev.upper()}</span>
          <div class="bar-track"><div class="bar-fill" style="width:{pct:.1f}%;background:{SEV_COLOR[sev]}"></div></div>
          <span class="bar-count">{cnt}</span>
        </div>"""

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>VibeHacking Pentest Report</title>
<style>
  :root {{
    --bg: #0d0d0d; --bg2: #141414; --bg3: #1c1c1c;
    --border: #2a2a2a; --text: #e0e0e0; --muted: #666;
    --accent: #ff4444; --code: #23c59e;
  }}
  * {{ box-sizing: border-box; margin: 0; padding: 0; }}
  body {{ background: var(--bg); color: var(--text); font: 14px/1.6 'Segoe UI', system-ui, sans-serif; padding: 24px; }}
  h1 {{ font-size: 1.8em; color: var(--accent); margin-bottom: 4px; }}
  h2 {{ font-size: 1.1em; color: var(--muted); margin: 24px 0 12px; border-bottom: 1px solid var(--border); padding-bottom: 6px; }}
  .meta-line {{ color: var(--muted); font-size: 12px; margin-bottom: 24px; }}
  .grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 12px; margin: 16px 0 28px; }}
  .card {{ background: var(--bg2); border: 1px solid var(--border); border-radius: 8px; padding: 16px; text-align: center; }}
  .card .num {{ font-size: 2.4em; font-weight: 700; line-height: 1; }}
  .card .lbl {{ font-size: 11px; color: var(--muted); margin-top: 4px; text-transform: uppercase; letter-spacing: .5px; }}
  .score-card .num {{ color: {score_color}; }}
  table {{ width: 100%; border-collapse: collapse; background: var(--bg2); border-radius: 8px; overflow: hidden; margin-bottom: 24px; }}
  th {{ background: var(--bg3); color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .5px; padding: 10px 12px; text-align: left; }}
  td {{ padding: 10px 12px; border-top: 1px solid var(--border); vertical-align: top; }}
  .finding-row:hover td {{ background: var(--bg3); cursor: pointer; }}
  .badge {{ display: inline-block; font-size: 11px; font-weight: 700; padding: 2px 8px; border-radius: 4px; color: #000; white-space: nowrap; }}
  .title-cell {{ font-weight: 500; max-width: 340px; }}
  .loc a {{ color: var(--code); text-decoration: none; font-size: 12px; word-break: break-all; }}
  code {{ background: var(--bg3); color: var(--code); padding: 1px 5px; border-radius: 3px; font-size: 12px; }}
  .detail-row td {{ padding: 0; }}
  .detail-box {{ background: var(--bg3); border-left: 3px solid var(--accent); padding: 16px; }}
  .detail-section {{ margin-bottom: 12px; }}
  .detail-section b {{ display: block; color: var(--muted); font-size: 11px; text-transform: uppercase; letter-spacing: .5px; margin-bottom: 4px; }}
  pre {{ background: var(--bg); color: #ccc; padding: 10px; border-radius: 4px; overflow-x: auto; font-size: 12px; white-space: pre-wrap; word-break: break-all; }}
  .meta {{ display: flex; flex-wrap: wrap; gap: 16px; font-size: 12px; color: var(--muted); }}
  .bar-row {{ display: flex; align-items: center; gap: 10px; margin-bottom: 8px; }}
  .bar-label {{ width: 120px; font-size: 12px; font-weight: 600; }}
  .bar-track {{ flex: 1; height: 12px; background: var(--bg3); border-radius: 6px; overflow: hidden; }}
  .bar-fill {{ height: 100%; border-radius: 6px; transition: width .4s ease; }}
  .bar-count {{ width: 28px; text-align: right; font-size: 12px; color: var(--muted); }}
  .filter-row {{ display: flex; gap: 8px; margin-bottom: 12px; flex-wrap: wrap; }}
  .filter-btn {{ background: var(--bg2); border: 1px solid var(--border); color: var(--text); padding: 4px 12px; border-radius: 4px; cursor: pointer; font-size: 12px; }}
  .filter-btn.active, .filter-btn:hover {{ border-color: var(--accent); color: var(--accent); }}
  .two-col {{ display: grid; grid-template-columns: 1fr 1fr; gap: 20px; }}
  @media(max-width:700px){{ .two-col{{ grid-template-columns: 1fr; }} }}
</style>
</head>
<body>
<h1>🛡️ VibeHacking Pentest Report</h1>
<p class="meta-line">Generated: {generated} &nbsp;|&nbsp; Source: {_esc(source_path)} &nbsp;|&nbsp; Total findings: {total} &nbsp;|&nbsp; Displayed (deduped): {len(display_findings)}</p>

<div class="grid">
  <div class="card score-card"><div class="num">{score}</div><div class="lbl">Resilience Score / 100</div></div>
  <div class="card"><div class="num" style="color:{SEV_COLOR['critical']}">{counts['critical']}</div><div class="lbl">Critical</div></div>
  <div class="card"><div class="num" style="color:{SEV_COLOR['high']}">{counts['high']}</div><div class="lbl">High</div></div>
  <div class="card"><div class="num" style="color:{SEV_COLOR['medium']}">{counts['medium']}</div><div class="lbl">Medium</div></div>
  <div class="card"><div class="num" style="color:{SEV_COLOR['low']}">{counts['low']}</div><div class="lbl">Low</div></div>
  <div class="card"><div class="num" style="color:{SEV_COLOR['info']}">{counts['info']}</div><div class="lbl">Info</div></div>
</div>

<div class="two-col">
  <div>
    <h2>Severity Distribution</h2>
    {sev_bars}
  </div>
  <div>
    <h2>By OWASP Category</h2>
    <table><tr><th>Category</th><th>#</th></tr>{owasp_rows}</table>
  </div>
</div>

<h2>By Tool</h2>
<table><tr><th>Tool</th><th>#</th></tr>{tool_rows}</table>

<h2>Findings</h2>
<div class="filter-row">
  <button class="filter-btn active" onclick="filter('all')">All ({len(display_findings)})</button>
  <button class="filter-btn" onclick="filter('critical')" style="color:{SEV_COLOR['critical']}">Critical ({counts['critical']})</button>
  <button class="filter-btn" onclick="filter('high')" style="color:{SEV_COLOR['high']}">High ({counts['high']})</button>
  <button class="filter-btn" onclick="filter('medium')" style="color:{SEV_COLOR['medium']}">Medium ({counts['medium']})</button>
  <button class="filter-btn" onclick="filter('low')" style="color:{SEV_COLOR['low']}">Low ({counts['low']})</button>
</div>

<table id="findings-table">
  <tr><th>Severity</th><th>Title (click to expand)</th><th>Tool</th><th>CWE</th><th>Location</th><th>Date</th></tr>
  {rows_html}
</table>

<script>
function toggle(i) {{
  var r = document.getElementById('detail-'+i);
  r.style.display = r.style.display === 'none' ? 'table-row' : 'none';
}}
function filter(sev) {{
  document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
  event.target.classList.add('active');
  document.querySelectorAll('.finding-row').forEach(function(row) {{
    var show = sev === 'all' || row.dataset.sev === sev;
    row.style.display = show ? '' : 'none';
    var detail = row.nextElementSibling;
    if (!show && detail) detail.style.display = 'none';
  }});
}}
</script>
</body>
</html>"""
    return html


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="chain_report — VibeHacking HTML Pentest Report Generator"
    )
    parser.add_argument("--findings", default=DEFAULT_FINDINGS,
                        help=f"Path to findings.jsonl (default: {DEFAULT_FINDINGS})")
    parser.add_argument("--out", default=DEFAULT_OUT,
                        help=f"Output HTML path (default: {DEFAULT_OUT})")
    parser.add_argument("--open", action="store_true", dest="open_browser",
                        help="Open the report in your browser after generating")
    parser.add_argument("-v", "--version", action="version", version="chain_report 1.0.0")
    args = parser.parse_args(argv)

    findings = _load_findings(args.findings)
    if not findings:
        print(f"[*] No findings in {args.findings} — report will be empty.")

    os.makedirs(os.path.dirname(os.path.abspath(args.out)), exist_ok=True)
    html = _build_html(findings, args.findings)
    with open(args.out, "w", encoding="utf-8") as fh:
        fh.write(html)

    counts = _severity_counts(findings)
    print(f"[+] Report saved: {args.out}")
    print(f"[+] {len(findings)} finding(s) — Critical:{counts['critical']} High:{counts['high']} Medium:{counts['medium']} Low:{counts['low']}")

    if args.open_browser:
        webbrowser.open(f"file://{os.path.abspath(args.out)}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
