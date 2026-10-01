#!/usr/bin/env python3
"""
live_dashboard.py v1.0 — VibeHacking Live Web Command Center & Cloud/Edge Telemetry UI.

Zero-dependency HTTP/1.1 server bound to 0.0.0.0 that provides a live browser UI for:
  - Launching Zero-Credential Attacker scans (Bot Breaker, Next.js/Vercel RSC Audit,
    Asymmetric Origin-Killer Probe, WAF Evasion Fuzzer, Cloud Scout, Deep Scan)
  - Viewing real-time Hyperion v2.1 HDR latency percentiles, Apdex, & Cloudflare/AWS/Vercel Edge telemetry
  - Inspecting structured CWE/OWASP findings from `logs/findings.jsonl`
"""
import argparse
import http.server
import json
import os
import subprocess
import sys
import threading
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from privacy_guard import sanitize_text
from vibe_core import FRAMEWORK_VERSION

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_RUN_LOCK = threading.Lock()
_LAST_JOB = {"running": False, "tool": "", "target": "", "output": "", "started_at": ""}

ALLOWED_WEB_TOOLS = {
    "bot_breaker": ["TOOLS/bot_breaker.py", "--url"],
    "nextjs_rsc": ["TOOLS/nextjs_rsc_audit.py", "--url"],
    "asymmetric": ["TOOLS/asymmetric_probe.py", "--url"],
    "waf_evade": ["TOOLS/waf_evade.py", "--url"],
    "cloud_scout": ["TOOLS/cloud_scout.py", "--url"],
    "scan": ["vibe.py", "scan"],
}


def collect_dashboard_state():
    log_dir = os.environ.get("VIBE_LOG_DIR") or os.path.join(_ROOT, "logs")
    sess_file = os.environ.get("VIBE_SESSION_FILE") or os.path.join(_ROOT, "vibe_session.json")
    findings_file = os.environ.get("VIBE_FINDINGS_FILE") or os.path.join(log_dir, "findings.jsonl")

    session = {}
    if os.path.isfile(sess_file):
        try:
            with open(sess_file, "r", encoding="utf-8") as fh:
                session = json.load(fh)
        except Exception:
            session = {}

    findings = []
    if os.path.isfile(findings_file):
        try:
            with open(findings_file, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            findings.append(json.loads(line))
                        except Exception:
                            pass
        except Exception:
            pass

    hyperion_metrics = {}
    for candidate in (
        os.path.join(log_dir, "hyperion_metrics.json"),
        os.path.join(log_dir, "vercel_metrics.json"),
        os.path.join(log_dir, "cloudflare_metrics.json"),
    ):
        if os.path.isfile(candidate):
            try:
                with open(candidate, "r", encoding="utf-8") as fh:
                    hyperion_metrics = json.load(fh)
                break
            except Exception:
                pass

    return {
        "version": FRAMEWORK_VERSION,
        "session": session,
        "findings": findings[-100:],
        "hyperion": hyperion_metrics,
        "job": dict(_LAST_JOB),
    }


DASHBOARD_HTML = """<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>VibeHacking Live Command Center</title>
  <style>
    :root {
      --bg: #0b0f17;
      --panel: #131b2e;
      --border: #23314f;
      --text: #e2e8f0;
      --muted: #94a3b8;
      --accent: #38bdf8;
      --crit: #ef4444;
      --high: #f97316;
      --med: #eab308;
      --pass: #22c55e;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0; font-family: ui-sans-serif, system-ui, -apple-system, sans-serif;
      background: var(--bg); color: var(--text); padding: 1.5rem;
    }
    header {
      display: flex; flex-wrap: wrap; justify-content: space-between; align-items: center;
      border-bottom: 1px solid var(--border); padding-bottom: 1rem; margin-bottom: 1.25rem;
    }
    h1 { margin: 0; font-size: 1.4rem; letter-spacing: 0.02em; }
    .badge {
      background: #1e293b; border: 1px solid var(--border); padding: 0.3rem 0.65rem;
      border-radius: 999px; font-size: 0.8rem; color: var(--accent);
    }
    .grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 1rem; margin-bottom: 1.25rem; }
    .card {
      background: var(--panel); border: 1px solid var(--border); border-radius: 0.65rem; padding: 1rem;
    }
    .card h2 { margin-top: 0; font-size: 0.95rem; color: var(--accent); text-transform: uppercase; letter-spacing: 0.05em; }
    .controls { display: flex; flex-wrap: wrap; gap: 0.5rem; margin-top: 0.5rem; }
    input[type="text"] {
      flex: 1; min-width: 240px; padding: 0.55rem 0.75rem; border-radius: 0.4rem;
      border: 1px solid var(--border); background: #090d16; color: var(--text);
    }
    button {
      background: #1e293b; color: var(--text); border: 1px solid var(--border);
      padding: 0.5rem 0.85rem; border-radius: 0.4rem; cursor: pointer; font-weight: 600; font-size: 0.82rem;
    }
    button:hover { border-color: var(--accent); color: var(--accent); }
    table { width: 100%; border-collapse: collapse; font-size: 0.85rem; }
    th, td { text-align: left; padding: 0.55rem; border-bottom: 1px solid var(--border); }
    .sev-critical { color: var(--crit); font-weight: 700; }
    .sev-high { color: var(--high); font-weight: 700; }
    .sev-medium { color: var(--med); font-weight: 700; }
    pre {
      background: #070a10; border: 1px solid var(--border); border-radius: 0.45rem;
      padding: 0.75rem; overflow-x: auto; font-size: 0.8rem; max-height: 240px; color: #cbd5e1;
    }
    .stat-row { display: flex; justify-content: space-between; padding: 0.3rem 0; border-bottom: 1px dashed #1e293b; font-size: 0.86rem; }
  </style>
</head>
<body>
  <header>
    <div>
      <h1>🛡️ VibeHacking Live Command Center</h1>
      <div style="color:var(--muted);font-size:0.85rem;margin-top:0.25rem">
        Zero-Credential Attacker Simulation • Cloudflare / AWS / .vercel.app Edge &amp; Bot-Breaker Suite
      </div>
    </div>
    <span class="badge" id="ver-badge">v1.0.0 • Zero-Key Attacker Mode</span>
  </header>

  <div class="card" style="margin-bottom:1.25rem">
    <h2>🚀 Launch Zero-Credential Attacker Module</h2>
    <div class="controls">
      <input type="text" id="target-input" placeholder="Target URL (e.g. http://127.0.0.1:3456 or https://your-app.vercel.app)" value="http://127.0.0.1:3456">
      <button onclick="runTool('bot_breaker')">🤖 Bot Breaker ('Are You a Robot?')</button>
      <button onclick="runTool('nextjs_rsc')">▲ Next.js / Vercel RSC Audit</button>
      <button onclick="runTool('asymmetric')">⚡ Asymmetric Origin-Killer</button>
      <button onclick="runTool('waf_evade')">🛡️ WAF Evasion Fuzzer</button>
      <button onclick="runTool('cloud_scout')">☁️ Cloud Scout</button>
      <button onclick="runTool('scan')">🔍 Full Deep Scan</button>
    </div>
    <pre id="job-output" style="margin-top:0.75rem">Ready. Select a module above to probe the target.</pre>
  </div>

  <div class="grid">
    <div class="card">
      <h2>🤖 AI-Agent Bot-Breaker &amp; Surface Profile</h2>
      <div id="bot-profile">Loading...</div>
    </div>
    <div class="card">
      <h2>⚡ Asymmetric Bottlenecks (Origin-Killer)</h2>
      <div id="asym-profile">Loading...</div>
    </div>
    <div class="card">
      <h2>📊 Hyperion v2.1 HDR &amp; Cloud Telemetry</h2>
      <div id="hyperion-profile">Loading...</div>
    </div>
  </div>

  <div class="card">
    <h2>🚨 Structured Security Findings (CWE / OWASP)</h2>
    <table>
      <thead>
        <tr><th>Severity</th><th>Tool</th><th>Title</th><th>CWE / OWASP</th><th>Location</th></tr>
      </thead>
      <tbody id="findings-body"></tbody>
    </table>
  </div>

  <script>
    async function refreshState() {
      try {
        const res = await fetch('api/state');
        const st = await res.json();
        const surf = (st.session && st.session.surface) || {};
        const ap = surf.agent_profile || {};

        document.getElementById('bot-profile').innerHTML = ap.winning_strategy ? `
          <div class="stat-row"><span>Gate Detected</span><b>${ap.gate_detected ? ap.gate_vendor : 'None'}</b></div>
          <div class="stat-row"><span>Winning Strategy</span><b style="color:#22c55e">${ap.winning_strategy}</b></div>
          <div class="stat-row"><span>Captured Cookies</span><b>${Object.keys(ap.cookies || {}).length}</b></div>
          <div class="stat-row"><span>Unchallenged API Side-Doors</span><b>${(ap.unchallenged_routes || []).length}</b></div>
          <div class="stat-row"><span>Shadow Origins</span><b>${(ap.shadow_origins || []).join(', ') || 'None'}</b></div>
        ` : '<div style="color:var(--muted)">Run Bot Breaker to fingerprint &amp; bypass bot gates.</div>';

        const asym = surf.asymmetric_targets || [];
        document.getElementById('asym-profile').innerHTML = asym.length ? asym.slice(0, 5).map(r => `
          <div class="stat-row"><span>${r.vector}</span><b>${r.ms}ms (${r.amplification_x}x)</b></div>
        `).join('') : '<div style="color:var(--muted)">Run Asymmetric Origin-Killer to rank high-cost routes.</div>';

        const hyp = st.hyperion || {};
        const lat = hyp.latency_ms || {};
        document.getElementById('hyperion-profile').innerHTML = hyp.total_requests ? `
          <div class="stat-row"><span>Throughput / Requests</span><b>${hyp.average_rps} RPS (${hyp.total_requests})</b></div>
          <div class="stat-row"><span>Apdex / Error Rate</span><b>${hyp.apdex_score} / ${hyp.error_rate_pct}%</b></div>
          <div class="stat-row"><span>HDR p50 / p95 / p99</span><b>${lat.p50}ms / ${lat.p95}ms / ${lat.p99}ms</b></div>
          <div class="stat-row"><span>Cloud Providers</span><b>${(hyp.cloud_providers || []).join(', ')}</b></div>
          <div class="stat-row"><span>Edge Cache HIT %</span><b>${(hyp.edge_cache && hyp.edge_cache.hit_rate_pct) || 0}%</b></div>
        ` : '<div style="color:var(--muted)">No Hyperion telemetry file in logs/ yet.</div>';

        if (st.job && (st.job.output || st.job.running)) {
          document.getElementById('job-output').textContent =
            (st.job.running ? `[RUNNING ${st.job.tool} on ${st.job.target}...]\n` : '') + (st.job.output || '');
        }

        const tbody = document.getElementById('findings-body');
        const rows = (st.findings || []).slice().reverse().map(f => {
          const sev = (f.severity || 'info').toLowerCase();
          return `<tr>
            <td class="sev-${sev}">${sev.toUpperCase()}</td>
            <td>${f.tool || ''}</td>
            <td>${f.title || ''}</td>
            <td>${f.cwe || ''} • ${f.owasp || ''}</td>
            <td style="color:var(--muted)">${f.location || ''}</td>
          </tr>`;
        });
        tbody.innerHTML = rows.join('') || '<tr><td colspan="5" style="color:var(--muted)">No findings logged yet.</td></tr>';
      } catch (e) {}
    }

    async function runTool(tool) {
      const target = document.getElementById('target-input').value.trim();
      if (!target) return;
      document.getElementById('job-output').textContent = `Launching ${tool} against ${target}...`;
      await fetch('api/run', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({tool, target})
      });
      setTimeout(refreshState, 400);
    }

    refreshState();
    setInterval(refreshState, 2000);
  </script>
</body>
</html>
"""


class DashboardHandler(http.server.BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    disable_nagle_algorithm = True

    def log_message(self, *args):
        pass

    def _send_bytes(self, status, data, content_type="application/json; charset=utf-8"):
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def do_GET(self):
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path.endswith("/api/state") or parsed.path == "/api/state":
            payload = json.dumps(collect_dashboard_state()).encode("utf-8")
            return self._send_bytes(200, payload)
        return self._send_bytes(200, DASHBOARD_HTML.encode("utf-8"), "text/html; charset=utf-8")

    def do_POST(self):
        parsed = urllib.parse.urlparse(self.path)
        if not (parsed.path.endswith("/api/run") or parsed.path == "/api/run"):
            return self._send_bytes(404, b'{"error":"not_found"}')

        length = int(self.headers.get("Content-Length", "0") or 0)
        raw = self.rfile.read(length) if length > 0 else b"{}"
        try:
            req = json.loads(raw.decode("utf-8", errors="ignore"))
        except Exception:
            req = {}

        tool = str(req.get("tool", "")).strip()
        target = str(req.get("target", "")).strip()
        if tool not in ALLOWED_WEB_TOOLS or not target:
            return self._send_bytes(400, b'{"error":"invalid_tool_or_target"}')

        if _LAST_JOB["running"]:
            return self._send_bytes(409, b'{"error":"job_already_running"}')

        def _worker():
            with _RUN_LOCK:
                _LAST_JOB["running"] = True
                _LAST_JOB["tool"] = tool
                _LAST_JOB["target"] = sanitize_text(target)
                _LAST_JOB["output"] = ""
                _LAST_JOB["started_at"] = time.strftime("%H:%M:%S")
                try:
                    cmd = [sys.executable, *ALLOWED_WEB_TOOLS[tool], target]
                    res = subprocess.run(
                        cmd, cwd=_ROOT, capture_output=True, text=True, timeout=60
                    )
                    _LAST_JOB["output"] = (res.stdout or "") + ("\n" + res.stderr if res.stderr else "")
                except Exception as exc:
                    _LAST_JOB["output"] = f"Error: {exc}"
                finally:
                    _LAST_JOB["running"] = False

        threading.Thread(target=_worker, daemon=True).start()
        return self._send_bytes(202, b'{"started":true}')


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Live Dashboard v1.0 - VibeHacking Web Command Center & Cloud/Edge Telemetry UI"
    )
    parser.add_argument("--host", default="0.0.0.0", help="Bind address (default: 0.0.0.0)")
    parser.add_argument("-p", "--port", type=int, default=8080, help="Port to listen on (default: 8080)")
    parser.add_argument("--dump-json", action="store_true", help="Print current dashboard state JSON and exit")
    parser.add_argument("-v", "--version", action="version", version="Live Dashboard 1.0.0")
    args = parser.parse_args(argv)

    if args.dump_json:
        print(json.dumps(collect_dashboard_state(), indent=2))
        return 0

    srv = http.server.ThreadingHTTPServer((args.host, args.port), DashboardHandler)
    print(f"[*] VibeHacking Live Command Center listening on http://{args.host}:{args.port}")
    sys.stdout.flush()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\n[!] Dashboard stopped.")
    finally:
        srv.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
