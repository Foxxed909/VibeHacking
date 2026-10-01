#!/usr/bin/env python3
"""
live_dashboard.py v2.0 — VibeAgent & BreakAgent Autonomous AI Security Platform + Live Command Center.

Binds to 0.0.0.0:8080 by default for live browser preview compatibility.
Provides:
  - pwn.ai-inspired Autonomous AI Pentesting & App-Breaking Platform
  - Mandatory Pre-Run Gate: Target App URL + 'I AM AUTHORIZED TO TEST THIS TARGET'
  - Visual Hierarchy:
      App (Target URL)
       ├── > VibeAgent  (Autonomous AI Recon, Full Surface Scan & Bug-Chain Discovery)
       └── > BreakAgent (Breaking Category: Bot/WAF/Auth Bypass, Exploit Proof & Stress/Break Engine)
  - Live Streaming Thread Viewer (/api/threads, /api/threads/<id>, POST /api/threads/start)
  - Free OpenRouter Model Selector (Ling 3.0 Flash Fin/Sante/VL, Laguna S 2.1, Laguna XS 2.1)
  - Real-time Findings, Attack Surface & PoC Inspector (/api/state)
"""
import argparse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import re
import subprocess
import sys
import tempfile
import time
import hmac
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from privacy_guard import sanitize_text
from vibe_agent import (
    FREE_MODEL_CATALOG,
    VibeAgentPlatform,
    get_thread_by_id,
    list_all_threads,
    load_openrouter_api_key,
    verify_authorization_phrase,
)

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
LOGS_DIR = os.environ.get("VIBE_LOG_DIR") or os.path.join(_ROOT, "logs")
FINDINGS_FILE = os.environ.get("VIBE_FINDINGS_FILE") or os.path.join(LOGS_DIR, "findings.jsonl")
SURFACE_FILE = os.environ.get("VIBE_SURFACE_FILE") or os.path.join(LOGS_DIR, "attack_surface.json")
POC_FILE = os.environ.get("VIBE_POC_FILE") or os.path.join(LOGS_DIR, "pocs.json")
HYPERION_JSON = os.environ.get("VIBE_HYPERION_FILE") or os.path.join(LOGS_DIR, "hyperion_last.json")

_PLATFORM = VibeAgentPlatform()

# Defensive-only tool bridge for trusted server-to-server callers such as the
# standalone VibeAgent product. Deliberately excludes bypass/forging/load tools.
REMOTE_AUDIT_TOOLS = {
    "cloud_scout": {"script": "cloud_scout.py"},
    "ash": {"script": "ash.py"},
    "spider": {"script": "spider.py"},
    "openapi_scout": {"script": "openapi_scout.py"},
    "vibe_headers": {"script": "vibe_headers.py"},
    "corscan": {"script": "corscan.py"},
    "phantom": {"script": "phantom.py"},
    "leep": {"script": "leep.py"},
    "env_probe": {"script": "env_probe.py"},
    "ghost": {"script": "ghost.py"},
    "api_finder": {"script": "api_finder.py"},
    "senoria": {"script": "senoria.py"},
}
_REMOTE_TOOL_TIMEOUT = 45
_REMOTE_OUTPUT_LIMIT = 96 * 1024

_SECRET_ASSIGN_RE = re.compile(
    r"(?im)\\b([A-Z0-9_]*(?:KEY|TOKEN|SECRET|PASSWORD|PASS|PWD)[A-Z0-9_]*)"
    r"\\s*[:=]\\s*([^\\s,;]+)"
)
_CONN_SECRET_RE = re.compile(
    r"(?im)\\b(DATABASE_URL|REDIS_URL|MONGODB_URI)\\s*[:=]\\s*([^\\s,;]+)"
)
_JWT_OUT_RE = re.compile(r"\\beyJ[A-Za-z0-9_-]{8,}\\.eyJ[A-Za-z0-9_-]{8,}\\.[A-Za-z0-9_-]*\\b")
_API_KEY_OUT_RE = re.compile(r"\\b(?:sk-proj-[A-Za-z0-9_-]{12,}|sk-[A-Za-z0-9_-]{12,}|AIza[A-Za-z0-9_-]{20,})\\b")
_PRIVATE_KEY_RE = re.compile(
    r"-----BEGIN [^-]*PRIVATE KEY-----.*?-----END [^-]*PRIVATE KEY-----",
    re.IGNORECASE | re.DOTALL,
)
_AUTH_VALUE_RE = re.compile(
    r"(?im)\\b(authorization|cookie|set-cookie|x-api-key)\\s*[:=]\\s*[^\\r\\n]+"
)
_PEEK_RE = re.compile(r"(?im)^.*\\bPeek:\\s*.*$")


def _sanitize_remote_tool_output(value):
    text = "" if value is None else str(value)
    text = _PEEK_RE.sub("Peek: <redacted sensitive preview>", text)
    text = _PRIVATE_KEY_RE.sub("<private-key-redacted>", text)
    text = _AUTH_VALUE_RE.sub(lambda m: f"{m.group(1)}=<redacted>", text)
    text = _SECRET_ASSIGN_RE.sub(lambda m: f"{m.group(1)}=<redacted>", text)
    text = _CONN_SECRET_RE.sub(lambda m: f"{m.group(1)}=<redacted>", text)
    text = _JWT_OUT_RE.sub("<jwt-redacted>", text)
    text = _API_KEY_OUT_RE.sub("<api-key-redacted>", text)
    return text[:_REMOTE_OUTPUT_LIMIT]


def _remote_tool_command(tool_name, url, args=None):
    spec = REMOTE_AUDIT_TOOLS.get(tool_name)
    if not spec:
        raise ValueError("Tool is not available through the remote audit bridge.")
    script = os.path.join(os.path.dirname(os.path.abspath(__file__)), spec["script"])
    cmd = [sys.executable, script, "--url", url]
    args = args or {}
    if tool_name == "spider":
        try:
            depth = int(args.get("depth", 1))
        except (TypeError, ValueError):
            depth = 1
        cmd.extend(["--depth", str(max(1, min(depth, 2)))])
    elif tool_name == "senoria":
        # Keep remote secret scanning deliberately bounded.
        cmd.extend(["--instances", "1", "--workers", "4", "--max-pages", "24", "--timeout", "6"])
    return cmd


def _run_remote_audit_tool(tool_name, url, args=None):
    cmd = _remote_tool_command(tool_name, url, args=args)
    with tempfile.TemporaryDirectory(prefix="vibehacking-remote-") as tmp:
        logs_dir = os.path.join(tmp, "logs")
        findings_file = os.path.join(logs_dir, "findings.jsonl")
        env = os.environ.copy()
        env.update(
            {
                "VIBE_LOG_DIR": logs_dir,
                "VIBE_FINDINGS_FILE": findings_file,
                "VIBE_SESSION_FILE": os.path.join(tmp, "session.json"),
                "VIBE_SURFACE_FILE": os.path.join(tmp, "attack_surface.json"),
                "VIBE_POC_FILE": os.path.join(tmp, "pocs.json"),
                "VIBE_HYPERION_FILE": os.path.join(tmp, "hyperion.json"),
            }
        )
        proc = subprocess.run(
            cmd,
            cwd=_ROOT,
            env=env,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=_REMOTE_TOOL_TIMEOUT,
        )

        findings = []
        if os.path.isfile(findings_file):
            try:
                with open(findings_file, "r", encoding="utf-8") as fh:
                    for line in fh:
                        if len(findings) >= 50:
                            break
                        try:
                            item = json.loads(line)
                        except Exception:
                            continue
                        if not isinstance(item, dict):
                            continue
                        clean = {}
                        for key, value in item.items():
                            clean[key] = (
                                _sanitize_remote_tool_output(value)
                                if isinstance(value, str)
                                else value
                            )
                        findings.append(clean)
            except OSError:
                pass

    return {
        "ok": proc.returncode == 0,
        "tool": tool_name,
        "url": url,
        "returncode": proc.returncode,
        "stdout": _sanitize_remote_tool_output(proc.stdout),
        "stderr": _sanitize_remote_tool_output(proc.stderr),
        "findings": findings,
    }


def load_dashboard_state():
    findings = []
    if os.path.isfile(FINDINGS_FILE):
        try:
            with open(FINDINGS_FILE, "r", encoding="utf-8") as fh:
                for line in fh:
                    line = line.strip()
                    if line:
                        try:
                            findings.append(json.loads(line))
                        except Exception:
                            pass
        except OSError:
            pass

    surface = {}
    if os.path.isfile(SURFACE_FILE):
        try:
            with open(SURFACE_FILE, "r", encoding="utf-8") as fh:
                surface = json.load(fh)
        except Exception:
            pass

    pocs = []
    if os.path.isfile(POC_FILE):
        try:
            with open(POC_FILE, "r", encoding="utf-8") as fh:
                data = json.load(fh)
                pocs = data.get("pocs", [])
        except Exception:
            pass

    hyperion = {}
    if os.path.isfile(HYPERION_JSON):
        try:
            with open(HYPERION_JSON, "r", encoding="utf-8") as fh:
                hyperion = json.load(fh)
        except Exception:
            pass

    counts = {"CRITICAL": 0, "HACK": 0, "WARN": 0, "PASS": 0, "INFO": 0}
    by_tool = {}
    for f in findings:
        lvl = str(f.get("level", "INFO")).upper()
        counts[lvl] = counts.get(lvl, 0) + 1
        t = f.get("tool", "Unknown")
        by_tool[t] = by_tool.get(t, 0) + 1

    threads = list_all_threads()
    has_key = bool(load_openrouter_api_key())

    return {
        "generated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        "openrouter_configured": has_key,
        "models": FREE_MODEL_CATALOG,
        "threads": threads[:25],
        "counts": counts,
        "total_findings": len(findings),
        "by_tool": by_tool,
        "findings": list(reversed(findings[-100:])),
        "surface": {
            "endpoints": surface.get("endpoints", [])[:50],
            "params": surface.get("params", [])[:50],
            "jwts_count": len(surface.get("jwts", [])),
            "leaked_keys_count": len(surface.get("leaked_keys", [])),
            "cloud_targets": surface.get("cloud_targets", {}),
            "agent_profile": {
                "zero_credential_mode": surface.get("agent_profile", {}).get("zero_credential_mode", True),
                "user_agent": surface.get("agent_profile", {}).get("user_agent", ""),
                "cookies_count": len(surface.get("agent_profile", {}).get("cookies", {})),
                "bypass_headers_count": len(surface.get("agent_profile", {}).get("bypass_headers", {})),
            },
        },
        "pocs": pocs[:30],
        "hyperion": hyperion,
    }


collect_dashboard_state = load_dashboard_state


DASHBOARD_HTML = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>VibeAgent & BreakAgent — Autonomous AI Offensive Security Platform</title>
<style>
  :root {
    --bg: #070a12;
    --panel: #0f1523;
    --panel2: #151d30;
    --border: #24314d;
    --text: #e2e8f0;
    --muted: #94a3b8;
    --crit: #ef4444;
    --hack: #f97316;
    --warn: #eab308;
    --pass: #22c55e;
    --accent: #38bdf8;
    --purple: #a855f7;
  }
  * { box-sizing: border-box; }
  body {
    margin: 0;
    font-family: ui-sans-serif, system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, monospace;
    background: radial-gradient(circle at top right, #131c33 0%, var(--bg) 65%);
    color: var(--text);
    padding: 20px 26px;
  }
  header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    border-bottom: 1px solid var(--border);
    padding-bottom: 14px;
    margin-bottom: 20px;
    flex-wrap: wrap;
    gap: 12px;
  }
  .brand h1 {
    margin: 0;
    font-size: 1.4rem;
    letter-spacing: 0.03em;
    color: #fff;
  }
  .brand p {
    margin: 4px 0 0;
    font-size: 0.84rem;
    color: var(--muted);
  }
  .badge-row {
    display: flex;
    gap: 8px;
    flex-wrap: wrap;
  }
  .pill {
    background: var(--panel2);
    border: 1px solid var(--border);
    padding: 6px 12px;
    border-radius: 999px;
    font-size: 0.76rem;
    color: var(--accent);
    font-weight: 600;
  }
  .pill.green { color: var(--pass); border-color: rgba(34,197,94,0.4); }
  .pill.purple { color: #c084fc; border-color: rgba(168,85,247,0.4); }

  /* Launchpad Card */
  .launchpad {
    background: linear-gradient(145deg, #11192c 0%, #0c1220 100%);
    border: 1px solid #2e4166;
    border-radius: 12px;
    padding: 18px 20px;
    margin-bottom: 20px;
    box-shadow: 0 10px 30px rgba(0,0,0,0.35);
  }
  .launchpad-header {
    display: flex;
    justify-content: space-between;
    align-items: center;
    margin-bottom: 14px;
    flex-wrap: wrap;
    gap: 10px;
  }
  .launchpad-header h2 {
    margin: 0;
    font-size: 1.05rem;
    color: #fff;
  }
  .tree-preview {
    font-family: monospace;
    font-size: 0.78rem;
    background: #070b14;
    border: 1px solid var(--border);
    padding: 8px 12px;
    border-radius: 8px;
    color: #93c5fd;
    line-height: 1.45;
  }
  .form-grid {
    display: grid;
    grid-template-columns: 1.3fr 1.1fr 1.3fr;
    gap: 12px;
    margin-bottom: 14px;
  }
  @media (max-width: 980px) {
    .form-grid { grid-template-columns: 1fr; }
  }
  .field label {
    display: flex;
    justify-content: space-between;
    font-size: 0.75rem;
    text-transform: uppercase;
    letter-spacing: 0.05em;
    color: var(--muted);
    margin-bottom: 6px;
    font-weight: 600;
  }
  .field input, .field select {
    width: 100%;
    background: #080d18;
    border: 1px solid var(--border);
    color: #fff;
    padding: 10px 12px;
    border-radius: 8px;
    font-size: 0.85rem;
    font-family: monospace;
  }
  .field input:focus, .field select:focus {
    outline: none;
    border-color: var(--accent);
  }
  .fill-link {
    color: var(--accent);
    cursor: pointer;
    text-decoration: underline;
    text-transform: none;
  }
  .btn-row {
    display: flex;
    gap: 10px;
    align-items: center;
    flex-wrap: wrap;
  }
  .btn {
    border: none;
    padding: 10px 16px;
    border-radius: 8px;
    font-weight: 700;
    font-size: 0.83rem;
    cursor: pointer;
    transition: transform 0.1s ease, opacity 0.15s ease;
  }
  .btn:hover { opacity: 0.92; transform: translateY(-1px); }
  .btn:disabled { cursor: not-allowed; opacity: 0.48; transform: none; }
  .btn-vibe { background: #0284c7; color: #fff; }
  .btn-break { background: #dc2626; color: #fff; }
  .btn-both { background: linear-gradient(90deg, #0284c7, #9333ea, #dc2626); color: #fff; }
  #launch-msg {
    font-size: 0.82rem;
    margin-left: 8px;
  }

  /* Two-column Thread Hierarchy + Live Thread Stream */
  .workspace-grid {
    display: grid;
    grid-template-columns: 380px 1fr;
    gap: 16px;
    margin-bottom: 20px;
  }
  @media (max-width: 1024px) {
    .workspace-grid { grid-template-columns: 1fr; }
  }
  .panel {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 15px;
    max-height: 540px;
    overflow-y: auto;
  }
  .panel h2 {
    margin: 0 0 12px;
    font-size: 0.95rem;
    color: #fff;
    border-bottom: 1px solid var(--border);
    padding-bottom: 8px;
    display: flex;
    justify-content: space-between;
    align-items: center;
  }
  .app-group {
    background: #0a101d;
    border: 1px solid var(--border);
    border-radius: 8px;
    padding: 10px;
    margin-bottom: 10px;
  }
  .app-title {
    font-family: monospace;
    font-size: 0.83rem;
    font-weight: 700;
    color: var(--accent);
    margin-bottom: 6px;
    word-break: break-all;
  }
  .thread-item {
    font-family: monospace;
    font-size: 0.78rem;
    padding: 8px 10px;
    border-left: 2px solid var(--border);
    margin-left: 8px;
    margin-top: 6px;
    background: var(--panel2);
    border-radius: 0 6px 6px 0;
    cursor: pointer;
    transition: border-color 0.15s;
  }
  .thread-item:hover, .thread-item.active {
    border-left-color: var(--accent);
    background: #1c2740;
  }
  .thread-item.break-agent { border-left-color: var(--crit); }
  .status-dot {
    display: inline-block;
    width: 8px;
    height: 8px;
    border-radius: 50%;
    margin-right: 5px;
  }
  .status-running { background: #38bdf8; box-shadow: 0 0 8px #38bdf8; }
  .status-completed { background: #22c55e; }

  .evt-card {
    background: #0a101d;
    border: 1px solid var(--border);
    border-left: 3px solid var(--accent);
    border-radius: 6px;
    padding: 10px 12px;
    margin-bottom: 8px;
    font-size: 0.81rem;
  }
  .evt-card.thought { border-left-color: #a855f7; }
  .evt-card.break { border-left-color: #ef4444; background: rgba(239,68,68,0.08); }
  .evt-card.verdict { border-left-color: #22c55e; background: rgba(34,197,94,0.08); }
  .evt-head {
    display: flex;
    justify-content: space-between;
    font-size: 0.73rem;
    color: var(--muted);
    margin-bottom: 4px;
  }
  .evt-title {
    font-weight: 700;
    color: #fff;
    margin-bottom: 4px;
  }
  .evt-detail {
    font-family: monospace;
    font-size: 0.75rem;
    color: #cbd5e1;
    white-space: pre-wrap;
    word-break: break-word;
    margin: 0;
  }

  /* KPI & Findings Grid */
  .kpi-grid {
    display: grid;
    grid-template-columns: repeat(auto-fit, minmax(155px, 1fr));
    gap: 12px;
    margin-bottom: 20px;
  }
  .kpi {
    background: var(--panel);
    border: 1px solid var(--border);
    border-radius: 10px;
    padding: 12px 14px;
  }
  .kpi .label { font-size: 0.72rem; color: var(--muted); text-transform: uppercase; }
  .kpi .val { font-size: 1.55rem; font-weight: 700; margin-top: 4px; }
  .val.crit { color: var(--crit); }
  .val.hack { color: var(--hack); }
  .val.warn { color: var(--warn); }
  .val.pass { color: var(--pass); }

  table { width: 100%; border-collapse: collapse; font-size: 0.8rem; }
  th, td { text-align: left; padding: 7px 6px; border-bottom: 1px solid #1e293b; vertical-align: top; }
  th { color: var(--muted); font-weight: 600; }
  .tag {
    display: inline-block;
    padding: 2px 7px;
    border-radius: 4px;
    font-size: 0.68rem;
    font-weight: 700;
  }
  .tag.CRITICAL { background: rgba(239,68,68,0.2); color: var(--crit); }
  .tag.HACK { background: rgba(249,115,22,0.2); color: var(--hack); }
  .tag.WARN { background: rgba(234,179,8,0.2); color: var(--warn); }
  .tag.PASS { background: rgba(34,197,94,0.2); color: var(--pass); }
</style>
</head>
<body>
  <header>
    <div class="brand">
      <h1>⚡ VibeAgent & BreakAgent — Autonomous AI Breach & Security Platform</h1>
      <p>Inspired by pwn.ai ("Exploits, not alerts") • Powered by Free OpenRouter Models • Zero-Credential Black-Box Attacker Mode</p>
    </div>
    <div class="badge-row">
      <div class="pill green" id="or-status">OpenRouter Key: Checking...</div>
      <div class="pill purple">Models: Ling 3.0 Flash Fin/Sante • Laguna S/XS 2.1 ($0/M)</div>
      <div class="pill" id="clock-pill">Live Stream</div>
    </div>
  </header>

  <!-- Pre-Run Authorization & App Launchpad -->
  <section class="launchpad">
    <div class="launchpad-header">
      <div>
        <h2>🚀 Launch Autonomous App Thread (Mandatory Authorization Gate)</h2>
        <div style="font-size:0.79rem;color:var(--muted);margin-top:3px;">
          Enter your Target App URL and sign the authorization statement before spawning a live <b>VibeAgent</b> or <b>BreakAgent</b> thread.
        </div>
      </div>
      <div class="tree-preview">
        App (Target URL)<br>
        &nbsp;├── &gt; <b>VibeAgent</b> &nbsp;(Autonomous Recon, Surface Map &amp; Bug-Chaining)<br>
        &nbsp;└── &gt; <b>BreakAgent</b> (Break Bot Gates, WAF/Auth Bypass, PoC &amp; Stress)
      </div>
    </div>

    <div class="form-grid">
      <div class="field">
        <label><span>1. Target App URL</span><span>Required</span></label>
        <input id="app-url" type="text" value="http://127.0.0.1:3456" placeholder="https://your-app.vercel.app or http://127.0.0.1:3456">
      </div>
      <div class="field">
        <label><span>2. Free OpenRouter Model ($0/M)</span><span>No-Refusal Prompt</span></label>
        <select id="model-select">
          <option value="laguna-s-2.1">Poolside Laguna S 2.1 (Free • 118B-A8B MoE • 262K)</option>
          <option value="laguna-xs-2.1">Poolside Laguna XS 2.1 (Free • 33B-A3B MoE • 256K)</option>
          <option value="ling-3.0-flash-fin">InclusionAI Ling 3.0 Flash Fin (Free • 124B MoE • 262K)</option>
          <option value="ling-3.0-flash-sante">InclusionAI Ling 3.0 Flash Sante (Free • 124B MoE • 262K)</option>
          <option value="ling-3.0-flash">InclusionAI Ling 3.0 Flash VL (Free • 124B MoE • 262K)</option>
          <option value="lfm-2.5">LiquidAI LFM 2.5 2.6B (Free • 65K)</option>
          <option value="openrouter-free">OpenRouter Auto-Free Router ($0/M)</option>
        </select>
      </div>
      <div class="field">
        <label>
          <span>3. Mandatory Authorization Statement</span>
          <span class="fill-link" onclick="fillAuth()">[Click to Fill]</span>
        </label>
        <input id="auth-input" type="text" placeholder="Type: I AM AUTHORIZED TO TEST THIS TARGET">
      </div>
    </div>

    <div class="btn-row">
      <button class="btn btn-vibe launch-button" onclick="startAgent('VibeAgent')">🔍 Launch VibeAgent Thread</button>
      <button class="btn btn-break launch-button" onclick="startAgent('BreakAgent')">💥 Launch BreakAgent Thread (Break App)</button>
      <button class="btn btn-both launch-button" onclick="startAgent('both')">⚡ Launch Both Parallel Threads (VibeAgent + BreakAgent)</button>
      <span id="launch-msg"></span>
    </div>
  </section>

  <!-- Live Hierarchy & Streaming Thread Inspector -->
  <div class="workspace-grid">
    <div class="panel">
      <h2>
        <span>🌳 App &rarr; Agent Threads</span>
        <span style="font-size:0.74rem;color:var(--muted);" id="thread-count">0 threads</span>
      </h2>
      <div id="hierarchy-tree">No threads launched yet. Use the launchpad above to start a VibeAgent or BreakAgent thread.</div>
    </div>

    <div class="panel">
      <h2>
        <span id="active-thread-title">📡 Live Thread Stream</span>
        <span style="font-size:0.75rem;color:var(--accent);" id="active-thread-meta">Select or launch a thread</span>
      </h2>
      <div id="thread-events">
        <div style="color:var(--muted);font-size:0.83rem;">
          When you launch a <b>VibeAgent</b> or <b>BreakAgent</b> run, its real-time AI thoughts, tool dispatches, and confirmed exploit proofs stream here automatically.
        </div>
      </div>
    </div>
  </div>

  <!-- Global Telemetry KPIs -->
  <div class="kpi-grid">
    <div class="kpi"><div class="label">Critical Breaches</div><div class="val crit" id="k-crit">0</div></div>
    <div class="kpi"><div class="label">Confirmed Exploits</div><div class="val hack" id="k-hack">0</div></div>
    <div class="kpi"><div class="label">Warnings</div><div class="val warn" id="k-warn">0</div></div>
    <div class="kpi"><div class="label">Passed Checks</div><div class="val pass" id="k-pass">0</div></div>
    <div class="kpi"><div class="label">Discovered Routes</div><div class="val" id="k-eps">0</div></div>
    <div class="kpi"><div class="label">Token Spend (Free Tier)</div><div class="val pass">$0.00</div></div>
  </div>

  <!-- Recent Findings Table -->
  <div class="panel" style="max-height:380px;">
    <h2><span>🛡️ Global Empirical Findings & Confirmed PoCs (logs/findings.jsonl)</span></h2>
    <table>
      <thead><tr><th>Severity</th><th>Module</th><th>CWE / OWASP</th><th>Finding Summary & Evidence</th></tr></thead>
      <tbody id="findings-tbody"></tbody>
    </table>
  </div>

<script>
let selectedThreadId = null;

function esc(s) {
  return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function fillAuth() {
  document.getElementById('auth-input').value = 'I AM AUTHORIZED TO TEST THIS TARGET';
}

let agentCapabilities = {can_launch: true};
async function loadCapabilities() {
  try {
    const r = await fetch('/api/capabilities', {cache: 'no-store'});
    const d = await r.json();
    agentCapabilities = d;
    document.querySelectorAll('.launch-button').forEach(button => {
      button.disabled = !d.can_launch;
    });
    if (!d.can_launch) {
      const msg = document.getElementById('launch-msg');
      msg.style.color = '#eab308';
      msg.textContent = 'ℹ️ ' + (d.message || 'Agent runs are unavailable in this deployment.');
    }
  } catch (e) {}
}

async function startAgent(mode) {
  const url = document.getElementById('app-url').value.trim();
  const model = document.getElementById('model-select').value;
  if (!agentCapabilities.can_launch) {
    const msg = document.getElementById('launch-msg');
    msg.style.color = '#eab308';
    msg.textContent = 'ℹ️ ' + (agentCapabilities.message || 'Agent runs are unavailable in this deployment.');
    return;
  }
  const auth = document.getElementById('auth-input').value.trim();
  const msg = document.getElementById('launch-msg');

  if (!url) {
    msg.style.color = '#ef4444';
    msg.textContent = '⚠️ Please enter a Target App URL first.';
    return;
  }
  if (auth.toUpperCase() !== 'I AM AUTHORIZED TO TEST THIS TARGET' && auth.toUpperCase() !== 'I AM AUTHORIZED TO TEST THIS TARGE') {
    msg.style.color = '#ef4444';
    msg.textContent = '⚠️ Refused: You must type "I AM AUTHORIZED TO TEST THIS TARGET" (or click [Click to Fill]).';
    return;
  }

  msg.style.color = '#38bdf8';
  msg.textContent = 'Launching autonomous thread(s)...';
  try {
    const r = await fetch('/api/threads/start', {
      method: 'POST',
      headers: {'Content-Type': 'application/json'},
      body: JSON.stringify({url, model, auth, mode})
    });
    const d = await r.json();
    if (!r.ok || d.error) {
      msg.style.color = '#ef4444';
      msg.textContent = '⚠️ ' + (d.error || 'Launch failed');
      return;
    }
    msg.style.color = '#22c55e';
    msg.textContent = '✅ Launched ' + d.launched.map(t => t.thread_id + ' (' + t.agent_type + ')').join(', ');
    if (d.launched.length > 0) {
      selectedThreadId = d.launched[0].thread_id;
    }
    await refresh();
  } catch (e) {
    msg.style.color = '#ef4444';
    msg.textContent = '⚠️ Error: ' + e;
  }
}

function renderHierarchy(threads) {
  document.getElementById('thread-count').textContent = threads.length + ' thread(s)';
  if (!threads.length) return;
  if (!selectedThreadId && threads.length > 0) {
    selectedThreadId = threads[0].thread_id;
  }

  // Group by app_url
  const groups = {};
  for (const t of threads) {
    if (!groups[t.app_url]) groups[t.app_url] = [];
    groups[t.app_url].push(t);
  }

  let html = '';
  for (const [appUrl, list] of Object.entries(groups)) {
    html += `<div class="app-group"><div class="app-title">📦 App: ${esc(appUrl)}</div>`;
    list.forEach((t, idx) => {
      const isBreak = t.agent_type === 'BreakAgent';
      const activeCls = t.thread_id === selectedThreadId ? 'active' : '';
      const breakCls = isBreak ? 'break-agent' : '';
      const dotCls = t.status === 'running' ? 'status-running' : 'status-completed';
      const branch = idx === list.length - 1 ? '└──' : '├──';
      const breaksCount = (t.confirmed_breaks || []).length;
      html += `
        <div class="thread-item ${activeCls} ${breakCls}" onclick="selectThread('${esc(t.thread_id)}')">
          <div>${branch} &gt; <b>${esc(t.agent_type)}</b> <span style="color:var(--muted)">#${esc(t.thread_id)}</span></div>
          <div style="margin-top:3px;font-size:0.72rem;color:var(--muted);">
            <span class="status-dot ${dotCls}"></span>${esc(t.status.toUpperCase())} (${t.current_step}/${t.total_steps} • ${esc(t.current_tool)})
            • Breaks: <b style="color:${breaksCount>0?'#ef4444':'#22c55e'}">${breaksCount}</b>
          </div>
          <div style="font-size:0.7rem;color:#93c5fd;margin-top:2px;">Model: ${esc((t.model||{}).id || '')}</div>
        </div>`;
    });
    html += `</div>`;
  }
  document.getElementById('hierarchy-tree').innerHTML = html;
}

function renderSelectedThread(threads) {
  const t = threads.find(x => x.thread_id === selectedThreadId);
  if (!t) return;
  document.getElementById('active-thread-title').innerHTML =
    `📡 Live Thread: <code>${esc(t.app_url)}</code> &rarr; <b>${esc(t.agent_type)}</b> (#${esc(t.thread_id)})`;
  document.getElementById('active-thread-meta').textContent =
    `${t.status.toUpperCase()} • Step ${t.current_step}/${t.total_steps} • Score: ${t.resilience_score}/100`;

  const evts = (t.events || []).slice().reverse();
  document.getElementById('thread-events').innerHTML = evts.map(e => `
    <div class="evt-card ${esc(e.kind)}">
      <div class="evt-head">
        <span>[${esc(e.timestamp)}] ${esc(e.kind.toUpperCase())} ${e.tool ? '• Tool: ' + esc(e.tool) : ''}</span>
        <span>${esc(e.model || '')}</span>
      </div>
      <div class="evt-title">${esc(e.title)}</div>
      ${e.detail ? `<pre class="evt-detail">${esc(e.detail)}</pre>` : ''}
    </div>
  `).join('');
}

function selectThread(id) {
  selectedThreadId = id;
  refresh();
}

async function refresh() {
  try {
    const r = await fetch('/api/state', {cache: 'no-store'});
    const d = await r.json();
    document.getElementById('clock-pill').textContent = 'Updated: ' + d.generated_at;
    document.getElementById('or-status').textContent = d.openrouter_configured
      ? 'OpenRouter Key: Active (.env loaded)'
      : 'OpenRouter Key: Offline Tactician Mode';
    document.getElementById('k-crit').textContent = d.counts.CRITICAL || 0;
    document.getElementById('k-hack').textContent = d.counts.HACK || 0;
    document.getElementById('k-warn').textContent = d.counts.WARN || 0;
    document.getElementById('k-pass').textContent = d.counts.PASS || 0;
    document.getElementById('k-eps').textContent = (d.surface.endpoints || []).length;

    renderHierarchy(d.threads || []);
    renderSelectedThread(d.threads || []);

    const tb = document.getElementById('findings-tbody');
    tb.innerHTML = (d.findings || []).slice(0, 35).map(f => `
      <tr>
        <td><span class="tag ${esc(f.level)}">${esc(f.level)}</span></td>
        <td><b>${esc(f.tool)}</b></td>
        <td style="color:var(--muted);font-family:monospace;font-size:0.72rem;">${esc(f.cwe || '')}<br>${esc(f.owasp || '')}</td>
        <td>
          <div>${esc(f.message)}</div>
          ${f.detail ? `<div style="color:var(--muted);font-family:monospace;font-size:0.72rem;margin-top:2px;">${esc(f.detail).slice(0,160)}</div>` : ''}
        </td>
      </tr>
    `).join('') || '<tr><td colspan="4" style="color:var(--muted)">No findings recorded yet. Launch a VibeAgent or BreakAgent thread above!</td></tr>';
  } catch (e) {}
}
loadCapabilities();
refresh();
setInterval(refresh, 1500);
</script>
</body>
</html>
"""


class DashboardHandler(BaseHTTPRequestHandler):
    disable_nagle_algorithm = True

    def log_message(self, fmt, *args):
        return

    def _require_worker_token(self):
        required = os.environ.get("VIBE_WORKER_TOKEN", "").strip()
        if not required:
            return False
        supplied = self.headers.get("X-Vibe-Worker-Token", "")
        if hmac.compare_digest(supplied, required):
            return False
        self._send_json(401, {"error": "Worker authentication required."})
        return True

    def _send_json(self, code, payload):
        body = json.dumps(payload, indent=2).encode("utf-8")
        self.send_response(code)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_OPTIONS(self):
        if os.environ.get("VIBE_WORKER_TOKEN", "").strip():
            self._send_json(403, {"error": "Cross-origin requests are disabled for this worker."})
            return
        self.send_response(204)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type")
        self.end_headers()

    def do_GET(self):
        if self._require_worker_token():
            return
        path = urllib.parse.urlsplit(self.path).path
        if path == "/api/capabilities":
            self._send_json(
                200,
                {
                    "deployment_mode": "self-hosted-worker" if os.environ.get("VIBE_WORKER_TOKEN") else "self-hosted",
                    "can_launch": True,
                    "message": "Agent worker is ready.",
                    "tool_endpoint": "/api/tools/run",
                    "remote_tools": sorted(REMOTE_AUDIT_TOOLS),
                },
            )
            return
        if path in ("/api/state", "/api/findings"):
            self._send_json(200, load_dashboard_state())
            return
        if path == "/api/threads":
            self._send_json(200, {"threads": list_all_threads()})
            return
        if path.startswith("/api/threads/"):
            tid = path.split("/api/threads/", 1)[1]
            th = get_thread_by_id(tid)
            if not th:
                self._send_json(404, {"error": "Thread not found"})
            else:
                self._send_json(200, th)
            return

        body = DASHBOARD_HTML.encode("utf-8")
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        if self._require_worker_token():
            return
        path = urllib.parse.urlsplit(self.path).path

        try:
            length = int(self.headers.get("Content-Length", "0") or 0)
        except ValueError:
            self._send_json(400, {"error": "Invalid Content-Length"})
            return
        if length < 0 or length > 16384:
            self._send_json(413, {"error": "Request body exceeds the 16 KB limit."})
            return
        raw = self.rfile.read(length).decode("utf-8", errors="ignore") if length > 0 else "{}"
        try:
            data = json.loads(raw)
        except Exception:
            self._send_json(400, {"error": "Invalid JSON body"})
            return
        if not isinstance(data, dict):
            self._send_json(400, {"error": "JSON body must be an object."})
            return

        url = str(data.get("url", "")).strip()
        auth = str(data.get("auth", "")).strip()
        if not url:
            self._send_json(400, {"error": "Target App URL is required."})
            return
        if "://" not in url:
            host_hint = url.split("/", 1)[0].split(":", 1)[0].lower()
            url = ("http://" if host_hint in ("localhost", "127.0.0.1", "::1") else "https://") + url
        parsed_url = urllib.parse.urlsplit(url)
        if parsed_url.scheme not in ("http", "https") or not parsed_url.hostname or parsed_url.username or parsed_url.password:
            self._send_json(400, {"error": "Target URL must be a valid http:// or https:// URL without embedded credentials."})
            return
        if not verify_authorization_phrase(auth):
            self._send_json(
                403,
                {"error": "Authorization gate rejected: valid authorization attestation required."},
            )
            return

        if path == "/api/tools/run":
            tool_name = str(data.get("tool", "")).strip()
            tool_args = data.get("args") if isinstance(data.get("args"), dict) else {}
            if tool_name not in REMOTE_AUDIT_TOOLS:
                self._send_json(400, {"error": "Tool is not available through the remote audit bridge."})
                return
            try:
                result = _run_remote_audit_tool(tool_name, url, args=tool_args)
                self._send_json(200, result)
            except subprocess.TimeoutExpired:
                self._send_json(504, {"error": "Remote audit tool timed out.", "tool": tool_name})
            except Exception as exc:
                self._send_json(500, {"error": f"Remote audit tool failed: {type(exc).__name__}", "tool": tool_name})
            return

        if path != "/api/threads/start":
            self._send_json(404, {"error": "Unknown endpoint"})
            return

        model = str(data.get("model", "laguna-s-2.1")).strip()
        mode = str(data.get("mode", "VibeAgent")).strip()
        mode_key = mode.lower()
        if mode_key not in ("vibeagent", "vibe", "breakagent", "break", "both"):
            self._send_json(400, {"error": "Mode must be VibeAgent, BreakAgent, or both."})
            return

        agents = ["VibeAgent", "BreakAgent"] if mode_key == "both" else ["BreakAgent"] if mode_key in ("breakagent", "break") else ["VibeAgent"]
        launched = []
        try:
            for ag in agents:
                st = _PLATFORM.start_Thread(
                    app_url=url,
                    agent_type=ag,
                    model_name=model,
                    auth_phrase=auth,
                    background=True,
                )
                launched.append(
                    {
                        "thread_id": st["thread_id"],
                        "agent_type": st["agent_type"],
                        "app_url": st["app_url"],
                        "model": st["model"],
                    }
                )
            self._send_json(200, {"ok": True, "launched": launched})
        except Exception as exc:
            self._send_json(400, {"error": str(exc)})


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="VibeAgent & BreakAgent Platform + Live Web Command Center v2.0"
    )
    parser.add_argument("--host", default="0.0.0.0", help="Bind host (default: 0.0.0.0)")
    parser.add_argument("--port", type=int, default=8080, help="Bind port (default: 8080)")
    parser.add_argument("--dump-json", action="store_true", help="Print JSON state and exit")
    parser.add_argument("-v", "--version", action="version", version="VibeHacking LiveDashboard 2.0.0")
    args = parser.parse_args(argv)

    if args.dump_json:
        print(json.dumps(load_dashboard_state(), indent=2))
        return 0

    server = ThreadingHTTPServer((args.host, args.port), DashboardHandler)
    print(f"[*] VibeAgent & BreakAgent Autonomous Platform listening on http://{args.host}:{args.port}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    sys.exit(main())
