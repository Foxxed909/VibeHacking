#!/usr/bin/env python3
"""
claude.py — the VibeHacking autonomous pentest brain.

Claude drives the existing VibeHacking toolset against ONE target you own or are
authorized to test. It picks which audit tool to run next, reads the output,
reasons about it, chains follow-up probes adaptively, records findings with
severity, and writes a report. Recon/audit tools run freely; load/stress tools
are gated behind the same trust + local-host check the rest of the framework uses.

    python claude.py http://127.0.0.1:5500/
    python claude.py https://your-app.example --objective "focus on auth + IDOR"
    VIBE_CLAUDE_MODEL=claude-fable-5 python claude.py http://127.0.0.1:5500/   # max power

Requires:
  * pip install anthropic
  * ANTHROPIC_API_KEY in the environment

Honesty note: to reason about your app, Claude is sent the target URL and the
(capped) stdout of each tool it runs. That data leaves your machine for the
Anthropic API. Run --dry-run to see the plan without any API call.
"""

import argparse
import json
import os
import subprocess
import sys
import time

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR = os.path.join(ROOT_DIR, "TOOLS")
sys.path.insert(0, TOOLS_DIR)
sys.path.insert(0, ROOT_DIR)

# Reuse the framework's gating + phase plan so claude.py can't drift from vibe.py.
import vibe  # noqa: E402  (vibe.py is import-safe: it guards on __main__)
from privacy_guard import sanitize_text  # noqa: E402

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

DEFAULT_MODEL = os.environ.get("VIBE_CLAUDE_MODEL", "claude-opus-4-8")
DEFAULT_EFFORT = os.environ.get("VIBE_CLAUDE_EFFORT", "high")
MAX_TOOL_OUTPUT = 8000          # chars of tool stdout fed back to the model
PER_TOOL_TIMEOUT = 150          # seconds before a single tool run is killed
MAX_TOKENS_PER_TURN = 24000

# Audit tools Claude may choose from — flattened from vibe.ATTACK_PHASES so the
# brain sees exactly the non-destructive kill-chain the `attack` command runs.
# Load/stress tools are deliberately NOT here; they live behind load_test().
AUDIT_TOOLS = []
for _title, _tools in vibe.ATTACK_PHASES:
    for _t in _tools:
        if _t not in AUDIT_TOOLS:
            AUDIT_TOOLS.append(_t)

LOAD_TOOLS = ["storm", "vibe_api", "maelstrom"]

SEVERITIES = ["critical", "high", "medium", "low", "info"]

_SEV_ICON = {
    "critical": "🔴",
    "high": "🟠",
    "medium": "🟡",
    "low": "🟢",
    "info": "🔵",
}


# --------------------------------------------------------------------------- #
# Tool schemas exposed to Claude
# --------------------------------------------------------------------------- #
def build_tools():
    audit_catalog = "\n".join(f"  - {t}" for t in AUDIT_TOOLS)
    return [
        {
            "name": "run_audit_tool",
            "description": (
                "Run ONE non-destructive VibeHacking audit/recon tool against the "
                "fixed target and get its stdout back. You choose WHICH tool; the "
                "target URL is locked at startup and cannot be changed. Call this "
                "when you want to map the surface or probe a specific weakness. "
                "Start with recon (ash, spider, ghost, api_finder), then adapt based "
                "on what you find. Available tools:\n" + audit_catalog
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "tool": {
                        "type": "string",
                        "enum": AUDIT_TOOLS,
                        "description": "Which audit tool to run.",
                    },
                    "rationale": {
                        "type": "string",
                        "description": "One line: why this tool now, given what you know.",
                    },
                },
                "required": ["tool", "rationale"],
            },
        },
        {
            "name": "record_finding",
            "description": (
                "Record a confirmed or strongly-suspected vulnerability. Call this as "
                "soon as a tool's output evidences a real issue — don't wait until the "
                "end. One call per distinct finding."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "severity": {"type": "string", "enum": SEVERITIES},
                    "title": {"type": "string", "description": "Short headline, e.g. 'Missing HSTS header'."},
                    "location": {
                        "type": "string",
                        "description": "Endpoint / parameter / header where it lives.",
                    },
                    "evidence": {
                        "type": "string",
                        "description": "The concrete signal from tool output that proves it.",
                    },
                    "recommendation": {
                        "type": "string",
                        "description": "How to fix it.",
                    },
                },
                "required": ["severity", "title", "evidence"],
            },
        },
        {
            "name": "load_test",
            "description": (
                "Run a load/stress tool (storm, vibe_api, or maelstrom). GATED: only "
                "runs against localhost, private hosts, or a host in the authorized "
                "allowlist. On a public untrusted host this returns an error and runs "
                "nothing — do not retry, just note it and move on. Use only when "
                "rate-limit or capacity behaviour is genuinely in scope."
            ),
            "input_schema": {
                "type": "object",
                "properties": {
                    "tool": {"type": "string", "enum": LOAD_TOOLS},
                    "intensity": {
                        "type": "string",
                        "enum": ["light", "medium"],
                        "description": "light = brief low-rate probe; medium = short moderate burst.",
                    },
                    "rationale": {"type": "string"},
                },
                "required": ["tool", "intensity", "rationale"],
            },
        },
    ]


# --------------------------------------------------------------------------- #
# System prompt
# --------------------------------------------------------------------------- #
def build_system_prompt(url, host, scope_label, objective):
    objective_line = (
        f"\nOperator's stated focus for this run: {objective}\n"
        if objective
        else ""
    )
    return f"""You are the VibeHacking brain — an autonomous black-box web-application \
penetration tester. You drive a fixed toolset against a single authorized target \
and reason about what comes back.

TARGET (locked — every tool runs against this, you cannot retarget):
  URL : {url}
  Host: {host}
  Scope: {scope_label}
{objective_line}
THE GOLDEN RULE
1. Authorization is absolute. This target is one the operator OWNS or is
   explicitly authorized to test. You never probe anything else — not even
   recon. If a lead points at an out-of-scope host, you stop.
2. Start black-box. Attack what you can SEE from the outside first, through the
   live app via the tools — that's where externally-reachable (highest-severity)
   findings live. Because this is the operator's own app, using source or logs
   to CONFIRM a finding and recommend a fix is allowed; you just lead with the
   outside-in view and never treat source access as a substitute for proving a
   bug is reachable from the outside.

HOW YOU WORK:
- Recon first. Begin with surface mapping (ash, spider, ghost, api_finder,
  cloud_scout) before probing specific weaknesses. You can't attack what you
  haven't mapped.
- Then adapt. Let each tool's output decide the next move — a discovered login
  form pulls you toward auth tools (leep, aukdoc, axios); a reflected parameter
  pulls you toward injection tools (fuzz_vibe, redirect, traversal_sniper). Do
  not just run every tool in a fixed order; chain deliberately.
- Record as you go. The moment a tool's output evidences a real issue, call
  record_finding with an honest severity. Severity scale: critical (drop
  everything), high, medium, low, info (good-to-know, not yet exploitable).
- Be honest over impressive. If output is clean, say so and move on. Do not
  invent vulnerabilities or inflate severity. A short accurate report beats a
  padded one. Missing a real bug is worse than a calm "nothing here".
- Autonomy: you are running unattended. For routine choices (which tool next,
  how to interpret output) decide and proceed — do not stop to ask. Only the
  human-gated load_test boundary is out of your hands.
- Load testing is gated. load_test only fires on local/private/trusted hosts.
  On a public untrusted host it returns an error and does nothing — accept that
  and continue with audit tools.

WHEN YOU'RE DONE:
When you've mapped the surface and chased down the leads worth chasing, stop
calling tools and write a final report as plain text: an executive summary, the
findings grouped by severity (each with location, evidence, and fix), and an
overall security read on the app. That final message is the deliverable."""


# --------------------------------------------------------------------------- #
# Tool execution
# --------------------------------------------------------------------------- #
class VibeBrain:
    def __init__(self, url, host, allow_load):
        self.url = url
        self.host = host
        self.allow_load = allow_load
        self.findings = []
        self.tool_runs = []

    def _run_script(self, args):
        env = os.environ.copy()
        env.setdefault("PYTHONIOENCODING", "utf-8")
        try:
            proc = subprocess.run(
                [sys.executable, *args],
                cwd=ROOT_DIR,
                env=env,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=PER_TOOL_TIMEOUT,
            )
        except subprocess.TimeoutExpired:
            return f"[tool timed out after {PER_TOOL_TIMEOUT}s]", 124
        out = (proc.stdout or "") + (proc.stderr or "")
        return out, proc.returncode

    # -- tool: run_audit_tool ------------------------------------------------
    def run_audit_tool(self, inp):
        tool = inp.get("tool", "")
        if tool not in AUDIT_TOOLS:
            return f"Error: '{tool}' is not an available audit tool.", True
        print(f"\n   ┌─ running {tool}  ({inp.get('rationale','')[:80]})")
        sys.stdout.flush()
        out, rc = self._run_script([os.path.join("TOOLS", f"{tool}.py"), "--url", self.url])
        self.tool_runs.append({"tool": tool, "rc": rc})
        truncated = out if len(out) <= MAX_TOOL_OUTPUT else out[:MAX_TOOL_OUTPUT] + "\n[...output truncated...]"
        print(f"   └─ {tool} exited rc={rc}, {len(out)} chars captured")
        sys.stdout.flush()
        header = f"Tool: {tool}\nExit code: {rc}\n--- output ---\n"
        return header + truncated, False

    # -- tool: record_finding ------------------------------------------------
    def record_finding(self, inp):
        sev = inp.get("severity", "info")
        if sev not in SEVERITIES:
            sev = "info"
        finding = {
            "severity": sev,
            "title": inp.get("title", "(untitled)"),
            "location": inp.get("location", ""),
            "evidence": inp.get("evidence", ""),
            "recommendation": inp.get("recommendation", ""),
        }
        self.findings.append(finding)
        print(f"\n   {_SEV_ICON.get(sev,'•')} FINDING [{sev.upper()}] {finding['title']}")
        sys.stdout.flush()
        return f"Recorded finding #{len(self.findings)} ({sev}).", False

    # -- tool: load_test (gated) --------------------------------------------
    def load_test(self, inp):
        tool = inp.get("tool", "")
        intensity = inp.get("intensity", "light")
        if tool not in LOAD_TOOLS:
            return f"Error: '{tool}' is not a load tool.", True

        local = vibe._is_local_or_private(self.host)
        trusted = self.host in vibe._read_trusted()
        if not (local or trusted):
            return (
                f"Refused: {self.host} is a public host not in the authorized "
                f"allowlist, so load testing is blocked. Nothing was run. "
                f"Continue with audit tools.",
                True,
            )
        if not self.allow_load:
            return (
                "Refused: load testing was not enabled for this run "
                "(start claude.py with --allow-load). Nothing was run.",
                True,
            )

        print(f"\n   ┌─ load_test {tool} ({intensity})  [{('local/private' if local else 'trusted')}]")
        sys.stdout.flush()
        if tool == "storm":
            dur, rate, conc = ("8", "300", "10") if intensity == "light" else ("15", "600", "20")
            args = ["TOOLS/storm.py", "--url", self.url, "--duration", dur,
                    "--entries-per-min", rate, "--concurrency", conc, "--timeout", "5", "--yes"]
            out, rc = self._run_script(args)
        elif tool == "vibe_api":
            out, rc = self._run_script(["TOOLS/vibe_api.py", "--url", self.url])
        else:  # maelstrom — go binary, run via vibe.py so its caps/gates apply
            dur, rate, workers = ("8s", "30", "16") if intensity == "light" else ("15s", "50", "32")
            env = os.environ.copy()
            env.setdefault("PYTHONIOENCODING", "utf-8")
            try:
                proc = subprocess.run(
                    ["go", "run", ".", "-t", self.url, "-d", dur, "-r", rate, "-w", workers],
                    cwd=os.path.join(ROOT_DIR, "TOOLS", "maelstrom"),
                    env=env, capture_output=True, text=True,
                    encoding="utf-8", errors="replace", timeout=PER_TOOL_TIMEOUT,
                )
                out, rc = (proc.stdout or "") + (proc.stderr or ""), proc.returncode
            except FileNotFoundError:
                out, rc = "[go not installed; maelstrom unavailable]", 127
            except subprocess.TimeoutExpired:
                out, rc = f"[maelstrom timed out after {PER_TOOL_TIMEOUT}s]", 124

        self.tool_runs.append({"tool": tool, "rc": rc, "load": True})
        truncated = out if len(out) <= MAX_TOOL_OUTPUT else out[:MAX_TOOL_OUTPUT] + "\n[...truncated...]"
        print(f"   └─ {tool} exited rc={rc}")
        sys.stdout.flush()
        return f"Load tool: {tool} ({intensity})\nExit code: {rc}\n--- output ---\n" + truncated, False

    def dispatch(self, name, inp):
        if name == "run_audit_tool":
            return self.run_audit_tool(inp)
        if name == "record_finding":
            return self.record_finding(inp)
        if name == "load_test":
            return self.load_test(inp)
        return f"Error: unknown tool '{name}'.", True


# --------------------------------------------------------------------------- #
# Report
# --------------------------------------------------------------------------- #
def write_report(brain, url, host, model, final_text):
    order = {s: i for i, s in enumerate(SEVERITIES)}
    findings = sorted(brain.findings, key=lambda f: order.get(f["severity"], 99))
    counts = {s: sum(1 for f in findings if f["severity"] == s) for s in SEVERITIES}

    lines = []
    lines.append("# VibeHacking — Autonomous Pentest Report")
    lines.append("")
    lines.append(f"- Target: {url}")
    lines.append(f"- Host: {host}")
    lines.append(f"- Brain: {model}")
    lines.append(f"- Tools run: {len(brain.tool_runs)}")
    lines.append(
        "- Findings: "
        + ", ".join(f"{_SEV_ICON[s]} {counts[s]} {s}" for s in SEVERITIES if counts[s])
        or "- Findings: none"
    )
    lines.append("")
    lines.append("## Findings")
    if not findings:
        lines.append("\n_No findings recorded._")
    for i, f in enumerate(findings, 1):
        lines.append("")
        lines.append(f"### {i}. {_SEV_ICON[f['severity']]} [{f['severity'].upper()}] {f['title']}")
        if f.get("location"):
            lines.append(f"- **Location:** {f['location']}")
        if f.get("evidence"):
            lines.append(f"- **Evidence:** {f['evidence']}")
        if f.get("recommendation"):
            lines.append(f"- **Fix:** {f['recommendation']}")
    lines.append("")
    lines.append("## Brain's closing summary")
    lines.append("")
    lines.append(final_text or "_(no closing summary produced)_")
    lines.append("")

    body = "\n".join(lines)
    if os.environ.get("VIBE_PRIVACY_MODE", "").lower() != "off":
        body = sanitize_text(body)

    reports_dir = os.path.join(ROOT_DIR, "reports")
    os.makedirs(reports_dir, exist_ok=True)
    safe_host = "".join(c if c.isalnum() or c in "-._" else "_" for c in (host or "target"))
    path = os.path.join(reports_dir, f"claude_pentest_{safe_host}_{time.strftime('%Y%m%d-%H%M%S')}.md")
    with open(path, "w", encoding="utf-8") as fh:
        fh.write(body)
    return path, counts


# --------------------------------------------------------------------------- #
# Agentic loop
# --------------------------------------------------------------------------- #
def run_brain(client, model, effort, system, tools, brain, kickoff, max_steps):
    messages = [{"role": "user", "content": kickoff}]
    final_text = ""

    for step in range(1, max_steps + 1):
        print(f"\n{'─'*64}\n[ step {step}/{max_steps} ]")
        sys.stdout.flush()
        try:
            with client.messages.stream(
                model=model,
                max_tokens=MAX_TOKENS_PER_TURN,
                system=system,
                tools=tools,
                messages=messages,
                thinking={"type": "adaptive", "display": "summarized"},
                output_config={"effort": effort},
            ) as stream:
                in_thinking = False
                for event in stream:
                    if event.type == "content_block_start":
                        if event.content_block.type == "thinking":
                            in_thinking = True
                            print("\n  · thinking · ", end="", flush=True)
                        elif event.content_block.type == "text":
                            in_thinking = False
                            print("\n", end="", flush=True)
                    elif event.type == "content_block_delta":
                        if event.delta.type == "thinking_delta":
                            print(event.delta.thinking, end="", flush=True)
                        elif event.delta.type == "text_delta":
                            print(event.delta.text, end="", flush=True)
                response = stream.get_final_message()
        except Exception as exc:  # noqa: BLE001
            _api_error_hint(exc)
            break

        messages.append({"role": "assistant", "content": response.content})
        text_now = "".join(b.text for b in response.content if b.type == "text")
        if text_now.strip():
            final_text = text_now

        if response.stop_reason == "tool_use":
            tool_results = []
            for block in response.content:
                if block.type == "tool_use":
                    content, is_error = brain.dispatch(block.name, block.input)
                    tool_results.append({
                        "type": "tool_result",
                        "tool_use_id": block.id,
                        "content": content,
                        "is_error": is_error,
                    })
            messages.append({"role": "user", "content": tool_results})
            continue

        if response.stop_reason == "max_tokens":
            print("\n  [hit max_tokens — nudging to continue]")
            messages.append({"role": "user", "content": "Continue."})
            continue

        if response.stop_reason == "refusal":
            print("\n  [model declined to continue]")
            break

        # end_turn / stop_sequence — the brain is done.
        break
    else:
        print(f"\n[reached step cap of {max_steps}; wrapping up]")

    return final_text


def _api_error_hint(exc):
    name = exc.__class__.__name__
    print(f"\n[!] Anthropic API error: {name}: {exc}")
    if name == "AuthenticationError":
        print("    Check ANTHROPIC_API_KEY.")
    elif name == "NotFoundError":
        print(f"    Model may be wrong. Try VIBE_CLAUDE_MODEL=claude-opus-4-8.")
    elif name in ("RateLimitError", "OverloadedError"):
        print("    Rate limited / overloaded — wait and retry.")


# --------------------------------------------------------------------------- #
# CLI
# --------------------------------------------------------------------------- #
def _scope_label(host):
    if not host:
        return "unknown"
    return "local/private (load tools allowed)" if vibe._is_local_or_private(host) else "external"


def main(argv=None):
    parser = argparse.ArgumentParser(
        prog="claude.py",
        description="Autonomous Claude-driven pentest of one authorized target.",
    )
    parser.add_argument("url", nargs="?", help="Target URL (e.g. http://127.0.0.1:5500/)")
    parser.add_argument("--objective", default="", help="Optional focus, e.g. 'auth and IDOR'")
    parser.add_argument("--model", default=DEFAULT_MODEL, help=f"Claude model (default {DEFAULT_MODEL})")
    parser.add_argument("--effort", default=DEFAULT_EFFORT, choices=["low", "medium", "high", "xhigh", "max"],
                        help=f"Reasoning effort (default {DEFAULT_EFFORT})")
    parser.add_argument("--max-steps", type=int, default=40, help="Max agent turns (default 40)")
    parser.add_argument("--allow-load", action="store_true",
                        help="Permit the gated load_test tool (still local/private/trusted only)")
    parser.add_argument("--dry-run", action="store_true",
                        help="Show the plan, tool surface, and disclosure — no API call")
    parser.add_argument("--list-tools", action="store_true", help="List the audit tools the brain can pick")
    parser.add_argument("--yes", action="store_true", help="Skip the external-target disclosure prompt")
    args = parser.parse_args(argv)

    print("=" * 64)
    print("  VIBEHACKING — CLAUDE AUTONOMOUS PENTEST BRAIN")
    print("=" * 64)

    if args.list_tools:
        print("Audit tools available to the brain:")
        for t in AUDIT_TOOLS:
            print(f"  - {t}")
        print("Gated load tools (--allow-load, local/private/trusted only):")
        for t in LOAD_TOOLS:
            print(f"  - {t}")
        return 0

    if not args.url:
        parser.print_help()
        return 2

    url = args.url
    host = vibe._normalize_host(url)
    if not host:
        print(f"[-] Could not parse a host from: {url}")
        return 2
    scope = _scope_label(host)

    print(f"  Target : {url}")
    print(f"  Host   : {host}")
    print(f"  Scope  : {scope}")
    print(f"  Model  : {args.model}   (effort={args.effort})")
    print(f"  Load   : {'enabled (gated)' if args.allow_load else 'disabled'}")
    print("=" * 64)

    # Honest disclosure about what leaves the machine.
    print("\n[i] Disclosure: the target URL and the captured stdout of each tool")
    print("    Claude runs are sent to the Anthropic API so the model can reason")
    print("    about your app. Use --dry-run to preview without any API call.")

    if args.dry_run:
        print("\n[dry-run] No API call will be made. Planned setup:\n")
        print(build_system_prompt(url, host, scope, args.objective))
        print(f"\n[dry-run] {len(AUDIT_TOOLS)} audit tools + {len(LOAD_TOOLS)} gated load tools exposed.")
        print("[dry-run] Set ANTHROPIC_API_KEY and drop --dry-run to run for real.")
        return 0

    if not vibe._is_local_or_private(host) and not args.yes:
        print(f"\n[!] {host} is an external host. Only proceed for a site you own")
        print("    or have written permission to test.")
        try:
            ans = input("    Type the hostname to confirm: ").strip()
        except EOFError:
            print("    No confirmation (non-interactive). Aborting.")
            return 2
        if ans != host:
            print("    Confirmation did not match. Aborting.")
            return 2

    if not os.environ.get("ANTHROPIC_API_KEY"):
        print("\n[-] ANTHROPIC_API_KEY is not set. Export it and retry, or use --dry-run.")
        return 2

    try:
        import anthropic  # noqa: F401
    except ImportError:
        print("\n[-] The 'anthropic' package isn't installed.")
        print("    pip install anthropic")
        return 2

    client = anthropic.Anthropic()
    system = build_system_prompt(url, host, scope, args.objective)
    tools = build_tools()
    brain = VibeBrain(url, host, args.allow_load)
    kickoff = (
        "Begin the assessment of the locked target. Start with recon to map the "
        "surface, then adapt. Record findings as you confirm them. When you've "
        "chased the worthwhile leads, write your final report."
    )

    started = time.time()
    final_text = run_brain(client, args.model, args.effort, system, tools, brain, kickoff, args.max_steps)
    elapsed = int(time.time() - started)

    path, counts = write_report(brain, url, host, args.model, final_text)

    print("\n" + "=" * 64)
    print(f"[+] Done in {elapsed}s. {len(brain.tool_runs)} tool runs, {len(brain.findings)} findings.")
    summary = ", ".join(f"{_SEV_ICON[s]}{counts[s]} {s}" for s in SEVERITIES if counts[s])
    print(f"    {summary or 'No findings recorded.'}")
    print(f"    Report: {path}")
    print("    Re-run after patching to confirm fixes.")
    return 0


if __name__ == "__main__":
    sys.exit(main() or 0)
