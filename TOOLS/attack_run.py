#!/usr/bin/env python3
"""Attack kill-chain runner used by vibe.py attack.

Keeps the heavy phase orchestration out of vibe.py so changes stay reviewable.
"""
import os
import sys
import time

from findings import record_tool, summarize, write_findings_json
from vibe_core import confirm_locked_tools, locked_tools


def run_attack(ctx):
    """Execute the ordered attack chain.

    ctx keys:
      url, host, skip_load, yes, user, password, user_field,
      skip_redteam, json_out,
      run_tool, run_command,
      ROOT_DIR, TOOLS_DIR, ATTACK_PHASES, version,
      is_local_or_private, read_trusted, external_warning, sanitize_text
    """
    url = ctx["url"]
    host = ctx["host"]
    run_tool = ctx["run_tool"]
    run_command = ctx["run_command"]
    ATTACK_PHASES = ctx["ATTACK_PHASES"]
    findings = []
    started = time.strftime("%Y-%m-%dT%H:%M:%S")

    # Locked tools must not run just because they sit inside the chain: same
    # consent step as a direct run, skipped (with a note) when not granted.
    locked = locked_tools()
    locked_in_chain = [t for _, tools in ATTACK_PHASES for t in tools if t in locked]
    allowed_locked = set()
    if locked_in_chain:
        if ctx.get("allow_locked"):
            allowed_locked = set(locked_in_chain)
            print(f"[*] --allow-locked: running {len(locked_in_chain)} gated tool(s).")
        else:
            allowed_locked = confirm_locked_tools(
                locked_in_chain, locked, assume_yes=False,
                log_path=os.path.join(ctx["ROOT_DIR"], "logs", "locked_cli_access.log"))
            if not allowed_locked:
                print(f"[i] Skipping gated tool(s): {', '.join(locked_in_chain)}")
                print("    Pass --allow-locked (only on a target you own) to include them.")

    # Phase 0: auth gate (internal edition when authcheck is present)
    authcheck = os.path.join(ctx["TOOLS_DIR"], "authcheck.py")
    if os.path.isfile(authcheck):
        print("\n" + "=" * 60)
        print("  PHASE 0: SESSION / AUTH GATE")
        print("=" * 60)
        print("\n[*] -> authcheck")
        sys.stdout.flush()
        result = run_tool(["TOOLS/authcheck.py", "--url", url], capture=True)
        entry = record_tool(findings, "Session / Auth Gate", "authcheck", result)
        if entry["returncode"] == 2:
            print("[!] Auth gate: CHALLENGED (anti-bot wall). Continuing audit tools; fix session for authed surface.")
        elif entry["returncode"] == 3:
            print("[!] Auth gate: ANONYMOUS (looks logged-out). Continuing; capture a session for authed testing.")

    executed = 0
    for phase_num, (title, tools) in enumerate(ATTACK_PHASES, start=1):
        print("\n" + "=" * 60)
        print(f"  PHASE {phase_num}: {title.upper()}")
        print("=" * 60)
        for tool in tools:
            tool_path = os.path.join(ctx["TOOLS_DIR"], f"{tool}.py")
            if not os.path.isfile(tool_path):
                print(f"\n[i] -> {tool} (missing on this edition, skip)")
                continue
            if tool in locked and tool not in allowed_locked:
                print(f"\n[i] -> {tool} skipped (locked tool; see --allow-locked)")
                continue
            print(f"\n[*] -> {tool}")
            sys.stdout.flush()
            result = run_tool([f"TOOLS/{tool}.py", "--url", url], capture=True)
            record_tool(findings, title, tool, result)
            executed += 1

    # Internal arsenal: redteam (present only on internal)
    redteam = os.path.join(ctx["TOOLS_DIR"], "redteam.py")
    if os.path.isfile(redteam) and not ctx.get("skip_redteam"):
        print("\n" + "=" * 60)
        print("  PHASE: INTERNAL ARSENAL (REDTEAM)")
        print("=" * 60)
        print("\n[*] -> redteam")
        sys.stdout.flush()
        rt_args = ["TOOLS/redteam.py", "--url", url]
        if ctx.get("user"):
            rt_args += ["--user", ctx["user"]]
        if ctx.get("password"):
            rt_args += ["--pass", ctx["password"]]
        if ctx.get("user_field"):
            rt_args += ["--user-field", ctx["user_field"]]
        result = run_tool(rt_args, capture=True)
        record_tool(findings, "Internal Arsenal", "redteam", result)
        executed += 1
    elif ctx.get("skip_redteam"):
        print("\n[i] Internal arsenal (redteam) skipped (--skip-redteam).")

    # Load & stress
    load_phase = len(ATTACK_PHASES) + 1
    if ctx.get("skip_load"):
        print(f"\n[i] Phase {load_phase} (Load & Stress) skipped (--skip-load).")
    else:
        print("\n" + "=" * 60)
        print(f"  PHASE {load_phase}: LOAD & STRESS")
        print("=" * 60)
        run_load = True
        is_local = ctx["is_local_or_private"]
        read_trusted = ctx["read_trusted"]
        external_warning = ctx["external_warning"]
        if host and not is_local(host):
            if host not in read_trusted():
                print(f"[-] {host} is not in the authorized load-test allowlist. Skipping load phase.")
                print(f"    Authorize it first (only if you own it):  python vibe.py trust add {host}")
                run_load = False
            elif not external_warning(host, rate_desc="storm 600/min + vibe_api + maelstrom 50 rps", assume_yes=ctx.get("yes")):
                print("[-] Load phase aborted — confirmation did not match.")
                run_load = False
        if run_load:
            for label, args in (
                ("storm (safe single-probe check)", ["TOOLS/storm.py", "--url", url, "--url-check"]),
                ("storm (stress)", ["TOOLS/storm.py", "--url", url, "--duration", "15",
                                    "--entries-per-min", "600", "--concurrency", "20", "--timeout", "5", "--yes"]),
                ("vibe_api (JSON endpoint stress)", ["TOOLS/vibe_api.py", "--url", url]),
            ):
                print(f"\n[*] -> {label}")
                sys.stdout.flush()
                result = run_tool(args, capture=True)
                record_tool(findings, "Load & Stress", label.split()[0], result)
            print("\n[*] -> maelstrom (Go load tester)")
            sys.stdout.flush()
            result = run_command(["go", "run", ".", "-t", url, "-d", "15s", "-r", "50", "-w", "32"],
                                 cwd=os.path.join("TOOLS", "maelstrom"), capture=True)
            record_tool(findings, "Load & Stress", "maelstrom", result)

    # Reporting
    print("\n" + "=" * 60)
    print("  PHASE: REPORTING & RECEIPTS")
    print("=" * 60)
    for label, args in (
        ("poc_gen", ["TOOLS/poc_gen.py", "--url", url]),
        ("lmx", ["TOOLS/lmx.py"]),
        ("backer", ["TOOLS/backer.py"]),
    ):
        print(f"\n[*] -> {label}")
        sys.stdout.flush()
        result = run_tool(args, capture=True)
        record_tool(findings, "Reporting", label, result)

    finished = time.strftime("%Y-%m-%dT%H:%M:%S")
    summary = summarize(findings)
    payload = {
        "schema": "vibe.findings.v1",
        "version": ctx.get("version", ""),
        "target": url,
        "host": host,
        "started_at": started,
        "finished_at": finished,
        "tools": findings,
        "summary": summary,
    }
    json_path = ctx.get("json_out") or os.path.join(
        ctx["ROOT_DIR"], "logs", f"findings-{time.strftime('%Y%m%d-%H%M%S')}.json"
    )
    path = write_findings_json(json_path, payload)

    print("\n" + "=" * 60)
    print(
        f"[+] Attack run complete. {executed} audit tools across "
        f"{len(ATTACK_PHASES)} base phases (+ gates/arsenal)."
    )
    if summary["flagged_tools"]:
        print(f"[!] Flagged tools (finding or error): {', '.join(summary['flagged_tools'])}")
    print(f"    Signals: {summary['hack_signals']} hack / {summary['crit_signals']} crit")
    print(f"    Findings JSON: {path}")
    print("    Logs in logs/, dashboard via lmx. Re-run after patching to confirm fixes.")
    return 0
