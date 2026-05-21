import sys
import argparse
import subprocess
import os
import json
import datetime

VERSION = "0.5.0"

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def run_command(args, cwd=None):
    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    return subprocess.run(args, cwd=cwd, env=env)


def run_tool(args):
    return run_command([sys.executable, *args])


def run_vibe():
    parser = argparse.ArgumentParser(description=f"🛡️ VIBE HACKING v{VERSION} - Central Command Interface")
    parser.add_argument('--version', action='version', version=f'VIBE HACKING {VERSION}')
    subparsers = parser.add_subparsers(dest="command")

    # Command: scan
    scan_parser = subparsers.add_parser("scan", help="Run an automated security audit on a URL")
    scan_parser.add_argument("url", help="Target URL (e.g. http://127.0.0.1:5500/)")
    scan_parser.add_argument("--extended", action="store_true", help="Also run WAF detection, SSL audit, and SQL probe")

    # Command: report
    report_parser = subparsers.add_parser("report", help="Generate the LMX Executive Dashboard")

    # Command: clean
    clean_parser = subparsers.add_parser("clean", help="Run the Environment Cleaner (Void)")
    clean_parser.add_argument("--db", help="Path to target database")

    # Command: storm
    storm_parser = subparsers.add_parser("storm", help="Run localhost traffic stress")
    storm_parser.add_argument("url", nargs="?", default="", help="Target URL (stress mode is localhost-only)")
    storm_parser.add_argument("--urls-file", default="", help="File containing one URL per line for --url-check")
    storm_parser.add_argument(
        "--url-check",
        action="store_true",
        help="Run safe one-request-per-URL checks. Required for external URLs.",
    )
    storm_parser.add_argument("--duration", type=int, default=15, help="Stress duration in seconds")
    storm_parser.add_argument("--entries-per-min", type=int, default=600, help="Request entries per minute")
    storm_parser.add_argument("--concurrency", type=int, default=20, help="Maximum concurrent requests")
    storm_parser.add_argument("--timeout", type=float, default=5, help="Per-request timeout in seconds")
    storm_parser.add_argument(
        "--full-send",
        action="store_true",
        help="Ignore entries/min pacing and submit as fast as local workers free up.",
    )
    storm_parser.add_argument(
        "--include-chat",
        action="store_true",
        help="Also send valid /api/chat payloads. May consume API credits if a key is loaded.",
    )

    # Command: maelstrom
    maelstrom_parser = subparsers.add_parser("maelstrom", help="Run the Go private-target load tester")
    maelstrom_parser.add_argument(
        "maelstrom_args",
        nargs=argparse.REMAINDER,
        help="Arguments forwarded to Maelstrom, e.g. -t http://localhost:3456/ -d 10s -r 5000 -w 256",
    )

    # Command: status
    status_parser = subparsers.add_parser("status", help="Check current session status")

    # Command: list
    list_parser = subparsers.add_parser("list", help="List all available hack tools")

    # Command: codex
    codex_parser = subparsers.add_parser("codex", help="Print a compact workspace snapshot")
    codex_parser.add_argument("target", nargs="?", default="", help="Optional target URL or note")
    codex_parser.add_argument("--ultra", action="store_true", help="Print the smallest useful snapshot")
    codex_parser.add_argument("--workdir", default="", help="Switch into a specific working directory first")

    if len(sys.argv) > 1 and sys.argv[1] == "maelstrom":
        raw_maelstrom_args = sys.argv[2:]
        args = parser.parse_args(["maelstrom"])
        args.maelstrom_args = raw_maelstrom_args[1:] if raw_maelstrom_args[:1] == ["--"] else raw_maelstrom_args
    else:
        args = parser.parse_args()

    if args.command != "codex":
        print("================================")
        print(f" VIBE HACKING COMMAND CENTER v{VERSION}")
        print("================================")

    if args.command == "scan":
        print(f"[*] Starting Real-World Audit of {args.url}...")
        
        # Save current target to session
        with open("vibe_session.json", "w") as f:
            json.dump({"target": args.url, "last_scan": datetime.datetime.now().isoformat()}, f)

        # Chain together multiple tools for a "Deep Scan"
        print("[*] Phase 1: Header Security Audit...")
        run_tool(["TOOLS/vibe_headers.py", "--url", args.url])
        
        print("[*] Phase 2: Hidden Asset Discovery (Ghost)...")
        run_tool(["TOOLS/ghost.py", "--url", args.url])
        
        print("[*] Phase 3: Logic Flow Audit (Leep)...")
        run_tool(["TOOLS/leep.py", "--url", args.url])

        if args.extended:
            print("[*] Phase 4 (Extended): WAF Detection...")
            run_tool(["TOOLS/waf_detect.py", "--url", args.url])
            print("[*] Phase 5 (Extended): SSL/TLS Audit...")
            run_tool(["TOOLS/ssl_audit.py", "--url", args.url])
            print("[*] Phase 6 (Extended): SQL Injection Probe...")
            run_tool(["TOOLS/sql_probe.py", "--url", args.url])

        print("\n[+] Scan Sequence Complete. See logs/ for detailed findings.")

    elif args.command == "report":
        print("[*] Compiling Real-Time Executive Dashboard...")
        run_tool(["TOOLS/lmx.py"])

    elif args.command == "clean":
        print("[*] Executing Environmental Decontamination...")
        cmd = ["TOOLS/void.py"]
        if args.db: cmd += ["--db", args.db]
        run_tool(cmd)

    elif args.command == "storm":
        if args.url_check or args.urls_file:
            print("[*] Launching Storm URL check...")
        else:
            print("[*] Launching localhost traffic storm...")
        cmd = [
            "TOOLS/storm.py",
            "--duration",
            str(args.duration),
            "--entries-per-min",
            str(args.entries_per_min),
            "--concurrency",
            str(args.concurrency),
            "--timeout",
            str(args.timeout),
        ]
        if args.url:
            cmd += ["--url", args.url]
        if args.urls_file:
            cmd += ["--urls-file", args.urls_file]
        if args.url_check:
            cmd.append("--url-check")
        if args.include_chat:
            cmd.append("--include-chat")
        if args.full_send:
            cmd.append("--full-send")
        run_tool(cmd)

    elif args.command == "maelstrom":
        print("[*] Launching Maelstrom private-target load test...")
        forwarded = list(args.maelstrom_args)
        if forwarded and forwarded[0] == "--":
            forwarded = forwarded[1:]
        run_command(["go", "run", ".", *forwarded], cwd=os.path.join("TOOLS", "maelstrom"))

    elif args.command == "status":
        if os.path.exists("vibe_session.json"):
            with open("vibe_session.json", "r") as f:
                data = json.load(f)
                print(f"[+] Current Target: {data.get('target', 'None')}")
        else:
            print("[-] No active session found.")

    elif args.command == "list":
        import re
        tools_dir = "TOOLS"
        print("[*] Available Professional Toolset:")
        if os.path.exists(os.path.join(tools_dir, "maelstrom")):
            print("  -> maelstrom                  - Go private-target load tester")
        for t in sorted(os.listdir(tools_dir)):
            if t.endswith(".py") and t not in ("vibe_core.py",):
                description = ""
                try:
                    with open(os.path.join(tools_dir, t), 'r', encoding='utf-8', errors='ignore') as f:
                        content = f.read(4000)
                    m = re.search(r'super\(\).__init__\([^,]+,\s*["\'](.+?)["\']\)', content)
                    if m:
                        description = m.group(1)
                except Exception:
                    pass
                name = t.replace('.py', '')
                print(f"  -> {name:<28} {('- ' + description) if description else ''}")

    elif args.command == "codex":
        cmd = ["TOOLS/codex_boot.py"]
        if args.target:
            cmd += ["--target", args.target]
        if args.ultra:
            cmd.append("--ultra")
        if args.workdir:
            cmd += ["--workdir", args.workdir]
        run_tool(cmd)

    else:
        parser.print_help()

if __name__ == "__main__":
    run_vibe()
