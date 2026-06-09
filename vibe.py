import sys
import argparse
import subprocess
import os
import json
import ipaddress
import urllib.parse

TOOLS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "TOOLS")
sys.path.insert(0, TOOLS_DIR)
from privacy_guard import privacy_summary_lines, sanitize_data, sanitize_text


def _read_version():
    """Single source of truth: the root VERSION file. Falls back if absent."""
    try:
        version_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "VERSION")
        with open(version_path, "r", encoding="utf-8") as f:
            return f.read().strip() or "1.0.0"
    except OSError:
        return "1.0.0"


VERSION = _read_version()

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


AUTHORIZED_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "authorized_targets.txt")

LOCAL_LITERALS = {"localhost", "127.0.0.1", "::1"}


def _normalize_host(raw):
    """Reduce a URL/host[:port] to a bare lowercase hostname. Returns '' if unusable."""
    host = (raw or "").strip()
    if not host or host.startswith("#") or "*" in host or "?" in host:
        return ""
    if "://" in host:
        host = urllib.parse.urlparse(host).hostname or host
    host = host.split("/")[0].strip().lower()
    if "@" in host:
        host = host.split("@")[-1]
    if host.count(":") == 1:  # strip a single trailing :port (ignores bare IPv6)
        host = host.split(":")[0]
    return host


def _read_trusted():
    """Return the list of exact hostnames currently in authorized_targets.txt."""
    hosts = []
    try:
        with open(AUTHORIZED_FILE, "r", encoding="utf-8") as handle:
            for line in handle:
                host = _normalize_host(line)
                if host and host not in hosts:
                    hosts.append(host)
    except OSError:
        pass
    return hosts


def _add_trusted(raw):
    host = _normalize_host(raw)
    if not host:
        print(f"[-] '{raw}' is not a valid host (wildcards are not allowed). Use a bare hostname like my-app.vercel.app")
        return 2
    if host in _read_trusted():
        print(f"[=] {host} is already trusted.")
        return 0
    needs_newline = os.path.exists(AUTHORIZED_FILE) and os.path.getsize(AUTHORIZED_FILE) > 0
    with open(AUTHORIZED_FILE, "a", encoding="utf-8") as handle:
        if needs_newline:
            handle.write("\n")
        handle.write(host + "\n")
    print(f"[+] Trusted {host}. The load tools will now accept it.")
    print(f"    Only do this for hosts you own or are authorized to test.")
    return 0


def _remove_trusted(raw):
    host = _normalize_host(raw)
    if not host:
        print(f"[-] '{raw}' is not a valid host.")
        return 2
    try:
        with open(AUTHORIZED_FILE, "r", encoding="utf-8") as handle:
            lines = handle.readlines()
    except OSError:
        print("[-] No authorized_targets.txt yet — nothing to remove.")
        return 0
    kept = [ln for ln in lines if _normalize_host(ln) != host]
    if len(kept) == len(lines):
        print(f"[=] {host} was not in the trusted list.")
        return 0
    with open(AUTHORIZED_FILE, "w", encoding="utf-8") as handle:
        handle.writelines(kept)
    print(f"[+] Removed {host} from the trusted list.")
    return 0


def _is_local_or_private(host):
    if host in LOCAL_LITERALS:
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_private or ip.is_link_local
    except ValueError:
        return False  # a hostname we can't classify without DNS — treat as external


def _extract_target(forwarded):
    """Pull the target host out of maelstrom-style args (-t/--target)."""
    for i, tok in enumerate(forwarded):
        if tok in ("-t", "--target") and i + 1 < len(forwarded):
            return _normalize_host(forwarded[i + 1])
        if tok.startswith("--target="):
            return _normalize_host(tok.split("=", 1)[1])
        if tok.startswith("-t="):
            return _normalize_host(tok.split("=", 1)[1])
    return ""


def _extract_flag(forwarded, names):
    """Return the value following any of the given flags (or '' if absent)."""
    for i, tok in enumerate(forwarded):
        if tok in names and i + 1 < len(forwarded):
            return forwarded[i + 1]
        for name in names:
            if tok.startswith(name + "="):
                return tok.split("=", 1)[1]
    return ""


def _external_warning(host, rate_desc="", assume_yes=False):
    """Show a danger banner for a non-local target and require typed confirmation.

    Returns True to proceed, False to abort."""
    bar = "=" * 64
    print(bar)
    print("  ⚠  EXTERNAL TARGET — ACTIVE LOAD TEST")
    print(bar)
    print(f"  Host : {host}")
    if rate_desc:
        print(f"  Rate : {rate_desc}")
    print("  You are about to send real load traffic to a NON-LOCAL host.")
    print("  Proceed ONLY if you own this host or have written permission to test it.")
    print("  Unauthorized load / DoS traffic is illegal in most jurisdictions —")
    print("  a disclaimer does not change that. This is on you.")
    print(bar)
    if assume_yes:
        print("  [--yes supplied: skipping interactive confirmation]")
        return True
    try:
        answer = input(f"  Type the hostname ({host}) to proceed, anything else to abort: ").strip().lower()
    except EOFError:
        return False
    if answer == host.lower():
        return True
    print("  Aborted — confirmation did not match.")
    return False



def run_vibe():
    parser = argparse.ArgumentParser(description=f"🛡️ VIBE HACKING v{VERSION} - Central Command Interface")
    subparsers = parser.add_subparsers(dest="command")

    # Command: scan
    scan_parser = subparsers.add_parser("scan", help="Run an automated security audit on a URL")
    scan_parser.add_argument("url", help="Target URL (e.g. http://127.0.0.1:5500/)")

    # Command: report
    report_parser = subparsers.add_parser("report", help="Generate the LMX Executive Dashboard")

    # Command: privacy
    privacy_parser = subparsers.add_parser("privacy", help="Show tester privacy controls and limits")

    # Command: clean
    clean_parser = subparsers.add_parser("clean", help="Run the Environment Cleaner (Void)")
    clean_parser.add_argument("--db", help="Path to target database")

    # Command: storm
    storm_parser = subparsers.add_parser("storm", help="Run traffic stress against an authorized target")
    storm_parser.add_argument("url", nargs="?", default="", help="Target URL (stress mode allows localhost or hosts in authorized_targets.txt)")
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

    storm_parser.add_argument(
        "--yes",
        action="store_true",
        help="Skip the interactive external-target confirmation (for scripted runs you trust).",
    )

    # Command: maelstrom
    maelstrom_parser = subparsers.add_parser("maelstrom", help="Run the Go load tester (localhost or trusted hosts)")
    maelstrom_parser.add_argument(
        "maelstrom_args",
        nargs=argparse.REMAINDER,
        help="Arguments forwarded to Maelstrom, e.g. -t http://localhost:3456/ -d 10s -r 5000 -w 256",
    )

    # Command: trust
    trust_parser = subparsers.add_parser("trust", help="Manage the authorized load-test target allowlist")
    trust_sub = trust_parser.add_subparsers(dest="trust_action")
    trust_add = trust_sub.add_parser("add", help="Authorize a host you own for load testing")
    trust_add.add_argument("host", help="Hostname or URL, e.g. my-app.vercel.app")
    trust_remove = trust_sub.add_parser("remove", help="Remove a host from the allowlist")
    trust_remove.add_argument("host", help="Hostname or URL to remove")
    trust_sub.add_parser("list", help="List currently trusted hosts")

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
        print(f"[*] Starting Real-World Audit of {sanitize_text(args.url)}...")
        
        # Save current target to session
        with open("vibe_session.json", "w") as f:
            json.dump(sanitize_data({"target": args.url, "last_scan": str(os.times())}), f)

        # Chain together multiple tools for a "Deep Scan"
        print("[*] Phase 1: Domain Recon (Ash)...")
        run_tool(["TOOLS/ash.py", "--url", args.url])

        print("[*] Phase 2: Header Security Audit...")
        run_tool(["TOOLS/vibe_headers.py", "--url", args.url])

        print("[*] Phase 3: Hidden Asset Discovery (Ghost)...")
        run_tool(["TOOLS/ghost.py", "--url", args.url])

        print("[*] Phase 4: Logic Flow Audit (Leep)...")
        run_tool(["TOOLS/leep.py", "--url", args.url])
        
        print("\n[+] Scan Sequence Complete. See logs/ for detailed findings.")

    elif args.command == "report":
        print("[*] Compiling Real-Time Executive Dashboard...")
        run_tool(["TOOLS/lmx.py"])

    elif args.command == "privacy":
        for line in privacy_summary_lines():
            print(line)

    elif args.command == "clean":
        print("[*] Executing Environmental Decontamination...")
        cmd = ["TOOLS/void.py"]
        if args.db: cmd += ["--db", args.db]
        run_tool(cmd)

    elif args.command == "storm":
        is_check = args.url_check or args.urls_file
        if is_check:
            print("[*] Launching Storm URL check...")
        else:
            print("[*] Launching authorized-target traffic storm...")
            host = _normalize_host(args.url) if args.url else ""
            if host and not _is_local_or_private(host):
                if host not in _read_trusted():
                    print(f"[-] {host} is not trusted. Authorize it first (only if you own it):")
                    print(f"      python vibe.py trust add {host}")
                    return
                rate = "full-send (unbounded)" if args.full_send else f"{args.entries_per_min}/min"
                if not _external_warning(host, rate_desc=rate, assume_yes=args.yes):
                    return
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
        if not is_check:
            cmd.append("--yes")  # vibe.py already ran the external confirmation
        run_tool(cmd)

    elif args.command == "maelstrom":
        forwarded = list(args.maelstrom_args)
        if forwarded and forwarded[0] == "--":
            forwarded = forwarded[1:]
        assume_yes = False
        if "--yes" in forwarded or "-y" in forwarded:
            assume_yes = True
            forwarded = [t for t in forwarded if t not in ("--yes", "-y")]

        host = _extract_target(forwarded)
        if host and not _is_local_or_private(host):
            if host not in _read_trusted():
                print(f"[-] {host} is not trusted. Authorize it first (only if you own it):")
                print(f"      python vibe.py trust add {host}")
                return
            rate = _extract_flag(forwarded, ("-r", "--rate")) or "1000 (default)"
            if not _external_warning(host, rate_desc=f"{rate} rps", assume_yes=assume_yes):
                return

        print("[*] Launching Maelstrom load test...")
        run_command(["go", "run", ".", *forwarded], cwd=os.path.join("TOOLS", "maelstrom"))

    elif args.command == "trust":
        if args.trust_action == "add":
            return _add_trusted(args.host)
        elif args.trust_action == "remove":
            return _remove_trusted(args.host)
        elif args.trust_action == "list":
            hosts = _read_trusted()
            if hosts:
                print("[*] Trusted load-test targets:")
                for h in hosts:
                    print(f"  -> {h}")
            else:
                print("[-] No trusted hosts yet. Add one with: python vibe.py trust add <host>")
        else:
            print("Usage: python vibe.py trust {add|remove|list} [host]")

    elif args.command == "status":
        if os.path.exists("vibe_session.json"):
            with open("vibe_session.json", "r") as f:
                data = json.load(f)
                print(f"[+] Current Target: {sanitize_text(data.get('target', 'None'))}")
        else:
            print("[-] No active session found.")

    elif args.command == "list":
        tools_dir = "TOOLS"
        print("[*] Available Professional Toolset:")
        if os.path.exists(os.path.join(tools_dir, "maelstrom")):
            print("  -> maelstrom - Go private-target load tester")
        for t in os.listdir(tools_dir):
            if t.endswith(".py") and t not in {"vibe_core.py", "privacy_guard.py"}:
                description = ""
                # Quick peek at first few lines for description
                try:
                    with open(os.path.join(tools_dir, t), 'r') as f:
                        content = f.read(500)
                        if "description" in content.lower():
                            description = " - Functional Tool"
                except: pass
                print(f"  -> {t.replace('.py', '')}{description}")

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
