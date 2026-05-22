import sys
import argparse
import subprocess
import os
import time
from urllib.parse import urlparse

VERSION = "1.0.0"

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

TOOLS_DIR = os.path.join(os.path.dirname(os.path.abspath(__file__)), "TOOLS")
LIVE_DIR  = os.path.join(TOOLS_DIR, "live")

AUTH_WARNING = """
╔══════════════════════════════════════════════════════════╗
║          ⚠  AUTHORIZATION REQUIRED ⚠                    ║
║                                                          ║
║  Only run against apps you own or have explicit written  ║
║  permission to test. Unauthorized scanning is illegal.   ║
║                                                          ║
║  Pass --authorized to confirm you have permission.       ║
╚══════════════════════════════════════════════════════════╝
"""


def run_tool(script, extra_args):
    """Run a tool subprocess. Extra flags (--delay, --timeout) are NOT forwarded
    here — the live/ tools accept them directly; the TOOLS/ tools use their own defaults."""
    cmd = [sys.executable, script] + extra_args
    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    subprocess.run(cmd, env=env)


def is_https(url):
    return urlparse(url).scheme == "https"


def run_vibe_live():
    parser = argparse.ArgumentParser(
        description=f"🌐 VIBE LIVE v{VERSION} — Remote-Safe Security Toolkit",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("--version", action="version", version=f"VIBE LIVE {VERSION}")

    sub = parser.add_subparsers(dest="command")

    # ── scan ──────────────────────────────────────────────────────────────────
    scan_p = sub.add_parser("scan", help="Full passive scan chain (requires --authorized)")
    scan_p.add_argument("url", help="Target URL (e.g. https://example.com)")
    scan_p.add_argument("--authorized", action="store_true",
                        help="Confirm you have permission to test this target")
    scan_p.add_argument("--delay",   type=float, default=0.7, help="Seconds between requests (default: 0.7)")
    scan_p.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout (default: 10)")
    scan_p.add_argument("--no-verify", action="store_true", help="Skip SSL cert verification")

    # ── individual tools ───────────────────────────────────────────────────────
    for name, help_text in [
        ("headers",  "HTTP security headers audit"),
        ("ssl",      "SSL/TLS certificate & cipher audit (HTTPS only)"),
        ("cors",     "CORS misconfiguration scan"),
        ("waf",      "WAF / firewall detection"),
        ("ghost",    "Sensitive asset & exposed file discovery"),
        ("redirect", "Open redirect scan"),
        ("sql",      "SQL injection probe"),
        ("leep",     "Auth bypass / logic flaw probe"),
    ]:
        p = sub.add_parser(name, help=help_text)
        p.add_argument("url", help="Target URL")
        p.add_argument("--delay",   type=float, default=0.7)
        p.add_argument("--timeout", type=float, default=10.0)
        p.add_argument("--no-verify", action="store_true")

    # ── jwt ───────────────────────────────────────────────────────────────────
    jwt_p = sub.add_parser("jwt", help="JWT security analyzer (static + optional replay)")
    jwt_p.add_argument("--token",    required=True, help="JWT token to analyze")
    jwt_p.add_argument("--endpoint", default=None,  help="Optional URL to replay forged tokens against")
    jwt_p.add_argument("--delay",    type=float, default=0.7)
    jwt_p.add_argument("--timeout",  type=float, default=10.0)
    jwt_p.add_argument("--no-verify", action="store_true")

    # ── timing ────────────────────────────────────────────────────────────────
    timing_p = sub.add_parser("timing", help="Timing attack / user enumeration detector")
    timing_p.add_argument("url",     help="Login endpoint URL")
    timing_p.add_argument("--email", required=True, help="A real known email on the target")
    timing_p.add_argument("--field-email", default="email")
    timing_p.add_argument("--field-pass",  default="password")
    timing_p.add_argument("--rounds",   type=int,   default=6)
    timing_p.add_argument("--threshold", type=float, default=150.0)
    timing_p.add_argument("--delay",     type=float, default=0.5)
    timing_p.add_argument("--timeout",   type=float, default=10.0)
    timing_p.add_argument("--no-verify", action="store_true")

    # ── header-inject ─────────────────────────────────────────────────────────
    hi_p = sub.add_parser("header-inject", help="HTTP header injection & host poisoning")
    hi_p.add_argument("url",   help="Target base URL")
    hi_p.add_argument("--path",    default="/", help="Path to probe (default: /)")
    hi_p.add_argument("--delay",   type=float, default=0.7)
    hi_p.add_argument("--timeout", type=float, default=10.0)
    hi_p.add_argument("--no-verify", action="store_true")

    # ── list ──────────────────────────────────────────────────────────────────
    sub.add_parser("list", help="List all available live tools")

    args = parser.parse_args()

    # ── banner ────────────────────────────────────────────────────────────────
    if args.command != "list":
        print("=" * 56)
        print(f"  🌐 VIBE LIVE v{VERSION} — Remote-Safe Security Toolkit")
        print("=" * 56)

    # ── dispatch ──────────────────────────────────────────────────────────────
    if args.command == "scan":
        if not args.authorized:
            print(AUTH_WARNING)
            sys.exit(1)

        url = args.url
        d   = args.delay
        nv  = args.no_verify
        t   = args.timeout

        print(f"[*] Target: {url}")
        print(f"[*] Delay: {d}s  |  Timeout: {t}s  |  SSL verify: {not nv}\n")

        steps = [
            ("Phase 1: Security Headers",   "vibe_headers.py", ["--url", url]),
            ("Phase 3: CORS Scan",          "corscan.py",      ["--url", url]),
            ("Phase 4: WAF Detection",      "waf_detect.py",   ["--url", url]),
            ("Phase 5: Exposed Assets",     "ghost.py",        ["--url", url]),
            ("Phase 6: Open Redirects",     "redirect.py",     ["--url", url]),
            ("Phase 7: SQL Injection Probe","sql_probe.py",    ["--url", url]),
        ]

        for label, script, extra in steps:
            print(f"\n[*] {label}...")
            run_tool(os.path.join(TOOLS_DIR, script), extra)
            time.sleep(1.0)

        if is_https(url):
            print("\n[*] Phase 2: SSL/TLS Audit...")
            run_tool(os.path.join(TOOLS_DIR, "ssl_audit.py"), ["--url", url])
            time.sleep(1.0)

        print("\n[+] Live scan complete. See logs/ for detailed findings.")

    elif args.command == "headers":
        run_tool(os.path.join(TOOLS_DIR, "vibe_headers.py"), ["--url", args.url])

    elif args.command == "ssl":
        if not is_https(args.url):
            print("[!] SSL audit requires an https:// URL.")
            sys.exit(1)
        run_tool(os.path.join(TOOLS_DIR, "ssl_audit.py"), ["--url", args.url])

    elif args.command == "cors":
        run_tool(os.path.join(TOOLS_DIR, "corscan.py"), ["--url", args.url])

    elif args.command == "waf":
        run_tool(os.path.join(TOOLS_DIR, "waf_detect.py"), ["--url", args.url])

    elif args.command == "ghost":
        run_tool(os.path.join(TOOLS_DIR, "ghost.py"), ["--url", args.url])

    elif args.command == "redirect":
        run_tool(os.path.join(TOOLS_DIR, "redirect.py"), ["--url", args.url])

    elif args.command == "sql":
        run_tool(os.path.join(TOOLS_DIR, "sql_probe.py"), ["--url", args.url])

    elif args.command == "leep":
        run_tool(os.path.join(TOOLS_DIR, "leep.py"), ["--url", args.url])

    elif args.command == "jwt":
        extra = ["--token", args.token]
        if args.endpoint:
            extra += ["--endpoint", args.endpoint]
        run_tool(os.path.join(TOOLS_DIR, "jwt_forge.py"), extra)

    elif args.command == "timing":
        run_tool(
            os.path.join(LIVE_DIR, "live_timebomb.py"),
            ["--url", args.url, "--email", args.email,
             "--field-email", args.field_email, "--field-pass", args.field_pass,
             "--rounds", str(args.rounds), "--threshold", str(args.threshold),
             "--delay", str(args.delay), "--timeout", str(args.timeout)]
            + (["--no-verify"] if args.no_verify else []),
        )

    elif args.command == "header-inject":
        run_tool(
            os.path.join(LIVE_DIR, "live_headers.py"),
            ["--url", args.url, "--path", args.path,
             "--delay", str(args.delay), "--timeout", str(args.timeout)]
            + (["--no-verify"] if args.no_verify else []),
        )

    elif args.command == "list":
        print("=" * 56)
        print(f"  🌐 VIBE LIVE v{VERSION} — Available Commands")
        print("=" * 56)
        commands = [
            ("scan <URL> --authorized", "Full 7-phase passive scan chain"),
            ("headers <URL>",           "HTTP security headers audit"),
            ("ssl <URL>",               "SSL/TLS cert & cipher audit (HTTPS)"),
            ("cors <URL>",              "CORS misconfiguration scan"),
            ("waf <URL>",               "WAF / firewall detection"),
            ("ghost <URL>",             "Sensitive asset & exposed file discovery"),
            ("redirect <URL>",          "Open redirect scan (15 params)"),
            ("sql <URL>",               "SQL injection probe"),
            ("leep <URL>",              "Auth bypass / logic flaw probe"),
            ("jwt --token <JWT>",       "JWT security analyzer"),
            ("timing <URL> --email X",  "Timing attack / user enumeration"),
            ("header-inject <URL>",     "Header injection & host poisoning"),
        ]
        for cmd, desc in commands:
            print(f"  vibe_live.py {cmd:<32} — {desc}")
        print("\n  Global flags: --delay --timeout --no-verify")
        print("  All tools write to logs/ alongside the localhost tools.")

    else:
        parser.print_help()


if __name__ == "__main__":
    run_vibe_live()
