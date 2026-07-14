import sys
import argparse
import concurrent.futures
import subprocess
import os
import json
import ipaddress
import re
import time
import urllib.parse

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
TOOLS_DIR = os.path.join(ROOT_DIR, "TOOLS")
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
MAX_MULTI_TARGETS = 14
MAX_MULTI_JOBS = 10
DEFAULT_MULTI_JOBS = 4

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")


def run_command(args, cwd=None, env_extra=None, capture=False):
    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    if env_extra:
        env.update(env_extra)
    kwargs = {}
    if capture:
        kwargs.update({
            "capture_output": True,
            "text": True,
            "encoding": "utf-8",
            "errors": "replace",
        })
    try:
        return subprocess.run(args, cwd=cwd, env=env, **kwargs)
    except KeyboardInterrupt:
        print("\n[!] Interrupted by user. Stopped cleanly; no traceback.")
        return subprocess.CompletedProcess(args, 130)


def run_tool(args, env_extra=None, capture=False):
    return run_command([sys.executable, *args], env_extra=env_extra, capture=capture)


AUTHORIZED_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "authorized_targets.txt")

LOCAL_LITERALS = {"localhost", "127.0.0.1", "::1"}
MAX_EXTERNAL_MAELSTROM_RPS = 9999.99

# Ordered kill-chain for `vibe.py attack`. Each phase is (title, [tool stems]).
# Every listed tool runs non-interactively as: python TOOLS/<stem>.py --url <target>.
# Load/stress tools are NOT here — they run separately behind the trust + confirm gate.
ATTACK_PHASES = [
    ("Recon & Discovery", ["ash", "spider", "ghost", "api_finder", "cloud_scout"]),
    ("Headers & Transport", ["vibe_headers", "corscan", "phantom", "header_inject"]),
    ("Auth & Access Control", ["leep", "aukdoc", "axios", "random_roll"]),
    ("Injection & Input", ["authdoc", "fuzz_vibe", "biz_logic", "redirect",
                            "traversal_sniper", "ssrf_probe", "prompt_injector", "timebomb"]),
    ("Secrets & Data Exposure", ["env_probe", "deep_extract", "key_stealer", "credit_drain"]),
]


def _session_file():
    return os.environ.get("VIBE_SESSION_FILE") or os.path.join(ROOT_DIR, "vibe_session.json")


def _write_session(url):
    session_path = _session_file()
    session_dir = os.path.dirname(os.path.abspath(session_path))
    if session_dir:
        os.makedirs(session_dir, exist_ok=True)
    with open(session_path, "w", encoding="utf-8") as f:
        json.dump(sanitize_data({"target": url, "last_scan": str(os.times())}), f)


def _dedupe_keep_order(values):
    seen = set()
    out = []
    for value in values:
        key = value.strip()
        if key and key not in seen:
            seen.add(key)
            out.append(key)
    return out


def _load_multi_targets(targets, targets_file):
    loaded = list(targets or [])
    if targets_file:
        with open(targets_file, "r", encoding="utf-8") as handle:
            for line in handle:
                line = line.strip()
                if line and not line.startswith("#"):
                    loaded.append(line)
    return _dedupe_keep_order(loaded)


def _validate_http_url(url):
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return False
    return True


def _is_multi_local_target(url):
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    return bool(host and _is_local_or_private(host))


def _external_multi_warning(command, targets, assume_yes=False):
    hosts = []
    for target in targets:
        host = _normalize_host(target)
        if host and host not in hosts:
            hosts.append(host)

    bar = "=" * 64
    print(bar)
    print(f"  EXTERNAL TARGETS - AUTHORIZED MULTI {command.upper()}")
    print(bar)
    for host in hosts[:14]:
        print(f"  Host : {sanitize_text(host)}")
    if command == "attack":
        print("  This mode runs the audit toolchain with --skip-load forced.")
    else:
        print("  This mode runs the scan toolchain only.")
    print("  Multi load/stress commands stay blocked for public targets.")
    print("  Proceed only for sites you own or have written permission to test.")
    print(bar)
    if assume_yes:
        print("  [--yes supplied: skipping interactive confirmation]")
        return True
    try:
        answer = input("  Type I AM AUTHORIZED to proceed, anything else to abort: ").strip()
    except EOFError:
        return False
    if answer == "I AM AUTHORIZED":
        return True
    print("  Aborted - confirmation did not match.")
    return False


def _target_slug(index, url):
    parsed = urllib.parse.urlparse(url)
    host = parsed.hostname or "target"
    port = f"-{parsed.port}" if parsed.port else ""
    path = parsed.path.strip("/").replace("/", "-")
    base = f"{host}{port}-{path}" if path else f"{host}{port}"
    base = re.sub(r"[^A-Za-z0-9._-]+", "-", base).strip("-").lower()
    return f"{index:02d}-{(base or 'target')[:80]}"


def _format_rate(rate):
    if abs(rate - round(rate)) < 0.0001:
        return str(int(round(rate)))
    return f"{rate:.4f}".rstrip("0").rstrip(".")


def _split_total_rate(raw_rate, target_count):
    if not raw_rate:
        return ""
    parsed = _parse_maelstrom_rate(raw_rate)
    if parsed is None or parsed <= 0:
        return raw_rate
    return _format_rate(parsed / max(1, target_count))


def _split_total_workers(raw_workers, target_count):
    if raw_workers in (None, ""):
        return ""
    workers = max(1, int(raw_workers))
    return str(max(1, workers // max(1, target_count)))


def _build_multi_command(args, target, target_count):
    if args.multi_command == "scan":
        return [sys.executable, os.path.join(ROOT_DIR, "vibe.py"), "scan", target]

    if args.multi_command == "attack":
        cmd = [sys.executable, os.path.join(ROOT_DIR, "vibe.py"), "attack", target]
        if args.skip_load or not _is_multi_local_target(target):
            cmd.append("--skip-load")
        return cmd

    if args.multi_command == "maelstrom":
        cmd = [sys.executable, os.path.join(ROOT_DIR, "vibe.py"), "maelstrom", "-t", target]
        if args.duration:
            cmd += ["-d", args.duration]
        rate = args.rate
        if args.rate_mode == "total":
            rate = _split_total_rate(args.rate, target_count)
        if rate:
            cmd += ["-r", rate]
        workers = args.workers
        if args.worker_mode == "total":
            workers = _split_total_workers(args.workers, target_count)
        if workers:
            cmd += ["-w", str(workers)]
        if args.method:
            cmd += ["-m", args.method]
        if args.timeout:
            cmd += ["--timeout", args.timeout]
        if args.payload:
            cmd += ["-p", args.payload]
        for header in args.header or []:
            cmd += ["-H", header]
        return cmd

    raise ValueError(f"unsupported multi command: {args.multi_command}")


def _run_one_multi_target(args, target, index, target_count, run_dir):
    target_dir = os.path.join(run_dir, _target_slug(index, target))
    os.makedirs(target_dir, exist_ok=True)
    env = {
        "VIBE_LOG_DIR": target_dir,
        "VIBE_SESSION_FILE": os.path.join(target_dir, "vibe_session.json"),
    }
    cmd = _build_multi_command(args, target, target_count)
    if args.dry_run:
        return {
            "target": target,
            "target_dir": target_dir,
            "returncode": 0,
            "cmd": cmd,
            "dry_run": True,
        }

    result = run_command(cmd, cwd=ROOT_DIR, env_extra=env, capture=True)
    stdout_path = os.path.join(target_dir, "stdout.log")
    stderr_path = os.path.join(target_dir, "stderr.log")
    with open(stdout_path, "w", encoding="utf-8") as handle:
        handle.write(result.stdout or "")
    with open(stderr_path, "w", encoding="utf-8") as handle:
        handle.write(result.stderr or "")
    return {
        "target": target,
        "target_dir": target_dir,
        "returncode": result.returncode,
        "cmd": cmd,
        "dry_run": False,
    }


def _run_multi(args):
    target_values = list(args.target or []) + list(args.targets or [])
    try:
        targets = _load_multi_targets(target_values, args.targets_file)
    except OSError as exc:
        print(f"[-] Could not read targets file: {exc}")
        return 2

    if not targets:
        print("[-] No targets provided. Use --target, --targets, or --targets-file.")
        return 2

    # Plan-aware caps (honor-system). Dry-run is a free preview (no execution),
    # so it keeps the global ceiling. Falls back to the global ceiling if the
    # plans module can't be loaded for any reason.
    max_targets, max_jobs = MAX_MULTI_TARGETS, MAX_MULTI_JOBS
    if not args.dry_run:
        try:
            from vb import plans
            plan_targets, plan_jobs = plans.multi_caps()
            max_targets = min(max_targets, plan_targets)
            max_jobs = min(max_jobs, plan_jobs)
        except Exception:
            pass

    if len(targets) > max_targets:
        print(f"[-] Refusing {len(targets)} targets. Your plan caps multi runs at {max_targets}.")
        print("    Raise it with a higher Vibe plan, or run `vibe unlock <code>`.")
        return 2

    invalid = [url for url in targets if not _validate_http_url(url)]
    if invalid:
        print(f"[-] Invalid target URL(s): {', '.join(sanitize_text(u) for u in invalid[:5])}")
        print("    Use full http(s) URLs, e.g. http://127.0.0.1:3000/")
        return 2

    non_local = [url for url in targets if not _is_multi_local_target(url)]
    external_audit_allowed = (
        args.multi_command in {"scan", "attack"}
        and getattr(args, "allow_external", False)
    )
    if non_local and not external_audit_allowed:
        print("[-] Multi-target launch is local/private only.")
        for url in non_local[:5]:
            print(f"    Refused: {sanitize_text(url)}")
        print("    Use localhost/private targets, or `multi scan|attack --allow-external` for authorized external audit runs.")
        return 2
    if non_local and not args.dry_run:
        if not _external_multi_warning(args.multi_command, non_local, assume_yes=getattr(args, "yes", False)):
            return 2

    jobs = int(args.jobs or DEFAULT_MULTI_JOBS)
    if jobs < 1 or jobs > max_jobs:
        print(f"[-] --jobs must be between 1 and {max_jobs} on your plan.")
        return 2
    jobs = min(jobs, len(targets))

    run_id = time.strftime("%Y%m%d-%H%M%S")
    run_dir = os.path.join(ROOT_DIR, "logs", "multi", f"{args.multi_command}-{run_id}")
    os.makedirs(run_dir, exist_ok=True)

    scope = "authorized external" if non_local else "local/private"
    print(f"[*] {scope} multi {args.multi_command}: {len(targets)} target(s), jobs={jobs}")
    print(f"[*] Artifacts: {run_dir}")
    sys.stdout.flush()

    if args.dry_run:
        print("[*] Dry run only; no child processes will launch.")

    results = []
    try:
        with concurrent.futures.ThreadPoolExecutor(max_workers=jobs) as pool:
            future_map = {
                pool.submit(_run_one_multi_target, args, target, i, len(targets), run_dir): target
                for i, target in enumerate(targets, start=1)
            }
            for future in concurrent.futures.as_completed(future_map):
                item = future.result()
                results.append(item)
                cmd_text = " ".join(item["cmd"])
                if item["dry_run"]:
                    print(f"[DRY] {sanitize_text(item['target'])}")
                    print(f"      {sanitize_text(cmd_text)}")
                    continue
                status = "PASS" if item["returncode"] == 0 else "FAIL"
                print(
                    f"[{status}] rc={item['returncode']} "
                    f"target={sanitize_text(item['target'])} artifacts={item['target_dir']}"
                )
                sys.stdout.flush()
    except KeyboardInterrupt:
        print("\n[!] Interrupted. Already-started child processes may still be draining.")
        return 130

    failed = [item for item in results if item["returncode"] != 0]
    if failed:
        print(f"[-] Multi run completed with {len(failed)} failing target(s).")
        return 1
    print("[+] Multi run complete.")
    return 0


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


def _parse_maelstrom_rate(raw):
    value = (raw or "1000").strip().lower()
    if value in {"0", "full", "full-send", "max"}:
        return 0.0

    per_minute = False
    for suffix in ("/min", "rpm", "permin", "per-minute"):
        if value.endswith(suffix):
            per_minute = True
            value = value[: -len(suffix)]
            break
    for suffix in ("/s", "rps", "persec", "per-second"):
        if value.endswith(suffix):
            value = value[: -len(suffix)]
            break

    multiplier = 1.0
    if value.endswith("k"):
        multiplier = 1_000.0
        value = value[:-1]
    elif value.endswith("m"):
        multiplier = 1_000_000.0
        value = value[:-1]
    elif value.endswith("g"):
        multiplier = 1_000_000_000.0
        value = value[:-1]

    try:
        rate = float(value) * multiplier
    except ValueError:
        return None
    if per_minute:
        rate /= 60.0
    return rate


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

    # Command: attack — full ordered kill-chain (every audit tool, then gated load phase)
    attack_parser = subparsers.add_parser("attack", help="Run every tool in phase order against a URL")
    attack_parser.add_argument("url", help="Target URL (e.g. https://your-app.com/)")
    attack_parser.add_argument("--skip-load", action="store_true", help="Skip the load/stress phase entirely")
    attack_parser.add_argument("--yes", action="store_true", help="Skip the external-target confirmation for the load phase")

    # Command: report
    report_parser = subparsers.add_parser("report", help="Generate the LMX Executive Dashboard")

    # Command: privacy
    privacy_parser = subparsers.add_parser("privacy", help="Show tester privacy controls and limits")

    # Command: clean
    clean_parser = subparsers.add_parser("clean", help="Run the Environment Cleaner (Void)")
    clean_parser.add_argument("--db", help="Path to target database")

    # Command: noloader
    noloader_parser = subparsers.add_parser("noloader", help="Verify that a URL stays unavailable for a time window")
    noloader_parser.add_argument(
        "noloader_args",
        nargs=argparse.REMAINDER,
        help="Arguments forwarded to NoLoader, e.g. -urlx https://example.com t-60 -f 3 -fx 7",
    )

    # Command: senoria
    senoria_parser = subparsers.add_parser("senoria", help="Find leaked API keys in served public web assets")
    senoria_parser.add_argument(
        "senoria_args",
        nargs=argparse.REMAINDER,
        help="Arguments forwarded to Senoria, e.g. --scan localhost --i 4 -w 72",
    )

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

    # Command: multi
    multi_parser = subparsers.add_parser("multi", help="Run scan/attack/maelstrom across local/private targets in parallel")
    multi_sub = multi_parser.add_subparsers(dest="multi_command")

    def add_multi_target_args(p):
        p.add_argument("--target", action="append", default=[], help="Local/private target URL. Repeatable.")
        p.add_argument("--targets", nargs="+", default=[], help="Local/private target URLs")
        p.add_argument("--targets-file", default="", help="File containing one local/private URL per line")
        p.add_argument("--jobs", type=int, default=DEFAULT_MULTI_JOBS, help=f"Parallel child processes, 1-{MAX_MULTI_JOBS}")
        p.add_argument("--dry-run", action="store_true", help="Print child commands without launching them")

    multi_scan = multi_sub.add_parser("scan", help="Run the deep scan against multiple local/private URLs")
    add_multi_target_args(multi_scan)
    multi_scan.add_argument("--allow-external", action="store_true", help="Allow authorized public targets for look-only scans")
    multi_scan.add_argument("--yes", action="store_true", help="Skip the external-target confirmation for scripted authorized scans")

    multi_attack = multi_sub.add_parser("attack", help="Run the ordered attack flow against multiple local/private URLs")
    add_multi_target_args(multi_attack)
    multi_attack.add_argument("--skip-load", action="store_true", help="Skip the load/stress phase inside each attack run")
    multi_attack.add_argument("--allow-external", action="store_true", help="Allow authorized public targets; --skip-load is forced")
    multi_attack.add_argument("--yes", action="store_true", help="Skip the external-target confirmation for scripted authorized attacks")

    multi_maelstrom = multi_sub.add_parser("maelstrom", help="Run Maelstrom against multiple local/private URLs")
    add_multi_target_args(multi_maelstrom)
    multi_maelstrom.add_argument("-d", "--duration", default="", help="Test duration, e.g. 10s")
    multi_maelstrom.add_argument("-r", "--rate", default="", help="Target rate. Default rate mode splits this total across targets.")
    multi_maelstrom.add_argument("-w", "--workers", default="", help="Worker count. Default worker mode splits this total across targets.")
    multi_maelstrom.add_argument("--rate-mode", choices=("total", "per-target"), default="total", help="Treat -r as total budget or per-target budget")
    multi_maelstrom.add_argument("--worker-mode", choices=("total", "per-target"), default="total", help="Treat -w as total workers or per-target workers")
    multi_maelstrom.add_argument("-m", "--method", default="", help="HTTP method")
    multi_maelstrom.add_argument("--timeout", default="", help="Per-request timeout")
    multi_maelstrom.add_argument("-p", "--payload", default="", help="Optional payload file")
    multi_maelstrom.add_argument("-H", "--header", action="append", default=[], help="Custom header, e.g. 'Name: value'. Repeatable.")

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

    argv = sys.argv[1:]
    if argv[:1] == ["--noloader"]:
        argv = ["noloader", *argv[1:]]

    if argv[:1] == ["maelstrom"]:
        raw_maelstrom_args = argv[1:]
        args = parser.parse_args(["maelstrom"])
        args.maelstrom_args = raw_maelstrom_args[1:] if raw_maelstrom_args[:1] == ["--"] else raw_maelstrom_args
    elif argv[:1] == ["noloader"]:
        raw_noloader_args = argv[1:]
        args = parser.parse_args(["noloader"])
        args.noloader_args = raw_noloader_args[1:] if raw_noloader_args[:1] == ["--"] else raw_noloader_args
    elif argv[:1] == ["senoria"]:
        raw_senoria_args = argv[1:]
        args = parser.parse_args(["senoria"])
        args.senoria_args = raw_senoria_args[1:] if raw_senoria_args[:1] == ["--"] else raw_senoria_args
    else:
        args = parser.parse_args(argv)

    if args.command != "codex":
        print("================================")
        print(f" VIBE HACKING COMMAND CENTER v{VERSION}")
        print("================================")
        sys.stdout.flush()

    if args.command == "multi":
        if not args.multi_command:
            multi_parser.print_help()
            return 2
        return _run_multi(args)

    if args.command == "scan":
        print(f"[*] Starting Real-World Audit of {sanitize_text(args.url)}...")
        
        # Save current target to session
        _write_session(args.url)

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

    elif args.command == "attack":
        url = args.url
        host = _normalize_host(url)
        print(f"[*] Full-spectrum attack run against {sanitize_text(url)}")
        print(f"    Target host: {host or '(unparsed)'}")

        _write_session(url)

        executed = 0
        flagged = []  # tools that exited non-zero (error OR finding — check logs)
        for phase_num, (title, tools) in enumerate(ATTACK_PHASES, start=1):
            print("\n" + "=" * 60)
            print(f"  PHASE {phase_num}: {title.upper()}")
            print("=" * 60)
            for tool in tools:
                print(f"\n[*] -> {tool}")
                sys.stdout.flush()
                rc = run_tool([f"TOOLS/{tool}.py", "--url", url]).returncode
                executed += 1
                if rc not in (0, None):
                    flagged.append(tool)

        # Load & stress phase — gated behind trust + typed confirmation for external hosts.
        load_phase = len(ATTACK_PHASES) + 1
        if args.skip_load:
            print(f"\n[i] Phase {load_phase} (Load & Stress) skipped (--skip-load).")
        else:
            print("\n" + "=" * 60)
            print(f"  PHASE {load_phase}: LOAD & STRESS")
            print("=" * 60)
            run_load = True
            if host and not _is_local_or_private(host):
                if host not in _read_trusted():
                    print(f"[-] {host} is not in the authorized load-test allowlist. Skipping load phase.")
                    print(f"    Authorize it first (only if you own it):  python vibe.py trust add {host}")
                    run_load = False
                elif not _external_warning(host, rate_desc="storm 600/min + vibe_api + maelstrom 50 rps", assume_yes=args.yes):
                    print("[-] Load phase aborted — confirmation did not match.")
                    run_load = False
            if run_load:
                print("\n[*] -> storm (safe single-probe check)")
                sys.stdout.flush()
                run_tool(["TOOLS/storm.py", "--url", url, "--url-check"])
                print("\n[*] -> storm (stress)")
                sys.stdout.flush()
                run_tool(["TOOLS/storm.py", "--url", url, "--duration", "15",
                          "--entries-per-min", "600", "--concurrency", "20", "--timeout", "5", "--yes"])
                print("\n[*] -> vibe_api (JSON endpoint stress)")
                sys.stdout.flush()
                run_tool(["TOOLS/vibe_api.py", "--url", url])
                print("\n[*] -> maelstrom (Go load tester)")
                sys.stdout.flush()
                run_command(["go", "run", ".", "-t", url, "-d", "15s", "-r", "50", "-w", "32"],
                            cwd=os.path.join("TOOLS", "maelstrom"))

        # Reporting & receipts.
        print("\n" + "=" * 60)
        print("  PHASE: REPORTING & RECEIPTS")
        print("=" * 60)
        print("\n[*] -> poc_gen")
        run_tool(["TOOLS/poc_gen.py", "--url", url])
        print("\n[*] -> lmx executive dashboard")
        run_tool(["TOOLS/lmx.py"])
        print("\n[*] -> backer (session backup)")
        run_tool(["TOOLS/backer.py"])

        print("\n" + "=" * 60)
        print(f"[+] Attack run complete. {executed} audit tools executed across {len(ATTACK_PHASES)} phases.")
        if flagged:
            print(f"[!] Exited non-zero (error or finding — check logs/): {', '.join(flagged)}")
        print("    Findings in logs/, dashboard in reports/. Re-run after patching to confirm fixes.")
        return 0

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

    elif args.command == "noloader":
        forwarded = list(args.noloader_args)
        if forwarded and forwarded[0] == "--":
            forwarded = forwarded[1:]
        print("[*] Launching NoLoader URL verifier...")
        sys.stdout.flush()
        return run_tool(["TOOLS/noloader.py", *forwarded]).returncode

    elif args.command == "senoria":
        forwarded = list(args.senoria_args)
        if forwarded and forwarded[0] == "--":
            forwarded = forwarded[1:]
        print("[*] Launching Senoria leaked-API audit...")
        sys.stdout.flush()
        return run_tool(["TOOLS/senoria.py", *forwarded]).returncode

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
        sys.stdout.flush()
        return run_tool(cmd).returncode

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
                return 2
            rate = _extract_flag(forwarded, ("-r", "--rate")) or "1000 (default)"
            parsed_rate = _parse_maelstrom_rate(rate)
            if parsed_rate is not None and (parsed_rate <= 0 or parsed_rate > MAX_EXTERNAL_MAELSTROM_RPS):
                print(f"[-] Refusing unsafe public-host rate: {rate} ({parsed_rate:.2f} rps).")
                print(f"    External Maelstrom runs are capped at {MAX_EXTERNAL_MAELSTROM_RPS:g} rps; use localhost/private labs for high-rate tests.")
                return 2
            if not _external_warning(host, rate_desc=f"{rate} rps", assume_yes=assume_yes):
                return 2

        print("[*] Launching Maelstrom load test...")
        return run_command(["go", "run", ".", *forwarded], cwd=os.path.join("TOOLS", "maelstrom")).returncode

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
        session_path = _session_file()
        if os.path.exists(session_path):
            with open(session_path, "r", encoding="utf-8") as f:
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
    sys.exit(run_vibe() or 0)
