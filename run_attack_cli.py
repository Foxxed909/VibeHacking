#!/usr/bin/env python3
"""CLI entry for the full attack chain (authcheck + phases + redteam + findings JSON).

Also used by `python -m vb.cli attack ...` so the internal arsenal is one command.
"""
import argparse
import ipaddress
import os
import subprocess
import sys
import urllib.parse

ROOT = os.path.dirname(os.path.abspath(__file__))
TOOLS = os.path.join(ROOT, "TOOLS")
sys.path.insert(0, TOOLS)

from privacy_guard import sanitize_text  # noqa: E402
from attack_run import run_attack  # noqa: E402


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


def _read_version():
    try:
        with open(os.path.join(ROOT, "VERSION"), encoding="utf-8") as f:
            return f.read().strip() or "1.0.0"
    except OSError:
        return "1.0.0"


def _normalize_host(raw):
    host = (raw or "").strip()
    if not host:
        return ""
    if "://" in host:
        host = urllib.parse.urlparse(host).hostname or host
    host = host.split("/")[0].strip().lower()
    if "@" in host:
        host = host.split("@")[-1]
    if host.count(":") == 1:
        host = host.split(":")[0]
    return host


def _is_local_or_private(host):
    if host in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_private or ip.is_link_local
    except ValueError:
        return False


def _read_trusted():
    path = os.path.join(ROOT, "authorized_targets.txt")
    hosts = []
    try:
        with open(path, encoding="utf-8") as handle:
            for line in handle:
                h = _normalize_host(line)
                if h and h not in hosts:
                    hosts.append(h)
    except OSError:
        pass
    return hosts


def _external_warning(host, rate_desc="", assume_yes=False):
    bar = "=" * 64
    print(bar)
    print("  EXTERNAL TARGET — ACTIVE LOAD TEST")
    print(bar)
    print(f"  Host : {host}")
    if rate_desc:
        print(f"  Rate : {rate_desc}")
    print("  Proceed ONLY if you own this host or have written permission.")
    print(bar)
    if assume_yes:
        print("  [--yes supplied: skipping interactive confirmation]")
        return True
    try:
        answer = input(f"  Type the hostname ({host}) to proceed, anything else to abort: ").strip().lower()
    except EOFError:
        return False
    return answer == host.lower()


ATTACK_PHASES = [
    ("Recon & Discovery", ["ash", "spider", "ghost", "api_finder", "cloud_scout"]),
    ("Headers & Transport", ["vibe_headers", "corscan", "phantom", "header_inject"]),
    ("Auth & Access Control", ["leep", "aukdoc", "axios", "random_roll"]),
    ("Injection & Input", ["authdoc", "fuzz_vibe", "biz_logic", "redirect",
                            "traversal_sniper", "ssrf_probe", "prompt_injector", "timebomb"]),
    ("Secrets & Data Exposure", ["env_probe", "deep_extract", "key_stealer", "credit_drain"]),
]


def main(argv=None):
    p = argparse.ArgumentParser(description="VibeHacking full attack chain")
    p.add_argument("url", help="Target URL you own / are authorized to test")
    p.add_argument("--skip-load", action="store_true")
    p.add_argument("--yes", action="store_true")
    p.add_argument("--user", default="")
    p.add_argument("--pass", dest="password", default="")
    p.add_argument("--user-field", default="username")
    p.add_argument("--skip-redteam", action="store_true")
    p.add_argument("--json-out", default="", help="Path for findings JSON (default logs/findings-<ts>.json)")
    args = p.parse_args(argv)

    url = args.url
    host = _normalize_host(url)
    print("================================")
    print(f" VIBE HACKING ATTACK v{_read_version()}")
    print("================================")
    print(f"[*] Full-spectrum attack run against {sanitize_text(url)}")
    print(f"    Target host: {host or '(unparsed)'}")

    return run_attack({
        "url": url,
        "host": host,
        "skip_load": bool(args.skip_load),
        "yes": bool(args.yes),
        "user": args.user or "",
        "password": args.password or "",
        "user_field": args.user_field or "username",
        "skip_redteam": bool(args.skip_redteam),
        "json_out": args.json_out or "",
        "run_tool": run_tool,
        "run_command": run_command,
        "ROOT_DIR": ROOT,
        "TOOLS_DIR": TOOLS,
        "ATTACK_PHASES": ATTACK_PHASES,
        "version": _read_version(),
        "is_local_or_private": _is_local_or_private,
        "read_trusted": _read_trusted,
        "external_warning": _external_warning,
        "sanitize_text": sanitize_text,
    })


if __name__ == "__main__":
    raise SystemExit(main() or 0)
