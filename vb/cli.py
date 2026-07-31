#!/usr/bin/env python3
import json
import os
import subprocess
import sys
import textwrap
import time


ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS_DIR = os.path.join(ROOT, "TOOLS")
LOCKED_MANIFEST = os.path.join(ROOT, "vb", "locked", "manifest.json")
LOG_DIR = os.path.join(ROOT, "logs")

VIBE_COMMANDS = {
    "scan",
    "report",
    "privacy",
    "clean",
    "noloader",
    "storm",
    "maelstrom",
    "multi",
    "trust",
    "status",
    "list",
    "codex",
}

NON_RUNNABLE = {
    "vibe_core",
    "privacy_guard",
    "add_version_flags",
    "run_lmx",
}

MENU_ITEMS = [
    ("Deep scan", "scan"),
    ("NoLoader availability window", "noloader"),
    ("Ash domain recon", "ash"),
    ("Spider attack-surface crawl", "spider"),
    ("Header security audit", "vibe_headers"),
    ("Ghost sensitive asset finder", "ghost"),
    ("Leep auth-flow audit", "leep"),
    ("Storm URL check", "storm_check"),
    ("Report dashboard", "report"),
    ("Privacy controls", "privacy"),
    ("Trusted target list", "trust_list"),
    ("Locked tools", "locked"),
]


def _configure_stdio():
    for stream in (sys.stdout, sys.stderr):
        if hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def _run(args, cwd=ROOT):
    env = os.environ.copy()
    env.setdefault("PYTHONIOENCODING", "utf-8")
    try:
        return subprocess.run(args, cwd=cwd, env=env).returncode
    except KeyboardInterrupt:
        print("\n[!] Interrupted.")
        return 130


def _tool_names():
    if not os.path.isdir(TOOLS_DIR):
        return []
    names = []
    for entry in os.listdir(TOOLS_DIR):
        path = os.path.join(TOOLS_DIR, entry)
        if entry.endswith(".py") and os.path.isfile(path):
            name = entry[:-3]
            if name not in NON_RUNNABLE:
                names.append(name)
    if os.path.isdir(os.path.join(TOOLS_DIR, "maelstrom")):
        names.append("maelstrom")
    return sorted(set(names))


def _load_locked_manifest():
    try:
        with open(LOCKED_MANIFEST, "r", encoding="utf-8") as handle:
            return json.load(handle)
    except (OSError, json.JSONDecodeError):
        return {"locked_tools": {}}


def _locked_tools():
    manifest = _load_locked_manifest()
    return manifest.get("locked_tools", {})


def _log_locked_access(tool, allowed, detail):
    os.makedirs(LOG_DIR, exist_ok=True)
    stamp = time.strftime("%Y-%m-%d %H:%M:%S")
    line = f"{stamp}\ttool={tool}\tallowed={str(allowed).lower()}\tdetail={detail}\n"
    with open(os.path.join(LOG_DIR, "locked_cli_access.log"), "a", encoding="utf-8") as handle:
        handle.write(line)


def _confirm_locked(tool):
    locked = _locked_tools()
    meta = locked.get(tool, {})
    reason = meta.get("reason", "high-impact authorized-testing tool")
    phrase = "I OWN THIS TARGET"

    print("=" * 64)
    print("LOCKED AUTHORIZED-ONLY TOOL")
    print(f"Tool   : {tool}")
    print(f"Reason : {reason}")
    print("Run this only on systems you own or have written permission to test.")
    print("Access is logged locally in logs/locked_cli_access.log.")
    print("=" * 64)
    sys.stdout.flush()

    if os.environ.get("VIBE_LOCKED_ACK") == phrase:
        _log_locked_access(tool, True, "env_ack")
        return True

    if not sys.stdin.isatty():
        _log_locked_access(tool, False, "noninteractive")
        print("[-] Locked tool refused in non-interactive mode.")
        return False

    try:
        answer = input(f"Type exactly '{phrase}' to continue: ").strip()
    except EOFError:
        _log_locked_access(tool, False, "eof")
        return False

    allowed = answer == phrase
    _log_locked_access(tool, allowed, "typed_ack" if allowed else "bad_ack")
    if not allowed:
        print("[-] Locked tool refused.")
    return allowed


def _route_vibe(args):
    return _run([sys.executable, os.path.join(ROOT, "vibe.py"), *args])


def _run_tool(tool, args):
    help_only = any(arg in {"-h", "--help", "-v", "--version"} for arg in args)
    if tool in _locked_tools() and not help_only and not _confirm_locked(tool):
        return 2

    if tool in VIBE_COMMANDS:
        return _route_vibe([tool, *args])

    if tool == "maelstrom":
        return _route_vibe(["maelstrom", *args])

    script = os.path.join(TOOLS_DIR, f"{tool}.py")
    if os.path.isfile(script):
        return _run([sys.executable, script, *args])

    print(f"[-] Unknown tool: {tool}")
    print("    Run `vibe list` to see available tools.")
    return 2


def _print_help():
    print(
        textwrap.dedent(
            f"""
            VibeHacking CLI

            Usage:
              vibe /                         Open the interactive picker
              vibe list                      List runnable tools
              vibe run <tool> [args...]      Run a tool from anywhere
              vibe <tool> [args...]          Shortcut for runnable tools
              vibe locked                    Show locked authorized-only tools
              vibe trust add <host>          Authorize a host you own

            Examples:
              vibe / 
              vibe scan http://127.0.0.1:5500/
              vibe noloader -urlx https://example.com t-60 -f 3
              vibe ash --url https://example.com
              vibe multi scan --targets http://127.0.0.1:3000 http://127.0.0.1:4000 --jobs 2
              vibe multi scan --allow-external --targets https://your-owned-site.example --jobs 1
              vibe multi attack --allow-external --targets https://your-owned-site.example --jobs 1
              vibe multi maelstrom --targets http://127.0.0.1:3000 http://127.0.0.1:4000 -d 10s -r 50000 -w 64
              vibe locked run storm http://127.0.0.1:5500/ --url-check

            Root: {ROOT}
            """
        ).strip()
    )


def _print_tools(plain=False):
    names = _tool_names()
    locked = _locked_tools()
    if plain:
        for name in names:
            suffix = " [locked]" if name in locked else ""
            print(f"{name}{suffix}")
        return 0

    print("Available VibeHacking tools:")
    for name in names:
        suffix = " [locked]" if name in locked else ""
        print(f"  - {name}{suffix}")
    return 0


def _print_locked(plain=False):
    locked = _locked_tools()
    if not locked:
        print("No locked tools configured.")
        return 0

    if plain:
        for name in sorted(locked):
            print(name)
        return 0

    print("Locked authorized-only tools:")
    for name, meta in sorted(locked.items()):
        print(f"  - {name}: {meta.get('reason', 'high-impact tool')}")
    print("\nRun through the CLI with: vibe locked run <tool> [args...]")
    print("This gate is explicit safety friction, not a secret or an encryption layer.")
    return 0


def _prompt(text, default=""):
    suffix = f" [{default}]" if default else ""
    value = input(f"{text}{suffix}: ").strip()
    return value or default


def _clear_screen():
    if sys.stdout.isatty():
        os.system("cls" if os.name == "nt" else "clear")


def _picker(options):
    if not sys.stdin.isatty() or not sys.stdout.isatty():
        for i, (label, _action) in enumerate(options, 1):
            print(f"{i}. {label}")
        choice = input("Pick a number: ").strip()
        try:
            index = int(choice) - 1
        except ValueError:
            return None
        return options[index][1] if 0 <= index < len(options) else None

    if os.name != "nt":
        for i, (label, _action) in enumerate(options, 1):
            print(f"{i}. {label}")
        choice = input("Pick a number: ").strip()
        try:
            index = int(choice) - 1
        except ValueError:
            return None
        return options[index][1] if 0 <= index < len(options) else None

    import msvcrt

    index = 0
    while True:
        _clear_screen()
        print("VibeHacking picker")
        print("Use Up/Down, Enter to run, Esc to cancel.\n")
        for i, (label, _action) in enumerate(options):
            marker = ">" if i == index else " "
            print(f"{marker} {label}")

        key = msvcrt.getch()
        if key in (b"\r", b"\n"):
            return options[index][1]
        if key == b"\x1b":
            return None
        if key in (b"\x00", b"\xe0"):
            key = msvcrt.getch()
            if key == b"H":
                index = (index - 1) % len(options)
            elif key == b"P":
                index = (index + 1) % len(options)


def _interactive():
    action = _picker(MENU_ITEMS)
    if not action:
        print("Cancelled.")
        return 1

    if action == "scan":
        url = _prompt("Target URL")
        return _route_vibe(["scan", url]) if url else 2
    if action == "noloader":
        url = _prompt("Target URL")
        seconds = _prompt("Seconds", "60")
        return _route_vibe(["noloader", "-urlx", url, f"t-{seconds}"]) if url else 2
    if action in {"ash", "spider", "vibe_headers", "ghost", "leep"}:
        url = _prompt("Target URL")
        return _run_tool(action, ["--url", url]) if url else 2
    if action == "storm_check":
        url = _prompt("Target URL")
        return _route_vibe(["storm", url, "--url-check"]) if url else 2
    if action == "report":
        return _route_vibe(["report"])
    if action == "privacy":
        return _route_vibe(["privacy"])
    if action == "trust_list":
        return _route_vibe(["trust", "list"])
    if action == "locked":
        return _print_locked()

    print(f"[-] No handler for picker action: {action}")
    return 2


def main(argv=None):
    _configure_stdio()
    argv = list(sys.argv[1:] if argv is None else argv)

    if not argv or argv[0] == "/":
        return _interactive()

    command = argv[0]
    rest = argv[1:]

    if command in {"-h", "--help", "help"}:
        _print_help()
        return 0

    if command in {"list", "tools"}:
        return _print_tools(plain="--plain" in rest)

    if command == "locked":
        if rest[:1] == ["run"] and len(rest) >= 2:
            return _run_tool(rest[1], rest[2:])
        return _print_locked(plain="--plain" in rest)

    if command == "run":
        if not rest:
            print("[-] Usage: vibe run <tool> [args...]")
            return 2
        return _run_tool(rest[0], rest[1:])

    if command in _tool_names() or command in VIBE_COMMANDS:
        return _run_tool(command, rest)

    print(f"[-] Unknown command: {command}")
    _print_help()
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
