import argparse
import os
import sys

if hasattr(sys.stdout, "reconfigure"):
    sys.stdout.reconfigure(encoding="utf-8", errors="replace")
if hasattr(sys.stderr, "reconfigure"):
    sys.stderr.reconfigure(encoding="utf-8", errors="replace")

_tools_dir = os.path.dirname(os.path.abspath(__file__))
_root = os.path.dirname(_tools_dir)


def _read_text(path):
    try:
        with open(path, "r", encoding="utf-8") as f:
            return f.read().strip()
    except (OSError, UnicodeDecodeError):
        return ""


def _list_tools():
    names = []
    for entry in sorted(os.listdir(_tools_dir)):
        if entry.endswith(".py") and entry not in {"vibe_core.py", "codex_boot.py"}:
            names.append(entry[:-3])
    return names


def run():
    parser = argparse.ArgumentParser(description="Codex Boot - Compact workspace snapshot")
    parser.add_argument("--target", default="", help="Optional target URL or note")
    parser.add_argument("--ultra", action="store_true", help="Print the smallest useful snapshot")
    parser.add_argument("--workdir", default="", help="Switch into a specific working directory first")
    args = parser.parse_args()

    if args.workdir:
        os.chdir(args.workdir)

    readme = _read_text(os.path.join(_root, "README.md"))
    guide  = _read_text(os.path.join(_root, "AGENTS.md"))
    tools  = _list_tools()

    print("== CODEX SNAPSHOT ==")
    if args.target:
        print(f"Target: {args.target}")
    print(f"Workdir: {os.path.abspath(os.getcwd())}")
    print(f"Tools: {', '.join(tools)}")
    print("")

    if args.ultra:
        return

    if guide:
        print("GUIDE")
        print(guide)
        print("")

    if readme:
        print("README HEAD")
        preview = "\n".join(readme.splitlines()[:24]).encode("utf-8", "replace").decode("utf-8")
        print(preview)


if __name__ == "__main__":
    run()
