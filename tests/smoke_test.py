#!/usr/bin/env python3
"""VibeHacking smoke tests — stdlib only, no pytest required.

Run from the repo root:

    python tests/smoke_test.py

Exits 0 if every check passes, 1 otherwise. Designed as a fast regression
guard for the v1.0 cleanup — it catches broken imports, syntax errors, CLI
wiring regressions, and version drift before they ship.

Checks
------
1. Version single-source-of-truth: the root VERSION file matches what
   vibe_core reports (locks in the 0.5.0-vs-1.0.0 drift fix).
2. Compile-check: every .py file byte-compiles (no execution, no side effects).
3. Orchestrator: `vibe.py --help` and `vibe.py list` exit cleanly.
4. Tool sweep: every CLI tool answers `--help` with exit code 0.

Mutating / non-CLI files are compile-checked but skipped in the runtime sweep.
"""
import os
import py_compile
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.join(ROOT, "TOOLS")
PY = sys.executable

# Compile-checked but skipped in the runtime `--help` sweep:
#   - vibe_core: shared base library, no CLI
#   - privacy_guard: shared privacy/redaction helpers, no CLI
#   - lmx: report generator with no argparse (would run, not print help)
#   - add_version_flags / patch_hynest: dev/project utilities that rewrite files
SKIP_RUNTIME = {
    "vibe_core.py",
    "privacy_guard.py",
    "lmx.py",
    "add_version_flags.py",
    "patch_hynest.py",
}


def run(args, timeout=25):
    # Tools reconfigure their own stdout to UTF-8 (emoji banners), so capture
    # as UTF-8 rather than the Windows locale default (cp1252) to avoid decode
    # errors in the reader thread.
    try:
        p = subprocess.run(
            [PY, *args],
            cwd=ROOT,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        return p.returncode, p.stderr
    except subprocess.TimeoutExpired:
        return 124, f"timeout after {timeout}s"


def main():
    failures = []
    checks = 0

    # 1. Version single-source-of-truth ------------------------------------
    checks += 1
    sys.path.insert(0, TOOLS)
    try:
        import vibe_core  # noqa: E402

        with open(os.path.join(ROOT, "VERSION"), encoding="utf-8") as f:
            file_v = f.read().strip()
        if vibe_core.FRAMEWORK_VERSION != file_v:
            failures.append(
                f"version drift: VERSION={file_v!r} but "
                f"vibe_core={vibe_core.FRAMEWORK_VERSION!r}"
            )
        else:
            print(f"[PASS] version single-source-of-truth ({file_v})")
    except Exception as e:  # noqa: BLE001
        failures.append(f"version check errored: {e}")

    # 1b. Privacy redaction defaults --------------------------------------
    checks += 1
    try:
        import privacy_guard  # noqa: E402

        sample = (
            "Target https://alice:secret@tester.example.com/api/u/"
            "550e8400-e29b-41d4-a716-446655440000?email=me@example.com&token=abc "
            "Authorization: Bearer secret123 C:\\Users\\WhitePC\\AppData\\x 203.0.113.5"
        )
        redacted = privacy_guard.sanitize_text(sample)
        leaks = [
            item
            for item in (
                "tester.example.com",
                "me@example.com",
                "secret123",
                "WhitePC",
                "203.0.113.5",
            )
            if item in redacted
        ]
        if leaks:
            failures.append(f"privacy redaction leaked: {leaks}")
        else:
            print("[PASS] privacy guard redacts common tester identifiers")
    except Exception as e:  # noqa: BLE001
        failures.append(f"privacy redaction check errored: {e}")

    # 2. Compile-check every Python file -----------------------------------
    py_files = [os.path.join(ROOT, "vibe.py")]
    py_files += [
        os.path.join(TOOLS, f) for f in os.listdir(TOOLS) if f.endswith(".py")
    ]
    compiled_ok = 0
    for path in sorted(py_files):
        checks += 1
        try:
            py_compile.compile(path, doraise=True)
            compiled_ok += 1
        except py_compile.PyCompileError as e:
            rel = os.path.relpath(path, ROOT)
            failures.append(f"compile failed: {rel}: {str(e).splitlines()[0][:160]}")
    print(f"[PASS] compile-check: {compiled_ok}/{len(py_files)} files OK")

    # 3. Orchestrator ------------------------------------------------------
    for sub in (["vibe.py", "--help"], ["vibe.py", "list"]):
        checks += 1
        code, err = run(sub)
        label = " ".join(sub)
        if code != 0:
            failures.append(f"`{label}` exited {code}: {err.strip()[:200]}")
        else:
            print(f"[PASS] {label}")

    # 4. Tool --help sweep -------------------------------------------------
    tools = sorted(
        f for f in os.listdir(TOOLS) if f.endswith(".py") and f not in SKIP_RUNTIME
    )
    helped_ok = 0
    for tool in tools:
        checks += 1
        code, err = run([os.path.join("TOOLS", tool), "--help"])
        if code != 0:
            failures.append(f"TOOLS/{tool} --help exited {code}: {err.strip()[:200]}")
        else:
            helped_ok += 1
    print(f"[PASS] --help sweep: {helped_ok}/{len(tools)} tools OK")

    # Summary --------------------------------------------------------------
    print("-" * 52)
    print(f"{checks - len(failures)}/{checks} checks passed")
    if failures:
        print("\nFAILURES:")
        for f in failures:
            print(f"  x {f}")
        return 1
    print("All smoke checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
