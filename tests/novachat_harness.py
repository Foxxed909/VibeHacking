#!/usr/bin/env python3
"""
NovaChat Regression Harness  —  tests/novachat_harness.py

A self-contained smoke + regression harness for VibeHacking. It boots the
bundled, deliberately-vulnerable practice target (``testapp/app.py``) on
localhost, runs a curated set of READ-ONLY recon/audit tools against it, and
asserts three things the project cares about:

  1. TOOLS RUN CLEAN   — every tool exits without an unhandled traceback
                         (a vuln scanner exiting non-zero because it *found*
                         something is success, so exit codes are not asserted).
  2. FINDINGS LAND      — the intentionally-vulnerable app yields real,
                         machine-readable findings in findings.jsonl.
  3. RAILS HOLD         — privacy redaction hides the planted key, and the
                         load-tool authorization gate refuses a public host.

Stdlib only (matches the repo). No network beyond localhost. No load/stress
tools run by default. Nothing in the repo is modified — all artifacts go to a
throwaway temp dir via VIBE_LOG_DIR / VIBE_SESSION_FILE / VIBE_FINDINGS_FILE.

Usage:
    python tests/novachat_harness.py            # full harness
    python tests/novachat_harness.py --quick    # recon/headers subset only
    python tests/novachat_harness.py --port 0   # auto-pick a free port (default)

Exit code 0 = all hard assertions passed, 1 = at least one failed.
It is also pytest-friendly: `test_novachat_harness()` is collected automatically.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import os
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request

# --------------------------------------------------------------------------- #
# Layout
# --------------------------------------------------------------------------- #
HARNESS_DIR = os.path.dirname(os.path.abspath(__file__))
# Harness is expected to live in <repo>/tests/. Fall back to the parent that
# actually contains vibe.py so it still works if dropped elsewhere.
ROOT = os.path.dirname(HARNESS_DIR)
if not os.path.exists(os.path.join(ROOT, "vibe.py")) and os.path.exists(
    os.path.join(HARNESS_DIR, "vibe.py")
):
    ROOT = HARNESS_DIR
TOOLS = os.path.join(ROOT, "TOOLS")
TESTAPP = os.path.join(ROOT, "testapp", "app.py")
VIBE = os.path.join(ROOT, "vibe.py")

# The key that only exists inside testapp/app.py. Redaction MUST hide this.
PLANTED_KEY = "sk-or-v1-3f9a2c7e8b1d4056a9e2f7c3b8d1054e6a2f9c7b4d8e1a305"

# Per-tool timeout (seconds). Local target, so these are generous.
TOOL_TIMEOUT = 60

# Read-only tools that are safe + meaningful against a local target.
# (No load/stress tools here — storm/maelstrom/hyperion/vibe_api are excluded
#  by design; this is a correctness smoke test, not a capacity test.)
FULL_TOOLS = [
    ("ash",              ["--url", "{t}"]),   # recon
    ("spider",           ["--url", "{t}"]),   # crawl
    ("ghost",            ["--url", "{t}"]),   # exposed assets
    ("api_finder",       ["--url", "{t}"]),   # endpoint discovery
    ("openapi_scout",    ["--url", "{t}"]),   # /openapi.json is served by testapp
    ("vibe_headers",     ["--url", "{t}"]),   # missing security headers
    ("corscan",          ["--url", "{t}"]),   # CORS
    ("phantom",          ["--url", "{t}"]),   # cookies / JWT header
    ("redirect",         ["--url", "{t}"]),   # /go open redirect
    ("axios",            ["--url", "{t}"]),   # IDOR on /api/user
    ("traversal_sniper", ["--url", "{t}"]),   # /files traversal
    ("exploit_final",    ["--url", "{t}"]),   # stored XSS confirmer
    ("env_probe",        ["--url", "{t}"]),   # stack-trace / config leak
    ("key_stealer",      ["--url", "{t}"]),   # multi-vector key extraction
    ("leep",             ["--url", "{t}"]),   # auth/logic flow
]

QUICK_TOOLS = [
    ("ash",          ["--url", "{t}"]),
    ("vibe_headers", ["--url", "{t}"]),
    ("env_probe",    ["--url", "{t}"]),
    ("exploit_final",["--url", "{t}"]),
]


# --------------------------------------------------------------------------- #
# Small result recorder
# --------------------------------------------------------------------------- #
class Report:
    def __init__(self) -> None:
        self.rows: list[tuple[str, bool, str]] = []

    def check(self, name: str, ok: bool, detail: str = "") -> bool:
        self.rows.append((name, bool(ok), detail))
        mark = "PASS" if ok else "FAIL"
        line = f"  [{mark}] {name}"
        if detail:
            line += f"  —  {detail}"
        print(line)
        sys.stdout.flush()
        return ok

    @property
    def failed(self) -> int:
        return sum(0 if ok else 1 for _, ok, _ in self.rows)

    def summary(self) -> None:
        total = len(self.rows)
        passed = total - self.failed
        print("\n" + "=" * 60)
        print(f"  HARNESS SUMMARY: {passed}/{total} checks passed")
        if self.failed:
            print("  FAILURES:")
            for name, ok, detail in self.rows:
                if not ok:
                    print(f"    - {name}: {detail}")
        print("=" * 60)


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #
def _free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def _wait_until_up(url: str, timeout: float = 10.0) -> bool:
    deadline = time.time() + timeout
    while time.time() < deadline:
        try:
            with urllib.request.urlopen(url, timeout=2) as r:
                r.read(64)
                return True
        except Exception:
            time.sleep(0.2)
    return False


def _tool_env(artifacts: str) -> dict:
    env = os.environ.copy()
    env["PYTHONIOENCODING"] = "utf-8"
    # Redirect ALL artifacts away from the real repo logs/.
    env["VIBE_LOG_DIR"] = artifacts
    env["VIBE_SESSION_FILE"] = os.path.join(artifacts, "vibe_session.json")
    env["VIBE_FINDINGS_FILE"] = os.path.join(artifacts, "findings.jsonl")
    # Privacy guard ON (the default) — this is what the redaction check verifies.
    env["VIBE_PRIVACY_MODE"] = "on"
    return env


def _run_tool(stem: str, extra: list[str], target: str, env: dict) -> tuple[int, str, bool]:
    """Run one tool. Returns (returncode, combined_output, crashed?)."""
    script = os.path.join(TOOLS, f"{stem}.py")
    if not os.path.exists(script):
        return (127, f"missing tool: {script}", True)
    cmd = [sys.executable, script] + [a.replace("{t}", target) for a in extra]
    try:
        proc = subprocess.run(
            cmd, cwd=ROOT, env=env, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=TOOL_TIMEOUT,
        )
    except subprocess.TimeoutExpired:
        return (-1, f"TIMEOUT after {TOOL_TIMEOUT}s", True)
    out = (proc.stdout or "") + (proc.stderr or "")
    crashed = "Traceback (most recent call last)" in out
    return (proc.returncode, out, crashed)


# --------------------------------------------------------------------------- #
# Phases
# --------------------------------------------------------------------------- #
def run_tools_phase(rep: Report, tools, target: str, env: dict) -> None:
    print("\n[1/3] Running read-only tools against the local practice target")
    for stem, extra in tools:
        rc, out, crashed = _run_tool(stem, extra, target, env)
        detail = "crashed with traceback" if crashed else f"rc={rc}"
        rep.check(f"tool:{stem} runs without crashing", not crashed, detail)


def findings_phase(rep: Report, env: dict) -> None:
    print("\n[2/3] Asserting findings landed")
    path = env["VIBE_FINDINGS_FILE"]
    entries = []
    if os.path.exists(path):
        with open(path, "r", encoding="utf-8") as fh:
            for line in fh:
                line = line.strip()
                if not line:
                    continue
                with contextlib.suppress(json.JSONDecodeError):
                    entries.append(json.loads(line))

    rep.check("findings.jsonl was created", os.path.exists(path), path)
    rep.check("at least one finding recorded", len(entries) > 0, f"{len(entries)} findings")

    tools_with_findings = {e.get("tool", "?") for e in entries}
    rep.check(
        "multiple tools recorded findings",
        len(tools_with_findings) >= 2,
        f"{len(tools_with_findings)} distinct tools",
    )

    # Soft signal: the planted key is genuinely leaked by the app, so at least
    # one secret/key-class finding is expected. Warn (don't hard-fail) to stay
    # resilient to tool-naming changes.
    sev = {e.get("severity", "") for e in entries}
    if "critical" not in sev and "high" not in sev:
        print("  [warn] no high/critical findings — expected on a deliberately "
              "vulnerable target; check the tool list.")


def rails_phase(rep: Report, env: dict) -> None:
    print("\n[3/3] Asserting the safety rails hold")

    # (a) Privacy redaction: the planted key must NOT appear in any artifact.
    leaked = False
    where = ""
    for root, _dirs, files in os.walk(env["VIBE_LOG_DIR"]):
        for fn in files:
            fp = os.path.join(root, fn)
            try:
                with open(fp, "r", encoding="utf-8", errors="ignore") as fh:
                    if PLANTED_KEY in fh.read():
                        leaked, where = True, fp
                        break
            except OSError:
                continue
        if leaked:
            break
    rep.check(
        "privacy guard redacts the planted key from local artifacts",
        not leaked,
        f"raw key found in {where}" if leaked else "key not present in artifacts",
    )

    # (b) Authorization gate: a public target must be refused with no traffic.
    #     `multi scan --dry-run` rejects non-local hosts *before* the dry-run
    #     branch, so this sends zero packets to the host.
    try:
        proc = subprocess.run(
            [sys.executable, VIBE, "multi", "scan",
             "--targets", "http://scanme.public.example/", "--dry-run"],
            cwd=ROOT, env=env, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=30,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        refused = proc.returncode == 2 and "local/private only" in out.lower()
    except Exception as exc:  # noqa: BLE001
        refused, out = False, str(exc)
    rep.check(
        "load/multi gate refuses a public host without --allow-external",
        refused,
        "refused (rc=2)" if refused else f"NOT refused: {out[:120]}",
    )

    # (c) Trust allowlist rejects wildcards.
    try:
        proc = subprocess.run(
            [sys.executable, VIBE, "trust", "add", "*.example.com"],
            cwd=ROOT, env=env, capture_output=True, text=True,
            encoding="utf-8", errors="replace", timeout=30,
        )
        out = (proc.stdout or "") + (proc.stderr or "")
        rejected = proc.returncode == 2 and "wildcard" in out.lower()
    except Exception as exc:  # noqa: BLE001
        rejected, out = False, str(exc)
    rep.check(
        "trust allowlist rejects wildcard hosts",
        rejected,
        "rejected" if rejected else f"NOT rejected: {out[:120]}",
    )


# --------------------------------------------------------------------------- #
# Orchestration
# --------------------------------------------------------------------------- #
def run_harness(port: int = 0, quick: bool = False) -> int:
    for needed in (VIBE, TESTAPP, TOOLS):
        if not os.path.exists(needed):
            print(f"[-] Can't find {needed}. Put this harness in <repo>/tests/.")
            return 1

    port = port or _free_port()
    target = f"http://127.0.0.1:{port}/"
    artifacts = tempfile.mkdtemp(prefix="novachat_harness_")
    env = _tool_env(artifacts)
    rep = Report()

    print("=" * 60)
    print(" NOVACHAT REGRESSION HARNESS")
    print(f" target    : {target}")
    print(f" artifacts : {artifacts}")
    print("=" * 60)

    app = subprocess.Popen(
        [sys.executable, TESTAPP, "--host", "127.0.0.1", "--port", str(port)],
        cwd=ROOT, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    try:
        if not rep.check("practice target comes up", _wait_until_up(target),
                         f"no response on {target}"):
            return 1

        tools = QUICK_TOOLS if quick else FULL_TOOLS
        run_tools_phase(rep, tools, target, env)
        findings_phase(rep, env)
        rails_phase(rep, env)
    finally:
        app.terminate()
        with contextlib.suppress(Exception):
            app.wait(timeout=5)
        shutil.rmtree(artifacts, ignore_errors=True)

    rep.summary()
    return 1 if rep.failed else 0


# pytest entry point
def test_novachat_harness() -> None:
    assert run_harness(port=0, quick=True) == 0


def main() -> int:
    ap = argparse.ArgumentParser(description="VibeHacking NovaChat regression harness")
    ap.add_argument("--port", type=int, default=0, help="Port for the practice target (0 = auto)")
    ap.add_argument("--quick", action="store_true", help="Run a recon/headers subset only")
    args = ap.parse_args()
    return run_harness(port=args.port, quick=args.quick)


if __name__ == "__main__":
    sys.exit(main())
