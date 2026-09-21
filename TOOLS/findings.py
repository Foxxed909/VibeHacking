"""Structured findings helpers for attack/scan runs.

Keeps JSON schemas stable so agents (and lmx later) can consume tool results
without scraping logs.
"""
import json
import os
import sys

from privacy_guard import sanitize_data


def count_signals(text):
    """Count toolkit log markers in captured tool output.

    Markers are counted once (the old code counted both the emoji and the
    bracketed form, doubling every number it reported).
    """
    text = text or ""
    hacks = text.count("[🔥 HACK]")
    crits = text.count("[🔴 CRITICAL]")
    fail_lines = text.count("[-] FAIL")
    return hacks, crits, fail_lines


def stream_captured(result):
    """Replay captured stdout/stderr so operators still see live-style output."""
    out = (getattr(result, "stdout", None) or "") + (getattr(result, "stderr", None) or "")
    if not out:
        return
    try:
        sys.stdout.write(out)
        if not out.endswith("\n"):
            sys.stdout.write("\n")
        sys.stdout.flush()
    except (BrokenPipeError, ValueError):
        pass


def record_tool(findings, phase, tool, result, stream=True):
    """Append one tool result to the findings list and return the entry."""
    if stream:
        stream_captured(result)
    out = (getattr(result, "stdout", None) or "") + (getattr(result, "stderr", None) or "")
    hacks, crits, fail_lines = count_signals(out)
    rc = 0 if result.returncode is None else result.returncode
    if hacks or crits:
        status = "finding"
    elif rc != 0:
        status = "error"
    elif fail_lines:
        status = "warn"
    else:
        status = "ok"
    entry = {
        "phase": phase,
        "tool": tool,
        "returncode": rc,
        "hack_signals": hacks,
        "crit_signals": crits,
        "fail_lines": fail_lines,
        "status": status,
    }
    findings.append(entry)
    return entry


def write_findings_json(path, payload):
    """Write sanitized findings JSON; return absolute path."""
    directory = os.path.dirname(os.path.abspath(path))
    if directory:
        os.makedirs(directory, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        json.dump(sanitize_data(payload), handle, indent=2)
    return os.path.abspath(path)


def summarize(findings):
    return {
        "executed": len(findings),
        "findings": sum(1 for f in findings if f.get("status") == "finding"),
        "errors": sum(1 for f in findings if f.get("status") == "error"),
        "warns": sum(1 for f in findings if f.get("status") == "warn"),
        "hack_signals": sum(int(f.get("hack_signals") or 0) for f in findings),
        "crit_signals": sum(int(f.get("crit_signals") or 0) for f in findings),
        "fail_lines": sum(int(f.get("fail_lines") or 0) for f in findings),
        "flagged_tools": [f["tool"] for f in findings
                          if f.get("status") in ("finding", "error", "warn")],
    }
