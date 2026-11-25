#!/usr/bin/env python3
"""Offline source-health benchmark. Never imports or executes tool modules."""
import argparse
import hashlib
import json
import platform
import statistics
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
MAX_SOURCE_BYTES = 2 * 1024 * 1024


def inventory(root):
    tools = Path(root) / "TOOLS"
    if not tools.is_dir():
        raise ValueError("Checkout has no TOOLS directory")
    files = {}
    for path in sorted(tools.rglob("*")):
        if path.suffix not in {".py", ".go", ".ps1", ".js", ".sh"}:
            continue
        if path.is_symlink() or any(p.is_symlink() for p in path.parents if p != tools.parent):
            continue
        if path.is_file():
            files[path.relative_to(tools).as_posix()] = path
    return files


def percentile(samples, fraction):
    ordered = sorted(samples)
    index = max(0, min(len(ordered) - 1, int(len(ordered) * fraction + 0.999999) - 1))
    return round(ordered[index], 4)


def inspect_source(name, path, repeats):
    row = {"file": name, "language": path.suffix[1:], "status": "inventory_only"}
    try:
        with path.open("rb") as handle:
            source = handle.read(MAX_SOURCE_BYTES + 1)
        if len(source) > MAX_SOURCE_BYTES:
            row["status"] = "skipped_size_limit"
            return row
        row["bytes"] = len(source)
        row["lines"] = len(source.splitlines())
        row["sha256"] = hashlib.sha256(source).hexdigest()
        if path.suffix != ".py":
            return row
        samples = []
        for _ in range(repeats):
            start = time.perf_counter_ns()
            compile(source, name, "exec", dont_inherit=True)
            samples.append((time.perf_counter_ns() - start) / 1_000_000)
        row.update(status="syntax_pass", compile_median_ms=round(statistics.median(samples), 4),
                   compile_p95_ms=percentile(samples, 0.95), samples=repeats)
    except SyntaxError as error:
        row.update(status="syntax_fail", error_type=type(error).__name__, line=error.lineno)
    except (OSError, ValueError, OverflowError) as error:
        row.update(status="read_or_compile_error", error_type=type(error).__name__)
    return row


def benchmark(root=ROOT, repeats=7, selected=None, compare_root=None):
    if not 1 <= repeats <= 50:
        raise ValueError("repeats must be between 1 and 50")
    files = inventory(root)
    if selected:
        names = [name for name in files if name == selected or name == selected + ".py"]
        if not names:
            raise ValueError("Unknown source file")
    else:
        names = list(files)
    rows = [inspect_source(name, files[name], repeats) for name in names]
    summary = {status: sum(row["status"] == status for row in rows)
               for status in sorted({row["status"] for row in rows})}
    result = {"schema_version": 1, "benchmark": "offline_source_health",
              "python_version": platform.python_version(), "platform": platform.system(),
              "repeats": repeats, "summary": summary, "files": rows,
              "limitations": "Compilation timing is not execution speed, detection accuracy or operational effectiveness. No tool code is executed."}
    if compare_root is not None:
        other = inventory(compare_root)
        common = set(files) & set(other)
        result["inventory_comparison"] = {
            "current_count": len(files), "reference_count": len(other),
            "shared_count": len(common), "current_only_count": len(set(files) - set(other)),
            "reference_only_count": len(set(other) - set(files))}
    return result


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--code", action="store_true", help="JSON-only output")
    parser.add_argument("--tool", help="Select one source name, without executing it")
    parser.add_argument("--repeats", type=int, default=7)
    parser.add_argument("--compare-root", type=Path, help="Optional local checkout for inventory comparison")
    args = parser.parse_args(argv)
    try:
        report = benchmark(repeats=args.repeats, selected=args.tool, compare_root=args.compare_root)
    except (ValueError, OSError) as error:
        if args.code:
            print(json.dumps({"schema_version": 1, "error": type(error).__name__, "message": str(error)}))
        else:
            print(str(error), file=sys.stderr)
        return 2
    if args.code:
        print(json.dumps(report, ensure_ascii=True, sort_keys=True))
    else:
        print("Offline source-health benchmark (no tool execution)")
        for name, count in report["summary"].items():
            print(f"{name}: {count}")
        if "inventory_comparison" in report:
            print(json.dumps(report["inventory_comparison"], sort_keys=True))
        print("Use --code for per-file JSON results.")
    return int(any(row["status"] in {"syntax_fail", "read_or_compile_error", "skipped_size_limit"}
                   for row in report["files"]))


if __name__ == "__main__":
    raise SystemExit(main())
