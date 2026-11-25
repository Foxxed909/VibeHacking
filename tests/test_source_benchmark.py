"""Regression tests for source-only benchmarks."""
import contextlib
import importlib.util
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location("source_benchmark", ROOT / "TOOLS" / "benchmark.py")
benchmark = importlib.util.module_from_spec(spec)
spec.loader.exec_module(benchmark)


class BenchmarkTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.tools = self.root / "TOOLS"
        self.tools.mkdir()

    def test_compilation_does_not_execute_source(self):
        (self.tools / "example.py").write_text("raise RuntimeError('must not run')\n", encoding="utf-8")
        row = benchmark.benchmark(self.root, repeats=2)["files"][0]
        self.assertEqual(row["status"], "syntax_pass")
        self.assertEqual(row["samples"], 2)
        self.assertGreaterEqual(row["compile_p95_ms"], 0)

    def test_syntax_error_is_reported(self):
        (self.tools / "bad.py").write_text("def broken(\n", encoding="utf-8")
        self.assertEqual(benchmark.benchmark(self.root)["summary"], {"syntax_fail": 1})

    def test_non_python_inventory_only(self):
        (self.tools / "example.go").write_text("package main\n", encoding="utf-8")
        row = benchmark.benchmark(self.root)["files"][0]
        self.assertEqual(row["status"], "inventory_only")
        self.assertNotIn("compile_median_ms", row)

    def test_compare_inventory(self):
        (self.tools / "shared.py").write_text("pass\n", encoding="utf-8")
        other = self.root / "reference"
        (other / "TOOLS").mkdir(parents=True)
        (other / "TOOLS" / "shared.py").write_text("pass\n", encoding="utf-8")
        (other / "TOOLS" / "additional.py").write_text("pass\n", encoding="utf-8")
        report = benchmark.benchmark(self.root, compare_root=other)
        self.assertEqual(report["inventory_comparison"]["shared_count"], 1)
        self.assertEqual(report["inventory_comparison"]["reference_only_count"], 1)

    def test_json_only_and_exit_code(self):
        (self.tools / "bad.py").write_text("def broken(\n", encoding="utf-8")
        out = io.StringIO()
        with patch.object(benchmark, "benchmark", wraps=lambda **kwargs: self.original(**kwargs)):
            with contextlib.redirect_stdout(out):
                code = benchmark.main(["--code", "--repeats", "1"])
        self.assertEqual(code, 1)
        self.assertEqual(json.loads(out.getvalue())["summary"]["syntax_fail"], 1)

    def original(self, **kwargs):
        return self.saved_benchmark(self.root, **kwargs)

    saved_benchmark = staticmethod(benchmark.benchmark)

    def test_invalid_repeat_count(self):
        with self.assertRaises(ValueError):
            benchmark.benchmark(self.root, repeats=51)


if __name__ == "__main__":
    unittest.main()
