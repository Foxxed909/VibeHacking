# Offline source benchmark

This benchmark inventories files in TOOLS, checks Python syntax without importing or executing tools, and reports compilation timings. Non-Python source files are inventory-only.

## Usage

```sh
python TOOLS/benchmark.py --code
python TOOLS/benchmark.py --code --tool privacy_guard
python TOOLS/benchmark.py --code --repeats 15
python TOOLS/benchmark.py --code --compare-root /path/to/another/checkout
```

With the existing global CLI, use `vibe benchmark --code` if installed from this checkout.

## Output

JSON schema version 1 contains per-file status, size, line count, SHA-256, median and p95 Python compilation time in milliseconds, Python version and platform. The optional comparison reports inventory counts, not behavioral equivalence. Nonzero exit indicates a source check failure or invalid arguments.

The CI workflow runs on Python 3.9 and 3.12 and uploads JSON artifacts. Compare timing results only on comparable environments. Compilation timings are not runtime latency, throughput, detection accuracy, or an effectiveness score. No network probes, attack execution, target access, or imported tool modules are involved.
