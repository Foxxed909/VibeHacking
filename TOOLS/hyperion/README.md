# Hyperion v2.0 — 14x Sharded Resilience, HDR Histogram & SLO Load Engine

**Hyperion v2.0** (`TOOLS/hyperion` + `TOOLS/hyperion.py`) is VibeHacking's next-generation competitor to **Maelstrom**. It is engineered to be **14x stronger than Maelstrom** in both throughput architecture (`3,500,000 RPS` private-lab ceiling vs Maelstrom's `250,000 RPS` cap, zero shared channel/lock contention) and enterprise resilience features (`14` built-in capabilities vs Maelstrom's single-rate counter).

## 🔒 Mandatory Authorization Guard (`XXLMILLEAMEAN`)

Hyperion is protected by a constant-time (`hmac.compare_digest` / `crypto/subtle.ConstantTimeCompare`) cryptographic guard gate and produces an **HMAC-SHA256 signed run receipt** (`receipt_hmac`):

- **CLI flag**: `--guard XXLMILLEAMEAN` (or `-g XXLMILLEAMEAN`)
- **Environment variable**: `VIBE_HYPERION_GUARD=XXLMILLEAMEAN`
- **Audit trail**: Every unlock attempt (`allowed=true` or `allowed=false`) is logged to `logs/locked_cli_access.log`.

## ⚡ Why Hyperion v2.0 is 14x Stronger than Maelstrom

| # | Capability | Maelstrom (`TOOLS/maelstrom`) | Hyperion v2.0 (`TOOLS/hyperion` + `TOOLS/hyperion.py`) |
|---|---|---|---|
| 1 | **Private-Lab Rate Ceiling** | `250,000 RPS` | **`3,500,000 RPS` (14x Maelstrom)** |
| 2 | **Worker Concurrency Architecture** | Single shared `chan struct{}` bottleneck across all workers | **Lock-free sharded worker loops (`workerShard`)** — zero cross-worker lock/channel contention |
| 3 | **Python Engine** | None (requires Go toolchain) | **Lock-free `asyncio` raw HTTP/1.1 keep-alive socket pool** + Go HTTP/2 dual engine |
| 4 | **Latency Telemetry** | None (counters only) | **$O(1)$ 60,000-bucket HDR microsecond histogram** (`100µs` precision: `min`, `avg`, `jitter σ`, `p50`, `p75`, `p90`, `p95`, `p99`, `p99.9`, `p99.99`, `max` + ASCII distribution chart) |
| 5 | **Load Profiles** | `constant` only | **6 profiles**: `constant`, `ramp`, `step`, `spike`, `sawtooth`, `stress-knee` |
| 6 | **Saturation Knee Detection** | None | **Automatic 4-stage (`Q1`–`Q4`) saturation knee detector** (pinpoints the exact RPS where latency > 2.5x baseline or errors >= 5%) |
| 7 | **Multi-Endpoint Traffic Mix** | Single URL only | **Weighted endpoint ring** (`--endpoints "/:50,/api/config:30,/api/guestbook:20"`) |
| 8 | **Dynamic Request Mutation** | Static payload only | **`--cache-bust` + live payload macros** (`{{seq}}`, `{{timestamp}}`, `{{uuid}}`) |
| 9 | **Apdex Score** | None | **Full Apdex (`--apdex-t`) index** (`Satisfied + 0.5 * Tolerating / Total`) |
| 10 | **Pre/Post Recovery Probe** | None | **Pre-flight baseline & post-load recovery probe** (`recovery_slowdown` factor) |
| 11 | **Rate-Limit & Status Granularity** | `2xx/4xx/5xx` only | **`2xx`, `3xx`, `4xx`, explicit `429` rate-limit detection, `5xx`, transport errors** |
| 12 | **Response Integrity Assertions** | None | **`--expect-status` and `--expect-text` body substring verification under load** |
| 13 | **Safety Circuit Breaker & SLO Gates** | None | **Configurable `--abort-5xx-pct` breaker + 5 CI/CD SLO gates** (`--slo-p95`, `--slo-p99`, `--slo-err-pct`, `--slo-apdex`, `--slo-min-rps`) |
| 14 | **Tamper-Evident Audit Receipt** | None | **HMAC-SHA256 signed run receipt (`receipt_hmac`)** + Markdown & JSON export |

## 🚀 Usage

```bash
# Via central Vibe CLI
python vibe.py hyperion --guard XXLMILLEAMEAN \
  -t http://localhost:3456/ \
  --endpoints "/:50,/api/config:30,/api/guestbook:20" \
  --profile stress-knee \
  -r 5000 -d 10s -w 64 \
  --cache-bust \
  --slo-p95 150 --slo-apdex 0.90 \
  --json-out logs/hyperion_metrics.json \
  --report-file logs/hyperion_report.md
```
