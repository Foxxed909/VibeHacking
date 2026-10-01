# ⚡ Hyperion — Next-Gen Guarded Resilience, Multi-Profile & SLO Load Engine

**Hyperion** is the next-generation Maelstrom competitor built for **VibeHacking**. It combines a high-concurrency **Go HTTP/2 engine (`TOOLS/hyperion/main.go`)** with a **persistent keep-alive Python stdlib engine (`TOOLS/hyperion.py`)** so it runs anywhere—even when Go is not installed—and adds enterprise load-testing capabilities that Maelstrom lacks.

---

## 🔒 Multi-Layer Safety & `XXLMILLEAMEAN` Guard Architecture

1. **Mandatory Guard Code (`XXLMILLEAMEAN`):**
   Every execution requires the explicit authorization guard code `XXLMILLEAMEAN` via `--guard XXLMILLEAMEAN`, `-g XXLMILLEAMEAN`, or `VIBE_HYPERION_GUARD=XXLMILLEAMEAN`. All unlock attempts (granted or denied) are recorded in `logs/locked_cli_access.log`.
2. **Strict Host Allowlist (`authorized_targets.txt`):**
   Like Maelstrom, Hyperion only runs against `localhost`, private/loopback/link-local IP literals, or exact hostnames listed in `authorized_targets.txt` (wildcards rejected).
3. **Public-Host Traffic Caps:**
   Authorized external runs are hard-capped at `9999.99 RPS` and `256 workers` with `full-send` disabled.
4. **Automatic Target-Protection Circuit Breaker:**
   Trips automatically if target `5xx`/transport errors reach `>=80%` after `50+` requests, preventing accidental staging self-meltdown.

---

## 🚀 Why Hyperion Beats Maelstrom

| Capability | Maelstrom | Hyperion |
| :--- | :--- | :--- |
| **Runtime Availability** | Requires Go installed | **Dual Engine:** Native Go HTTP/2 + Pure-Python Keep-Alive Socket Pool fallback |
| **Guard Code Gate** | None | **`XXLMILLEAMEAN` constant-time guard + audit log** |
| **Load Profiles** | Flat constant rate only | **`constant`, `ramp` (knee-of-curve), `step` (25/50/75/100%), `spike`** |
| **Target Routing** | Single URL only (`-t`) | **Multi-endpoint scenario rotation (`--endpoints "/,/api/config,..."`)** |
| **Latency Sampling** | Capped at first 250k samples | **Algorithm R Reservoir Sampling + `p50/p90/p95/p99/p99.9` + Jitter ($\sigma$)** |
| **CI/CD SLO Gates** | None | **`--slo-p95 <ms>` & `--slo-err-pct <pct>` pass/fail gates** |
| **Target Safety** | Keeps firing if server crashes | **Smart Circuit Breaker (`--circuit-breaker`)** |

---

## 💻 Usage

```bash
# Via central orchestrator
python vibe.py hyperion --guard XXLMILLEAMEAN -t http://127.0.0.1:3456/ -d 10s -r 2000 -w 64 --profile ramp

# Multi-endpoint step-load benchmark with SLO gate
python TOOLS/hyperion.py --guard XXLMILLEAMEAN \
  -t http://127.0.0.1:3456/ \
  --endpoints "/,/api/config,/api/guestbook" \
  --profile step \
  -d 12s -r 1000 -w 32 \
  --slo-p95 150 --slo-err-pct 1.0 \
  --json-out reports/hyperion_metrics.json
```
