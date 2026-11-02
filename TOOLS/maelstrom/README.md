# Maelstrom v3

Go-based high-concurrency load tester for VibeHacking.

Built for localhost, LAN, VPN, and private staging systems, plus public hosts you own and have explicitly authorized via `authorized_targets.txt`.

## New in v3

- Proper rate limiter (token-bucket style)
- User-Agent rotation (browser + tool UAs)
- Multi-path / wordlist support (`--paths`)
- Proxy support (`--proxy`)
- TLS skip (`--tls-skip`)
- Cache-bust (`--cache-bust`)
- Warmup phase (`--warmup N`)
- Inline body (`--body`)
- Error classification (timeout / connect / tls / reset / dns)
- Live error breakdown in window stats
- JSON report (`--json`)
- Richer Markdown report + per-path stats
- Real byte transfer accounting

Public internet hosts remain gated by `authorized_targets.txt` and the public RPS/worker caps.

## Run

```bash
# From VibeHacking root
python vibe.py maelstrom -t http://localhost:3456/ -d 10s -r 5000 -w 256

# Direct
cd TOOLS/maelstrom
go run . -t http://localhost:3456/ -d 15s -r 10000 -w 512 --report-file report.md --json report.json

# Full-send (private only)
go run . -t http://localhost:3456/ -d 5s -r 0 -w 1024

# Multi-path + cache-bust + warmup
go run . -t http://localhost:3456/ -d 20s -r 2000 -w 128 \
  --paths paths.txt --cache-bust --warmup 50 --tls-skip
```

## Flags

| Flag | Description |
|------|-------------|
| `-t / --target` | Target URL |
| `-m / --method` | GET/POST/PUT/DELETE/PATCH/HEAD/OPTIONS |
| `-r / --rate` | RPS (`0`/`full`/`max` = full-send). Also `3m/min`, `50k`, etc. |
| `-d / --duration` | e.g. `30s`, `5m` |
| `-w / --workers` | Goroutines |
| `--body` | Inline body string |
| `-p / --payload` | Body file |
| `--paths` | Wordlist of paths or full URLs |
| `--proxy` | HTTP/HTTPS proxy |
| `--timeout` | Per-request timeout (default 5s) |
| `--report-file` | Markdown report |
| `--json` | JSON report |
| `--warmup` | Warmup request count |
| `--tls-skip` | Skip certificate verification |
| `--no-rotate-ua` | Fixed User-Agent |
| `--cache-bust` | Append random `?v=` / `&v=` every request |
| `-H` | Custom header (repeatable) |

## Authorization

Public hosts must appear as exact hostnames in `authorized_targets.txt` at the VibeHacking root. Wildcards are ignored on purpose.

Public caps: **9999.99 RPS / 256 workers**. Full-send is private-only.

## Host Tuning (high rate labs)

```bash
ulimit -n 1048576
sudo sysctl -w net.ipv4.ip_local_port_range="10000 65535"
sudo sysctl -w net.ipv4.tcp_tw_reuse=1
```
