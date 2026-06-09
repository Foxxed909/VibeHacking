# Maelstrom

Maelstrom is the Go-based load tester for VibeHacking. It is built for localhost, LAN, VPN, and private staging systems, plus public hosts you own and have explicitly authorized.

Public internet hosts are blocked **unless** you list them in `authorized_targets.txt` at the VibeHacking root (one exact hostname per line — wildcards are ignored on purpose, so you cannot authorize a whole platform like `*.vercel.app`). Only add hosts you own or have written permission to test. For everything else, use `storm --url-check` for safe one-request availability checks instead of load generation.

> **Shared platforms (Vercel, Netlify, etc.):** their acceptable-use policies restrict load/stress testing. Keep rates moderate, avoid full-send (`-r 0`), prefer a preview deployment, and confirm you're within the provider's policy first.

## Run

From the VibeHacking root:

```powershell
python vibe.py maelstrom -t http://localhost:3456/ -d 10s -r 5000 -w 256
```

Direct Go run:

```powershell
cd TOOLS\maelstrom
go run . -t http://localhost:3456/ -d 10s -r 3m/min -w 512 --report-file maelstrom_report.md
```

Build a local binary:

```powershell
cd TOOLS\maelstrom
go build -o maelstrom.exe .
.\maelstrom.exe -t http://localhost:3456/ -d 10s -r 50000 -w 512
```

Full-send mode is worker-limited and should only be used against local/private labs:

```powershell
python vibe.py maelstrom -t http://localhost:3456/ -d 5s -r 0 -w 1024
```

## Flags

- `--target`, `-t`: target URL.
- `--method`, `-m`: `GET`, `POST`, `PUT`, `DELETE`, `PATCH`, `HEAD`, or `OPTIONS`.
- `--rate`, `-r`: request rate. Bare values are RPS. Also accepts values like `50000rps`, `120000rpm`, or `3m/min`. Use `0`, `full`, or `max` for full-send mode.
- `--duration`, `-d`: run time, such as `30s` or `5m`.
- `--workers`, `-w`: worker goroutines.
- `--payload`, `-p`: JSON payload file for body methods.
- `--headers`, `-H`: custom header. Repeat as needed, for example `-H "Authorization: Bearer TOKEN"`.
- `--timeout`: per-request timeout. Default is `5s`.
- `--report-file`: optional Markdown report path.

## Privacy

Maelstrom follows VibeHacking's default privacy mode for console and Markdown
reports: targets are displayed as `http://<host>/path` and query strings are
redacted. Set `VIBE_PRIVACY_MODE=off` only for private local debugging when the
exact target must appear in the report.

This does not hide network metadata from the target, DNS resolver, ISP/VPN, or
hosting provider. Use an approved test gateway or privacy relay when tester
identity must be separated from the target.

## Host Tuning

Keep-alive is enabled by default to reduce socket churn and ephemeral port exhaustion. For high-rate private lab tests, raise limits on the generator host before running.

Linux lab example:

```bash
ulimit -n 1048576
sudo sysctl -w net.ipv4.ip_local_port_range="10000 65535"
sudo sysctl -w net.ipv4.tcp_tw_reuse=1
```

Windows lab checks:

```powershell
netsh int ipv4 show dynamicport tcp
netstat -ano | findstr TIME_WAIT
```

If generator CPU is saturated, lower `--workers` or split the test across multiple authorized private generators instead of testing from the same machine that hosts the app.
