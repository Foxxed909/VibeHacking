# Hyperion — authorized load measurement and SLO checks

Hyperion provides Python HTTP/1.1 keep-alive and Go HTTP/2-capable engines,
weighted endpoints, six traffic profiles, latency buckets, Apdex and response
assertions. Requested-rate ceilings are input validation, not achieved capacity.
No comparative benchmark establishes a performance multiplier over Maelstrom.

## Measure successful responses

| Field | Meaning |
|---|---|
| `requested_rate` / `requested_rps` | Configured rate, not a throughput result |
| `average_rps` | Completed attempts per measured second, including failures |
| `successful_requests` / `successful_rps` | HTTP 2xx/3xx responses without transport errors, failed assertions or detected challenges |
| `failed_requests` / `error_rate_pct` | Each failed request counted once, including HTTP 4xx/5xx, transport/body-read errors, assertions and challenges |
| `histogram_overflow` | Latencies beyond the fixed-width histogram range |

A run with no successful samples fails. Assertion failures always fail the run.
The default failed-request budget is zero. `--slo-err-pct` sets an explicit
percentage budget; `--slo-min-rps` checks **successful** throughput. An entirely
blocked run cannot pass even with a permissive budget.

Both circuit breakers include failed HTTP 4xx responses and detected challenges.
The existing `--abort-5xx-pct` name remains for compatibility with the new
failed-request threshold. Percentiles use 0.1 ms buckets up to six seconds;
overflow estimates do not have that resolution. Go latency includes reading the
response body, and its test window excludes the separate recovery probe.

## Small loopback check

Start your local app, then run:

```bash
python TOOLS/hyperion.py --guard XXLMILLEAMEAN --engine python \
  -t http://127.0.0.1:3456/ -r 5 -d 2s -w 1 \
  --expect-status 200 --json-out logs/hyperion-check.json
```

The same measurement rules apply to `--engine go` when a Go toolchain is
available. Profiles: `constant`, `ramp`, `step`, `spike`, `sawtooth`, and
`stress-knee`. A missing observed knee does not prove linear scaling or a
maximum sustainable rate.

## Scope and credentials

Public hosts require an exact entry in `authorized_targets.txt`, explicit
confirmation, and the existing public rate/worker caps. Private requested-rate
ceilings remain validation constants. This change does not raise those caps or
remove the guard or circuit breaker.

The published guard is confirmation friction. The legacy `receipt_hmac` uses
that published constant; it is not independent report authentication.

The Python surface reader tolerates absent or malformed session data. A saved
BotBreaker profile is reused only for the same scheme, hostname and effective
port, so its cookies are not automatically replayed to another origin.

## Cloud/edge observations

Provider headers can identify cache classifications, PoP markers and challenges.
These observations do not prove that a backend was reached or a protection was
defeated. `origin-bypass` requests cache revalidation and varies the query;
provider and origin policy still determine the result. Cloudflare Access,
Vercel deployment protection and API Gateway options send operator-supplied
credentials.

## Verification

```bash
python -m unittest discover -s tests -p test_hyperion.py -v
cd TOOLS/hyperion
go test -race ./...
```

Tests use controlled loopback fixtures and synthetic samples: healthy, forbidden,
rate-limited, challenge and truncated-body responses; assertions; empty runs;
successful-throughput SLOs; report-write failures; and credential-origin matching.
They do not establish a throughput multiplier. Compare engines on identical
hardware, endpoint behavior, protocols and settings; publish measured successful
throughput, latency and errors.

