# 🧰 VibeHacking Tool Catalog

Every tool in `TOOLS/`, grouped by what it does. All tools inherit from
[`vibe_core.py`](vibe_core.py) (shared HTTP client, privacy redaction, logging,
session, banner) and run standalone via `python TOOLS/<tool>.py --url <target>`
or through the `vibe.py` orchestrator.

> **Golden Rule:** these are for apps you **own** or are **explicitly authorized**
> to test. Load/stress tools are restricted to localhost, private targets, and
> exact public hosts you add to `authorized_targets.txt`.

Two practice targets ship with the repo so you can exercise everything below:
- **`testapp/app.py`:** Also exposes `/openapi.json` so `openapi_scout` can exercise full schema discovery in local testing.
- **`/home/user/secretvault/` (SecretVault)** — a hardened, fully-encrypted vault; the honest "comes up empty" control.

---

## 🔍 Recon & Discovery
Map the attack surface before touching it.

| Tool | Role |
|------|------|
| `ash` | Domain reconnaissance — DNS, TLS, tech/WAF fingerprint, public path probe |
| `spider` | Attack-surface crawler — walks links/forms to enumerate routes |
| `ghost` | Sensitive asset finder — hunts exposed files, backups, dotfiles |
| `api_finder` | Hidden endpoint discovery — guesses/derives undocumented API paths (with SPA soft-404 & WAF challenge suppression) |
| `api_check` | Single-endpoint checker — quick one-off probe of a specific route |
| `openapi_scout` | **OpenAPI / Swagger / GraphQL / AI-Plugin schema auditor** — discovers exposed specs, feeds undocumented routes into the shared Attack-Surface Graph, and audits GraphQL introspection & batching |
| `cloud_scout` | Cloud environment prober — classifies public vs sensitive paths |

## 📶 Availability & Health
Watch your own app without generating stress traffic.

| Tool | Role |
|------|------|
| `noloader` | **App availability & health monitor.** `--health` watches an app you expect UP and reports uptime %, latency (avg/p50/p95/max), and flapping; `--expect-text` asserts a health string in the body. Default mode confirms a URL stays DOWN for a window. Serial probes only — never floods. e.g. `python TOOLS/noloader.py --url http://127.0.0.1:3456/ --health -t 30s --expect-text ok` |

## 🛡️ Headers & Transport Security
What the server tells the browser to do (or fails to).

| Tool | Role |
|------|------|
| `vibe_headers` | HTTP security-policy auditor — CSP, HSTS, X-Frame-Options, etc. (context-aware: downgrades HSTS on HTTP and treats deprecated X-XSS-Protection as info) |
| `corscan` | CORS misconfiguration scanner — reflected origins, credentialed wildcards |
| `phantom` | Cookie & session-token analyzer — HttpOnly/Secure/SameSite flags, JWT `alg:none` header inspection, and HS256 weak-secret cracking |
| `header_inject` | HTTP header injection & Host-header poisoning suite |
| `smuggle_probe` | **HTTP protocol, verb-tampering & cache-control auditor** — detects sensitive API responses missing `Cache-Control: no-store`, HTTP TRACE/XST, and `X-HTTP-Method-Override` bypasses |
| `bot_breaker` | **AI-Agent 'Are You a Robot?' Solver & Cloudflare/Vercel/AWS Evasion Engine** (`vibe.py bot <url> [--fetch]`) — runs an 8-strategy zero-credential solver/bypass matrix (Client-Hint personas, math/checkbox/Altcha PoW solver, XHR/JSON pivot, crawler impersonation, IP spoofing, shadow origin discovery) and shares the winning profile with all tools |
| `waf_evade` | **Cloudflare / AWS WAF / Vercel Firewall & Rate-Limit Evasion Fuzzer** — tests 16KB oversized body padding, JSON Unicode escaping, `Content-Type` confusion, HTTP Parameter Pollution, and spoofed IP rate-limit bypasses |

## 🔐 Auth & Access Control
Who can do what — and who shouldn't.

| Tool | Role |
|------|------|
| `nextjs_rsc_audit` | **Next.js / Vercel Middleware Bypass (`CVE-2025-29927`), RSC & Server Actions Auditor** — tests `x-middleware-subrequest` auth bypass, React Server Components (`RSC: 1`) Flight payload leaks, `Next-Action` invocation, and `__NEXT_DATA__` / `/_next/data/<buildId>/*.json` exposure |
| `leep` | Logic-flow / auth-bypass auditor |
| `aukdoc` | Authentication boundary auditor — baseline-aware auth-bypass and privilege-escalation scanner |
| `jwt_forge` | **Cryptographic JWT & token forgery auditor** — tests `alg:none` stripping, offline HS256/384/512 weak-secret cracking + live admin token forgery, and `kid` traversal/SQLi |
| `axios` | IDOR / object-ID exposure scanner (path `/<id>` and query `?id=<id>` modes with soft-404 filtering) |
| `random_roll` | Password-policy auditor — weak-password acceptance, lockout, enumeration |

## 💉 Injection & Input Attacks
Send malformed input, watch what breaks.

| Tool | Role |
|------|------|
| `authdoc` | WAF & input-filter auditor |
| `fuzz_vibe` | URL parameter fuzzer |
| `biz_logic` | Business-logic & parameter-pollution fuzzer |
| `redirect` | Open-redirect scanner |
| `traversal_sniper` | Path traversal / LFI for `.env` & config files. `--app-root <path>` adds precise absolute-path payloads when a stack trace leaks the real root |
| `ssrf_probe` | Server-side request forgery (via computer-use / instruct endpoints) |
| `prompt_injector` | LLM prompt-injection suite (targets `/api/chat`-style endpoints) |
| `timebomb` | Timing-attack / timing-oracle detector |
| `exploit_final` | **Reflected/stored XSS confirmer** — injects a unique canary, reads it back, and reports a finding only if it comes back *unescaped*. `--field` picks the body field, `--check-url` reads a stored-XSS surface |

## 🗝️ Secrets & Data Exposure
Find the things that should never have left the server.

| Tool | Role |
|------|------|
| `env_probe` | Environment-variable & stack-trace leakage probe |
| `senoria` | Public web asset secret scanner — crawls served pages/JS/config for API-key/token leaks. Redacts by default; `--show-keys` reveals raw matches for localhost/private targets only |
| `deep_extract` | Focused API-key deep extraction |
| `key_stealer` | Multi-vector API-key extraction (injection, error-based, header oracle, SSRF, config-mining). Redacts findings by default; `--show-keys` reveals raw on your own app |
| `credit_drain` | API credit-drain / rate-limit auditor |
| `asymmetric_probe` | **Asymmetric 'Origin-Killer & Wallet-Drainer' Amplification Auditor** — profiles 1-request-equals-50x-CPU/DB/LLM-cost bottlenecks (`/_next/image` resize abuse, GraphQL array batching, wildcard DB scan cache misses, and unauthenticated LLM wallet drain) |
| `exploit_vault` | Generates a localStorage-exfil XSS payload (PoC for a confirmed XSS sink) |

## 🔥 Load & Stress — _localhost, private, or explicitly trusted targets only_
Capacity and rate-limit testing. Public hosts require an exact entry in
`authorized_targets.txt` plus a typed confirmation, and are rate-capped.

| Tool | Role |
|------|------|
| `storm` | Authorized-target traffic stressor (Python), with a safe `--url-check` mode |
| `vibe_api` | JSON endpoint stressor |
| `maelstrom` | Go authorized-target load tester (`vibe.py maelstrom ...`); double-gated + rate-capped |
| `hyperion` | **Next-gen guarded resilience, multi-profile & SLO load engine** (`vibe.py hyperion --guard XXLMILLEAMEAN ...`) — dual Go HTTP/2 + Python keep-alive engine supporting `constant`/`ramp`/`step`/`spike` profiles, multi-endpoint rotation, Reservoir-sampled `p50/p90/p95/p99/p99.9` + jitter ($\sigma$), smart circuit breaker, and CI/CD SLO gates (`--slo-p95`, `--slo-err-pct`) |

## 📊 Reporting & Session
Turn findings into receipts; manage the workspace.

| Tool | Role |
|------|------|
| `lmx` | Executive security-dashboard generator (`vibe.py report`) with structured CWE/OWASP vulnerability register |
| `sarif_export` | **Enterprise SARIF 2.1.0, JUnit XML & JSON exporter** (`vibe.py sarif [--fail-on critical]`) for GitHub Advanced Security & CI/CD gates |
| `live_dashboard` | **Live Web Command Center & Cloud/Edge Telemetry UI** (`vibe.py dashboard`) — real-time browser UI for launching scans, viewing Bot Breaker profiles, and inspecting Hyperion HDR & Cloudflare/AWS/Vercel telemetry |
| `poc_gen` | Exploit proof-of-concept generator (`xss`, `csrf`, `cors`, `clickjacking`) |
| `backer` | Session-data backup utility |
| `seagull` | Log-noise filter — strips info chatter, keeps warnings/criticals |
| `void` | Environment cleaner — scrubs injected test payloads from a target DB (`vibe.py clean`) |
| `codex_boot` | Compact workspace snapshot (`vibe.py codex`) |

## 🤖 Orchestration
| Entry | Role |
|------|------|
| `vibe_agent` | **VibeAgent & BreakAgent Autonomous AI Platform** (`vibe.py agent`) — `pwn.ai`-inspired autonomous AI security & app-breaking platform powered by Free OpenRouter models (`Laguna S 2.1`, `Laguna XS 2.1`, `Ling 3.0 Flash Fin`, `Ling 3.0 Flash Sante`, `Ling 3.0 Flash VL`). Enforces Target App URL + `I AM AUTHORIZED TO TEST THIS TARGET` before spawning live `VibeAgent` and `BreakAgent` threads |
| `vibe.py scan` | Chained deep scan (bot_breaker → ash → cloud_scout → vibe_headers → ghost → nextjs_rsc_audit → asymmetric_probe → leep) |
| `vibe.py attack` | Full ordered kill-chain across all phases, then the gated load phase |
| `vibe.py multi` | Parallel launcher: local/private by default; `multi scan/attack --allow-external` permit authorized public audit runs, while load/stress stays local/private |
| `vibe.py trust` | Manage the `authorized_targets.txt` load-test allowlist |
| `claude.py` | Autonomous brain — Claude drives the toolset adaptively against one authorized target and writes a report |

---

## 🏷️ Not general web-app scanners

### 📡 Off-topic — WiFi/network
Candidates to split into a separate `network/` toolkit.
- `vibe_recon` — WiFi environment scout
- `vox` — WiFi intruder detector

### 🔧 Libraries & dev utilities (not runnable scanners)
- `vibe_core` — shared base class (HTTP client, logging, privacy)
- `privacy_guard` — shared privacy/redaction helpers
- `add_version_flags` — dev maintenance script that injects `--version` flags

---

_Web-app pentest tools + demos + reporting/session utilities in `TOOLS/`, plus
the Go `maelstrom` load tester. The plan/subscription system has been removed —
the only gates are the load-test allowlist and the `locked` typed-confirmation._
