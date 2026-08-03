# 🧰 VibeHacking Tool Catalog

Every tool in `TOOLS/`, grouped by what it does. All tools inherit from
[`vibe_core.py`](vibe_core.py) (shared HTTP client, privacy redaction, logging,
session, banner) and run standalone via `python TOOLS/<tool>.py --url <target>`
or through the `vibe.py` orchestrator.

> **Golden Rule:** these are for apps you **own** or are **explicitly authorized**
> to test. Load/stress tools are restricted to localhost, private targets, and
> exact public hosts you add to `authorized_targets.txt`.

Two practice targets ship with the repo so you can exercise everything below:
- **`testapp/` (NovaChat)** — a deliberately vulnerable AI-chat app; every tool lands real findings.
- **`/home/user/secretvault/` (SecretVault)** — a hardened, fully-encrypted vault; the honest "comes up empty" control.

---

## 🔍 Recon & Discovery
Map the attack surface before touching it.

| Tool | Role |
|------|------|
| `ash` | Domain reconnaissance — DNS, TLS, tech/WAF fingerprint, public path probe |
| `spider` | Attack-surface crawler — walks links/forms to enumerate routes |
| `ghost` | Sensitive asset finder — hunts exposed files, backups, dotfiles |
| `api_finder` | Hidden endpoint discovery — guesses/derives undocumented API paths |
| `api_check` | Single-endpoint checker — quick one-off probe of a specific route |
| `cloud_scout` | Cloud environment prober — metadata endpoints, bucket/role hints. *Note: flags any public 200 as "unprotected" — verify before trusting* |

## 📶 Availability & Health
Watch your own app without generating stress traffic.

| Tool | Role |
|------|------|
| `noloader` | **App availability & health monitor.** `--health` watches an app you expect UP and reports uptime %, latency (avg/p50/p95/max), and flapping; `--expect-text` asserts a health string in the body. Default mode confirms a URL stays DOWN for a window. Serial probes only — never floods. e.g. `python TOOLS/noloader.py --url http://127.0.0.1:3456/ --health -t 30s --expect-text ok` |

## 🛡️ Headers & Transport Security
What the server tells the browser to do (or fails to).

| Tool | Role |
|------|------|
| `vibe_headers` | HTTP security-policy auditor — CSP, HSTS, X-Frame-Options, etc. *Note: flags deprecated X-XSS-Protection and HSTS-on-loopback as critical — treat those as info* |
| `corscan` | CORS misconfiguration scanner — reflected origins, credentialed wildcards |
| `phantom` | Cookie & session-token analyzer — HttpOnly/Secure/SameSite flags |
| `header_inject` | HTTP header injection & Host-header poisoning suite |

## 🔐 Auth & Access Control
Who can do what — and who shouldn't.

| Tool | Role |
|------|------|
| `leep` | Logic-flow / auth-bypass auditor |
| `aukdoc` | Authentication boundary auditor. *Now baseline/differential — a 200 is only a breach if the endpoint was actually protected* |
| `axios` | IDOR / object-ID exposure scanner (unauthenticated) |
| `random_roll` | Password-policy auditor — weak-password acceptance, lockout, enumeration |

## 🔥 Advanced Attacks — _internal edition only_
The heavier artillery. Everything else hits the target unauthenticated and
error-based; these log in, forge credentials, and go blind — the way an actual
attacker does. All confirm only real, verified findings.

| Tool | Role |
|------|------|
| `intruder` | **Authenticated multi-account attack engine.** Stands up two throwaway accounts (attacker + victim), captures both sessions, harvests the victim's object IDs, then has the attacker try to reach them — a true differential cross-account IDOR test — plus vertical privilege-escalation probes and session-cookie analysis (HttpOnly/Secure/SameSite + token entropy). Endpoint-autodetects login/signup. |
| `jwt_forge` | **Schema-adaptive JWT forgery.** Obtains a real token, decodes the actual claim schema, escalates the privilege claims *that token uses*, and forges `alg:none` (all case variants) + weak-secret HS256 (recovers the secret from a wordlist and re-signs). Sends each to a protected endpoint and confirms which unlock it. `--login`/`--token`/`--protected`/`--token-mode`. |
| `blind_sqli` | **Boolean- and time-based blind SQLi detector.** Boolean: diffs a TRUE-condition vs a FALSE-condition response against the baseline. Time: injects DB-specific sleeps (MySQL/PostgreSQL/MSSQL/sqlite-heavy) and confirms via response stall. Catches silent injection the error/reflection tools miss. `--param`/`--method`/`--value`. |
| `credstuff` | **Credential stuffing / brute-force auditor.** Learns the failure response, sprays a wordlist (built-in common list or `--passwords` file), and reports cracked creds, whether a lockout/rate-limit ever kicks in (or the endpoint is freely brute-forceable), and whether a valid password triggers 2FA. `--login`/`--user`/`--user-field`. |
| `csrf_forge` | **CSRF tester + PoC generator.** Logs in, then replays a state-changing request from a simulated cross-site context (foreign Origin/Referer, no token) and weighs it against the cookie's SameSite — only calls it exploitable when the server *and* the cookie both leave the door open. Writes a ready-to-fire HTML PoC on a confirmed finding. `--endpoint`/`--data`/`--login`. |
| `redteam` | **Autonomous chained kill-chain.** Recons the target, detects the surface (login/signup, JWT, GraphQL, URL params, POST forms), then dispatches the right specialist at each opportunity with args derived from recon — one adaptive pass, results aggregated. `--url` (+ optional `--user`/`--pass` for authed phases). |

## 🧬 Modern Attack Classes — _internal edition only_
The classes a real bounty/pentest workflow hits that the classic scanners miss.
Each confirms with a concrete oracle (evaluated math, a stall, leaked internal
content), not a guess.

| Tool | Role |
|------|------|
| `graphql_raider` | **GraphQL attack suite.** Autodetects the endpoint, dumps the schema via introspection (flags sensitive fields), enumerates object-level auth (IDOR) through `user(id)`-style queries, and detects query batching (defeats rate limits, amplifies brute-force). `--endpoint`. |
| `racer` | **Race-condition / limit-overrun tester.** Aligns N requests on a barrier so they hit together, then counts how many succeeded past a single-use limit (coupon redeem-twice, balance double-spend). More than one == non-atomic read-then-write. `--endpoint`/`--data`/`--count`/`--success`. |
| `ssrf_cloud` | **SSRF → cloud metadata / internal.** Injects a URL-accepting param with AWS/GCP/Azure IMDS, internal ranges, `file://`/`gopher://`, and a same-host canary; confirms only when the server returns real internal/metadata content (strips reflected URLs to avoid false positives). `--param`/`--self`. |
| `deserial` | **Insecure deserialization detector.** Sends a Python pickle whose `__reduce__` sleeps; a matching stall proves the server executes attacker pickles (RCE). Also fingerprints deserializer errors (pickle/PyYAML/Java/PHP/.NET) and probes `__proto__`/mass-assignment. `--endpoint`/`--field`. |
| `ssti` | **Server-side template injection.** Fires arithmetic polyglots for Jinja2/Twig/Freemarker/ERB/Velocity/Handlebars/Smarty/Razor and confirms only when the server *evaluates* the expression (product present, payload not reflected verbatim). `--field`/`--param`/`--method`. |
| `nosqli` | **NoSQL operator injection.** Sends Mongo-style operators (`$ne`/`$gt`/`$regex`/`$exists`) as a password value and confirms an auth bypass differentially against a known-bad baseline. `--user-field`/`--pass-field`/`--user`. |

## 🧨 Exotic / Protocol-Level — _internal edition only_
The deep cuts: parser-, proxy-, protocol-, and DNS-layer bugs. Each confirms
with a hard oracle (leaked file contents, a reproduced hang, a 302 to your
sink, an unclaimed-resource fingerprint) — never a status-code guess.

| Tool | Role |
|------|------|
| `xxe_raider` | **XML external entity injection.** Runs a differential entity-expansion probe first (unique canary — a parser that echoes literal `&xxe;` is reported safe), then confirms file read (`/etc/passwd`, `win.ini`) and SSRF-via-XXE by fingerprinting fetched content *after* stripping the payload echo. Emits a blind/OOB parameter-entity DTD with `--collab`. `--template`/`--self`/`--collab`. |
| `smuggler` | **HTTP request smuggling / desync detection.** Timing technique only (no shared-queue poisoning): a battery of Transfer-Encoding obfuscations (space/tab/dup/CL) probes CL.TE and TE.CL; a hang is only a finding when it beats the endpoint's own baseline *and* an absolute floor *and* reproduces on re-test. `--threshold`. |
| `oauth_abuse` | **OAuth 2.0 / OIDC flow abuse.** Baselines the registered `redirect_uri`, then mutates it (full replace, subdomain, `@`-userinfo, path traversal, backslash) and only flags a 302/consent-page steer to your `--attacker` sink; also tests missing-`state` (login CSRF), implicit-flow token leak, and PKCE downgrade. `--url`/`--attacker`. |
| `takeover` | **Subdomain enumeration + takeover detection.** `--enum <domain>` discovers subdomains (built-in wordlist + `--wordlist`, optional `--ct` Certificate Transparency) and resolves them over DoH into a live map — which exist (A/AAAA), which are CNAMEs and to what, which are absent — then takeover-checks every CNAME. Calls a takeover only when the CNAME target is NXDOMAIN *or* the live response carries the service's unclaimed-resource fingerprint (S3/GH Pages/Heroku/Azure/Fastly/Shopify/Netlify/…); a live service reads safe. `--host`/`--list`/`--enum`. |

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
| `exploit_vault` | Generates a localStorage-exfil XSS payload (PoC for a confirmed XSS sink) |

## 🔥 Load & Stress — _localhost, private, or explicitly trusted targets only_
Capacity and rate-limit testing. Public hosts require an exact entry in
`authorized_targets.txt` plus a typed confirmation, and are rate-capped.

| Tool | Role |
|------|------|
| `storm` | Authorized-target traffic stressor (Python), with a safe `--url-check` mode |
| `vibe_api` | JSON endpoint stressor |
| `maelstrom` | Go authorized-target load tester (`vibe.py maelstrom ...`); double-gated + rate-capped |

## 🔓 Authenticated Testing — _browser-assisted session_
For targets behind Cloudflare or a login. Capture your own real session once in a
browser, then every tool reuses it — you *are* the authorized user, not a spoof.
See [`helpers/browser/README.md`](../helpers/browser/README.md).

| Tool | Role |
|------|------|
| `authcheck` | **Session verifier.** Loads your session (`VIBE_AUTH_FILE`/`VIBE_COOKIE`/`VIBE_UA`/`VIBE_HEADERS` or `--cookie`/`--auth-file`), fetches a URL, and reports **CHALLENGED** (still behind anti-bot), **ANONYMOUS** (logged-out), or **AUTHENTICATED** (good to go). Run it right after capturing a session. |
| `helpers/browser/grab_session.js` | **Session grabber** (Node/Playwright, runs on *your* machine). Opens a real Chromium; you solve the challenge + log in; it exports cookies + UA to `session_auth.json`. Not a stdlib tool — an optional browser helper. |

> Once a session is set, **all** tools that use the shared HTTP client (and any
> `urllib.urlopen` tool) carry your cookies + matching User-Agent automatically —
> no per-tool flag needed. `cf_clearance` is UA-bound, so the toolkit sends the
> browser's UA to match. `session_auth.json` is a live login: it's git-ignored.

## 📊 Reporting & Session
Turn findings into receipts; manage the workspace.

| Tool | Role |
|------|------|
| `lmx` | Executive security-dashboard generator (`vibe.py report`) |
| `poc_gen` | Exploit proof-of-concept generator |
| `backer` | Session-data backup utility |
| `seagull` | Log-noise filter — strips info chatter, keeps warnings/criticals |
| `void` | Environment cleaner — scrubs injected test payloads from a target DB (`vibe.py clean`) |
| `codex_boot` | Compact workspace snapshot (`vibe.py codex`) |

## 🤖 Orchestration
| Entry | Role |
|------|------|
| `vibe.py scan` | Chained deep scan (ash → vibe_headers → ghost → leep) |
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
- `patch_hynest` — auth-guard injector specific to the "Hynest API" project

---

_Web-app pentest tools + demos + reporting/session utilities in `TOOLS/`, plus
the Go `maelstrom` load tester. The plan/subscription system has been removed —
the only gates are the load-test allowlist and the `locked` typed-confirmation._
