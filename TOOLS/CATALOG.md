# 🧰 VibeHacking Tool Catalog

Every tool in `TOOLS/`, grouped by what it does. All tools inherit from
[`vibe_core.py`](vibe_core.py) (shared HTTP client, privacy redaction, logging,
session, banner) and run standalone via `python TOOLS/<tool>.py --url <target>`
or through the `vibe.py` orchestrator.

> Scope reminder: these are for **your own apps** and **in-scope, authorized
> bug-bounty targets** only. Load/stress tools are restricted to localhost,
> private targets, and exact public hosts you explicitly authorize.

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
| `cloud_scout` | Cloud environment prober — metadata endpoints, bucket/role hints |

## 🛡️ Headers & Transport Security
What the server tells the browser to do (or fails to).

| Tool | Role |
|------|------|
| `vibe_headers` | HTTP security-policy auditor — CSP, HSTS, X-Frame-Options, etc. |
| `corscan` | CORS misconfiguration scanner — reflected origins, credentialed wildcards |
| `phantom` | Cookie & session-token analyzer — HttpOnly/Secure/SameSite flags |
| `header_inject` | HTTP header injection & Host-header poisoning suite |

## 🔐 Auth & Access Control
Who can do what — and who shouldn't.

| Tool | Role |
|------|------|
| `leep` | Logic-flow / auth-bypass auditor |
| `aukdoc` | Authentication boundary auditor |
| `axios` | IDOR / object-ID exposure scanner |
| `random_roll` | Password-policy auditor |

## 💉 Injection & Input Attacks
Send malformed input, watch what breaks.

| Tool | Role |
|------|------|
| `authdoc` | WAF & input-filter auditor |
| `fuzz_vibe` | URL parameter fuzzer |
| `biz_logic` | Business-logic & parameter-pollution fuzzer |
| `redirect` | Open-redirect scanner |
| `traversal_sniper` | Targeted path traversal (e.g. `.env` key extraction) |
| `ssrf_probe` | Server-side request forgery (via computer-use sessions) |
| `prompt_injector` | LLM prompt-injection attack suite |
| `timebomb` | Timing-attack detector |

## 🗝️ Secrets & Data Exposure
Find the things that should never have left the server.

| Tool | Role |
|------|------|
| `env_probe` | Environment-variable & stack-trace leakage probe |
| `deep_extract` | Focused API-key deep extraction |
| `key_stealer` | Multi-vector API-key extraction suite |
| `credit_drain` | API credit-drain / rate-limit auditor |

## Load & Stress - _localhost, private, or explicitly trusted targets only_
Capacity and rate-limit testing. Public hosts require an exact entry in
`authorized_targets.txt` plus confirmation.

| Tool | Role |
|------|------|
| `storm` | Authorized-target traffic stressor (Python) |
| `vibe_api` | JSON endpoint stressor |
| `maelstrom` | Go authorized-target load tester (`vibe.py maelstrom ...`) |

## 📊 Reporting & Session
Turn findings into receipts; manage the workspace.

| Tool | Role |
|------|------|
| `lmx` | Executive security-dashboard generator (`vibe.py report`) |
| `poc_gen` | Exploit proof-of-concept generator |
| `backer` | Session-data backup utility |
| `void` | Environment cleaner / anti-artifact tool (`vibe.py clean`) |
| `codex_boot` | Compact workspace snapshot (`vibe.py codex`) |
| `privacy_guard` | Shared tester-privacy redaction helpers (library, not a CLI tool) |

---

## 🏷️ Flagged for review

### 🎭 Demos (illustrative payloads, not scanners)
These demonstrate a technique rather than audit a target. Keep, but label as demos.
- `exploit_final` — XSS payload-injector demo
- `exploit_vault` — localStorage exfiltration demo

### 📡 Off-topic — WiFi/network (not web-app pentest)
These don't fit a web-application pentest suite. Candidates to split into a
separate `network/` toolkit so the core roster stays focused.
- `vibe_recon` — WiFi environment scout
- `vox` — WiFi intruder detector

### 🔧 Dev / project-specific (not general pentest tools)
- `vibe_core` — shared base class (library, not a runnable tool)
- `privacy_guard` — shared privacy/redaction helper (library, not a runnable tool)
- `add_version_flags` — dev maintenance script that injects `--version` flags
- `patch_hynest` — auth-guard injector specific to the "Hynest API" project

---

_Total: 42 `.py` files in `TOOLS/` — 1 base library, ~33 pentest tools,
2 demos, 2 off-topic, 3 dev/project utilities, plus the Go `maelstrom` tester._
