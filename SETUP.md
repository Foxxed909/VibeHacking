# ⚙️ Setup

VibeHacking is a self-hosted, black-box pentest toolkit for testing apps you
**own** or are **explicitly authorized** to test. Everything runs from the
Python standard library — there is nothing to `pip install`.

> **Requirements:** Python 3.8+ (tested to 3.14). Optional: **Go 1.20+** only for
> `maelstrom` (the high-rate load tester); a **browser-capable agent**
> (Antigravity / Playwright MCP) for true browser-driven black-box testing.

---

## 1. Get the code

```bash
git clone <your-repo-url> VibeHacking
cd VibeHacking

# Optional venv — installs nothing (the toolset is stdlib-only, by design)
python -m venv .venv
# macOS/Linux:
source .venv/bin/activate
# Windows (PowerShell):
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt   # stdlib-only: this installs nothing
```

Verify the install:

```bash
python tests/smoke_test.py   # should end "All smoke checks passed."
python vibe.py list          # list every runnable tool
```

---

## 2. Spin up the practice target (optional)

A real, deliberately vulnerable app ships in `testapp/` so you can exercise the
whole toolkit against something legitimately yours to break.

```bash
python testapp/app.py            # serves http://localhost:3456/
```

Then, in a second terminal:

```bash
python vibe.py scan http://127.0.0.1:3456/     # chained deep scan
python vibe.py attack http://127.0.0.1:3456/   # full ordered kill-chain
```

See **[testapp/README.md](testapp/README.md)** for what it exposes.

---

## 3. Everyday use

```bash
# Recon / audit — works on any URL you own or are authorized to test
python TOOLS/ash.py --url http://127.0.0.1:3456/           # domain recon
python TOOLS/vibe_headers.py --url http://127.0.0.1:3456/  # header audit
python vibe.py senoria --scan localhost:3456 --show-keys   # local secret scan

# Confirm a URL stays down for a window (safe serial probes — never floods)
python vibe.py --noloader -urlx http://127.0.0.1:3456/ t-30 -f 3

# Run several local/private targets in parallel (refuses public hosts)
python vibe.py multi scan --targets http://127.0.0.1:3456/ http://127.0.0.1:5500/ --jobs 2

# Authorized external audit (look-only; load/stress stays off)
python vibe.py multi scan --allow-external --targets https://your-owned-site.example --jobs 1

# Reporting & session
python vibe.py report    # executive HTML dashboard
python vibe.py status    # current session target
python vibe.py privacy   # privacy controls and hard limits
```

Full categorized roster: **[TOOLS/CATALOG.md](TOOLS/CATALOG.md)**.

---

## 4. Global CLI (optional)

Install once, then run `vibe` from anywhere:

```powershell
# Windows
.\install_vibe_cli.ps1
```

```bash
vibe /                              # interactive picker
vibe list                           # all runnable tools
vibe scan http://127.0.0.1:3456/
vibe locked                         # gated authorized-only tools
```

The `locked` gate is visible safety friction for high-impact tools — a typed
confirmation, logged locally in `logs/locked_cli_access.log`. It is not a secret
vault or an encryption layer.

---

## 5. Load-testing a remote app you own

Recon/audit tools work on any URL. The **load tools** (`storm` stress mode,
`maelstrom`) only fire at localhost/private hosts or hosts you've explicitly
authorized. Add yours to the trust list first:

```bash
python vibe.py trust add my-app.example      # authorize a host you OWN
python vibe.py trust list                     # see what's trusted
python vibe.py trust remove my-app.example    # revoke

# now load-test it (danger banner + typed confirmation required):
python vibe.py maelstrom -t https://my-app.example/ -d 20s -r 50 -w 32
```

> Only ever trust a host you own or have **written** permission to test.
> Wildcards are rejected on purpose. On shared platforms (Vercel, Netlify…)
> keep rates moderate — their policies restrict load testing, and a disclaimer
> doesn't make unauthorized traffic legal.

---

## ⚖️ The Golden Rule

> **1. Only ever test an app you own — or one you have explicit written
> permission to test. No exceptions.**
>
> **2. Prefer black-box. Attack what you can see from the outside first, like a
> real attacker would.**

Rule 1 is the hard line and never negotiable — authorization is per-app and
per-host; recon included. Rule 2 is a preference: because the target is your own
app, opening the box (source, logs, config) to confirm a finding and write the
fix is fully allowed and often the fastest path.

---

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| `python: command not found` | Use `python3`. Confirm 3.8+ with `python3 --version`. |
| `maelstrom` won't build | Install Go 1.20+ — it's optional; every other tool is pure Python. |
| A tool "finds nothing" | That's a valid result. The tools confirm real findings and stay quiet on hardened targets by design. |
| Permission/`403` on external target | You must own it or hold written authorization, and load tools need a trust-list entry. |
