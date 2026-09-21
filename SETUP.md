# ⚙️ Setup & Editions

VibeHacking ships as **two editions** that live on two git **branches** (not two
folders — the branch you check out decides which files are on disk):

| Branch | Edition | Tools | Use it for |
|--------|---------|------|------------|
| `main` | **External** — public, shareable | ~44 | showing people, the clean subset |
| `internal` | **Full** — everything | ~63 | your actual work (all external tools **+** the arsenal) |

`internal` is a **strict superset**: every external tool works there too, plus
`redteam`, `jwt_forge`, `ssrf_cloud`, `intruder`, `blind_sqli`, `credstuff`,
`csrf_forge`, `deserial`, `graphql_raider`, `nosqli`, `racer`, `ssti`, and the
exotic/protocol-level set `xxe_raider`, `smuggler`, `oauth_abuse`, `takeover`.
For day-to-day use, **stay on `internal`**.

> **Requirements:** Python 3.9+ (CI runs 3.9 and 3.12) — the toolset is standard-library, nothing to
> `pip install`. Optional: Go 1.20+ for `maelstrom`; `pip install anthropic` for the
> `claude.py` AI brain.

---

## Pick your setup

### A) Simplest — one folder, switch editions with a branch

```bash
# fresh clone (repo is private → you'll need to be authenticated)
git clone https://github.com/Foxxed909/VibeHacking.git
cd VibeHacking

git switch internal     # full edition (everything)  ← recommended
#   ...or...
git switch main         # public edition only
```

Already have an old clone? Update it:

```bash
git fetch origin
git switch internal && git pull origin internal      # update the full edition
git switch main     && git pull origin main          # update the public edition
# if pull complains about divergence and you have no local edits:
#   git reset --hard origin/internal
```

**Never type-free tip — the `everything` alias.** So you never think about
branches, add a git alias once:

```bash
git config alias.everything "switch internal"
git config alias.public     "switch main"
# then just:
git everything     # → you're on the full edition
```

### B) Two folders at once — `external/` and `internal/` side by side

If you'd rather have both editions open in separate folders simultaneously
(they share one git history, so it's cheap), run the setup script in an **empty**
directory:

```bash
# macOS / Linux (scripts live under scripts/)
bash scripts/setup-editions.sh

# Windows PowerShell
.\scripts\setup-editions.ps1
```

You'll get:

```
external/    → public edition   (main)
internal/    → full edition     (internal, all tools)
```

Update either later:

```bash
git -C internal pull      # full edition
git -C external pull      # public edition
```

---

## Run it (from the `internal` folder/branch you have everything)

```bash
python vibe.py list                                     # every tool on this branch
python testapp/app.py                                   # bundled practice target :3456

# external tools (present on both editions)
python vibe.py scan http://127.0.0.1:3456/
python TOOLS/vibe_headers.py --url http://127.0.0.1:3456/

# internal tools (only on the full edition)
python TOOLS/redteam.py --url http://127.0.0.1:8800/ --user demo --pass demo1234
```

Sanity check after any update: `python tests/smoke_test.py` — it reports
`N/N checks passed` dynamically (compile + CLI wiring + tool `--help` sweep).
On a healthy full edition every check should pass.

> **Golden rule, always:** only test an app you own or are explicitly authorized
> to test — recon included.
