# 🌐 Browser-assisted session (for Cloudflare'd / login-required targets)

Some targets sit behind an anti-bot wall (Cloudflare "Just a moment…") or require
you to be logged in. The plain HTTP tools can't solve a JS challenge or a login
form. The fix isn't to *fake* a browser — it's to **use a real one, as yourself**,
capture your own verified session, and let the toolkit reuse it.

This is standard, above-board bug-bounty practice: you are the authorized user the
program invited to test. Nothing here spoofs a fingerprint or evades detection —
it carries **your own real cookies + User-Agent**.

> ⚠️ Runs on **your** machine (real browser, real home IP). It does not work from a
> datacenter/CI sandbox — that's the whole point.

## One-time setup
```bash
cd helpers/browser
npm install playwright
npx playwright install chromium
```

## Capture your session
```bash
node grab_session.js https://www.bridgemind.ai/ ../../session_auth.json
```
A real Chromium opens. In it: solve any verify-human check, **log into your
account**, navigate to the area you'll test, then press **ENTER** in the terminal.
It writes `session_auth.json` (cookies + your User-Agent).

## Point the toolkit at it
```bash
# macOS / Linux
export VIBE_AUTH_FILE="$PWD/../../session_auth.json"
# Windows PowerShell
$env:VIBE_AUTH_FILE = "$PWD\..\..\session_auth.json"
```

Every tool now reuses that verified session automatically. Confirm it worked:
```bash
python TOOLS/authcheck.py --url https://app.bridgemind.ai/dashboard
# -> AUTHENTICATED  (or it tells you: CHALLENGED / ANONYMOUS, and why)
```

Then run the real tests — now against the **authenticated** surface:
```bash
python TOOLS/vibe_headers.py --url https://app.bridgemind.ai/
python TOOLS/axios.py        --url https://api.bridgemind.ai/api/projects/
python TOOLS/redteam.py      --url https://app.bridgemind.ai/
```

## Other ways to supply a session (no Node needed)
Grab the values from your browser DevTools (Application → Cookies, and the
request's User-Agent) and export them directly:
```bash
export VIBE_COOKIE="cf_clearance=…; session=…"
export VIBE_UA="Mozilla/5.0 (…) Chrome/128.0.0.0 Safari/537.36"
export VIBE_HEADERS='{"Authorization":"Bearer …"}'   # if the API uses a bearer token
```
Or pass them per-run: `python TOOLS/authcheck.py --url … --cookie "…" --ua "…"`.

## Rules
- `session_auth.json` **is a live login** — it's git-ignored; never commit or share it.
- `cf_clearance` is bound to your IP **and** User-Agent — always set `VIBE_UA` to the
  browser that solved the challenge, or the session won't be honored.
- Sessions expire. If `authcheck` flips to CHALLENGED/ANONYMOUS, re-capture.
- Only ever do this against a target you own or are authorized to test.
