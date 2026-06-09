# 👾 Welcome to Vibe Hacking
### By BlackPC, Vine & Foxxino Inc.

This is where we test our own apps and games by hacking them —
because who better to break something than the people who built it?

Since these are **our own projects**, we have full permission to poke,
prod, and push them to their limits.

**Our goals:**
- 🔍 Test app security from the inside out
- 🐛 Hunt down bugs before users find them
- 🔒 Patch vulnerabilities and lock things down tight
- ⚡ Make everything faster, smoother, and fully secure

No harm. No foul. Just good, clean chaos —
and occasionally, **BlackPC** doing it purely for the fun of it. 😄

---

## 🚀 Quickstart

```powershell
# 1. (Optional) create the venv — no third-party packages are required
python -m venv .venv
.\.venv\Scripts\Activate.ps1
pip install -r requirements.txt   # stdlib-only: installs nothing, by design

# 2. Run a deep scan against a target you own / are authorized to test
python vibe.py scan http://127.0.0.1:5500/

# 3. See everything you can do
python vibe.py list      # list all tools
python vibe.py status    # current session target
python vibe.py privacy   # show tester privacy controls and hard limits
python vibe.py report    # build the executive HTML dashboard
python vibe.py codex     # compact workspace snapshot
```

Individual tools run standalone too:

```powershell
python TOOLS/ash.py --url http://127.0.0.1:5500/          # recon
python TOOLS/vibe_headers.py --url http://127.0.0.1:5500/ # header audit
```

### 🎯 Testing a remote app you own

Recon/audit tools work on any URL out of the box. The **load tools** (`storm`
stress mode, `maelstrom`) only fire at localhost/private hosts or hosts you've
explicitly authorized — add yours to the trust list first:

```powershell
python vibe.py trust add my-app.vercel.app   # authorize a host you OWN
python vibe.py trust list                     # see what's trusted
python vibe.py trust remove my-app.vercel.app # revoke

# now load-test it (you'll get a danger banner + typed confirmation):
python vibe.py maelstrom -t https://my-app.vercel.app/ -d 20s -r 50 -w 32
```

> Only ever trust a host you own or have **written** permission to test.
> Wildcards (`*.vercel.app`) are rejected on purpose. On shared platforms
> (Vercel, Netlify…) keep rates moderate and avoid full-send — their policies
> restrict load testing, and a disclaimer doesn't make unauthorized traffic legal.

See **[TOOLS/CATALOG.md](TOOLS/CATALOG.md)** for the full categorized tool roster.

> **Antigravity** (or any agent with a live browser — e.g. Playwright MCP) is the
> black-box *driver* that scopes the target through its UI. `vibe.py` is the
> command engine that runs the probes. Use either, or both together.

---

## 📦 Requirements

- **Python 3.8+** (tested on 3.14) — the entire toolset is **standard-library only**, so there is nothing to `pip install`.
- **Go 1.20+** *(optional)* — only for `vibe.py maelstrom`, the high-rate private-target load tester.
- **A browser-capable agent** *(optional)* — Antigravity / Playwright MCP for true browser-driven black-box testing.

---

## 🗂️ How It Works

**The Setup looks like this:**
```
<path-to-your-project>\WestAPI>       ← The App/Game being targeted
<path-to-vibehacking>>                            ← Where we hack from
```

**The Flow:**

1. 🚀 **Fire up the app** — Run it on a localhost server like normal
2. 🤖 **Switch to Antigravity** — Head over to the VibeHacking dir and boot up Antigravity
3. 🌐 **Antigravity scopes the target** — It opens up its built-in browser reviewer
   and analyzes the live app through the web interface — poking at endpoints,
   forms, responses, headers, behaviors. Everything a real attacker would see.
4. 📋 **Attack surface report** — Antigravity lays out all the possible attacks
   we could run — XSS, injection, auth bypasses, broken logic, whatever it finds
5. 🔥 **We pick our shots and start hacking** — working through the attack list,
   one exploit at a time

---

## ⚖️ The One Golden Rule

> **Never read the project's source files directly. That's cheating.**

We go in blind — just like a real attacker would.
Everything Antigravity learns, it learns through the live running app.
No peeking at the code. No shortcuts. Black-box only. 🖤

---

## 🛡️ Tester Privacy

VibeHacking now runs with a default-on privacy guard for local artifacts. Tool
logs, session files, and generated dashboard rows redact URLs, IPs, email
addresses, auth headers, cookies, tokens, MAC addresses, and Windows user paths.
HTTP clients also use a generic authorized-test User-Agent instead of a tester's
real browser/device fingerprint.

```powershell
python vibe.py privacy
```

Network reality check: no app can honestly promise that a tester is completely
untraceable by IP, DNS, hosting, ISP/VPN, or target-server logs. If tester
identity must be separated from the target, route authorized tests through an
approved privacy relay, VPN, or test gateway managed for the program. Keep
written authorization and access-control records outside public reports.

Extra DNS recon is blocked by default in privacy mode. Enable it only when it is
approved for the target:

```powershell
$env:VIBE_ALLOW_DNS_PROBES = "1"
```

Exact local artifacts can be restored for private debugging only:

```powershell
$env:VIBE_PRIVACY_MODE = "off"
```

Still protect tester safety by using pseudonymous tester handles by default,
collecting only the minimum personal information needed for authorization, and
keeping any identity records encrypted, access-controlled, and separate from
public reports.

Public reports should identify testers by handle only. Program admins may retain
confidential accountability records for legal authorization, abuse prevention,
payment, and incident response.

---

## 💡 Why Browser Analysis (Not File Reading)?

Real penetration testing is **black-box** — you attack what you *see*, not what you *know*.
Using Antigravity's browser reviewer to analyze the app through the web keeps things
honest, realistic, and actually more fun. If it can't be found from the outside,
it doesn't count as a real vulnerability anyway.

Plus — it lines up perfectly with the golden rule. No file snooping. Ever.

---

## 🧠 Features

### 1. 📓 Session Hack Log
Every session gets its own log file saved in the VibeHacking dir.
Antigravity tracks everything — what was tried, what landed, what flopped.
So nothing gets lost and you always know where you left off.
```
<path-to-vibehacking>\logs\WestAPI_session_01.md
```

---

### 2. 🚦 Severity Tagging
When Antigravity lists possible attacks, every one gets a severity tag
so you know exactly what to hit first and what to patch ASAP:

- 🔴 **Critical** — Drop everything and fix this now
- 🟡 **Medium** — Needs fixing, not urgent
- 🟢 **Low** — Minor, patch when you get to it
- 🔵 **Informational** — Good to know, not exploitable yet

---

### 3. 🔁 Patch & Replay
After you fix a vulnerability — go back and re-run the exact same attack.
If it holds, you're good. If it breaks again, back to the drawing board.
No vulnerability gets marked "fixed" until it survives a replay. 💪

---

### 4. 📄 Auto Pentest Report Generator
At the end of every session, Antigravity auto-generates a clean,
structured report covering:
- All vulnerabilities found
- Severity levels
- How each one was exploited
- The fix that was applied (or recommended fix if not patched yet)
- Overall security score for the app

Saved right in the logs folder. Useful for tracking progress across
versions of the same app over time.
```
<path-to-vibehacking>\reports\WestAPI_report_01.pdf
```

---

### 5. 🎯 Challenge Mode
Feeling competitive? Flip on Challenge Mode.
A timer starts, and the goal is simple —
find as many vulnerabilities as you can before time runs out.

- Set your own time limit (e.g. 30 mins, 1 hour)
- Antigravity keeps score in real time
- At the end, you get a challenge summary with a rating
```
⏱️ Time: 30:00 | 🔴 Critical: 2 | 🟡 Medium: 4 | 🟢 Low: 1 | 🏆 Score: 847pts
```

Great for keeping sessions focused and making solo testing actually fun.

---

### 6. 💡 Hint System
Stuck on a target and nothing's landing?
Ask Antigravity for a hint — it nudges you in the right direction
without just handing you the answer.

Three hint levels:
- 🌡️ **Warm** — Vague direction ("Think about how the auth tokens are handled")
- 🔥 **Hot** — More specific ("Look at what happens when you tamper with the session cookie")
- 💣 **Burn** — Basically tells you ("Try a JWT none-algorithm bypass on /api/auth")

You control how much help you want. No judgment. 😄

---

### 7. 🧬 Exploit PoC Generator
Every time a vulnerability is confirmed, Antigravity auto-generates
a clean **Proof of Concept** — a minimal reproducible script or payload
that demonstrates the exploit. Saved to the session log so you always
have receipts.

Useful for:
- Showing exactly how something was broken
- Regression testing after patches
- Building your own personal exploit library over time

---

*Built for fun. Built for learning. Built by us, for us.* 🚀
