# 🎯 NovaChat — the practice target

A small, **deliberately vulnerable** AI-assistant web app so VibeHacking has
something real to break. Every vulnerability is genuine and actually
exploitable — nothing here is faked, scripted, or a canned "you got hacked"
message. Point the tools at it and you land real findings.

Stdlib only. No `pip install`. **Do not deploy this anywhere reachable from the
internet** — it exists to be broken on your own machine (Golden Rule #1).

## Run it

```bash
python testapp/app.py            # http://localhost:3456/
python testapp/app.py --port 5500
```

By default the "LLM" is a local deterministic responder — no API cost, no real
key at risk. To proxy a live model instead:

```bash
NOVACHAT_LLM=real OPENROUTER_API_KEY=sk-... python testapp/app.py
```

The baked-in `OPENROUTER_API_KEY` is a **fake-but-real-shaped** value that lives
only inside this target. The app genuinely leaks it through real bugs, so the
tools confirm a true finding without any live credential being exposed.

## What's broken (and which tool finds it)

| Vulnerability | Endpoint | Tool |
| :-- | :-- | :-- |
| Stored XSS (unescaped guestbook) | `POST /api/guestbook` → `GET /` | `exploit_final`, `prompt_injector` |
| API key leak via error trace | `POST /api/chat` (type-confuse `model`) | `key_stealer`, `env_probe`, `deep_extract` |
| Prompt-injection persona leak | `POST /api/chat` | `key_stealer`, `prompt_injector` |
| Debug/config secret leak | `GET /api/config?debug=true`, `/api/debug` | `key_stealer`, `deep_extract` |
| SSRF (fetches any URL, incl. `file://`) | `POST /api/computer/instruct` | `ssrf_probe`, `key_stealer` |
| JWT `alg:none` + weak-secret bypass | `GET /api/admin` | `leep`, `aukdoc`, `axios` |
| IDOR (any user record) | `GET /api/user?id=N` | `biz_logic` |
| Open redirect | `GET /go?url=` | `redirect` |
| Path traversal | `GET /files?path=../` | `traversal_sniper` |
| User enumeration + no login rate-limit | `POST /api/login` | `leep`, `random_roll` |
| Missing security headers | all responses | `vibe_headers`, `corscan` |

## Quick end-to-end

```bash
python testapp/app.py &                       # start the target
python vibe.py scan http://127.0.0.1:3456/    # deep scan
python TOOLS/exploit_final.py --url http://127.0.0.1:3456/api/guestbook --field text --check-url http://127.0.0.1:3456/
python TOOLS/key_stealer.py --url http://127.0.0.1:3456/          # redacted
python TOOLS/key_stealer.py --url http://127.0.0.1:3456/ --show-keys   # raw (your own app)
```
