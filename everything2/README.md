# everything2 — hardened full app

A **non-deliberately-vulnerable** NovaChat-style app. Same feature surface as the
practice target, but built to resist the classic issues the toolkit hunts for.

Use this to see whether tools still flag real residual risk — not to farm
canned findings.

| Target | Purpose |
|--------|---------|
| **`everything2/`** | Hardened full app (this folder) |
| **`testapp/`** | Deliberately vulnerable practice target ("everything3") |

Stdlib only. Local / authorized testing only.

## Run

```bash
python everything2/app.py              # http://127.0.0.1:3457/
python everything2/app.py --port 4000
```

Optional strong JWT secret:

```bash
EVERYTHING2_JWT_SECRET='long-random-value' python everything2/app.py
```

## Hardening applied

- Stored XSS: guestbook HTML-escaped
- Secrets: no key in system persona, errors, or public config
- JWT: rejects `alg:none`; secret from env or random at boot (not `secret`)
- IDOR: `/api/user` requires bearer token; users only see themselves (admin can list by id)
- Open redirect: only same-origin relative paths
- Path traversal: resolved path must stay under `public/`
- SSRF: blocks `file://`, loopback, link-local, private ranges
- Login: uniform error messages; simple per-IP rate limit
- Passwords: length policy on register; hashes not returned in API bodies
- Security headers: CSP, X-Frame-Options, nosniff, Referrer-Policy, Permissions-Policy

## Smoke against tools

```bash
python everything2/app.py --port 3457 &
python TOOLS/vibe_headers.py --url http://127.0.0.1:3457/
python TOOLS/exploit_final.py --url http://127.0.0.1:3457/api/guestbook \
  --field text --check-url http://127.0.0.1:3457/ || true
python TOOLS/key_stealer.py --url http://127.0.0.1:3457/
```

Expect headers to look much healthier; XSS/key-leak checks should **not** land
the same easy confirms as on `testapp/`.
