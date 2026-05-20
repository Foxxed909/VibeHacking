# VibeHacking Report — Cortex v1.0.0
**Date:** 2026-05-20 | **Tester:** Antigravity (black-box) | **Target:** `http://localhost:4321`

## Status: FULLY COMPROMISED

---

## Vulnerabilities

### 🔴 CRITICAL-1 — Default JWT Secret Never Changed
- **Secret:** `change_me_to_a_long_random_string` (copied from .env.example, never updated)
- **Impact:** Forge any JWT with any role. Admin token created, full user DB dumped (13 users + emails), attacker_b promoted to admin.
- **Fix:** Set a strong random JWT_SECRET in .env.

### 🔴 CRITICAL-2 — Stack Traces Leak Internal File Paths
- **Triggers:** Malformed JSON body on any endpoint; file upload > 10 MB
- **Leaked:** `C:\Users\WhitePC\Rooms\Coderoom\Projects\Cortex\node_modules\...` — full Windows path, dep tree, Node version
- **Fix:** Global error handler returning `{"error":"Internal server error"}` only.

### 🟡 MEDIUM-1 — No Rate Limiting on Login
- 20 rapid requests → all 401, no 429, no lockout
- **Fix:** `express-rate-limit` on `/api/auth/login`.

### 🟡 MEDIUM-2 — CRLF Injection Stored in Username
- `PATCH /api/auth/me` accepts `\r\n` in username; stored and reflected in `/api/notes/public`
- **Fix:** Strip control characters from username input.

### 🟡 MEDIUM-3 — File Upload: No Extension or MIME Restrictions
- Accepted: `.html`, `.js`, polyglots. HTML served with `Content-Disposition: attachment` (download forced).
- **Fix:** Allowlist safe MIME types.

### 🟢 LOW-1 — IDOR Existence Oracle on Notes
- `GET /api/notes/:id` returns 403 (exists, not yours) vs 404 (doesn't exist)
- **Fix:** Return 404 for both cases.

### 🟢 LOW-2 — X-Powered-By: Express Exposed
- **Fix:** `app.disable('x-powered-by')` or use `helmet`.

### 🟢 LOW-3 — `env:"development"` Leaked to All Authenticated Users
- **Fix:** Admin-only.

### 🟢 LOW-4 — CORS Wildcard on All Endpoints
- `Access-Control-Allow-Origin: *` everywhere
- **Fix:** Restrict to known origins in production.

### 🔵 INFO-1 — User Enumeration via Registration
- 409 on duplicate username/email confirms account existence.

### 🔵 INFO-2 — AI Service Provider Leaked in Errors
- OpenRouter errors (incl. account billing status) passed through to client.

---

## What Held Up
- IDOR on notes/files/chat: all properly 403'd
- SQL injection: parameterized queries blocked all attempts
- JWT none-algorithm: rejected with 400
- Mass assignment on register: ignored
- Path traversal via download: DB-lookup-before-filesystem

---

## Summary
| Severity | Count |
|---|---|
| 🔴 Critical | 2 |
| 🟡 Medium | 3 |
| 🟢 Low | 4 |
| 🔵 Info | 2 |

**Kill chain:** Default JWT secret → forged admin token → full user DB dump → privilege escalation. Owned without touching source files.
