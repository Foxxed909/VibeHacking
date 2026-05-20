# VibeHacking Report — StudioCLI
**Date:** 2026-05-20 | **Tester:** Antigravity (black-box) | **Target:** `http://localhost:3456`

## Status: CRITICAL HOLES — KEY BURNING + COMMUNITY INJECTION

---

## Recon Summary
- **App:** StudioCLI — AI chat platform
- **Stack:** Node.js + Express, Supabase auth, OpenRouter AI, Stripe payments
- **Hardening:** Helmet (full header suite), DOMPurify, rate limiting active
- **Supabase project:** `yhranfhtggpzgadsyctw`
- **Active users at time of test:** 1 (via `/api/community/stream` SSE count)

---

## Vulnerabilities

### 🔴 CRITICAL-1 — Unauthenticated AI Chat (`/api/chat`)
- Zero auth required. Live OpenRouter key runs on every hit.
- Anyone on the network can use AI credits for free indefinitely.
- Also enables unlimited prompt injection with no lockout.
- **Proof:** `POST /api/chat` with no token → 200 + full SSE stream
- **Fix:** Require auth on `/api/chat`.

### 🔴 CRITICAL-2 — Unauthenticated Community Message Injection
- `POST /api/community/message` with `{"text":"..."}` posts to the live shared stream.
- No auth. Field name mismatch (`text` not `message`) = obscurity only.
- **Proof:** Injected `"[NOTICE] Session token rotation required..."` → `{"ok":true}` → visible to all connected users
- **Fix:** Require auth. Attach real user identity to posts.

### 🟡 MEDIUM-1 — Stripe Plan Oracle (Unauthenticated)
- `GET /api/stripe/plan?email=anyone@example.com` → returns subscription plan for any email
- **Proof:** `nifemifoxx@gmail.com` → `{"plan":"creator",...}`
- **Fix:** Require auth; only allow users to query their own email.

### 🟡 MEDIUM-2 — Unauthenticated Web Search (`/api/search`)
- `GET /api/search?q=anything` runs without a token.
- Burns server resources and rate-limit budget.
- **Fix:** Require auth.

### 🟢 LOW-1 — Config Info Disclosure (`/api/config`)
- Full model list, all personas, `"hasKey":true` — unauthenticated.
- Reveals exact AI provider stack to anyone.

### 🟢 LOW-2 — Stats Info Disclosure (`/api/stats`)
- `{"chat":9,"search":0,"research":0,"errors":334,"uptime":50834}` — unauthenticated.
- **Note:** 334 errors in ~14h is worth investigating.

### 🔵 INFO-1 — Community Stream User Count
- `/api/community/stream` broadcasts real-time connected user count with no auth.

### 🔵 INFO-2 — Computer-Use SSRF Surface
- `/api/computer/instruct` reachable (not 404). Needs browser extension active.
- Once extension is running, this is a live SSRF vector back into localhost.

---

## key_stealer.py Results
- Vector 1 (Prompt Injection): No key extracted — AI model well-aligned, refused all probes
- Vector 3 (Hidden Endpoints): `/api/config` flagged open on all query params (correct, not a bypass)
- Vector 5 (X-OR-Key Oracle): Timed out — header not accepted
- Vector 6 (Computer-Use SSRF): Endpoint alive but extension not running
- **Overall:** Key string never exposed. Risk is open *usage* of the key, not leakage of the string.

---

## What Held Up
- Helmet — full security header suite
- DOMPurify — XSS via markdown blocked
- Rate limiting — `rlHitsPerMin` counter active
- AI model — refused all env/key probes
- X-Forwarded-For spoofing — DEV_SKIP_AUTH correctly ignores spoofed IPs
- Supabase auth on protected routes

---

## Cortex vs StudioCLI
| | Cortex | StudioCLI |
|---|---|---|
| How it fell | Default JWT secret | Open AI endpoint + community injection |
| Hardening | None | Helmet + DOMPurify + rate limit |
| Kill chain | Forge admin token → full DB dump | Hit `/api/chat` free + inject community feed |
| Most critical fix | Change JWT_SECRET | Auth-gate `/api/chat` |
