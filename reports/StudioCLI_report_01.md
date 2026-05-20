# Pentest Report — StudioCLI
**Date:** 2026-05-19  
**Tester:** Antigravity (VibeHacking)  
**Target App:** StudioCLI — localhost:3456  
**Methodology:** Black-box (no source code access)  
**Overall Score:** 3.5 / 10

---

## Executive Summary

StudioCLI has **1 Critical**, **1 High**, **3 Medium**, and **2 Low** severity vulnerabilities. The most dangerous is an unauthenticated API key injection endpoint — any attacker on the network can replace the server's OpenRouter API key with their own, redirecting all AI spend, hijacking prompts, or killing the service entirely. This must be fixed before the app is deployed to any shared environment.

---

## Findings

### [CRITICAL] Unauthenticated API Key Injection — `/api/key`

**What it is:** The `POST /api/key` endpoint accepts any request and stores the provided key with no authentication. The only check is that the key starts with `sk-or-`.

**What an attacker can do:**
- Replace the server key with a key they monitor → steal all user prompts
- Replace it with a garbage key → DoS all AI features for every user
- Replace it with a key they own → use the server as a free OpenRouter proxy

**Proof of Concept:**
```bash
# Overwrite the server's API key with attacker's key
curl -X POST http://TARGET/api/key \
  -H "Content-Type: application/json" \
  -d '{"key":"sk-or-attacker-key-xxxx"}'
# {"ok":true} — key overwritten, no auth required
```

**Fix:**
```javascript
// Require authentication before allowing key changes
app.post('/api/key', requireAuth, async (req, res) => {
  // Also validate key against OpenRouter before storing
  const valid = await verifyKeyWithOpenRouter(req.body.key);
  if (!valid) return res.status(400).json({ error: 'Key rejected by OpenRouter' });
  storeKey(req.body.key);
  res.json({ ok: true });
});
```

---

### [HIGH] Unauthenticated Stripe Checkout Creation — `/api/stripe/create-checkout`

**What it is:** Anyone can trigger Stripe checkout session creation without being logged in.

**What an attacker can do:**
- Generate valid-looking payment links for phishing
- Flood the Stripe API with junk checkout sessions
- Test Stripe integration with arbitrary emails

**Proof of Concept:**
```bash
curl -X POST http://TARGET/api/stripe/create-checkout \
  -H "Content-Type: application/json" \
  -d '{"plan":"pro","email":"victim@example.com"}'
# Returns live cs_test_... checkout URL
```

**Fix:** Require a valid session/JWT before creating checkout sessions.

---

### [MEDIUM] Unauthenticated Config Endpoint — `/api/config`

**What it is:** Full server configuration is exposed to anyone — 11 system personas with their full prompts, complete model list, and `hasKey` status.

**What an attacker can do:**
- Read all internal AI persona prompts (intellectual property)
- Know exactly which AI models are available
- Confirm whether an API key is set (`hasKey: true`) before attempting key injection

**Fix:** Either require auth, or strip sensitive fields (personas, `hasKey`) from the public config.

---

### [MEDIUM] Unauthenticated Dashboard Page — `/dashboard.html`

**What it is:** The dashboard page is served without any server-side authentication check.

**Fix:** Add a middleware guard that redirects to login if no valid session exists.

---

### [MEDIUM] Implicit DoS via Minimal Key Format — `/api/key`

**What it is:** The server accepts keys as short as `sk-or-` (6 chars). When stored, this causes the server to omit the `Authorization` header in all OpenRouter requests — breaking all AI features silently.

**Fix:** Enforce a minimum key length (e.g. 20+ chars) in addition to the `sk-or-` prefix check.

---

### [LOW] Unauthenticated User Plan Enumeration — `/api/stripe/plan`

**What it is:** Any unauthenticated request can query a user's subscription plan status by email.

**Fix:** Require authentication, or at minimum rate-limit more aggressively.

---

### [LOW] Community Messages Stored Raw Server-Side

**What it is:** The community chat endpoint stores messages server-side with no server-side sanitization. The client escapes output via `esc()`, which prevents XSS in the official UI. However, future clients or API consumers may render unescaped content.

**Fix:** Sanitize/strip HTML tags server-side at ingest, not just at render.

---

## Fix Priority

| Priority | Finding | Action |
|---|---|---|
| 1 | API key injection | Add auth + live OpenRouter validation |
| 2 | Stripe checkout unauthed | Require session |
| 3 | Config exposure | Strip personas + hasKey from public route |
| 4 | Dashboard unauthed | Server-side auth guard |
| 5 | Minimal key DoS | Enforce min key length |
| 6 | Plan enumeration | Add auth or rate limit |
| 7 | Community raw storage | Sanitize at ingest |

---

## Replay Test Checklist

After applying fixes, re-run each exploit to confirm the patch holds:

- [ ] `POST /api/key` without auth → should return `401 Unauthorized`
- [ ] `POST /api/key` with `{"key":"sk-or-"}` → should return `400` (too short)
- [ ] `POST /api/stripe/create-checkout` without auth → should return `401`
- [ ] `GET /api/config` → should NOT include persona prompts or `hasKey`
- [ ] `GET /dashboard.html` without session → should redirect to login
- [ ] `GET /api/stripe/plan?email=x` without auth → should return `401`

---

*Report generated by Antigravity — VibeHacking*  
*Session log: `logs/StudioCLI_session_01.md`*
