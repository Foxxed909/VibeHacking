# 🔍 BridgeMind — External Assessment Findings

**Target:** BridgeMind (`bridgemind.ai` and subdomains)
**Authorization:** Public bug bounty — https://www.bridgemind.ai/bug-bounty
**Date:** 2026-08-04
**Tester vantage:** Unauthenticated, external, from a datacenter IP (see limitation below)

---

## ⚠️ Read this first — scope of what was actually tested

This pass tested only the **externally-reachable, unauthenticated** surface. Two
hard limits shaped it, and I'm stating them so nothing here is overclaimed:

1. **Cloudflare blocks this vantage.** Every HTML app host (`www`, `app`, `api`,
   `docs`, `admin`) returns a `403` managed challenge to a datacenter IP. The
   logged-in application was **not reachable** from here.
2. **No authenticated session.** The high-value surface — IDOR/broken object
   access, the admin panel, billing logic, prompt-injection on the agents, the
   *authenticated* MCP tool surface — was **not tested**. That requires a real
   browser session from your own machine (see "Untested" below).

**Bottom line: no exploitable vulnerability was found in the reachable surface.
Everything I could reach is properly secured.** I'm not padding this with
invented findings — a false report wastes Matthew's time and burns trust.

---

## Findings

| # | Severity | Title | Status |
|---|----------|-------|--------|
| 1 | 🟢 Low | MTA-STS policy is in `testing` mode, not `enforce` | Real, reportable |
| 2 | 🔵 Info | DMARC policy is `quarantine`, not `reject` | Hardening suggestion |
| 3 | 🔵 Info | MCP endpoint error discloses the auth mechanism | Likely accepted-risk |

### 1. 🟢 Low — MTA-STS published in `testing` mode
`https://www.bridgemind.ai/.well-known/mta-sts.txt`:
```
version: STSv1
mode: testing
mx: bridgemind-ai.mail.protection.outlook.com
max_age: 86400
```
**Impact:** In `testing` mode the sender does **not** enforce TLS or MX matching —
it only reports. A network attacker able to MITM inbound SMTP can strip TLS or
redirect mail without the policy blocking it. Low severity (requires network
position), but a legitimate, commonly-accepted email-security finding.
**Fix:** after confirming reports look clean, set `mode: enforce`.

### 2. 🔵 Info — DMARC set to `p=quarantine` rather than `p=reject`
`_dmarc.bridgemind.ai` publishes:
```
v=DMARC1; p=quarantine; rua=mailto:dmarc@bridgemind.ai;
```
SPF is strong (`v=spf1 include:spf.protection.outlook.com include:amazonses.com -all`
— hard fail, scoped). DMARC exists and reports. The only nit: `quarantine` sends
spoofed mail to spam rather than rejecting it outright, and there's no `sp=`
subdomain policy or `pct=`.
**Impact:** minor — spoofed BridgeMind email is spam-filtered, not blocked.
**Fix:** after reviewing `rua` reports, move to `p=reject; sp=reject;`.
**Note:** this is a common accepted-risk item; many programs treat it as info.

### 3. 🔵 Info — MCP endpoint discloses its auth scheme in the error
`POST https://mcp.bridgemind.ai/mcp` (unauthenticated) returns:
```json
{"jsonrpc":"2.0","error":{"code":-32001,
 "message":"API key required. Provide a Bearer token in the Authorization header."},"id":null}
```
**Impact:** negligible — this is standard, helpful API behavior; it reveals only
the (obvious) auth mechanism, not a weakness. Included for completeness; probably
not worth submitting.

---

## ✅ Security done right (verified, no action needed)

These are worth telling Matthew — his external posture is genuinely solid:

- **Cloudflare WAF** fronts every app host; datacenter/bot traffic is challenged.
- **MCP server (`mcp.bridgemind.ai/mcp`) is properly auth-gated** — auth is
  enforced *before* method dispatch: **25 JSON-RPC methods** tried (initialize,
  tools/call, resources/read, logging/setLevel, sampling/createMessage, …) plus
  batch, notification, and alternate-header shapes ALL returned the identical
  `-32001 API key required` — no per-method bypass. Rejects no/empty/bogus/`null`/
  `undefined` tokens identically (fails closed, no oracle). CORS does not reflect
  arbitrary origins. Ships HSTS `includeSubDomains; preload` + `nosniff`.
- **`downloads.bridgemind.ai` is a locked S3+CloudFront bucket** — returns
  `AccessDenied`; bucket listing (`?list-type=2`) denied. No object enumeration.
- **No origin-IP leak** — all 8 hosts resolve to the same Cloudflare IPs
  (104.26.2.38 / 104.26.3.38 / 172.67.74.236); no direct-hittable origin to
  bypass the WAF.
- **No subdomain takeover** — 8 live subdomains enumerated (`www api app admin
  mcp docs downloads` + apex), all on A-records, zero dangling CNAMEs.
- **Email:** SPF `-all` hard-fail + DMARC with aggregate reporting.
- **`.well-known/security.txt`** present (RFC 9116) with contact + policy — mature
  disclosure setup.

---

## 🚧 Untested (where real findings would live) — needs YOUR session

The externally-hardened shell means the interesting bugs, if any, are on the
**authenticated** surface, which this vantage can't reach. To test it, capture
your own browser session (you're an authorized participant) and re-run from your
machine:

```bash
cd helpers/browser && npm install playwright && npx playwright install chromium
node grab_session.js https://www.bridgemind.ai/ ../../session_auth.json   # solve CF + log in
export VIBE_AUTH_FILE="$PWD/../../session_auth.json"
python TOOLS/authcheck.py --url https://app.bridgemind.ai/dashboard        # want: AUTHENTICATED
```

Then, in priority order:
1. **MCP authed tool surface** — `python TOOLS/mcp_probe.py --url https://mcp.bridgemind.ai/mcp --authed`
   (what dangerous tools can your normal account call?)
2. **IDOR / cross-tenant** — two accounts, reach B's projects/memory/billing as A
   (`TOOLS/intruder.py`, `TOOLS/axios.py`)
3. **`admin.bridgemind.ai`** — does it reject a normal account? (authz)
4. **Prompt injection** on BridgeAgent/BridgeSwarm — leak system prompt, SSRF via
   the agent's fetch/browser (`TOOLS/prompt_injector.py`, `TOOLS/ssrf_cloud.py`)
5. **Billing logic** — Free→Pro bypass (`TOOLS/biz_logic.py`)

---

## Summary
External unauthenticated posture: **strong**. No exploitable vulnerability found
in the reachable surface; two info-level hardening notes. The assessment is
**incomplete by design** — the authenticated application, where real bugs would
be, is pending a session-authenticated run from your own machine.
