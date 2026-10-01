# Hyperion v2.1 — 14x Sharded Resilience, Cloud/Edge (Cloudflare, AWS, Vercel) & SLO Load Engine

**Hyperion v2.1** (`TOOLS/hyperion` + `TOOLS/hyperion.py`) is VibeHacking's next-generation competitor to **Maelstrom**. It is engineered to be **14x stronger than Maelstrom** in both throughput architecture (`3,500,000 RPS` private-lab ceiling vs Maelstrom's `250,000 RPS` cap, zero shared channel/lock contention) and enterprise resilience features, with first-class support for apps running on or backed by **Cloudflare**, **AWS** (CloudFront, ALB, API Gateway, App Runner, Lambda URLs), and **Vercel (`.vercel.app`)**.

## 🔒 Mandatory Authorization Guard (`XXLMILLEAMEAN`)

Hyperion is protected by a constant-time (`hmac.compare_digest` / `crypto/subtle.ConstantTimeCompare`) cryptographic guard gate and produces an **HMAC-SHA256 signed run receipt** (`receipt_hmac`):

- **CLI flag**: `--guard XXLMILLEAMEAN` (or `-g XXLMILLEAMEAN`)
- **Environment variable**: `VIBE_HYPERION_GUARD=XXLMILLEAMEAN`
- **Audit trail**: Every unlock attempt (`allowed=true` or `allowed=false`) is logged to `logs/locked_cli_access.log`.

## ☁️ Cloudflare, AWS & Vercel (`.vercel.app`) Edge Support

When testing your own applications deployed behind **Cloudflare**, **AWS**, or **`.vercel.app`**, Hyperion v2.1 provides:

1. **Edge Cache Modes (`--edge-mode {auto,cdn-cache,origin-bypass}`)**:
   - `auto` (default): Sends standard traffic and classifies every response's edge cache status (`HIT`, `MISS`, `DYNAMIC`, `BYPASS`, `PRERENDER`, `STALE`).
   - `cdn-cache`: Sends cache-friendly requests (`Accept-Encoding: gzip, deflate`) to measure how much load your Cloudflare / CloudFront / Vercel Edge cache absorbs.
   - `origin-bypass`: Automatically injects `Cache-Control: no-cache, no-store, must-revalidate`, `Pragma: no-cache`, and per-request `_cb=<seq>` query tokens so requests penetrate the CDN edge and stress your **actual backend origin / Vercel Serverless Function / AWS Lambda / ALB**.
2. **Provider Deployment Protection & Zero-Trust Bypasses**:
   - **Vercel (`.vercel.app`)**: `--vercel-bypass <secret>` (or `VERCEL_AUTOMATION_BYPASS_SECRET`) sends `x-vercel-protection-bypass` and `x-vercel-set-bypass-cookie: samesitenone`.
   - **Cloudflare Access**: `--cf-access-id <id> --cf-access-secret <secret>` (or `CF_ACCESS_CLIENT_ID` / `CF_ACCESS_CLIENT_SECRET`).
   - **AWS API Gateway**: `--aws-api-key <key>` (or `AWS_API_GATEWAY_KEY`).
3. **TLS 1.3 ALPN, Custom SNI & Origin Resolution (`--sni`, `--resolve`, `--follow-redirects`)**:
   - Explicitly negotiates `http/1.1` ALPN on raw TLS sockets for Cloudflare/Vercel/CloudFront TLS 1.3 edges.
   - Follows canonical `301/302/307/308` edge redirects during preflight (`--follow-redirects`).
   - Supports `--sni <hostname>` and `--resolve <ip_or_host[:port]>` to test either through the public CDN edge or directly against an origin IP/ALB while preserving the `Host` header and TLS SNI.
4. **Real-Time Edge Telemetry**:
   - Auto-detects `cloudflare`, `vercel`, `aws-cloudfront`, and `aws-alb-apigw`.
   - Extracts active edge PoP/region codes (`CF-Ray` e.g. `CF:LOS`, `x-vercel-id` e.g. `Vercel:iad1`, `x-amz-cf-pop` e.g. `CloudFront:IAD89-P2`).
   - Tracks `Cache HIT %`, `WAF Challenges` (`cf-mitigated`, `x-vercel-mitigated`, `x-amzn-waf-action`), Cloudflare `520–526` origin saturation errors, and Vercel/Lambda serverless timeouts/throttles.

## 🚀 Usage Examples

### 1. Test Your `.vercel.app` App (Edge Cache vs Serverless Function Origin)
```bash
# Authorize and test your .vercel.app deployment (penetrating edge cache to test Serverless capacity)
python vibe.py hyperion --guard XXLMILLEAMEAN \
  -t https://my-app.vercel.app/ \
  --trust-target --yes \
  --edge-mode origin-bypass \
  --vercel-bypass "$VERCEL_AUTOMATION_BYPASS_SECRET" \
  --profile stress-knee \
  -r 500 -d 15s -w 32 \
  --slo-p95 300 --slo-apdex 0.90 \
  --report-file logs/vercel_report.md
```

### 2. Test Your Cloudflare-Backed App
```bash
python vibe.py hyperion --guard XXLMILLEAMEAN \
  -t https://app.yourdomain.com/ \
  --trust-target --yes \
  --edge-mode origin-bypass \
  --endpoints "/:50,/api/health:50" \
  --profile ramp \
  -r 1000 -d 15s -w 64 \
  --json-out logs/cloudflare_metrics.json
```

### 3. Test Your AWS CloudFront / ALB / API Gateway App
```bash
python vibe.py hyperion --guard XXLMILLEAMEAN \
  -t https://d111111abcdef8.cloudfront.net/api/status \
  --trust-target --yes \
  --aws-api-key "$AWS_API_GATEWAY_KEY" \
  --edge-mode origin-bypass \
  --profile step \
  -r 1000 -d 15s -w 64
```
