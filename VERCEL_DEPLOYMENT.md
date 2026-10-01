# Deploy the VibeAgent dashboard to Vercel

Vercel hosts the dashboard as a Python WSGI function (`app.py`). It can serve a
safe, read-only preview by itself. **Live agent runs require a separately hosted,
persistent worker**: the existing agent stores live thread state on disk and
runs background threads, neither of which should be relied on across Vercel
serverless invocations.

The Vercel preview therefore disables launch buttons until a worker, a worker
token, and a dashboard password are all configured. No target is scanned by the
Vercel function itself.

## Preview deployment

```bash
npx vercel@latest deploy --temporary
```

A temporary deployment can be claimed by signing in to Vercel later. For a
linked Vercel project, deploy a Preview with `npx vercel` or Production with
`npx vercel --prod`.

`.vercelignore` excludes `.env`, logs, reports, the deliberately vulnerable
`testapp/`, and unrelated static landing pages. Add provider secrets through
Vercel Project Settings or `vercel env add`; never commit them or paste them
into source files.

## Enable protected live runs

1. Deploy `TOOLS/live_dashboard.py` as a **persistent, long-running worker** on a
   host that supports background processes and durable storage. Put it behind
   HTTPS and firewall it so only the Vercel app can reach it.
2. Generate a random worker token (at least 32 characters), then configure the
   same value in both environments. For example:

   ```bash
   python -c "import secrets; print(secrets.token_urlsafe(32))"
   ```

3. On the worker, set `VIBE_WORKER_TOKEN` to that secret and run:

   ```bash
   python TOOLS/live_dashboard.py --host 0.0.0.0 --port 8080
   ```

   Requests to the worker must use `X-Vibe-Worker-Token`; requests without the
   matching token are rejected. Configure `OPENROUTER_API_KEY` on the worker
   only if you want its agent runs to use OpenRouter.
4. In the Vercel project, set these Environment Variables (Preview and/or
   Production), then redeploy:

   - `VIBE_AGENT_WORKER_URL` — the worker's HTTPS origin, with no path
   - `VIBE_AGENT_WORKER_TOKEN` — same random token as `VIBE_WORKER_TOKEN`
   - `VIBE_DASHBOARD_USER` — optional; defaults to `admin`
   - `VIBE_DASHBOARD_PASSWORD` — a strong, unique dashboard password

   The site uses HTTP Basic Authentication when a dashboard password is set.
   Live runs remain disabled unless all required worker settings are present.

Every run still requires a Target App URL and the existing authorization
statement. Only test apps you own or have explicit written permission to assess.

## Standalone VibeAgent remote audit bridge

The persistent worker also exposes a token-protected `POST /api/tools/run`
endpoint for the standalone VibeAgent product. `GET /api/capabilities`
advertises the supported `remote_tools` list.

This bridge is intentionally limited to bounded audit/recon tools such as
headers, CORS, session policy, API/schema discovery, same-origin crawling and
redacted secret-marker checks. It does **not** expose challenge-bypass,
JWT-forging, WAF-evasion, exploit, or load/stress tools.

The bridge is also fail-closed on target scope. Configure an exact-host
allowlist on the worker itself:

```bash
export VIBE_WORKER_ALLOWED_HOSTS=app.example.com,api.example.com
```

Wildcards and subdomain expansion are not accepted. If the allowlist is empty,
`/api/capabilities` advertises no remote audit tools and `/api/tools/run`
rejects execution.

Standalone VibeAgent should connect directly to the persistent worker origin
using the same `VIBE_WORKER_TOKEN`; the Vercel dashboard proxy is not the tool
execution endpoint.

## Limitations

- A worker is necessary for real-time threads, scans, and durable thread history.
- Vercel's `/tmp` storage is best-effort scratch space only; it is not used as
  the source of truth for live worker threads.
- `testapp/` is intentionally excluded from deployment. Run the practice target
  locally with `python testapp/app.py` instead.
