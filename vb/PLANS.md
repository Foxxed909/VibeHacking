# Vibe Plans

VibeHacking ships three subscription tiers. They're defined in one place —
[`vb/plans.py`](plans.py) — and enforced as **honor-system gating**, not a real
paywall.

> **Read this first.** The whole toolkit is plain Python on the user's own disk.
> Anyone can open `vb/plans.py` and delete a check. Plans are *product structure
> and upsell*, not security. If you need a paywall that actually holds, the
> enforcement has to live on a server you control (see "Why it's honor-system").

## Tiers

| | Vibe Free | Vibe Pro | Vibe Elite |
|---|---|---|---|
| Recon & header tools | ✅ | ✅ | ✅ |
| Auth / injection / secrets tools | — | ✅ | ✅ |
| Bundled flows (`scan`, `attack`, `multi`) | — | ✅ | ✅ |
| Local / private load testing | — | ✅ | ✅ |
| Claude autonomous brain (`claude.py`) | preview only | ✅ | ✅ |
| Authorized **external** audits | — | — | ✅ |
| Multi targets / jobs | 1 / 1 | 5 / 4 | 14 / 10 |

`--dry-run` and `--list-tools` on the Claude brain stay free as a teaser.

## Choosing a plan

```powershell
vibe plan                  # show the active plan and what it unlocks
vibe setplan pro           # persist a plan choice to vibe_plan.json
$env:VIBE_PLAN = "pro"     # env var wins for the current shell only
```

## The founder override

There is a single dev/founder master code that flips the active plan to the top
tier:

```powershell
vibe unlock CLAUDEISMYBABE  # -> Vibe Elite, written to logs/plan_access.log
vibe lock                   # drop the override
$env:VIBE_UNLOCK = "CLAUDEISMYBABE"  # one-shot, no persisted state
```

This is **documented on purpose**. Every use is logged to
`logs/plan_access.log`. Because the code ships in plaintext source, it is **not a
secret** — `grep CLAUDEISMYBABE` finds it instantly. Treat it as a convenience
toggle for the people building VibeHacking, never as protection.

## Plans gate features, not safety

The override unlocks *tiers*. It does **not** touch the framework's
authorization gates. External load testing still requires:

- the host in `authorized_targets.txt`,
- the typed hostname confirmation, and
- the rate caps in `vibe.py` (external Maelstrom is hard-capped at 9999.99 rps).

Elite / unlocked cannot send unauthorized load at a public host any more than
Free can. Two different layers; the override only touches the first.

## Why it's honor-system (and how to make it real)

You can't paywall code you hand to the user. To actually enforce plans you'd
need a server: a license API issues short-lived **signed** entitlement tokens,
the client verifies a signature with a public key (so no secret ships), and the
genuinely-paid capability — e.g. the Claude brain billing *your* API credits
instead of the user's own key — runs server-side where the user can't reach it.
That's a separate build; this module is the local, friendly version.
