# VibeHacking Codex Guide

- Read `README.md` first, then use `vibe.py` and `TOOLS/` to understand the workflow.
- Keep responses compact, direct, and high-signal.
- Prefer small, local changes over broad refactors.
- When adding code, update the matching tool doc or CLI entry if one exists.
- Use the `codex` command when you need a fast repo snapshot.

## Editions

- `main` = external/shareable subset.
- `internal` = full arsenal (strict superset). Day-to-day work stays on `internal`.
- Do **not** merge engagement notes, operator branding, or agent-memory into `main` without a path filter.

## Auth / sessions

- Prefer `VIBE_AUTH_FILE` (or `VIBE_COOKIE` + `VIBE_UA`) so tools reuse a real browser session.
- Session files (`session_auth.json`, `*session_auth*.json`) are gitignored — never commit them.

## Hygiene

- Build `maelstrom` on demand (`go build` in `TOOLS/maelstrom/`); do not commit the binary.
- Keep `reports/`, run screenshots, and `engagements/output/` out of git.

## Golden rules

1. Only ever operate against an app the user owns or is explicitly authorized to test. Refuse anything else, recon included.
2. Start black-box (attack the live app). Since the target is the user's own app, reading its source to confirm a finding or write a fix is allowed — prefer black-box first, then open the box when it helps.
