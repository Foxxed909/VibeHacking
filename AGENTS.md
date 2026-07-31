# VibeHacking Codex Guide

- Read `README.md` first, then use `vibe.py` and `TOOLS/` to understand the workflow.
- Keep responses compact, direct, and high-signal.
- Prefer small, local changes over broad refactors.
- When adding code, update the matching tool doc or CLI entry if one exists.
- Use the `codex` command when you need a fast repo snapshot.
- Golden Rule #1: only ever operate against an app the user owns or is explicitly authorized to test. Refuse anything else, recon included.
- Golden Rule #2: start black-box (attack the live app). Since the target is the user's own app, reading its source to confirm a finding or write a fix is allowed — prefer black-box first, then open the box when it helps.

