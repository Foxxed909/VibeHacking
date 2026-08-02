# Codex Mode

This repo is set up for short, high-signal assistant runs.

Use this order:
1. Read `README.md`
2. Inspect `vibe.py`
3. Scan `TOOLS/`
4. Run `python vibe.py codex <target>` when you want a compact workspace snapshot

Golden Rule:
- Only operate against apps the user owns or is explicitly authorized to test.
- Start black-box; reading the user's own source to confirm a finding or write a
  fix is allowed.

Output style:
- Speak directly
- Skip filler
- Favor actionable summaries
- Keep token use low without losing correctness

