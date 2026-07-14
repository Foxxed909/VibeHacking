# Locked Tool Area

This folder is intentionally a safety boundary, not a stash of hidden offensive
variants.

The global CLI reads `vb/locked/manifest.json` to gate high-impact existing
tools behind an explicit authorization prompt and a local audit log. Keep that
gate visible when sharing the repo.

Rules for anything placed here:

- No hidden payloads or secret backdoors.
- No public-target load or denial-of-service helpers.
- No credential theft, persistence, evasion, or destructive automation.
- Preserve host allowlists, typed confirmation, rate caps, and logs.

