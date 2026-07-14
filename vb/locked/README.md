# Locked CLI Gate

This folder holds the visible policy for high-impact VibeHacking tools.

It is not a secret payload vault and it is not an encryption layer. The global
CLI uses this folder to decide which existing tools require an explicit
authorized-testing confirmation before launch.

Locked CLI access writes to `logs/locked_cli_access.log`.

Do not store private passphrases in this repo. If a local-only secret is ever
needed, keep it outside source control and outside shared copies.

