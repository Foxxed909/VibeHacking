#!/usr/bin/env bash
#
# setup-editions.sh — set up VibeHacking as two side-by-side folders you can use
# at the same time, from one clone (`main` is a separate, squashed history):
#
#   external/   -> the public edition   (main branch,     ~44 tools)
#   internal/   -> the full edition     (internal branch, ~63 tools = all + arsenal)
#
# Usage (run in an empty folder where you want the two editions to live):
#   bash setup-editions.sh
#   bash setup-editions.sh git@github.com:Foxxed909/VibeHacking.git   # custom remote/SSH
#
# Update later:  git -C internal pull   (full edition)
#                git -C external pull    (public edition)
set -euo pipefail

REPO="${1:-https://github.com/Foxxed909/VibeHacking.git}"

if [ -e internal ] || [ -e external ]; then
  echo "[-] An 'internal' or 'external' folder already exists here. Run this in an empty directory."
  exit 1
fi

echo "[*] Cloning $REPO into ./internal (full edition) ..."
git clone "$REPO" internal
git -C internal switch internal

echo "[*] Adding ./external as a linked worktree on main (public edition) ..."
git -C internal worktree add ../external main

cat <<'DONE'

[+] Done. Two live editions from one clone (separate histories):

    external/   ->  public edition   (git branch: main)
    internal/   ->  full edition     (git branch: internal)

Use everything from ./internal:
    cd internal
    python vibe.py list                                   # see all tools
    python vibe.py scan http://127.0.0.1:3456/            # external tool
    python TOOLS/redteam.py --url http://127.0.0.1:8800/  # internal tool

Update later:
    git -C internal pull
    git -C external pull
DONE
