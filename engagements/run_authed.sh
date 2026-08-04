#!/usr/bin/env bash
# run_authed.sh — authenticated attack chain for the BridgeMind bounty.
#
# Run this from YOUR machine AFTER capturing a session:
#   cd helpers/browser && npm install playwright && npx playwright install chromium
#   node grab_session.js https://www.bridgemind.ai/ ../../session_auth.json   # solve CF + log in
#   export VIBE_AUTH_FILE="$PWD/../../session_auth.json"
#   # optional, for account-based tests:
#   export BM_USER="you@example.com" BM_PASS="yourpassword"
#   bash engagements/run_authed.sh
#
# It verifies the session, then runs the high-value authed tools in priority
# order, saving each tool's output and printing a candidate-findings summary.
# DoS-class tools (maelstrom/storm/vibe_api) are intentionally NOT run — never
# on his prod.
set -u

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT" || exit 1
OUT="engagements/output/$(date +%Y%m%d-%H%M%S)"
mkdir -p "$OUT"

WWW="https://www.bridgemind.ai"
APP="https://app.bridgemind.ai"
API="https://api.bridgemind.ai"
ADMIN="https://admin.bridgemind.ai"
MCP="https://mcp.bridgemind.ai/mcp"

say() { printf '\n\033[1;36m== %s ==\033[0m\n' "$*"; }
run() { # run <name> <cmd...>
  local name="$1"; shift
  printf '  → %s\n' "$name"
  ( "$@" ) >"$OUT/$name.txt" 2>&1
}

# 0. Session gate --------------------------------------------------------------
say "0. Verifying session"
if [ -z "${VIBE_AUTH_FILE:-}${VIBE_COOKIE:-}" ]; then
  echo "  [-] No session set. export VIBE_AUTH_FILE=... (see helpers/browser/README.md)"; exit 2
fi
python3 TOOLS/authcheck.py --url "$APP/dashboard" | tee "$OUT/authcheck.txt"
if ! grep -q "AUTHENTICATED" "$OUT/authcheck.txt"; then
  echo "  [-] Not authenticated (see above). Re-capture the session and retry."; exit 3
fi

# 1. MCP authed tool surface (highest value) -----------------------------------
say "1. MCP authed tool surface"
run mcp_probe python3 TOOLS/mcp_probe.py --url "$MCP" --authed

# 2. Headers / CORS / cookies on the real (now reachable) app ------------------
say "2. Header / CORS / cookie hygiene"
run vibe_headers_www python3 TOOLS/vibe_headers.py --url "$WWW/"
run vibe_headers_api python3 TOOLS/vibe_headers.py --url "$API/"
run corscan_api      python3 TOOLS/corscan.py      --url "$API/"
run phantom_app      python3 TOOLS/phantom.py      --url "$APP/"

# 3. IDOR / object access (needs the session; deepest with 2 accounts) ---------
say "3. IDOR / broken object access"
run axios_api python3 TOOLS/axios.py --url "$API/api/projects/"
if [ -n "${BM_USER:-}" ]; then
  run intruder python3 TOOLS/intruder.py --url "$APP/" --login /api/auth/login --user-field email
fi

# 4. Admin authz — should reject your normal account ---------------------------
say "4. Admin authz"
run admin_headers python3 TOOLS/vibe_headers.py --url "$ADMIN/"
run admin_aukdoc  python3 TOOLS/aukdoc.py       --url "$ADMIN/"

# 5. Adaptive kill-chain (recon → classify → dispatch, session-aware) ----------
say "5. Adaptive redteam pass (throttled)"
if [ -n "${BM_USER:-}" ]; then
  run redteam python3 TOOLS/redteam.py --url "$APP/" --user "$BM_USER" --pass "${BM_PASS:-}" --user-field email
else
  run redteam python3 TOOLS/redteam.py --url "$APP/"
fi

# 6. Prompt injection on the agent chat (manual confirm recommended) -----------
say "6. Prompt injection surface"
run prompt_injector python3 TOOLS/prompt_injector.py --url "$API/api/chat" || true

# Summary ----------------------------------------------------------------------
say "CANDIDATE FINDINGS (verify each by hand before reporting)"
grep -rHnE 'HACK|CRITICAL' "$OUT" | sed "s#$OUT/##" | sort -u || echo "  (no HACK/CRITICAL flags — dig manually into the saved output)"
echo
echo "Raw output saved under: $OUT/"
echo "Reminder: confirm every candidate manually, then submit via the BridgeMind dashboard."
