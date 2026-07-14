#!/usr/bin/env python3
"""
plans.py — VibeHacking subscription tiers (honor-system gating).

Single source of truth for what each Vibe plan unlocks. This is an HONEST
honor-system layer, NOT a real paywall: the whole toolkit is plain Python on the
user's own disk, so anyone can edit these checks out in ten seconds. Treat plans
as product structure and friendly upsell — never as security.

The founder/dev override (FOUNDER_CODE) flips the active plan to the top tier.
It is intentionally documented and logged — not a hidden backdoor. Because it
ships in plaintext source, it is NOT a secret; do not rely on it to protect
anything that actually matters.

IMPORTANT — plans gate FEATURES, not SAFETY. The override unlocks tiers; it does
NOT bypass the framework's authorization gates. External load testing still
requires the host in authorized_targets.txt, the typed confirmation, and the
rate caps in vibe.py. Elite/unlocked cannot DoS a public host any more than Free
can. Those are two different layers and the override only touches the first.

Activate a plan:
    set VIBE_PLAN=pro                  # env var wins for one shell
    vibe setplan pro                   # persist a plan choice
    vibe unlock CLAUDEISMYBABE         # founder override -> top tier (logged)
    vibe plan                          # show the active plan + what it unlocks
    vibe lock                          # drop the override

Plan state persists in vibe_plan.json next to vibe.py (override VIBE_PLAN_FILE).
"""

import json
import os
import time

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
PLAN_FILE = os.environ.get("VIBE_PLAN_FILE") or os.path.join(ROOT, "vibe_plan.json")
LOG_DIR = os.path.join(ROOT, "logs")

# Founder / dev master override. Honor-system only, logged on use, NOT a secret.
FOUNDER_CODE = "CLAUDEISMYBABE"
FOUNDER_TIER = "elite"

TIER_ORDER = ["free", "pro", "elite"]

# Tool families (mirrors TOOLS/CATALOG.md groupings).
_RECON   = {"ash", "spider", "ghost", "api_finder", "api_check", "cloud_scout", "noloader"}
_HEADERS = {"vibe_headers", "corscan", "phantom", "header_inject"}
_AUTH    = {"leep", "aukdoc", "axios", "random_roll"}
_INJECT  = {"authdoc", "fuzz_vibe", "biz_logic", "redirect",
            "traversal_sniper", "ssrf_probe", "prompt_injector", "timebomb"}
_SECRETS = {"env_probe", "deep_extract", "key_stealer", "credit_drain"}
_LOAD    = {"storm", "vibe_api", "maelstrom"}

# Reporting / session / meta commands — never gated by plan.
ALWAYS_FREE = {
    "report", "status", "list", "tools", "privacy", "clean", "codex",
    "trust", "help", "plan", "unlock", "lock", "setplan",
    "lmx", "poc_gen", "backer", "void", "codex_boot",
}

FREE_TOOLS = _RECON | _HEADERS
PRO_TOOLS  = FREE_TOOLS | _AUTH | _INJECT | _SECRETS | _LOAD

TIERS = {
    "free": {
        "label": "Vibe Free",
        "blurb": "Recon & header audits — look, don't poke.",
        "tools": sorted(FREE_TOOLS),
        "flows": [],
        "max_multi_targets": 1,
        "max_multi_jobs": 1,
        "max_maelstrom_rps": 0,
        "allow_load": False,
        "allow_brain": False,
        "allow_external": False,
        "allow_locked": False,
    },
    "pro": {
        "label": "Vibe Pro",
        "blurb": "Full kill-chain on local/owned targets + the Claude brain.",
        "tools": sorted(PRO_TOOLS),
        "flows": ["scan", "attack", "multi"],
        "max_multi_targets": 5,
        "max_multi_jobs": 4,
        "max_maelstrom_rps": 1000,
        "allow_load": True,
        "allow_brain": True,
        "allow_external": False,
        "allow_locked": True,
    },
    "elite": {
        "label": "Vibe Elite",
        "blurb": "Everything, max caps, authorized external audits.",
        "tools": "*",
        "flows": ["scan", "attack", "multi"],
        "max_multi_targets": 14,
        "max_multi_jobs": 10,
        "max_maelstrom_rps": 9999.99,
        "allow_load": True,
        "allow_brain": True,
        "allow_external": True,   # still allowlist + typed-confirm gated in vibe.py
        "allow_locked": True,
    },
}


# --------------------------------------------------------------------------- #
# State
# --------------------------------------------------------------------------- #
def _read_state():
    try:
        with open(PLAN_FILE, "r", encoding="utf-8") as fh:
            data = json.load(fh)
            if isinstance(data, dict):
                return data
    except (OSError, json.JSONDecodeError):
        pass
    return {}


def _write_state(state):
    try:
        with open(PLAN_FILE, "w", encoding="utf-8") as fh:
            json.dump(state, fh, indent=2)
    except OSError:
        pass


def _normalize_tier(name):
    name = (name or "").strip().lower()
    return name if name in TIERS else None


def configured_plan():
    """Plan the user selected: env var wins, then state file, else free."""
    env = _normalize_tier(os.environ.get("VIBE_PLAN"))
    if env:
        return env
    return _normalize_tier(_read_state().get("plan")) or "free"


def is_unlocked():
    """True if the founder override is active (env one-shot or persisted)."""
    if os.environ.get("VIBE_UNLOCK", "").strip() == FOUNDER_CODE:
        return True
    return bool(_read_state().get("unlocked"))


def active_tier():
    return FOUNDER_TIER if is_unlocked() else configured_plan()


def entitlements():
    return dict(TIERS[active_tier()])


# --------------------------------------------------------------------------- #
# Mutations
# --------------------------------------------------------------------------- #
def unlock(code):
    if (code or "").strip() != FOUNDER_CODE:
        _log("unlock_fail", "bad_code")
        return False, "[-] That code didn't work."
    state = _read_state()
    state["unlocked"] = True
    _write_state(state)
    _log("unlock", "founder_code")
    return True, f"[+] Founder override accepted — {TIERS[FOUNDER_TIER]['label']} unlocked. (Logged.)"


def lock():
    state = _read_state()
    had = bool(state.get("unlocked"))
    state["unlocked"] = False
    _write_state(state)
    if had:
        _log("lock", "manual")
    return had


def set_plan(name):
    tier = _normalize_tier(name)
    if not tier:
        return False, f"[-] Unknown plan '{name}'. Choose: {', '.join(TIER_ORDER)}."
    state = _read_state()
    state["plan"] = tier
    _write_state(state)
    _log("set_plan", tier)
    return True, f"[+] Plan set to {TIERS[tier]['label']}."


def _log(event, detail=""):
    try:
        os.makedirs(LOG_DIR, exist_ok=True)
        stamp = time.strftime("%Y-%m-%d %H:%M:%S")
        line = f"{stamp}\tevent={event}\ttier={active_tier()}\tdetail={detail}\n"
        with open(os.path.join(LOG_DIR, "plan_access.log"), "a", encoding="utf-8") as fh:
            fh.write(line)
    except OSError:
        pass


# --------------------------------------------------------------------------- #
# Gating
# --------------------------------------------------------------------------- #
def min_tier_for(name):
    name = (name or "").strip()
    if name in ALWAYS_FREE or name in FREE_TOOLS:
        return "free"
    if name in _AUTH or name in _INJECT or name in _SECRETS or name in _LOAD:
        return "pro"
    if name in {"scan", "attack", "multi"}:
        return "pro"
    return "free"  # unknown command -> never block meta/reporting


def gate(name):
    """Return (allowed, message) for running `name` on the active plan."""
    need = min_tier_for(name)
    have = active_tier()
    if TIER_ORDER.index(have) >= TIER_ORDER.index(need):
        return True, ""
    return False, _upsell(name, need, have)


def _upsell(name, need, have):
    need_label = TIERS[need]["label"]
    have_label = TIERS[have]["label"]
    return "\n".join([
        f"🔒 '{name}' is a {need_label} feature — you're on {have_label}.",
        f"   Upgrade to {need_label}, set VIBE_PLAN={need}, or run `vibe unlock <code>`",
        "   if you have a founder code.",
    ])


def multi_caps():
    ent = entitlements()
    return ent["max_multi_targets"], ent["max_multi_jobs"]


# --------------------------------------------------------------------------- #
# Display
# --------------------------------------------------------------------------- #
def describe():
    tier = active_tier()
    ent = TIERS[tier]
    unlocked = is_unlocked()
    tools = ent["tools"]
    if tools == "*":
        tool_line = "ALL tools"
    else:
        preview = ", ".join(tools[:6])
        extra = f", +{len(tools) - 6} more" if len(tools) > 6 else ""
        tool_line = f"{len(tools)} ({preview}{extra})"

    out = []
    out.append("=" * 60)
    out.append(f"  ACTIVE PLAN: {ent['label']}" + ("   (founder override)" if unlocked else ""))
    out.append("=" * 60)
    out.append(f"  {ent['blurb']}")
    out.append("")
    out.append(f"  Tools          : {tool_line}")
    out.append(f"  Bundled flows  : {', '.join(ent['flows']) or '—'}")
    out.append(f"  Claude brain   : {'yes' if ent['allow_brain'] else 'no'}")
    out.append(f"  Local load     : {'yes' if ent['allow_load'] else 'no'}")
    out.append(f"  External audit : {'yes (still allowlist + confirm gated)' if ent['allow_external'] else 'no'}")
    out.append(f"  Multi targets  : {ent['max_multi_targets']}    jobs: {ent['max_multi_jobs']}")
    out.append("")
    out.append("  Plans:")
    for t in TIER_ORDER:
        mark = "->" if t == tier else "  "
        out.append(f"   {mark} {TIERS[t]['label']:<11} {TIERS[t]['blurb']}")
    out.append("")
    out.append("  Honor-system note: this gating is product structure, not security.")
    out.append("  The toolkit is local Python you can edit; plans don't protect code.")
    return out


if __name__ == "__main__":
    for _line in describe():
        print(_line)
