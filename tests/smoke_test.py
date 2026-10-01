#!/usr/bin/env python3
"""VibeHacking smoke tests — stdlib only, no pytest required.

Run from the repo root:

    python tests/smoke_test.py

Exits 0 if every check passes, 1 otherwise. Designed as a fast regression
guard for the v1.0 cleanup — it catches broken imports, syntax errors, CLI
wiring regressions, and version drift before they ship.

Checks
------
1. Version single-source-of-truth: the root VERSION file matches what
   vibe_core reports (locks in the 0.5.0-vs-1.0.0 drift fix).
2. Compile-check: every .py file byte-compiles (no execution, no side effects).
3. Orchestrator: `vibe.py --help` and `vibe.py list` exit cleanly.
4. Tool sweep: every CLI tool answers `--help` with exit code 0.

Mutating / non-CLI files are compile-checked but skipped in the runtime sweep.
"""
import os
import py_compile
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOOLS = os.path.join(ROOT, "TOOLS")
PY = sys.executable

# Compile-checked but skipped in the runtime `--help` sweep:
#   - vibe_core: shared base library, no CLI
#   - privacy_guard: shared privacy/redaction helpers, no CLI
#   - lmx: report generator with no argparse (would run, not print help)
#   - add_version_flags: dev utility that rewrites files
SKIP_RUNTIME = {
    "vibe_core.py",
    "privacy_guard.py",
    "add_version_flags.py",
}


def run(args, timeout=25):
    # Tools reconfigure their own stdout to UTF-8 (emoji banners), so capture
    # as UTF-8 rather than the Windows locale default (cp1252) to avoid decode
    # errors in the reader thread.
    try:
        p = subprocess.run(
            [PY, *args],
            cwd=ROOT,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout,
        )
        return p.returncode, p.stderr
    except subprocess.TimeoutExpired:
        return 124, f"timeout after {timeout}s"


def main():
    failures = []
    checks = 0

    # 1. Version single-source-of-truth ------------------------------------
    checks += 1
    sys.path.insert(0, TOOLS)
    try:
        import vibe_core  # noqa: E402

        with open(os.path.join(ROOT, "VERSION"), encoding="utf-8") as f:
            file_v = f.read().strip()
        if vibe_core.FRAMEWORK_VERSION != file_v:
            failures.append(
                f"version drift: VERSION={file_v!r} but "
                f"vibe_core={vibe_core.FRAMEWORK_VERSION!r}"
            )
        else:
            print(f"[PASS] version single-source-of-truth ({file_v})")
    except Exception as e:  # noqa: BLE001
        failures.append(f"version check errored: {e}")

    # 1b. Privacy redaction defaults --------------------------------------
    checks += 1
    try:
        import privacy_guard  # noqa: E402

        sample = (
            "Target https://alice:secret@tester.example.com/api/u/"
            "550e8400-e29b-41d4-a716-446655440000?email=me@example.com&token=abc "
            "Authorization: Bearer secret123 C:\\Users\\TestUser\\AppData\\x 203.0.113.5"
        )
        redacted = privacy_guard.sanitize_text(sample)
        leaks = [
            item
            for item in (
                "tester.example.com",
                "me@example.com",
                "secret123",
                "TestUser",
                "203.0.113.5",
            )
            if item in redacted
        ]
        if leaks:
            failures.append(f"privacy redaction leaked: {leaks}")
        else:
            print("[PASS] privacy guard redacts common tester identifiers")
    except Exception as e:  # noqa: BLE001
        failures.append(f"privacy redaction check errored: {e}")

    # 1c. Case-insensitive response headers -------------------------------
    checks += 1
    try:
        import vibe_core  # noqa: E402

        headers = vibe_core._CaseInsensitiveHeaders(
            {"content-security-policy": "default-src 'self'", "Server": "nginx"}
        )
        ok = (
            headers.get("Content-Security-Policy") == "default-src 'self'"
            and headers.get("SERVER") == "nginx"
            and "x-frame-options" not in headers
            and "Content-Security-Policy" in headers
        )
        if not ok:
            failures.append("safe_request headers are not case-insensitive")
        else:
            print("[PASS] response headers look up case-insensitively")
    except Exception as e:  # noqa: BLE001
        failures.append(f"case-insensitive header check errored: {e}")

    # 1d. Phantom JWT header alg:none & weak-secret detection ---------------
    checks += 1
    try:
        import phantom  # noqa: E402
        import jwt_forge  # noqa: E402

        p = phantom.Phantom()
        forged_none = jwt_forge._forge_jwt({"alg": "none", "typ": "JWT"}, {"sub": 1, "role": "admin"}, alg_mode="none")
        forged_weak = jwt_forge._forge_jwt({"alg": "HS256", "typ": "JWT"}, {"sub": 1, "role": "admin"}, secret=b"secret")
        issues_none = p._audit_jwt(forged_none)
        issues_weak = p._audit_jwt(forged_weak)
        has_none = any("alg:none" in msg for msg, _ in issues_none)
        has_weak = any("weak/default secret" in msg for msg, _ in issues_weak)
        if not (has_none and has_weak):
            failures.append(f"Phantom JWT audit missed alg:none ({has_none}) or weak secret ({has_weak})")
        else:
            print("[PASS] Phantom detects JWT alg:none in header and weak HS256 secret")
    except Exception as e:  # noqa: BLE001
        failures.append(f"Phantom JWT check errored: {e}")

    # 1e. SARIF 2.1.0 builder validation -----------------------------------
    checks += 1
    try:
        import sarif_export  # noqa: E402

        exporter = sarif_export.SarifExporter()
        sarif_doc = exporter.build_sarif([
            {
                "tool": "JWT Forge",
                "title": "JWT Authentication Bypass via alg:none",
                "severity": "critical",
                "location": "http://127.0.0.1:3456/api/admin",
                "evidence": "200 OK",
                "recommendation": "Reject alg:none",
                "cwe": "CWE-347",
                "owasp": "A07:2021",
            }
        ])
        run0 = sarif_doc["runs"][0]
        if sarif_doc.get("version") != "2.1.0" or len(run0.get("results", [])) != 1:
            failures.append("SARIF 2.1.0 builder produced invalid structure")
        else:
            print("[PASS] SARIF 2.1.0 exporter builds valid schema")
    except Exception as e:  # noqa: BLE001
        failures.append(f"SARIF check errored: {e}")

    # 1f. Hyperion v2.0 14x ceiling, guard, weighted ring & profiles --------
    checks += 1
    try:
        import hyperion  # noqa: E402

        ring, specs = hyperion.Hyperion._build_weighted_ring(
            "http://127.0.0.1:3456/", "/:50,/api/config:30,/api/guestbook:20"
        )
        ok_14x = hyperion.MAX_PRIVATE_RPS == 3_500_000.0
        ok_guard = (
            hyperion.verify_guard_code("XXLMILLEAMEAN", interactive=False)
            and not hyperion.verify_guard_code("WRONG", interactive=False)
        )
        ok_ring = len(ring) == 100 and len(specs) == 3
        ok_profiles = (
            hyperion._effective_rate(1000.0, "sawtooth", 0.5) > 0
            and hyperion._effective_rate(1000.0, "stress-knee", 0.8) == 1000.0
        )
        if not (ok_14x and ok_guard and ok_ring and ok_profiles):
            failures.append(
                f"Hyperion v2.0 unit check failed: 14x={ok_14x} guard={ok_guard} ring={ok_ring} profiles={ok_profiles}"
            )
        else:
            print("[PASS] Hyperion v2.0 14x ceiling (3.5M RPS), XXLMILLEAMEAN guard, weighted ring & 6 profiles")
    except Exception as e:  # noqa: BLE001
        failures.append(f"Hyperion v2.0 unit check errored: {e}")

    # 1g. Cloudflare, AWS & Vercel (.vercel.app) edge support check ---------
    checks += 1
    try:
        import cloud_scout  # noqa: E402
        import hyperion  # noqa: E402

        cf_p, cf_pops = hyperion._detect_cloud_provider_from_host_or_headers(
            "app.example.com", {"cf-ray": "8ab123-LOS", "cf-cache-status": "HIT"}
        )
        vc_p, vc_pops = hyperion._detect_cloud_provider_from_host_or_headers(
            "my-app.vercel.app", {"x-vercel-id": "iad1::sfo1-999", "x-vercel-cache": "HIT"}
        )
        aws_p, aws_pops = hyperion._detect_cloud_provider_from_host_or_headers(
            "api.execute-api.us-east-1.amazonaws.com",
            {"x-amz-cf-pop": "IAD89-P2", "x-amzn-requestid": "req-123"},
        )
        cs_stack, _ = cloud_scout.detect_cloud_stack(
            "https://my-app.vercel.app",
            {"cf-ray": "8ab123-LOS", "x-vercel-id": "iad1::123", "x-amz-cf-pop": "IAD89-P2"},
        )
        if (
            "cloudflare" not in cf_p
            or "vercel" not in vc_p
            or "aws-cloudfront" not in aws_p
            or "aws-alb-apigw" not in aws_p
            or len(cs_stack) < 3
        ):
            failures.append(f"Cloud/Edge detection failed: cf={cf_p} vc={vc_p} aws={aws_p} cs={cs_stack}")
        else:
            print("[PASS] Cloudflare, AWS & Vercel (.vercel.app) edge provider & PoP detection")
    except Exception as e:  # noqa: BLE001
        failures.append(f"Cloud/Edge detection check errored: {e}")

    # 1h. Bot Breaker ('Are you a robot?' solver & zero-key bypass) check ---
    checks += 1
    try:
        import bot_breaker  # noqa: E402
        import hashlib  # noqa: E402

        blocked, vendor, _ = bot_breaker.is_robot_interstitial(
            403, "<html><title>Just a moment...</title></html>", {"cf-mitigated": "challenge"}
        )
        solved_form = bot_breaker.BotBreaker._solve_math_or_form_challenge(
            "https://app.example.com/",
            '<form action="/verify">What is 15 + 9? <input name="captcha_answer" value="">'
            '<input type="checkbox" name="not_a_robot" value="1">'
            '<input name="honeypot_field" value="trap"></form>',
        )
        pow_hash = hashlib.sha256(b"salt12342").hexdigest()
        solved_pow = bot_breaker.BotBreaker._solve_altcha_pow(
            {"salt": "salt123", "challenge": pow_hash, "maxnumber": 100}
        )
        shadows = bot_breaker.BotBreaker._discover_shadow_origins(
            "https://app.example.com/",
            '<script src="https://my-app-backend.vercel.app/_next/main.js"></script>',
            {},
        )
        ok_bot = (
            blocked
            and "Cloudflare" in vendor
            and solved_form is not None
            and solved_form["fields"].get("captcha_answer") == "24"
            and solved_form["fields"].get("honeypot_field") == ""
            and solved_pow is not None
            and solved_pow["number"] == 42
            and "https://my-app-backend.vercel.app" in shadows
        )
        if not ok_bot:
            failures.append(f"BotBreaker check failed: blocked={blocked} form={solved_form} pow={solved_pow} shadows={shadows}")
        else:
            print("[PASS] Bot Breaker solves 'Are you a robot?' math/PoW challenges & detects shadow origins")
    except Exception as e:  # noqa: BLE001
        failures.append(f"BotBreaker unit check errored: {e}")

    # 1i. Next.js RSC Audit, Asymmetric Probe, WAF Evade & Live Dashboard ---
    checks += 1
    try:
        import asymmetric_probe  # noqa: E402
        import live_dashboard  # noqa: E402
        import nextjs_rsc_audit  # noqa: E402
        import waf_evade  # noqa: E402

        has_cve_hdr = any(
            "x-middleware-subrequest" in h for h in nextjs_rsc_audit.MIDDLEWARE_BYPASS_HEADERS
        )
        dash_state = live_dashboard.collect_dashboard_state()
        ok_suite = (
            has_cve_hdr
            and isinstance(dash_state, dict)
            and "findings" in dash_state
            and hasattr(asymmetric_probe, "AsymmetricProbe")
            and hasattr(waf_evade, "WAFEvade")
        )
        if not ok_suite:
            failures.append("Full Attacker & Cloud Suite module check failed")
        else:
            print("[PASS] Next.js RSC (CVE-2025-29927), Asymmetric Probe, WAF Evade & Live Dashboard ready")
    except Exception as e:  # noqa: BLE001
        failures.append(f"Full Attacker & Cloud Suite check errored: {e}")

    # 2. Compile-check every Python file -----------------------------------
    py_files = [os.path.join(ROOT, "vibe.py")]
    py_files += [
        os.path.join(TOOLS, f) for f in os.listdir(TOOLS) if f.endswith(".py")
    ]
    vb_dir = os.path.join(ROOT, "vb")
    if os.path.isdir(vb_dir):
        for dirpath, _dirnames, filenames in os.walk(vb_dir):
            py_files += [
                os.path.join(dirpath, f) for f in filenames if f.endswith(".py")
            ]
    compiled_ok = 0
    for path in sorted(py_files):
        checks += 1
        try:
            py_compile.compile(path, doraise=True)
            compiled_ok += 1
        except py_compile.PyCompileError as e:
            rel = os.path.relpath(path, ROOT)
            failures.append(f"compile failed: {rel}: {str(e).splitlines()[0][:160]}")
    print(f"[PASS] compile-check: {compiled_ok}/{len(py_files)} files OK")

    # 3. Orchestrator ------------------------------------------------------
    for sub in (["vibe.py", "--help"], ["vibe.py", "list"]):
        checks += 1
        code, err = run(sub)
        label = " ".join(sub)
        if code != 0:
            failures.append(f"`{label}` exited {code}: {err.strip()[:200]}")
        else:
            print(f"[PASS] {label}")

    checks += 1
    code, err = run(["vibe.py", "--noloader", "--help"])
    if code != 0:
        failures.append(f"`vibe.py --noloader --help` exited {code}: {err.strip()[:200]}")
    else:
        print("[PASS] vibe.py --noloader --help")

    checks += 1
    code, err = run(["vibe.py", "multi", "--help"])
    if code != 0:
        failures.append(f"`vibe.py multi --help` exited {code}: {err.strip()[:200]}")
    else:
        print("[PASS] vibe.py multi --help")

    checks += 1
    code, err = run(
        [
            "vibe.py",
            "multi",
            "scan",
            "--targets",
            "http://127.0.0.1:1/",
            "http://localhost:1/",
            "--jobs",
            "2",
            "--dry-run",
        ]
    )
    if code != 0:
        failures.append(f"`vibe.py multi scan --dry-run` exited {code}: {err.strip()[:200]}")
    else:
        print("[PASS] vibe.py multi scan dry-runs local targets")

    checks += 1
    code, err = run(["vibe.py", "multi", "scan", "--targets", "https://example.com", "--dry-run"])
    if code == 0:
        failures.append("vibe.py multi scan allowed a public target")
    else:
        print("[PASS] vibe.py multi scan refuses public targets")

    checks += 1
    code, err = run(
        [
            "vibe.py",
            "multi",
            "scan",
            "--allow-external",
            "--yes",
            "--targets",
            "https://example.com",
            "--dry-run",
        ]
    )
    if code != 0:
        failures.append(f"`vibe.py multi scan --allow-external --dry-run` exited {code}: {err.strip()[:200]}")
    else:
        print("[PASS] vibe.py multi scan can dry-run authorized external targets")

    checks += 1
    code, err = run(["vibe.py", "multi", "attack", "--targets", "https://example.com", "--dry-run"])
    if code == 0:
        failures.append("vibe.py multi attack allowed a public target without --allow-external")
    else:
        print("[PASS] vibe.py multi attack refuses public targets by default")

    checks += 1
    code, err = run(
        [
            "vibe.py",
            "multi",
            "attack",
            "--allow-external",
            "--yes",
            "--targets",
            "https://example.com",
            "--dry-run",
        ]
    )
    if code != 0:
        failures.append(f"`vibe.py multi attack --allow-external --dry-run` exited {code}: {err.strip()[:200]}")
    else:
        print("[PASS] vibe.py multi attack can dry-run authorized external targets")

    checks += 1
    code, err = run(
        [
            "vibe.py",
            "--noloader",
            "-urlx",
            "http://127.0.0.1:1/",
            "t-1",
            "--interval",
            "0.2",
            "--request-timeout",
            "0.2",
            "-f",
            "1",
        ],
        timeout=8,
    )
    if code != 0:
        failures.append(f"`vibe.py --noloader` failed local no-load check: {err.strip()[:200]}")
    else:
        print("[PASS] vibe.py --noloader verifies a closed local port")

    checks += 1
    code, err = run(["-m", "vb.cli", "--help"])
    if code != 0:
        failures.append(f"`python -m vb.cli --help` exited {code}: {err.strip()[:200]}")
    else:
        print("[PASS] python -m vb.cli --help")

    checks += 1
    code, err = run(["-m", "vb.cli", "multi", "--help"])
    if code != 0:
        failures.append(f"`python -m vb.cli multi --help` exited {code}: {err.strip()[:200]}")
    else:
        print("[PASS] python -m vb.cli routes multi")

    checks += 1
    code, err = run(["-m", "vb.cli", "attack", "--help"])
    if code != 0:
        failures.append(f"`python -m vb.cli attack --help` exited {code}: {err.strip()[:200]}")
    else:
        print("[PASS] python -m vb.cli routes attack")

    checks += 1
    code, err = run(["-m", "vb.cli", "sarif", "--help"])
    if code != 0:
        failures.append(f"`python -m vb.cli sarif --help` exited {code}: {err.strip()[:200]}")
    else:
        print("[PASS] python -m vb.cli routes sarif")

    checks += 1
    code, err = run(["-m", "vb.cli", "list", "--plain"])
    if code != 0:
        failures.append(f"`python -m vb.cli list --plain` exited {code}: {err.strip()[:200]}")
    else:
        print("[PASS] python -m vb.cli list --plain")

    checks += 1
    code, err = run(["-m", "vb.cli", "locked", "--plain"])
    if code != 0:
        failures.append(f"`python -m vb.cli locked --plain` exited {code}: {err.strip()[:200]}")
    else:
        print("[PASS] python -m vb.cli locked --plain")

    checks += 1
    code, err = run(["-m", "vb.cli", "storm", "--help"])
    if code != 0:
        failures.append(f"`python -m vb.cli storm --help` exited {code}: {err.strip()[:200]}")
    else:
        print("[PASS] python -m vb.cli allows locked tool help")

    checks += 1
    code, err = run(["vibe.py", "agent", "--list-models"])
    if code != 0:
        failures.append(f"`python vibe.py agent --list-models` exited {code}: {err.strip()[:200]}")
    else:
        print("[PASS] vibe.py agent --list-models OK")

    checks += 1
    code, err = run(["vibe.py", "agent", "--url", "http://127.0.0.1:3456", "--auth", "WRONG_PHRASE"])
    if code == 0:
        failures.append("vibe.py agent allowed execution without 'I AM AUTHORIZED TO TEST THIS TARGET'")
    else:
        print("[PASS] vibe.py agent refuses execution without mandatory authorization phrase")

    checks += 1
    try:
        import vibe_agent  # noqa: E402

        assert vibe_agent.verify_authorization_phrase("I AM AUTHORIZED TO TEST THIS TARGET")
        assert vibe_agent.verify_authorization_phrase("I AM AUTHORIZED TO TEST THIS TARGE")
        assert not vibe_agent.verify_authorization_phrase("unauthorized")
        assert vibe_agent.resolve_model_spec("laguna-s-2.1")["id"] == "poolside/laguna-s-2.1:free"
        assert vibe_agent.resolve_model_spec("laguna-xs-2.1")["id"] == "poolside/laguna-xs-2.1:free"
        assert vibe_agent.resolve_model_spec("ling-3.0-flash-fin")["id"] == "inclusionai/ling-3.0-flash-fin:free"
        assert vibe_agent.resolve_model_spec("ling-3.0-flash-sante")["id"] == "inclusionai/ling-3.0-flash-sante:free"
        assert vibe_agent.resolve_model_spec("ling-3.0-flash")["id"] == "inclusionai/ling-3.0-flash-vl:free"
        print("[PASS] VibeAgent & BreakAgent authorization gate + Free OpenRouter models OK")
    except Exception as e:  # noqa: BLE001
        failures.append(f"vibe_agent unit check failed: {e}")

    checks += 1
    code, err = run(["vibe.py", "maelstrom", "-t", "https://example.com", "-d", "1s", "-r", "10", "-w", "1"])
    if code == 0:
        failures.append("vibe.py maelstrom allowed an untrusted public host")
    else:
        print("[PASS] vibe.py maelstrom requires public hosts to be trusted")

    checks += 1
    code, err = run(["vibe.py", "hyperion", "-t", "http://127.0.0.1:1/", "-d", "1s", "-r", "10", "-w", "1", "--yes"])
    if code == 0:
        failures.append("vibe.py hyperion ran without XXLMILLEAMEAN guard code")
    else:
        print("[PASS] vibe.py hyperion refuses execution without XXLMILLEAMEAN guard code")

    checks += 1
    code, err = run(["vibe.py", "hyperion", "--guard", "WRONG_CODE", "-t", "http://127.0.0.1:1/", "-d", "1s", "--yes"])
    if code == 0:
        failures.append("vibe.py hyperion accepted an invalid guard code")
    else:
        print("[PASS] vibe.py hyperion rejects invalid guard codes")

    checks += 1
    code, err = run(["vibe.py", "hyperion", "--guard", "XXLMILLEAMEAN", "-t", "https://example.com", "-d", "1s", "-r", "10", "-w", "1", "--yes"])
    if code == 0:
        failures.append("vibe.py hyperion allowed an untrusted public host even with guard code")
    else:
        print("[PASS] vibe.py hyperion requires public hosts to be in authorized_targets.txt")

    checks += 1
    try:
        if ROOT not in sys.path:
            sys.path.insert(0, ROOT)
        import vibe  # noqa: E402

        if vibe.MAX_EXTERNAL_MAELSTROM_RPS != 9999.99:
            failures.append(f"unexpected external Maelstrom cap: {vibe.MAX_EXTERNAL_MAELSTROM_RPS}")
        else:
            print("[PASS] external Maelstrom cap is 9999.99 rps")
    except Exception as e:  # noqa: BLE001
        failures.append(f"Maelstrom cap check errored: {e}")

    checks += 1
    code, err = run(["tests/vercel_test.py"])
    if code != 0:
        failures.append(f"Vercel adapter tests exited {code}: {err.strip()[:300]}")
    else:
        print("[PASS] Vercel adapter: preview mode, fail-closed runs, and dashboard auth")

    # 4. Tool --help sweep -------------------------------------------------
    tools = sorted(
        f for f in os.listdir(TOOLS) if f.endswith(".py") and f not in SKIP_RUNTIME
    )
    helped_ok = 0
    for tool in tools:
        checks += 1
        code, err = run([os.path.join("TOOLS", tool), "--help"])
        if code != 0:
            failures.append(f"TOOLS/{tool} --help exited {code}: {err.strip()[:200]}")
        else:
            helped_ok += 1
    print(f"[PASS] --help sweep: {helped_ok}/{len(tools)} tools OK")

    # Summary --------------------------------------------------------------
    print("-" * 52)
    print(f"{checks - len(failures)}/{checks} checks passed")
    if failures:
        print("\nFAILURES:")
        for f in failures:
            print(f"  x {f}")
        return 1
    print("All smoke checks passed.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
