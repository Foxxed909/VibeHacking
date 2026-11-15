#!/usr/bin/env python3
"""MAEL security divisions: web baseline, offline AD audit, local exploit lab."""
import argparse
import ipaddress
import json
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PRIVATE_V4 = [ipaddress.ip_network(x) for x in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "127.0.0.0/8")]
PRIVATE_V6 = ipaddress.ip_network("fc00::/7")


def finding(code, severity, asset, detail, remediation):
    return {"id": code, "severity": severity, "asset": asset,
            "detail": detail, "remediation": remediation}


def validate_target(url, allow_public=False):
    """Constrain default live probes to loopback/RFC1918/ULA IP addresses."""
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError("Expected an absolute http:// or https:// URL")
    if parsed.username is not None or parsed.password is not None:
        raise ValueError("Credentials in URLs are not supported")
    hostname = parsed.hostname.lower()
    local = hostname == "localhost" or hostname.endswith(".localhost")
    try:
        ip = ipaddress.ip_address(hostname)
        local = local or ip.is_loopback or (
            any(ip in n for n in PRIVATE_V4) if ip.version == 4 else ip in PRIVATE_V6
        )
    except ValueError:
        pass
    if not local and not allow_public:
        raise ValueError("External or DNS host: supply --allow-public for a specifically authorized target")
    return parsed


def assess_headers(headers, scheme, asset):
    """Assess the response without retaining cookies or authentication data."""
    def has(name):
        return bool(headers.get(name))
    out = []
    for name, sev in (
        ("Content-Security-Policy", "medium"),
        ("X-Content-Type-Options", "low"),
        ("Referrer-Policy", "low"),
    ):
        if not has(name):
            out.append(finding("WEB_MISSING_" + name.upper().replace("-", "_"),
                               sev, asset, "Missing " + name,
                               "Configure and validate the appropriate header"))
    csp = headers.get("Content-Security-Policy", "")
    if not has("X-Frame-Options") and "frame-ancestors" not in csp.lower():
        out.append(finding("WEB_FRAME_POLICY", "medium", asset,
                           "No X-Frame-Options or CSP frame-ancestors directive",
                           "Restrict framing via CSP frame-ancestors"))
    if scheme == "https" and not has("Strict-Transport-Security"):
        out.append(finding("WEB_HSTS", "medium", asset,
                           "HTTPS response does not set HSTS",
                           "Enable HSTS after validating HTTPS readiness"))
    cookies = headers.get_all("Set-Cookie", []) if hasattr(headers, "get_all") else []
    for cookie in cookies:
        name = cookie.partition("=")[0].strip()[:60] or "(unnamed)"
        attributes = {piece.strip().split("=", 1)[0].lower()
                      for piece in cookie.split(";")[1:]}
        for attribute in ("httponly", "samesite", "secure"):
            if attribute not in attributes:
                out.append(finding("WEB_COOKIE_" + attribute.upper(), "medium", name,
                                   "Cookie missing " + attribute + " attribute",
                                   "Review cookie attributes for its purpose and transport"))
    return out


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def web_probe(url, allow_public=False, timeout=5):
    parsed = validate_target(url, allow_public)
    req = urllib.request.Request(url, headers={"User-Agent": "VibeHacking-MAEL/1.0"})
    opener = urllib.request.build_opener(NoRedirect)
    try:
        with opener.open(req, timeout=timeout) as response:
            status = response.status
            headers = response.headers
    except urllib.error.HTTPError as exc:
        status = exc.code
        headers = exc.headers
        exc.close()
    return {"module": "WEBSTRIKE", "url": url, "status": status,
            "findings": assess_headers(headers, parsed.scheme, parsed.hostname)}


UAC_DISABLED = 0x0002
UAC_PASSWD_NOTREQD = 0x0020
UAC_DONT_EXPIRE_PASSWORD = 0x10000
UAC_TRUSTED_FOR_DELEGATION = 0x80000
UAC_DONT_REQ_PREAUTH = 0x400000
UAC_TRUSTED_TO_AUTH_FOR_DELEGATION = 0x1000000


def analyze_control_paths(snapshot):
    """Discover declared control paths to tier-zero objects in exported ACL data."""
    from collections import defaultdict, deque
    edges = defaultdict(list)
    allowed = {"GenericAll", "WriteDacl", "WriteOwner", "AddMember",
               "ForceChangePassword", "DCSync"}
    for edge in snapshot.get("controlEdges", []):
        if not isinstance(edge, dict):
            raise ValueError("controlEdges entries must be objects")
        source, destination = str(edge.get("from", "")), str(edge.get("to", ""))
        right = str(edge.get("right", ""))
        if source and destination and right in allowed:
            edges[source].append((destination, right))
    targets = set(str(x) for x in snapshot.get("tierZero", []))
    result = []
    for entry in snapshot.get("entryPrincipals", []):
        entry = str(entry)
        queue = deque([(entry, [])])
        visited = {entry}
        while queue:
            principal, path = queue.popleft()
            if principal in targets and path:
                result.append({"entry": entry, "tierZero": principal, "hops": path})
                continue
            if len(path) >= 5:
                continue
            for next_principal, right in edges[principal]:
                if next_principal not in visited:
                    visited.add(next_principal)
                    queue.append((next_principal, path + [{"from": principal,
                                                            "to": next_principal,
                                                            "right": right}]))
    return result


def audit_ad(snapshot):
    """Read-only, offline analysis of a sanitized AD export (never contacts DCs)."""
    if not isinstance(snapshot, dict):
        raise ValueError("Snapshot must be a JSON object")
    findings = []
    policy = snapshot.get("domainPolicy", {})
    if not isinstance(policy, dict):
        raise ValueError("domainPolicy must be an object")
    if "minPwdLength" in policy and int(policy["minPwdLength"]) < 14:
        findings.append(finding("AD_PASSWORD_LENGTH", "medium", "domainPolicy",
                                "Minimum password length below 14",
                                "Review domain password policy and adopt longer passphrases"))
    if "lockoutThreshold" in policy and int(policy["lockoutThreshold"]) == 0:
        findings.append(finding("AD_NO_LOCKOUT", "medium", "domainPolicy",
                                "No account lockout threshold configured",
                                "Review account lockout and smart lockout protections"))
    for objtype, records in (("user", snapshot.get("users", [])),
                             ("computer", snapshot.get("computers", []))):
        if not isinstance(records, list):
            raise ValueError(objtype + "s must be a list")
        for obj in records:
            if not isinstance(obj, dict):
                raise ValueError(objtype + " entry must be an object")
            account = str(obj.get("samAccountName", obj.get("name", "unknown")))[:150]
            flags = int(obj.get("userAccountControl", 0))
            if flags & UAC_DISABLED:
                continue
            checks = (
                (UAC_PASSWD_NOTREQD, "AD_PASSWORD_NOT_REQUIRED", "high",
                 "Password not required flag set", "Require password protection for this principal"),
                (UAC_DONT_REQ_PREAUTH, "AD_PREAUTH_DISABLED", "high",
                 "Kerberos pre-authentication disabled", "Require Kerberos pre-authentication"),
                (UAC_TRUSTED_FOR_DELEGATION, "AD_UNCONSTRAINED_DELEGATION", "high",
                 "Unconstrained delegation enabled", "Remove unconstrained delegation"),
                (UAC_TRUSTED_TO_AUTH_FOR_DELEGATION, "AD_PROTOCOL_TRANSITION", "medium",
                 "Protocol transition enabled", "Review constrained delegation configuration"),
            )
            for flag, code, sev, detail, remedy in checks:
                if flags & flag:
                    findings.append(finding(code, sev, account, detail, remedy))
            if flags & UAC_DONT_EXPIRE_PASSWORD:
                findings.append(finding("AD_PASSWORD_NEVER_EXPIRES", "low", account,
                                        "Account password never expires",
                                        "Review account purpose and credential rotation controls"))
            allowed = obj.get("msDS-AllowedToDelegateTo", [])
            if allowed:
                findings.append(finding("AD_DELEGATION_TARGETS", "info", account,
                                        "Constrained delegation targets configured",
                                        "Verify each delegation target is justified and least-privileged"))
    paths = analyze_control_paths(snapshot)
    for path in paths:
        findings.append(finding("AD_TIER_ZERO_CONTROL_PATH", "high", path["entry"],
                                "Exported permissions indicate a control path to " + path["tierZero"],
                                "Validate each ACL hop and remove unnecessary control rights"))
    return {"module": "DOMAINOPS", "findings": findings,
            "count": len(findings), "controlPaths": paths}


def crash_exercise(compiler=None):
    """Compile/run only the bundled toy program, in a temporary directory."""
    cc = shutil.which(compiler) if compiler else (shutil.which("cc") or shutil.which("gcc") or shutil.which("clang"))
    if not cc:
        raise RuntimeError("C compiler not available; install gcc or clang")
    source = ROOT / "crash_demo.c"
    with tempfile.TemporaryDirectory(prefix="vibehacking-mael-") as directory:
        exe = str(Path(directory) / "demo")
        compile_cmd = [cc, "-g", "-O0", "-fno-omit-frame-pointer",
                       "-fsanitize=address", str(source), "-o", exe]
        build = subprocess.run(compile_cmd, capture_output=True, text=True, timeout=25)
        if build.returncode:
            raise RuntimeError("Compilation failed: " + build.stderr[-600:])
        baseline = subprocess.run([exe, "MAEL"], capture_output=True, text=True, timeout=5, cwd=directory)
        overflow = subprocess.run([exe, "A" * 96], capture_output=True, text=True, timeout=5, cwd=directory)
        sanitizer = "AddressSanitizer" in overflow.stderr
        return {"module": "EXPLOITLAB", "baseline_exit": baseline.returncode,
                "oversized_exit": overflow.returncode,
                "sanitizer_reported": sanitizer,
                "crash_observed": overflow.returncode != 0,
                "stderr_excerpt": overflow.stderr[-1000:]}


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="MAEL security divisions for authorized testing and local research")
    sub = parser.add_subparsers(dest="command", required=True)
    web = sub.add_parser("web", help="WEBSTRIKE: bounded HTTP response policy audit")
    web.add_argument("url")
    web.add_argument("--allow-public", action="store_true",
                     help="Explicitly allow a public host you are authorized to test")
    web.add_argument("--timeout", type=float, default=5)
    ad = sub.add_parser("ad", help="DOMAINOPS: offline AD configuration audit")
    ad.add_argument("snapshot", help="Path to a sanitized AD JSON export")
    crash = sub.add_parser("crash", help="EXPLOITLAB: local ASan crash reproduction")
    crash.add_argument("--compiler", help="Name/path of installed gcc or clang compiler")
    sub.add_parser("range", help="CYBERRANGE: show Docker launch instructions")
    args = parser.parse_args(argv)
    try:
        if args.command == "web":
            if not 0 < args.timeout <= 30:
                raise ValueError("--timeout must be between 0 and 30 seconds")
            result = web_probe(args.url, args.allow_public, args.timeout)
        elif args.command == "ad":
            with open(args.snapshot, encoding="utf-8") as stream:
                result = audit_ad(json.load(stream))
        elif args.command == "crash":
            result = crash_exercise(args.compiler)
        else:
            result = {"module": "CYBERRANGE", "start": "docker compose -f MAEL/compose.yaml up --build",
                      "stop": "docker compose -f MAEL/compose.yaml down",
                      "url": "http://127.0.0.1:3456/"}
        print(json.dumps(result, indent=2))
        return 0
    except (ValueError, OSError, RuntimeError, subprocess.TimeoutExpired,
            urllib.error.URLError, json.JSONDecodeError) as exc:
        print(json.dumps({"error": str(exc), "module": args.command}), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())
