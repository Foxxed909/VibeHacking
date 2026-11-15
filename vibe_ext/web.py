"""Low-impact web configuration audit, one GET and no redirect following."""
from urllib import error, request
from urllib.parse import urlsplit

from .scope import require_scope


class NoRedirect(request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def analyze_headers(status, headers, scheme):
    findings = []

    def record(severity, check, evidence, remediation):
        findings.append({
            "severity": severity,
            "check": check,
            "evidence": evidence,
            "remediation": remediation,
        })

    for name, remediation in (
        ("Content-Security-Policy", "Deploy a restrictive, tested CSP."),
        ("X-Content-Type-Options", "Set X-Content-Type-Options: nosniff."),
        ("Referrer-Policy", "Configure an explicit Referrer-Policy."),
    ):
        if not headers.get(name):
            record("low", "missing_header", name + " absent", remediation)

    if scheme == "https" and not headers.get("Strict-Transport-Security"):
        record("medium", "missing_hsts",
               "Strict-Transport-Security absent on HTTPS",
               "Enable HSTS after validating HTTPS coverage.")

    acao = headers.get("Access-Control-Allow-Origin", "")
    acac = headers.get("Access-Control-Allow-Credentials", "")
    if acao == "*" and acac.lower() == "true":
        record("medium", "cors_policy", "Wildcard ACAO with credentials",
               "Use a reviewed origin allowlist and avoid wildcard credentials.")

    for cookie in headers.get_all("Set-Cookie", []) or []:
        # Do not persist cookie values or names in output.
        flags = cookie.lower().split(";")
        attrs = {part.strip().split("=")[0] for part in flags[1:]}
        missing = []
        if "httponly" not in attrs:
            missing.append("HttpOnly")
        if scheme == "https" and "secure" not in attrs:
            missing.append("Secure")
        if "samesite" not in attrs:
            missing.append("SameSite")
        if missing:
            record("medium", "cookie_flags",
                   "A Set-Cookie header lacks " + ", ".join(missing),
                   "Set appropriate attributes on session cookies.")

    return {"status": status, "findings": findings, "finding_count": len(findings)}


def audit_url(url, scope_path=None, timeout=8):
    origin = require_scope(url, scope_path)
    opener = request.build_opener(NoRedirect)
    req = request.Request(url, headers={
        "User-Agent": "VibeHacking-Scope-Audit/0.1",
        "Accept": "*/*",
    })
    try:
        response = opener.open(req, timeout=timeout)
    except error.HTTPError as exc:
        response = exc  # 4xx and 3xx still have auditable response headers.
    try:
        result = analyze_headers(response.status, response.headers, urlsplit(url).scheme)
        result.update({"origin": origin, "redirect_followed": False,
                       "requests": 1})
        # Never record cookies, bodies, or response tokens.
        return result
    finally:
        response.close()

