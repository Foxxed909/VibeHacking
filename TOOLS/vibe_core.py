import sys
import http.cookiejar
import urllib.request
import urllib.parse
import urllib.error
import json
import os
import datetime
import uuid
import re

from privacy_guard import privacy_enabled, privacy_user_agent, sanitize_data, sanitize_text

for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read_version():
    """Single source of truth: the root VERSION file. Falls back if absent."""
    try:
        with open(os.path.join(_root, "VERSION"), "r", encoding="utf-8") as f:
            return f.read().strip() or "1.0.0"
    except OSError:
        return "1.0.0"


FRAMEWORK_VERSION = _read_version()

# Default CWE & OWASP mappings per tool for enterprise compliance & SARIF reporting.
DEFAULT_TOOL_TAXONOMY = {
    "ash":              {"cwe": "CWE-200", "owasp": "A05:2021-Security Misconfiguration"},
    "spider":           {"cwe": "CWE-200", "owasp": "A05:2021-Security Misconfiguration"},
    "ghost":            {"cwe": "CWE-538", "owasp": "A05:2021-Security Misconfiguration"},
    "api finder":       {"cwe": "CWE-200", "owasp": "API9:2023-Improper Inventory Management"},
    "api check":        {"cwe": "CWE-200", "owasp": "API9:2023-Improper Inventory Management"},
    "cloud scout":      {"cwe": "CWE-16",  "owasp": "A05:2021-Security Misconfiguration"},
    "header auditor":   {"cwe": "CWE-693", "owasp": "A05:2021-Security Misconfiguration"},
    "corscan":          {"cwe": "CWE-942", "owasp": "A05:2021-Security Misconfiguration"},
    "phantom":          {"cwe": "CWE-614", "owasp": "A07:2021-Identification and Authentication Failures"},
    "header inject":    {"cwe": "CWE-113", "owasp": "A03:2021-Injection"},
    "leep":             {"cwe": "CWE-285", "owasp": "A01:2021-Broken Access Control"},
    "aukdoc":           {"cwe": "CWE-287", "owasp": "A07:2021-Identification and Authentication Failures"},
    "axios":            {"cwe": "CWE-639", "owasp": "API1:2023-Broken Object Level Authorization"},
    "random roll":      {"cwe": "CWE-521", "owasp": "A07:2021-Identification and Authentication Failures"},
    "authdoc":          {"cwe": "CWE-20",  "owasp": "A03:2021-Injection"},
    "fuzz vibe":        {"cwe": "CWE-20",  "owasp": "A03:2021-Injection"},
    "biz logic":        {"cwe": "CWE-840", "owasp": "A04:2021-Insecure Design"},
    "redirect":         {"cwe": "CWE-601", "owasp": "A01:2021-Broken Access Control"},
    "traversal sniper": {"cwe": "CWE-22",  "owasp": "A01:2021-Broken Access Control"},
    "ssrf probe":       {"cwe": "CWE-918", "owasp": "A10:2021-Server-Side Request Forgery"},
    "prompt injector":  {"cwe": "CWE-1427","owasp": "LLM01:2025-Prompt Injection"},
    "timebomb":         {"cwe": "CWE-208", "owasp": "A07:2021-Identification and Authentication Failures"},
    "exploit final":    {"cwe": "CWE-79",  "owasp": "A03:2021-Injection"},
    "env probe":        {"cwe": "CWE-209", "owasp": "A05:2021-Security Misconfiguration"},
    "senoria":          {"cwe": "CWE-798", "owasp": "A02:2021-Cryptographic Failures"},
    "deep extract":     {"cwe": "CWE-200", "owasp": "LLM02:2025-Sensitive Information Disclosure"},
    "key stealer":      {"cwe": "CWE-798", "owasp": "LLM02:2025-Sensitive Information Disclosure"},
    "creditdrain":      {"cwe": "CWE-770", "owasp": "API4:2023-Unrestricted Resource Consumption"},
    "jwt forge":        {"cwe": "CWE-347", "owasp": "A07:2021-Identification and Authentication Failures"},
    "openapi scout":    {"cwe": "CWE-200", "owasp": "API9:2023-Improper Inventory Management"},
    "smuggle probe":    {"cwe": "CWE-444", "owasp": "A05:2021-Security Misconfiguration"},
    "bot breaker":      {"cwe": "CWE-807", "owasp": "A07:2021-Identification and Authentication Failures"},
}

WAF_CHALLENGE_PATTERNS = (
    "just a moment...",
    "are you a robot",
    "verify you are human",
    "cf-browser-verification",
    "_cf_chl_opt",
    "attention required! | cloudflare",
    "ddos-guard",
    "akamai ghost",
    "incapsula incident id",
)


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class _CaseInsensitiveHeaders(dict):
    """HTTP response headers whose lookups ignore case.

    HTTP header names are case-insensitive, but ``dict(response.info())`` keeps
    whatever casing the server sent — and HTTP/2 front-ends and some CDNs send
    them lowercased. Wrapping the result here lets tools look up
    ``headers.get('Content-Security-Policy')`` and still find a
    ``content-security-policy`` header. Iteration preserves the original casing.
    """

    def __init__(self, source=None):
        super().__init__()
        self._lower = {}
        if source is not None:
            items = source.items() if hasattr(source, "items") else source
            for key, value in items:
                self[key] = value

    def __setitem__(self, key, value):
        super().__setitem__(key, value)
        if isinstance(key, str):
            self._lower[key.lower()] = value

    def __getitem__(self, key):
        if isinstance(key, str) and key.lower() in self._lower:
            return self._lower[key.lower()]
        return super().__getitem__(key)

    def get(self, key, default=None):
        if isinstance(key, str):
            return self._lower.get(key.lower(), default)
        return super().get(key, default)

    def __contains__(self, key):
        if isinstance(key, str):
            return key.lower() in self._lower
        return super().__contains__(key)


class VibeTool:
    def __init__(self, name, description):
        self.name = name
        self.description = description
        self.version = FRAMEWORK_VERSION
        self.session_file = os.environ.get("VIBE_SESSION_FILE") or os.path.join(_root, "vibe_session.json")
        self.log_dir = os.environ.get("VIBE_LOG_DIR") or os.path.join(_root, "logs")
        self.findings_file = os.environ.get("VIBE_FINDINGS_FILE") or os.path.join(self.log_dir, "findings.jsonl")
        self.recorded_findings = []
        self._soft_404_signature = None
        self._cookie_jar = http.cookiejar.CookieJar()

        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir, exist_ok=True)
        session_dir = os.path.dirname(os.path.abspath(self.session_file))
        if session_dir and not os.path.exists(session_dir):
            os.makedirs(session_dir, exist_ok=True)

    def log(self, message, type="info"):
        prefix = {
            "info": "[*]",
            "warn": "[🟡 WARN]",
            "crit": "[🔴 CRITICAL]",
            "pass": "[🟢 PASS]",
            "fail": "[-] FAIL",
            "hack": "[🔥 HACK]"
        }.get(type, "[*]")

        timestamp = datetime.datetime.now().strftime("%H:%M:%S")
        safe_message = sanitize_text(message)
        formatted_msg = f"[{timestamp}] {prefix} {safe_message}"
        # Stay quiet if stdout is closed early (e.g. piped to `head` or `grep -q`)
        # instead of crashing the tool with a BrokenPipeError traceback.
        try:
            print(formatted_msg)
            sys.stdout.flush()
        except (BrokenPipeError, ValueError):
            pass

        filename = f"{self.name.lower().replace(' ', '_')}_session.log"
        # Preserve backward compatibility for existing tools whose log name used raw lower()
        legacy_filename = f"{self.name.lower()}_session.log"
        target_log = os.path.join(self.log_dir, legacy_filename)
        try:
            with open(target_log, "a", encoding="utf-8") as f:
                f.write(formatted_msg + "\n")
        except OSError:
            pass

        # Automatically capture high-signal findings into structured JSONL
        # so SARIF / JUnit / Executive Dashboards have clean machine-readable records.
        if type in ("crit", "hack"):
            self._auto_record_from_log(message, "critical" if type == "crit" else "high")

    def _auto_record_from_log(self, message, severity):
        msg = str(message).strip()
        # Skip generic summary footer lines when individual findings were already logged
        lower = msg.lower()
        if lower.startswith(("restrict access to these files", "the injected markup would execute")):
            return
        if re.match(r"^=+$", msg):
            return
        tax = DEFAULT_TOOL_TAXONOMY.get(self.name.lower(), {"cwe": "CWE-200", "owasp": "A05:2021"})
        self.record_finding(
            title=f"{self.name}: {msg[:100]}",
            severity=severity,
            evidence=msg,
            cwe=tax["cwe"],
            owasp=tax["owasp"],
            _from_log=True,
        )

    def record_finding(
        self,
        title,
        severity="medium",
        location="",
        evidence="",
        recommendation="",
        cwe="",
        owasp="",
        _from_log=False,
    ):
        """Record a structured security finding to logs/findings.jsonl for SARIF/CI/Reporting."""
        tax = DEFAULT_TOOL_TAXONOMY.get(self.name.lower(), {"cwe": "CWE-200", "owasp": "A05:2021"})
        sev_norm = str(severity).lower().strip()
        if sev_norm not in ("critical", "high", "medium", "low", "info"):
            sev_norm = "medium"

        session = self.load_session()
        target = location or session.get("target", "")

        entry = {
            "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z"),
            "tool": self.name,
            "title": sanitize_text(title),
            "severity": sev_norm,
            "location": sanitize_text(target),
            "evidence": sanitize_text(evidence or title),
            "recommendation": sanitize_text(recommendation),
            "cwe": cwe or tax.get("cwe", "CWE-200"),
            "owasp": owasp or tax.get("owasp", "A05:2021"),
            "auto_captured": bool(_from_log),
        }
        self.recorded_findings.append(entry)
        try:
            with open(self.findings_file, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(entry) + "\n")
        except OSError:
            pass
        return entry

    def banner(self):
        print("================================")
        print(f" 🛡️ {self.name.upper()} v{self.version}")
        print(f" {self.description}")
        print("================================")
        sys.stdout.flush()

    def save_session(self, data):
        existing = self.load_session()
        if isinstance(existing, dict) and isinstance(data, dict):
            merged = dict(existing)
            merged.update(data)
        else:
            merged = data
        with open(self.session_file, 'w', encoding="utf-8") as f:
            json.dump(sanitize_data(merged), f, indent=4)

    def load_session(self):
        if os.path.exists(self.session_file):
            try:
                with open(self.session_file, 'r', encoding="utf-8") as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

    def update_surface(self, endpoints=None, forms=None, jwt_tokens=None, tech=None):
        """Persist discovered attack-surface intelligence so downstream tools can chain."""
        session = self.load_session()
        surface = session.get("surface", {}) if isinstance(session, dict) else {}
        if not isinstance(surface, dict):
            surface = {}

        if endpoints:
            cur = list(surface.get("endpoints", []))
            for ep in endpoints:
                if ep and ep not in cur:
                    cur.append(ep)
            surface["endpoints"] = cur[:200]

        if forms:
            cur_forms = list(surface.get("forms", []))
            for fm in forms:
                if fm and fm not in cur_forms:
                    cur_forms.append(fm)
            surface["forms"] = cur_forms[:100]

        if jwt_tokens:
            cur_tokens = list(surface.get("jwt_tokens", []))
            for tok in jwt_tokens:
                if tok and tok not in cur_tokens:
                    cur_tokens.append(tok)
            surface["jwt_tokens"] = cur_tokens[:20]

        if tech:
            cur_tech = list(surface.get("tech", []))
            for item in tech:
                if item and item not in cur_tech:
                    cur_tech.append(item)
            surface["tech"] = cur_tech[:50]

        if isinstance(session, dict):
            session["surface"] = surface
            try:
                with open(self.session_file, "w", encoding="utf-8") as f:
                    json.dump(sanitize_data(session), f, indent=4)
            except OSError:
                pass

    def get_surface(self):
        session = self.load_session()
        if isinstance(session, dict) and isinstance(session.get("surface"), dict):
            return session["surface"]
        return {}

    @staticmethod
    def is_waf_challenge(status, body, headers=None):
        """Return True if a response is a CDN/WAF interstitial challenge masquerading as content."""
        headers = headers or {}
        if str(headers.get("cf-mitigated", "")).lower() == "challenge":
            return True
        body_l = (body or "")[:4096].lower()
        return any(pat in body_l for pat in WAF_CHALLENGE_PATTERNS)

    def calibrate_soft_404(self, base_url):
        """Probe a random nonexistent path to detect SPA catch-all 200 OK responses."""
        canary_path = f"{base_url.rstrip('/')}/vibe-404-check-{uuid.uuid4().hex[:10]}"
        status, body, headers = self.safe_request(canary_path, timeout=5)
        if status == 200 and body:
            norm = re.sub(r"\s+", " ", body[:2000]).strip()
            self._soft_404_signature = {
                "length": len(body),
                "prefix": norm[:240],
                "content_type": headers.get("Content-Type", ""),
            }
        else:
            self._soft_404_signature = None
        return self._soft_404_signature

    def is_soft_404(self, status, body):
        """Check whether a 200 response matches the target's soft-404 catch-all page."""
        if status != 200 or not self._soft_404_signature or not body:
            return False
        norm = re.sub(r"\s+", " ", body[:2000]).strip()
        sig = self._soft_404_signature
        if norm[:240] == sig["prefix"]:
            return True
        if sig["length"] > 0 and abs(len(body) - sig["length"]) / float(sig["length"]) < 0.05:
            if norm[:100] == sig["prefix"][:100]:
                return True
        return False

    def safe_request(self, url, method='GET', data=None, headers=None, timeout=10, follow_redirects=True):
        if url and "://" not in url:
            first_host = url.split("/")[0].split(":")[0].lower()
            default_scheme = "http" if first_host in ("localhost", "127.0.0.1", "::1") else "https"
            url = f"{default_scheme}://{url}"

        if headers is None:
            headers = {}
        else:
            headers = dict(headers)

        # Inherit any zero-credential BotBreaker profile (headers + cookies) from vibe_session.json
        surface = self.get_surface()
        agent_profile = surface.get("agent_profile", {}) if isinstance(surface, dict) else {}
        if isinstance(agent_profile, dict):
            prof_hdrs = agent_profile.get("headers")
            if isinstance(prof_hdrs, dict):
                for pk, pv in prof_hdrs.items():
                    headers.setdefault(pk, pv)
            prof_cookies = agent_profile.get("cookies")
            if isinstance(prof_cookies, dict) and prof_cookies and "Cookie" not in headers:
                headers["Cookie"] = "; ".join(f"{ck}={cv}" for ck, cv in prof_cookies.items())

        # Default to realistic zero-credential attacker browser persona (Chrome 128 + Client Hints)
        # so Cloudflare/Vercel/AWS heuristic bot gates don't block tools on sight.
        if os.environ.get("VIBE_SYNTHETIC_UA", "").strip() in ("1", "true", "yes"):
            headers.setdefault('User-Agent', privacy_user_agent(self.name))
        else:
            headers.setdefault(
                'User-Agent',
                'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36',
            )
            headers.setdefault('Sec-CH-UA', '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"')
            headers.setdefault('Sec-CH-UA-Mobile', '?0')
            headers.setdefault('Sec-CH-UA-Platform', '"Windows"')
            headers.setdefault('Accept-Language', 'en-US,en;q=0.9')
            headers.setdefault('Sec-Fetch-Dest', 'document')
            headers.setdefault('Sec-Fetch-Mode', 'navigate')
            headers.setdefault('Sec-Fetch-Site', 'none')
            headers.setdefault('Upgrade-Insecure-Requests', '1')

        if privacy_enabled():
            headers.setdefault('DNT', '1')
            headers.setdefault('Sec-GPC', '1')
        headers.setdefault('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,application/json,*/*;q=0.8')

        # Zero-Credential Black-Box Attacker Mode is ON by default (no API keys or access tokens).
        # Internal keys are only injected if VIBE_USE_INTERNAL_KEYS=1 or VIBE_BLACKBOX_MODE=0 is set.
        blackbox_mode = os.environ.get("VIBE_BLACKBOX_MODE", "1").strip().lower() not in ("0", "false", "off", "no")
        use_internal_keys = os.environ.get("VIBE_USE_INTERNAL_KEYS", "").strip().lower() in ("1", "true", "yes", "on")

        if use_internal_keys or not blackbox_mode:
            env_auth = os.environ.get("VIBE_AUTH_HEADER", "").strip()
            if env_auth and ":" in env_auth:
                k, v = env_auth.split(":", 1)
                headers.setdefault(k.strip(), v.strip())
            elif env_auth and "Authorization" not in headers:
                headers["Authorization"] = env_auth

            env_cookie = os.environ.get("VIBE_COOKIE", "").strip()
            if env_cookie and "Cookie" not in headers:
                headers["Cookie"] = env_cookie

            vercel_bypass = os.environ.get("VERCEL_AUTOMATION_BYPASS_SECRET", "").strip()
            if vercel_bypass:
                headers.setdefault("x-vercel-protection-bypass", vercel_bypass)
                headers.setdefault("x-vercel-set-bypass-cookie", "samesitenone")

            cf_id = os.environ.get("CF_ACCESS_CLIENT_ID", "").strip()
            cf_sec = os.environ.get("CF_ACCESS_CLIENT_SECRET", "").strip()
            if cf_id and cf_sec:
                headers.setdefault("CF-Access-Client-Id", cf_id)
                headers.setdefault("CF-Access-Client-Secret", cf_sec)

            aws_key = os.environ.get("AWS_API_GATEWAY_KEY", "").strip()
            if aws_key:
                headers.setdefault("x-api-key", aws_key)

        body = None
        if data is not None:
            if isinstance(data, bytes):
                body = data
            elif isinstance(data, str):
                body = data.encode('utf-8')
            else:
                body = json.dumps(data).encode('utf-8')
            if 'Content-Type' not in headers:
                headers['Content-Type'] = 'application/json'

        def _do_open(req_headers):
            req = urllib.request.Request(url, method=method, data=body, headers=req_headers)
            handlers = [urllib.request.HTTPCookieProcessor(self._cookie_jar)]
            if not follow_redirects:
                handlers.append(_NoRedirectHandler())
            opener = urllib.request.build_opener(*handlers)
            try:
                with opener.open(req, timeout=timeout) as response:
                    return (
                        response.getcode(),
                        response.read().decode('utf-8', errors='ignore'),
                        _CaseInsensitiveHeaders(response.info()),
                    )
            except urllib.error.HTTPError as e:
                try:
                    err_body = e.read().decode('utf-8', errors='ignore')
                except Exception:
                    err_body = ""
                return e.code, err_body, _CaseInsensitiveHeaders(e.headers)
            except Exception as e:
                return 0, str(e), _CaseInsensitiveHeaders({})

        status, resp_body, resp_headers = _do_open(headers)

        # If blocked by a Cloudflare / WAF "Are you a robot?" HTML interstitial, automatically
        # retry once with zero-credential AJAX/JSON content negotiation & cookie persistence.
        if status in (403, 503) and self.is_waf_challenge(status, resp_body, resp_headers):
            retry_headers = dict(headers)
            retry_headers.update({
                "Accept": "application/json, text/plain, */*",
                "X-Requested-With": "XMLHttpRequest",
                "Sec-Fetch-Dest": "empty",
                "Sec-Fetch-Mode": "cors",
                "Sec-Fetch-Site": "same-origin",
            })
            r_status, r_body, r_hdrs = _do_open(retry_headers)
            if r_status != 0 and not self.is_waf_challenge(r_status, r_body, r_hdrs):
                return r_status, r_body, r_hdrs

        return status, resp_body, resp_headers
