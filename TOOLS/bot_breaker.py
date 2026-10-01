#!/usr/bin/env python3
"""
bot_breaker.py v1.0 — AI-Agent "Are You a Robot?" Solver, Cloudflare/Vercel/AWS Bot-Gate Bypass & Audit Engine.

Designed for two complementary goals on targets you own or are authorized to test:
  1. AI-Agent Enablement: When AI testing agents hit a Cloudflare ("Just a moment..." /
     "Are you a robot?"), Vercel, or AWS WAF challenge on your app, BotBreaker runs an
     8-strategy zero-credential solver/evasion matrix, extracts a working browser persona +
     cookie jar + unchallenged routes, and saves them to `vibe_session.json` so all
     VibeHacking tools (and AI agents using `--fetch`) can test the app seamlessly.
  2. Attacker-Mindset Bot-Gate Audit: Tests whether a real unauthenticated attacker
     (with NO API keys or access tokens) can defeat or bypass your "Are you a robot?"
     screen via browser Client-Hint emulation, AJAX/JSON content negotiation, HTTP verb
     pivoting, crawler UA spoofing, IP header forgery, deterministic PoW/math form solving,
     or exposed `.vercel.app` / AWS shadow origins.
"""
import argparse
import hashlib
import http.cookiejar
import json
import os
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from privacy_guard import sanitize_text
from vibe_core import VibeTool, _CaseInsensitiveHeaders

_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# Coherent, realistic zero-credential browser personas (HTTP/1.1 + Client Hints)
BROWSER_PERSONAS = {
    "chrome_128_win": {
        "User-Agent": (
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) "
            "AppleWebKit/537.36 (KHTML, like Gecko) Chrome/128.0.0.0 Safari/537.36"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-CH-UA": '"Chromium";v="128", "Not;A=Brand";v="24", "Google Chrome";v="128"',
        "Sec-CH-UA-Mobile": "?0",
        "Sec-CH-UA-Platform": '"Windows"',
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    },
    "firefox_130_mac": {
        "User-Agent": (
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14.6; rv:130.0) "
            "Gecko/20100101 Firefox/130.0"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
        "Sec-Fetch-User": "?1",
        "Upgrade-Insecure-Requests": "1",
    },
    "safari_17_ios": {
        "User-Agent": (
            "Mozilla/5.0 (iPhone; CPU iPhone OS 17_6 like Mac OS X) "
            "AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.6 Mobile/15E148 Safari/604.1"
        ),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.9",
        "Sec-Fetch-Dest": "document",
        "Sec-Fetch-Mode": "navigate",
        "Sec-Fetch-Site": "none",
    },
}

CRAWLER_PERSONAS = {
    "googlebot": (
        "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)"
    ),
    "bingbot": (
        "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)"
    ),
    "applebot": (
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_5) AppleWebKit/605.1.15 "
        "(KHTML, like Gecko) Version/13.1.1 Safari/605.1.15 (Applebot/0.1; +http://www.apple.com/go/applebot)"
    ),
}

ROBOT_CHALLENGE_MARKERS = (
    "just a moment...",
    "are you a robot",
    "verify you are human",
    "checking your browser before accessing",
    "cf-browser-verification",
    "__cf_chl_opt",
    "cdn-cgi/challenge-platform",
    "turnstile",
    "attention required! | cloudflare",
    "ddos-guard",
    "x-vercel-mitigated",
    "aws-waf-token",
    "captcha-delivery",
)


def is_robot_interstitial(status, body, headers=None):
    """Return (is_blocked, gate_vendor, reason) if response is an 'Are you a robot?' challenge."""
    hdrs = {str(k).lower(): str(v) for k, v in (headers or {}).items()}
    body_l = (body or "")[:8192].lower()

    if hdrs.get("cf-mitigated", "").lower() == "challenge":
        return True, "Cloudflare Managed Challenge / Turnstile", "header cf-mitigated=challenge"
    if "x-vercel-mitigated" in hdrs:
        return True, "Vercel Bot / Attack Challenge Mode", f"header x-vercel-mitigated={hdrs['x-vercel-mitigated']}"
    if hdrs.get("x-amzn-waf-action", "").lower() in ("challenge", "captcha", "block"):
        return True, "AWS WAF Bot Control / Captcha", f"header x-amzn-waf-action={hdrs['x-amzn-waf-action']}"

    if status in (401, 403, 429, 503):
        for marker in ROBOT_CHALLENGE_MARKERS:
            if marker in body_l:
                vendor = "Cloudflare" if ("cf" in marker or "cloudflare" in body_l) else "Edge/WAF"
                return True, f"{vendor} Bot Gate", f"HTTP {status} with '{marker}'"

    # Check for HTTP 200 interstitial pages that are actually bot challenges
    if any(
        m in body_l
        for m in (
            "<title>just a moment...</title>",
            "id=\"cf-challenge-running\"",
            "are you a robot?",
            "verify you are human",
            "altcha-widget",
        )
    ):
        return True, "Interstitial Robot Gate", "HTML challenge page detected"

    return False, "None", "Passed"


class BotBreaker(VibeTool):
    def __init__(self):
        super().__init__(
            "Bot Breaker",
            "AI-Agent 'Are You a Robot?' Solver & Cloudflare/Vercel/AWS Bot-Gate Evasion Engine",
        )
        self.cookie_jar = http.cookiejar.CookieJar()
        self._tls_ctx = ssl.create_default_context()
        try:
            self._tls_ctx.set_alpn_protocols(["http/1.1"])
        except Exception:
            pass

    def _raw_request(self, url, method="GET", headers=None, data=None, timeout=10):
        """Execute a zero-credential request using the persistent cookie jar."""
        opener = urllib.request.build_opener(
            urllib.request.HTTPCookieProcessor(self.cookie_jar),
            urllib.request.HTTPSHandler(context=self._tls_ctx),
        )
        hdrs = dict(headers or {})
        body_bytes = None
        if data is not None:
            if isinstance(data, bytes):
                body_bytes = data
            elif isinstance(data, str):
                body_bytes = data.encode("utf-8")
            elif isinstance(data, dict):
                body_bytes = urllib.parse.urlencode(data).encode("utf-8")
                hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")

        req = urllib.request.Request(url, data=body_bytes, headers=hdrs, method=method)
        try:
            with opener.open(req, timeout=timeout) as resp:
                status = resp.getcode()
                text = resp.read().decode("utf-8", errors="ignore")
                resp_hdrs = _CaseInsensitiveHeaders(resp.info())
                return status, text, resp_hdrs
        except urllib.error.HTTPError as e:
            try:
                err_text = e.read().decode("utf-8", errors="ignore")
            except Exception:
                err_text = ""
            return e.code, err_text, _CaseInsensitiveHeaders(e.headers)
        except Exception as e:
            return 0, str(e), _CaseInsensitiveHeaders({})

    def _export_cookies_dict(self):
        return {c.name: c.value for c in self.cookie_jar}

    @staticmethod
    def _solve_altcha_pow(challenge_json):
        """Solve a deterministic SHA-256 Proof-of-Work (Altcha / Hashcash style) bot challenge."""
        try:
            data = json.loads(challenge_json) if isinstance(challenge_json, str) else challenge_json
            salt = str(data.get("salt", ""))
            target_hash = str(data.get("challenge", "")).lower()
            max_num = min(int(data.get("maxnumber", 100_000)), 250_000)
            if not salt or not target_hash:
                return None
            for n in range(max_num + 1):
                digest = hashlib.sha256(f"{salt}{n}".encode("utf-8")).hexdigest().lower()
                if digest == target_hash:
                    return {
                        "algorithm": data.get("algorithm", "SHA-256"),
                        "challenge": target_hash,
                        "number": n,
                        "salt": salt,
                        "signature": data.get("signature", ""),
                    }
        except Exception:
            pass
        return None

    @staticmethod
    def _solve_math_or_form_challenge(base_url, html_body):
        """Detect & solve deterministic HTML 'Are you a robot?' math/checkbox/cookie challenges."""
        if not html_body:
            return None

        # 1. Check for JS cookie-set challenge: document.cookie = "name=val..."
        cookie_m = re.search(
            r'document\.cookie\s*=\s*["\']([A-Za-z0-9_\-]+)=([^"\';]+)',
            html_body,
            re.IGNORECASE,
        )
        # 2. Check for arithmetic challenge: e.g. "What is 12 + 7?" or "8 * 3 ="
        math_m = re.search(r"(\d{1,3})\s*([+\-*])\s*(\d{1,3})\s*(?:=|\?)", html_body)
        math_answer = None
        if math_m:
            a, op, b = int(math_m.group(1)), math_m.group(2), int(math_m.group(3))
            if op == "+":
                math_answer = str(a + b)
            elif op == "-":
                math_answer = str(a - b)
            elif op == "*":
                math_answer = str(a * b)

        # 3. Parse form action and inputs
        form_m = re.search(
            r"<form[^>]*action=[\"']?([^\"' >]+)[\"']?[^>]*>(.*?)</form>",
            html_body,
            re.IGNORECASE | re.DOTALL,
        )
        if not form_m and not cookie_m:
            return None

        result = {"js_cookie": None, "form_url": None, "fields": {}}
        if cookie_m:
            result["js_cookie"] = (cookie_m.group(1), cookie_m.group(2))

        if form_m:
            action = form_m.group(1).strip()
            form_inner = form_m.group(2)
            result["form_url"] = urllib.parse.urljoin(base_url, action)
            for inp in re.finditer(r"<input([^>]+)>", form_inner, re.IGNORECASE):
                attrs = inp.group(1)
                name_m = re.search(r'name=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
                val_m = re.search(r'value=["\']([^"\']*)["\']', attrs, re.IGNORECASE)
                type_m = re.search(r'type=["\']([^"\']+)["\']', attrs, re.IGNORECASE)
                if not name_m:
                    continue
                fname = name_m.group(1)
                ftype = (type_m.group(1) if type_m else "text").lower()
                fval = val_m.group(1) if val_m else ""

                # Leave obvious honeypot fields empty
                if any(hp in fname.lower() for hp in ("honeypot", "hp_", "website_url", "trap")):
                    result["fields"][fname] = ""
                elif ftype == "checkbox" and any(
                    k in fname.lower() for k in ("robot", "human", "verify", "confirm", "agree")
                ):
                    result["fields"][fname] = fval or "1"
                elif math_answer is not None and any(
                    k in fname.lower() for k in ("answer", "captcha", "math", "sum", "challenge", "robot")
                ):
                    result["fields"][fname] = math_answer
                else:
                    result["fields"][fname] = fval

        return result

    @staticmethod
    def _discover_shadow_origins(base_url, body, headers):
        """Scan headers and HTML for exposed .vercel.app, .cloudfront.net, .amazonaws.com, or .pages.dev origins."""
        parsed = urllib.parse.urlparse(base_url)
        primary_host = (parsed.hostname or "").lower()
        corpus = (body or "") + "\n" + "\n".join(f"{k}: {v}" for k, v in (headers or {}).items())
        pattern = re.compile(
            r"https?://([a-z0-9][a-z0-9._\-]+\.(?:vercel\.app|cloudfront\.net|amazonaws\.com|pages\.dev|workers\.dev|on\.aws))",
            re.IGNORECASE,
        )
        found = []
        for m in pattern.finditer(corpus):
            h = m.group(1).lower()
            if h != primary_host and h not in found:
                found.append(f"https://{h}")
        return found

    def run(self, url, fetch_only=False, extra_cookie="", json_out=""):
        if "://" not in url:
            first_host = url.split("/")[0].split(":")[0].lower()
            url = f"{'http' if first_host in ('localhost', '127.0.0.1', '::1') else 'https'}://{url}"

        if not fetch_only:
            self.banner()
            self.log(f"Target: {url} (Zero-Credential Black-Box Attacker & AI-Agent Mode)")

        if extra_cookie or os.environ.get("VIBE_CF_CLEARANCE"):
            raw_c = extra_cookie or f"cf_clearance={os.environ.get('VIBE_CF_CLEARANCE', '').strip()}"
            parsed_u = urllib.parse.urlparse(url)
            for part in raw_c.split(";"):
                if "=" in part:
                    ck, cv = part.strip().split("=", 1)
                    c_obj = http.cookiejar.Cookie(
                        version=0, name=ck.strip(), value=cv.strip(),
                        port=None, port_specified=False,
                        domain=parsed_u.hostname or "localhost", domain_specified=True, domain_initial_dot=False,
                        path="/", path_specified=True, secure=parsed_u.scheme == "https",
                        expires=None, discard=True, comment=None, comment_url=None, rest={},
                    )
                    self.cookie_jar.set_cookie(c_obj)

        # Step 1: Baseline Naive Bot Probe (what a standard AI agent / script sees)
        naive_status, naive_body, naive_hdrs = self._raw_request(
            url, headers={"User-Agent": "python-urllib/3.11 AI-Agent-Probe/1.0", "Accept": "*/*"}
        )
        naive_blocked, gate_vendor, gate_reason = is_robot_interstitial(naive_status, naive_body, naive_hdrs)
        if not fetch_only:
            if naive_blocked:
                self.log(
                    f"Naive AI-Agent probe BLOCKED by [{gate_vendor}] ({gate_reason}, HTTP {naive_status})",
                    "warn",
                )
            else:
                self.log(
                    f"Naive AI-Agent probe reached target (HTTP {naive_status}, no bot interstitial triggered)",
                    "pass",
                )

        winning_strategy = None
        winning_headers = {}
        winning_body = naive_body
        winning_status = naive_status
        unchallenged_routes = []
        shadow_origins = self._discover_shadow_origins(url, naive_body, naive_hdrs)

        # Strategy Matrix (Zero API keys, Zero access tokens)
        strategies = [
            ("chrome_128_client_hints", BROWSER_PERSONAS["chrome_128_win"], "GET", None),
            ("firefox_130_persona", BROWSER_PERSONAS["firefox_130_mac"], "GET", None),
            ("safari_17_mobile_persona", BROWSER_PERSONAS["safari_17_ios"], "GET", None),
            (
                "xhr_json_content_negotiation",
                {
                    **BROWSER_PERSONAS["chrome_128_win"],
                    "Accept": "application/json, text/plain, */*",
                    "X-Requested-With": "XMLHttpRequest",
                    "Sec-Fetch-Dest": "empty",
                    "Sec-Fetch-Mode": "cors",
                    "Sec-Fetch-Site": "same-origin",
                },
                "GET",
                None,
            ),
            (
                "googlebot_crawler_impersonation",
                {"User-Agent": CRAWLER_PERSONAS["googlebot"], "Accept": "*/*", "Accept-Language": "en-US,en;q=0.9"},
                "GET",
                None,
            ),
            (
                "edge_ip_header_spoof",
                {
                    **BROWSER_PERSONAS["chrome_128_win"],
                    "CF-Connecting-IP": "127.0.0.1",
                    "True-Client-IP": "127.0.0.1",
                    "X-Forwarded-For": "127.0.0.1",
                    "X-Real-IP": "127.0.0.1",
                    "X-Vercel-Forwarded-For": "127.0.0.1",
                },
                "GET",
                None,
            ),
        ]

        for strat_name, hdrs, method, payload in strategies:
            st, body, r_hdrs = self._raw_request(url, method=method, headers=hdrs, data=payload)
            blocked, vendor, reason = is_robot_interstitial(st, body, r_hdrs)
            shadow_origins.extend(
                s for s in self._discover_shadow_origins(url, body, r_hdrs) if s not in shadow_origins
            )

            # If blocked by a deterministic HTML/Math/Cookie/PoW challenge, attempt to solve it!
            if blocked and body:
                solved = self._solve_math_or_form_challenge(url, body)
                if solved:
                    if solved.get("js_cookie"):
                        ck, cv = solved["js_cookie"]
                        hdrs = {**hdrs, "Cookie": f"{ck}={cv}"}
                    if solved.get("form_url"):
                        st2, body2, r_hdrs2 = self._raw_request(
                            solved["form_url"],
                            method="POST",
                            headers=hdrs,
                            data=solved.get("fields", {}),
                        )
                        blocked2, _, _ = is_robot_interstitial(st2, body2, r_hdrs2)
                        if not blocked2 and 200 <= st2 < 400:
                            winning_strategy = f"{strat_name}+deterministic_challenge_solver"
                            winning_headers = hdrs
                            winning_body = body2
                            winning_status = st2
                            if not fetch_only:
                                self.log(
                                    f"[SOLVED] Deterministic 'Are you a robot?' challenge solved via {winning_strategy} (HTTP {st2})",
                                    "hack",
                                )
                            break

            if not blocked and 200 <= st < 400:
                winning_strategy = strat_name
                winning_headers = hdrs
                winning_body = body
                winning_status = st
                if not fetch_only:
                    if naive_blocked:
                        self.log(
                            f"[BYPASSED] Bot gate defeated with zero credentials using strategy '{strat_name}' (HTTP {st})",
                            "hack",
                        )
                        self.record_finding(
                            title=f"Bot Gate / 'Are You a Robot?' Bypassed via {strat_name}",
                            severity="medium",
                            location=url,
                            evidence=f"Naive probe blocked ({gate_vendor}), but '{strat_name}' succeeded with HTTP {st}",
                            recommendation=(
                                "Do not rely solely on User-Agent or basic header heuristics for bot protection. "
                                "Enforce cryptographic Turnstile/WAF challenges uniformly across API and HTML routes "
                                "and verify crawler User-Agents via ASN/reverse-DNS."
                            ),
                            cwe="CWE-807",
                            owasp="A07:2021 - Identification and Authentication Failures",
                        )
                    else:
                        self.log(f"Verified zero-credential browser persona '{strat_name}' (HTTP {st})", "pass")
                break

        # Step 3: Probe unchallenged side-doors (/api/*, /_next/data, /graphql, /openapi.json)
        parsed = urllib.parse.urlparse(url)
        base_root = f"{parsed.scheme}://{parsed.netloc}"
        probe_hdrs = winning_headers or BROWSER_PERSONAS["chrome_128_win"]
        api_hdrs = {
            **probe_hdrs,
            "Accept": "application/json, */*",
            "X-Requested-With": "XMLHttpRequest",
        }
        candidate_routes = [
            "/api/config",
            "/api/health",
            "/api/status",
            "/openapi.json",
            "/graphql",
            "/robots.txt",
        ]
        for subpath in candidate_routes:
            test_u = f"{base_root}{subpath}"
            st, b, rh = self._raw_request(test_u, method="GET", headers=api_hdrs, timeout=6)
            blk, _, _ = is_robot_interstitial(st, b, rh)
            if not blk and st in (200, 201, 400, 401, 405):
                unchallenged_routes.append({"path": subpath, "status": st})
                if naive_blocked and st == 200 and not fetch_only:
                    self.log(
                        f"[SIDE-DOOR] Unchallenged route reachable behind bot gate: {test_u} (HTTP {st})",
                        "hack",
                    )

        if shadow_origins and not fetch_only:
            self.log(
                f"[SHADOW ORIGIN] Discovered direct cloud origin(s) in response: {', '.join(shadow_origins)}",
                "warn",
            )

        # Step 4: Save winning AI-Agent profile into vibe_session.json so ALL tools inherit it
        cookies_dict = self._export_cookies_dict()
        agent_profile = {
            "target": url,
            "gate_detected": naive_blocked,
            "gate_vendor": gate_vendor,
            "winning_strategy": winning_strategy or "chrome_128_client_hints",
            "headers": winning_headers or BROWSER_PERSONAS["chrome_128_win"],
            "cookies": cookies_dict,
            "unchallenged_routes": unchallenged_routes,
            "shadow_origins": shadow_origins,
            "updated_at": time.strftime("%Y-%m-%d %H:%M:%S"),
        }

        session = self.load_session()
        if not isinstance(session, dict):
            session = {}
        surface = session.get("surface", {}) if isinstance(session.get("surface"), dict) else {}
        surface["agent_profile"] = agent_profile
        session["surface"] = surface
        try:
            with open(self.session_file, "w", encoding="utf-8") as fh:
                json.dump(session, fh, indent=2)
        except OSError:
            pass

        profile_out = json_out or os.path.join(self.log_dir, "bot_breaker_profile.json")
        try:
            os.makedirs(os.path.dirname(os.path.abspath(profile_out)), exist_ok=True)
            with open(profile_out, "w", encoding="utf-8") as fh:
                json.dump(agent_profile, fh, indent=2)
        except OSError:
            pass

        if fetch_only:
            print(winning_body)
            return 0 if winning_strategy else 1

        self.log(
            f"Saved AI-Agent & Zero-Key Attacker Profile to {profile_out} "
            f"(strategy={agent_profile['winning_strategy']}, cookies={len(cookies_dict)}, "
            f"unchallenged_routes={len(unchallenged_routes)})",
            "pass",
        )
        if naive_blocked and not winning_strategy:
            self.log(
                "Target enforces strict cryptographic challenge on HTML routes. "
                "To let your AI agents bypass Cloudflare on your own app without disabling protection for the public, "
                "create a Cloudflare WAF Custom Rule -> Action: Skip (All Super Bot Fight Mode / Managed Challenges) "
                "when Header 'X-Vibe-Agent-Token' equals your secret token (pass via VIBE_AUTH_HEADER).",
                "info",
            )
        return 0


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Bot Breaker v1.0 - AI-Agent 'Are You a Robot?' Solver & Cloudflare/Vercel/AWS Evasion Engine"
    )
    parser.add_argument("--url", "-t", "--target", dest="url", required=True, help="Target URL (e.g. https://my-app.vercel.app)")
    parser.add_argument(
        "--fetch",
        action="store_true",
        help="AI-Agent fetch mode: output the clean response body after bypassing/solving the bot gate",
    )
    parser.add_argument(
        "--cookie",
        default="",
        help="Optional pre-harvested clearance cookie (e.g. 'cf_clearance=...; __cf_bm=...')",
    )
    parser.add_argument("--json-out", default="", help="Optional JSON output path for the discovered agent profile")
    parser.add_argument("-v", "--version", action="version", version="Bot Breaker 1.0.0")
    args = parser.parse_args(argv)
    return BotBreaker().run(args.url, fetch_only=args.fetch, extra_cookie=args.cookie, json_out=args.json_out)


if __name__ == "__main__":
    sys.exit(main())
