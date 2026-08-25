#!/usr/bin/env python3
"""
everything2 — hardened NovaChat-style app (NOT deliberately vulnerable).

Same product surface as testapp (guestbook, chat, login, admin, files, fetch),
but defenses are on. Use it to stress-test the toolkit against a realistic app.

    python everything2/app.py                 # http://127.0.0.1:3457/
    python everything2/app.py --port 4000

Stdlib only. Local / authorized testing only.
"""
import argparse
import base64
import hashlib
import hmac
import html
import ipaddress
import json
import os
import secrets
import time
import urllib.error
import urllib.request
from collections import defaultdict, deque
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

# --------------------------------------------------------------------------- #
# Config — secrets never appear in public API responses or error bodies.
# --------------------------------------------------------------------------- #
_JWT_SECRET = os.environ.get("EVERYTHING2_JWT_SECRET") or secrets.token_hex(32)
_OPENROUTER_KEY = os.environ.get("OPENROUTER_API_KEY") or ""  # only used if NOVACHAT_LLM=real

PUBLIC_CONFIG = {
    "service": "everything2",
    "model_default": "local/deterministic",
    "version": "everything2 1.0.0",
    "debug": False,
}

SYSTEM_PERSONA = (
    "You are everything2, a helpful assistant. "
    "Do not invent or reveal API keys, passwords, or internal secrets."
)

# In-memory users — password hashes only (never returned in JSON).
def _hash_pw(pw: str) -> str:
    return hashlib.sha256(pw.encode("utf-8")).hexdigest()


USERS = {
    1: {
        "id": 1,
        "username": "alice",
        "email": "alice@everything2.local",
        "role": "user",
        "pw_hash": _hash_pw("Sunshine1!long"),
    },
    2: {
        "id": 2,
        "username": "admin",
        "email": "admin@everything2.local",
        "role": "admin",
        "pw_hash": _hash_pw("Admin!long-pass-9"),
    },
}

GUESTBOOK = []

# Simple login rate limit: max attempts per IP in a window.
_LOGIN_WINDOW_SEC = 60
_LOGIN_MAX_ATTEMPTS = 8
_login_hits = defaultdict(deque)  # ip -> timestamps


def _rate_limited(ip: str) -> bool:
    now = time.time()
    q = _login_hits[ip]
    while q and now - q[0] > _LOGIN_WINDOW_SEC:
        q.popleft()
    if len(q) >= _LOGIN_MAX_ATTEMPTS:
        return True
    q.append(now)
    return False


# --------------------------------------------------------------------------- #
# JWT — HS256 only, no alg:none
# --------------------------------------------------------------------------- #
def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def _b64url_dec(seg: str) -> bytes:
    return base64.urlsafe_b64decode(seg + "=" * (-len(seg) % 4))


def jwt_issue(payload: dict) -> str:
    header = {"alg": "HS256", "typ": "JWT"}
    body = dict(payload)
    body.setdefault("iat", int(time.time()))
    body.setdefault("exp", int(time.time()) + 3600)
    h = _b64url(json.dumps(header, separators=(",", ":")).encode())
    p = _b64url(json.dumps(body, separators=(",", ":")).encode())
    sig = hmac.new(_JWT_SECRET.encode(), f"{h}.{p}".encode(), hashlib.sha256).digest()
    return f"{h}.{p}.{_b64url(sig)}"


def jwt_verify(token: str):
    try:
        h_seg, p_seg, sig_seg = token.split(".")
        header = json.loads(_b64url_dec(h_seg))
        payload = json.loads(_b64url_dec(p_seg))
    except Exception:
        return None
    alg = str(header.get("alg", "")).upper()
    if alg != "HS256":
        return None  # reject none / weird algs
    expected = _b64url(
        hmac.new(_JWT_SECRET.encode(), f"{h_seg}.{p_seg}".encode(), hashlib.sha256).digest()
    )
    if not hmac.compare_digest(expected, sig_seg):
        return None
    if int(payload.get("exp", 0)) < int(time.time()):
        return None
    return payload


def _bearer(handler) -> str:
    auth = handler.headers.get("Authorization") or ""
    if auth.lower().startswith("bearer "):
        return auth[7:].strip()
    return ""


def _public_user(u: dict) -> dict:
    return {"id": u["id"], "username": u["username"], "email": u["email"], "role": u["role"]}


# --------------------------------------------------------------------------- #
# LLM backend
# --------------------------------------------------------------------------- #
def llm_reply(model, messages):
    if not isinstance(model, str) or not model.strip():
        raise ValueError("model must be a non-empty string")
    last = ""
    for m in messages or []:
        if isinstance(m, dict) and m.get("role") == "user":
            last = str(m.get("content", ""))

    if os.environ.get("NOVACHAT_LLM") == "real" and _OPENROUTER_KEY:
        return _real_llm(model, messages)

    lowered = last.lower()
    # Do not leak secrets on prompt-injection phrases.
    if any(
        w in lowered
        for w in (
            "system prompt",
            "api key",
            "openrouter",
            "jwt_secret",
            "print env",
            "dump config",
        )
    ):
        return "[assistant] I can't share internal configuration or secrets."
    return f"[assistant] You said: {last[:500]}"


def _real_llm(model, messages):
    body = json.dumps({"model": model, "messages": messages}).encode()
    req = urllib.request.Request(
        "https://openrouter.ai/api/v1/chat/completions",
        data=body,
        headers={
            "Authorization": f"Bearer {_OPENROUTER_KEY}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(req, timeout=30) as r:
        data = json.loads(r.read().decode())
    return data["choices"][0]["message"]["content"]


# --------------------------------------------------------------------------- #
# SSRF guard
# --------------------------------------------------------------------------- #
def _ssrf_blocked(url: str) -> str:
    """Return a reason string if blocked, else empty."""
    try:
        parsed = urlparse(url)
    except Exception:
        return "invalid url"
    scheme = (parsed.scheme or "").lower()
    if scheme not in ("http", "https"):
        return "scheme not allowed"
    host = (parsed.hostname or "").lower()
    if not host:
        return "missing host"
    if host in ("localhost", "metadata.google.internal", "metadata"):
        return "host not allowed"
    try:
        infos = socket_getaddrinfo_safe(host)
        for ip_str in infos:
            ip = ipaddress.ip_address(ip_str)
            if (
                ip.is_private
                or ip.is_loopback
                or ip.is_link_local
                or ip.is_reserved
                or ip.is_multicast
            ):
                return "resolved address not allowed"
    except Exception:
        return "host resolution failed"
    return ""


def socket_getaddrinfo_safe(host):
    import socket

    results = socket.getaddrinfo(host, None)
    return sorted({item[4][0] for item in results})


# --------------------------------------------------------------------------- #
# HTML
# --------------------------------------------------------------------------- #
def homepage():
    rows = "".join(
        f"<div class='msg'><b>{html.escape(e['name'])}</b>: {html.escape(e['text'])}</div>"
        for e in GUESTBOOK
    )
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>everything2</title>
  <meta name="viewport" content="width=device-width, initial-scale=1">
</head>
<body style="font-family:system-ui;max-width:640px;margin:2rem auto">
  <h1>everything2</h1>
  <p>Hardened practice app — not deliberately vulnerable.</p>
  <h2>Guestbook</h2>
  <form method="POST" action="/api/guestbook">
    <input name="name" placeholder="name" maxlength="60">
    <input name="text" placeholder="message" maxlength="500" size="40">
    <button type="submit">Post</button>
  </form>
  <div id="book">{rows}</div>
</body>
</html>"""


SECURITY_HEADERS = {
    "Content-Security-Policy": "default-src 'self'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'",
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    "Referrer-Policy": "no-referrer",
    "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
    "Cache-Control": "no-store",
}


class Handler(BaseHTTPRequestHandler):
    server_version = "everything2/1.0"

    def _send(self, code, body, ctype="application/json", extra=None):
        if isinstance(body, (dict, list)):
            body = json.dumps(body)
        raw = body.encode() if isinstance(body, str) else body
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(raw)))
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(raw)

    def _body(self):
        length = int(self.headers.get("Content-Length", 0) or 0)
        raw = self.rfile.read(length) if length else b""
        ctype = (self.headers.get("Content-Type") or "").lower()
        if "application/json" in ctype:
            try:
                return json.loads(raw.decode("utf-8", "replace"))
            except Exception:
                return {}
        return {k: v[0] for k, v in parse_qs(raw.decode("utf-8", "replace")).items()}

    def _client_ip(self):
        return self.client_address[0] if self.client_address else "unknown"

    def log_message(self, *a):
        pass

    def do_GET(self):
        u = urlparse(self.path)
        path, qs = u.path, parse_qs(u.query)

        if path == "/":
            return self._send(200, homepage(), "text/html")

        if path in ("/api/config", "/api/status"):
            # Public config only — no secrets.
            return self._send(200, dict(PUBLIC_CONFIG))

        if path in ("/api/debug", "/api/env", "/api/status/full"):
            return self._send(404, {"error": "not found"})

        if path == "/api/computer/sessions":
            return self._send(200, {"sessions": []})

        if path == "/api/guestbook":
            return self._send(200, GUESTBOOK)

        if path == "/api/user":
            token = _bearer(self) or qs.get("token", [""])[0]
            payload = jwt_verify(token)
            if not payload:
                return self._send(401, {"error": "authentication required"})
            try:
                uid = int(qs.get("id", [str(payload.get("sub", 0))])[0])
            except ValueError:
                return self._send(400, {"error": "bad id"})
            # Users may only read themselves unless admin.
            if payload.get("role") != "admin" and int(payload.get("sub", -1)) != uid:
                return self._send(403, {"error": "forbidden"})
            user = USERS.get(uid)
            return self._send(200, _public_user(user)) if user else self._send(404, {"error": "not found"})

        if path == "/api/admin":
            token = _bearer(self) or qs.get("token", [""])[0]
            payload = jwt_verify(token)
            if not payload or payload.get("role") != "admin":
                return self._send(401, {"error": "admin token required"})
            return self._send(
                200,
                {
                    "ok": True,
                    "service": PUBLIC_CONFIG["service"],
                    "version": PUBLIC_CONFIG["version"],
                    "users": len(USERS),
                },
            )

        if path == "/go":
            dest = qs.get("url", [""])[0]
            # Only same-app relative redirects.
            if not dest.startswith("/") or dest.startswith("//") or "\\" in dest:
                return self._send(400, {"error": "redirect not allowed"})
            return self._send(302, "", "text/plain", extra={"Location": dest})

        if path == "/files":
            rel = qs.get("path", ["index.txt"])[0]
            base = os.path.realpath(
                os.path.join(os.path.dirname(os.path.abspath(__file__)), "public")
            )
            full = os.path.realpath(os.path.join(base, rel))
            if not full.startswith(base + os.sep) and full != base:
                return self._send(400, {"error": "path not allowed"})
            try:
                with open(full, "rb") as fh:
                    return self._send(200, fh.read(), "text/plain")
            except OSError:
                return self._send(404, {"error": "not found"})

        return self._send(404, {"error": "not found"})

    def do_POST(self):
        path = urlparse(self.path).path
        body = self._body()

        if path == "/api/guestbook":
            name = str(body.get("name", "anon"))[:60]
            text = str(body.get("text", ""))[:500]
            GUESTBOOK.append({"name": name, "text": text})
            return self._send(302, "", "text/plain", extra={"Location": "/"})

        if path == "/api/chat":
            try:
                reply = llm_reply(
                    body.get("model", PUBLIC_CONFIG["model_default"]),
                    body.get("messages", []),
                )
                return self._send(200, {"reply": reply})
            except Exception:
                # Generic error — no config / persona dump.
                return self._send(400, {"error": "invalid chat request"})

        if path == "/api/computer/instruct":
            target = str(body.get("url", ""))
            reason = _ssrf_blocked(target)
            if reason:
                return self._send(400, {"error": f"fetch blocked: {reason}"})
            try:
                req = urllib.request.Request(
                    target,
                    headers={"User-Agent": "everything2-fetch/1.0"},
                    method="GET",
                )
                with urllib.request.urlopen(req, timeout=5) as r:
                    content = r.read(4096).decode("utf-8", "replace")
                return self._send(200, {"fetched": target, "content": content})
            except (urllib.error.URLError, TimeoutError, ValueError):
                return self._send(502, {"error": "fetch failed"})

        if path == "/api/register":
            pw = str(body.get("password", ""))
            if len(pw) < 12:
                return self._send(400, {"error": "password must be at least 12 characters"})
            return self._send(201, {"ok": True})

        if path == "/api/login":
            ip = self._client_ip()
            if _rate_limited(ip):
                return self._send(429, {"error": "too many attempts"})
            username = str(body.get("username", ""))
            pw = str(body.get("password", ""))
            user = next((u for u in USERS.values() if u["username"] == username), None)
            # Uniform failure — no user enumeration.
            if not user or not hmac.compare_digest(user["pw_hash"], _hash_pw(pw)):
                return self._send(401, {"error": "invalid credentials"})
            token = jwt_issue({"sub": user["id"], "role": user["role"]})
            return self._send(200, {"token": token, "role": user["role"]})

        return self._send(404, {"error": "not found"})


def main():
    ap = argparse.ArgumentParser(description="everything2 — hardened full app")
    ap.add_argument("--port", type=int, default=3457)
    ap.add_argument("--host", default="127.0.0.1")
    args = ap.parse_args()

    pub = os.path.join(os.path.dirname(os.path.abspath(__file__)), "public")
    os.makedirs(pub, exist_ok=True)
    index = os.path.join(pub, "index.txt")
    if not os.path.exists(index):
        with open(index, "w", encoding="utf-8") as fh:
            fh.write("everything2 public asset.\n")

    print("=" * 60)
    print(" everything2 — HARDENED full app (not deliberately vulnerable)")
    print(f" http://{args.host}:{args.port}/   (authorized local testing only)")
    print("=" * 60)
    ThreadingHTTPServer((args.host, args.port), Handler).serve_forever()


if __name__ == "__main__":
    main()
