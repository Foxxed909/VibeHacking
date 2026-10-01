#!/usr/bin/env python3
"""Vercel WSGI entrypoint for the VibeAgent dashboard.

Vercel serves the dashboard and proxies API requests to an optional, persistent
VibeAgent worker. Agent scans are deliberately not started inside a serverless
invocation: Vercel instances are ephemeral and cannot reliably retain the
background threads or filesystem state used by live agent runs.
"""
import base64
import hmac
import json
import os
import re
import sys
import tempfile
import urllib.error
import urllib.parse
import urllib.request
from http import HTTPStatus

_ROOT = os.path.dirname(os.path.abspath(__file__))
_TOOLS = os.path.join(_ROOT, "TOOLS")

# Vercel's source tree is read-only. Keep best-effort local telemetry in /tmp;
# durable live thread state belongs on the separately hosted worker. These
# defaults also keep local WSGI tests from touching the checkout's ignored logs.
_runtime_dir = os.path.join(tempfile.gettempdir(), "vibehacking")
os.environ.setdefault("VIBE_LOG_DIR", os.path.join(_runtime_dir, "logs"))
os.environ.setdefault("VIBE_FINDINGS_FILE", os.path.join(_runtime_dir, "logs", "findings.jsonl"))
os.environ.setdefault("VIBE_SURFACE_FILE", os.path.join(_runtime_dir, "logs", "attack_surface.json"))
os.environ.setdefault("VIBE_POC_FILE", os.path.join(_runtime_dir, "logs", "pocs.json"))
os.environ.setdefault("VIBE_HYPERION_FILE", os.path.join(_runtime_dir, "logs", "hyperion_last.json"))
os.environ.setdefault("VIBE_THREADS_DIR", os.path.join(_runtime_dir, "threads"))
os.environ.setdefault("VIBE_SESSION_FILE", os.path.join(_runtime_dir, "vibe_session.json"))

if _TOOLS not in sys.path:
    sys.path.insert(0, _TOOLS)

from live_dashboard import DASHBOARD_HTML, load_dashboard_state  # noqa: E402
from vibe_agent import (  # noqa: E402
    FREE_MODEL_CATALOG,
    MODEL_ALIASES,
    get_thread_by_id,
    list_all_threads,
    verify_authorization_phrase,
)

_MAX_REQUEST_BYTES = 16 * 1024
_MAX_RESPONSE_BYTES = 2 * 1024 * 1024


class _NoRedirectHandler(urllib.request.HTTPRedirectHandler):
    """Do not forward the worker token to a redirect destination."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _json_bytes(payload):
    return json.dumps(payload, ensure_ascii=False).encode("utf-8")


def _response(start_response, status, body, content_type="application/json; charset=utf-8", extra_headers=None):
    if isinstance(body, str):
        body = body.encode("utf-8")
    headers = [
        ("Content-Type", content_type),
        ("Content-Length", str(len(body))),
        ("Cache-Control", "no-store"),
        ("X-Content-Type-Options", "nosniff"),
        ("X-Frame-Options", "DENY"),
        ("Referrer-Policy", "no-referrer"),
        ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
        ("Content-Security-Policy", "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; connect-src 'self'; img-src 'self' data:; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"),
    ]
    if extra_headers:
        headers.extend(extra_headers)
    phrase = HTTPStatus(status).phrase if status in HTTPStatus._value2member_map_ else "Unknown"
    start_response(f"{status} {phrase}", headers)
    return [body]


def _json_response(start_response, status, payload, extra_headers=None):
    return _response(start_response, status, _json_bytes(payload), extra_headers=extra_headers)


def _basic_auth_is_valid(environ):
    expected_password = os.environ.get("VIBE_DASHBOARD_PASSWORD", "")
    if not expected_password:
        return False
    expected_user = os.environ.get("VIBE_DASHBOARD_USER", "admin")
    header = environ.get("HTTP_AUTHORIZATION", "")
    scheme, _, encoded = header.partition(" ")
    if scheme.lower() != "basic" or not encoded:
        return False
    try:
        decoded = base64.b64decode(encoded, validate=True).decode("utf-8")
        supplied_user, supplied_password = decoded.split(":", 1)
    except (ValueError, UnicodeDecodeError):
        return False
    return hmac.compare_digest(supplied_user, expected_user) and hmac.compare_digest(
        supplied_password, expected_password
    )


def _worker_config():
    """Return (url, token) only when all fail-closed production gates are set."""
    base = os.environ.get("VIBE_AGENT_WORKER_URL", "").strip().rstrip("/")
    token = os.environ.get("VIBE_AGENT_WORKER_TOKEN", "").strip()
    password = os.environ.get("VIBE_DASHBOARD_PASSWORD", "")
    if not base or len(token) < 32 or len(password) < 16:
        return None
    parsed = urllib.parse.urlsplit(base)
    if (
        parsed.scheme != "https"
        or not parsed.hostname
        or parsed.username
        or parsed.password
        or parsed.query
        or parsed.fragment
        or parsed.path not in ("", "/")
    ):
        return None
    return base, token


def _capabilities():
    config = _worker_config()
    if config:
        return {
            "deployment_mode": "vercel-proxy",
            "can_launch": True,
            "message": "Protected persistent worker is configured.",
        }
    return {
        "deployment_mode": "vercel-read-only",
        "can_launch": False,
        "message": (
            "Vercel preview is read-only until a protected, persistent worker is connected. "
            "Configure VIBE_AGENT_WORKER_URL, VIBE_AGENT_WORKER_TOKEN, and VIBE_DASHBOARD_PASSWORD."
        ),
    }


def _read_body(environ):
    raw_length = environ.get("CONTENT_LENGTH", "")
    try:
        length = int(raw_length or "0")
    except (TypeError, ValueError):
        return None, "Invalid Content-Length."
    if length < 0:
        return None, "Invalid Content-Length."
    if length > _MAX_REQUEST_BYTES:
        return None, "Request body exceeds the 16 KB limit."
    stream = environ.get("wsgi.input")
    if stream is None:
        return b"", ""
    body = stream.read(length) if length else b""
    if len(body) != length:
        return None, "Request body was incomplete."
    return body, ""


def _proxy_worker(environ, start_response, path, body=None):
    config = _worker_config()
    if not config:
        return _json_response(start_response, 503, {"error": _capabilities()["message"]})
    base, token = config
    method = environ.get("REQUEST_METHOD", "GET").upper()
    query = environ.get("QUERY_STRING", "")
    target = base + path
    if query:
        target += "?" + query
    headers = {
        "Accept": "application/json",
        "X-Vibe-Worker-Token": token,
    }
    if body is not None:
        headers["Content-Type"] = environ.get("CONTENT_TYPE", "application/json")
    request = urllib.request.Request(target, data=body, headers=headers, method=method)
    opener = urllib.request.build_opener(_NoRedirectHandler)
    try:
        with opener.open(request, timeout=12) as result:
            status = result.status
            payload = result.read(_MAX_RESPONSE_BYTES + 1)
            content_type = result.headers.get("Content-Type", "application/json; charset=utf-8")
    except urllib.error.HTTPError as exc:
        status = exc.code
        payload = exc.read(_MAX_RESPONSE_BYTES + 1)
        content_type = exc.headers.get("Content-Type", "application/json; charset=utf-8")
    except Exception:
        return _json_response(start_response, 502, {"error": "The configured VibeAgent worker could not be reached."})
    if len(payload) > _MAX_RESPONSE_BYTES:
        return _json_response(start_response, 502, {"error": "Worker response exceeded the 2 MB limit."})
    return _response(start_response, status, payload, content_type=content_type)


def _validate_launch_request(body):
    try:
        data = json.loads(body.decode("utf-8") if body else "{}")
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None, "Invalid JSON body."
    if not isinstance(data, dict):
        return None, "JSON body must be an object."

    target = str(data.get("url", "")).strip()
    if not target:
        return None, "Target App URL is required."
    if "://" not in target:
        target = "https://" + target
    parsed = urllib.parse.urlsplit(target)
    if parsed.scheme not in ("http", "https") or not parsed.hostname or parsed.username or parsed.password:
        return None, "Target URL must be a valid http:// or https:// URL without embedded credentials."
    if not verify_authorization_phrase(str(data.get("auth", ""))):
        return None, "Authorization gate rejected: enter the required authorization statement."

    mode = str(data.get("mode", "VibeAgent")).strip().lower()
    if mode not in ("vibeagent", "vibe", "breakagent", "break", "both"):
        return None, "Mode must be VibeAgent, BreakAgent, or both."

    model = str(data.get("model", "laguna-s-2.1")).strip().lower()
    canonical_model = MODEL_ALIASES.get(model, model)
    if canonical_model not in FREE_MODEL_CATALOG:
        return None, "Select one of the configured free OpenRouter models."

    data["url"] = target
    data["mode"] = "both" if mode == "both" else "BreakAgent" if mode in ("break", "breakagent") else "VibeAgent"
    data["model"] = canonical_model
    return data, ""


def app(environ, start_response):
    """WSGI callable loaded by Vercel for every dashboard request."""
    method = environ.get("REQUEST_METHOD", "GET").upper()
    path = urllib.parse.unquote(environ.get("PATH_INFO", "/") or "/")
    if path != "/":
        path = path.rstrip("/") or "/"

    if path == "/healthz" and method == "GET":
        return _json_response(start_response, 200, {"ok": True})

    password_set = bool(os.environ.get("VIBE_DASHBOARD_PASSWORD", ""))
    if password_set and not _basic_auth_is_valid(environ):
        return _json_response(
            start_response,
            401,
            {"error": "Dashboard login required."},
            extra_headers=[("WWW-Authenticate", 'Basic realm="VibeHacking Dashboard", charset="UTF-8"')],
        )

    if method == "OPTIONS":
        return _response(start_response, 204, b"")

    if method == "GET" and path == "/":
        html = DASHBOARD_HTML.replace('value="http://127.0.0.1:3456"', 'value=""')
        html = html.replace(
            "placeholder=\"https://your-app.vercel.app or http://127.0.0.1:3456\"",
            "placeholder=\"https://your-authorized-app.example\"",
        )
        return _response(start_response, 200, html, content_type="text/html; charset=utf-8")

    if method == "GET" and path == "/api/capabilities":
        return _json_response(start_response, 200, _capabilities())

    if method == "GET" and path in ("/api/state", "/api/findings", "/api/threads"):
        if _worker_config():
            return _proxy_worker(environ, start_response, path)
        if path == "/api/threads":
            return _json_response(start_response, 200, {"threads": list_all_threads()})
        return _json_response(start_response, 200, load_dashboard_state())

    if method == "GET" and path.startswith("/api/threads/"):
        thread_id = path.split("/api/threads/", 1)[1]
        if not re.fullmatch(r"[A-Za-z0-9_-]{1,100}", thread_id):
            return _json_response(start_response, 404, {"error": "Thread not found."})
        if _worker_config():
            return _proxy_worker(environ, start_response, "/api/threads/" + urllib.parse.quote(thread_id, safe="-_"))
        thread = get_thread_by_id(thread_id)
        if not thread:
            return _json_response(start_response, 404, {"error": "Thread not found."})
        return _json_response(start_response, 200, thread)

    if method == "POST" and path == "/api/threads/start":
        body, error = _read_body(environ)
        if error:
            status = 413 if "16 KB" in error else 400
            return _json_response(start_response, status, {"error": error})
        data, error = _validate_launch_request(body)
        if error:
            return _json_response(start_response, 400, {"error": error})
        if not _worker_config():
            return _json_response(start_response, 503, {"error": _capabilities()["message"]})
        forwarded_body = _json_bytes(data)
        return _proxy_worker(environ, start_response, "/api/threads/start", body=forwarded_body)

    if path.startswith("/api/"):
        return _json_response(start_response, 404, {"error": "Unknown API endpoint."})
    if method not in ("GET", "HEAD", "POST", "OPTIONS"):
        return _json_response(start_response, 405, {"error": "Method not allowed."})
    return _json_response(start_response, 404, {"error": "Not found."})


# Vercel's Python runtime uses the top-level WSGI object named `app`.
application = app
