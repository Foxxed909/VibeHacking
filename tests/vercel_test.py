#!/usr/bin/env python3
"""Small stdlib regression test for the Vercel WSGI adapter."""
import base64
import io
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if ROOT not in sys.path:
    sys.path.insert(0, ROOT)

# Simulate the Vercel read-only runtime without requiring Vercel credentials.
os.environ["VERCEL"] = "1"
for name in (
    "VIBE_DASHBOARD_PASSWORD",
    "VIBE_DASHBOARD_USER",
    "VIBE_AGENT_WORKER_URL",
    "VIBE_AGENT_WORKER_TOKEN",
):
    os.environ.pop(name, None)

import app as vercel_app  # noqa: E402


def request(path, method="GET", body=b"", authorization=""):
    captured = {}
    environ = {
        "REQUEST_METHOD": method,
        "PATH_INFO": path,
        "QUERY_STRING": "",
        "CONTENT_LENGTH": str(len(body)),
        "CONTENT_TYPE": "application/json",
        "HTTP_HOST": "example.vercel.app",
        "wsgi.url_scheme": "https",
        "wsgi.input": io.BytesIO(body),
    }
    if authorization:
        environ["HTTP_AUTHORIZATION"] = authorization

    def start_response(status, headers):
        captured["status"] = int(status.split(" ", 1)[0])
        captured["headers"] = dict(headers)

    payload = b"".join(vercel_app.app(environ, start_response))
    captured["body"] = payload
    return captured


def main():
    page = request("/")
    assert page["status"] == 200
    assert b"VibeAgent" in page["body"]
    assert b"127.0.0.1:3456" not in page["body"]
    assert page["headers"]["X-Frame-Options"] == "DENY"

    caps = request("/api/capabilities")
    assert caps["status"] == 200
    caps_json = json.loads(caps["body"])
    assert caps_json["deployment_mode"] == "vercel-read-only"
    assert caps_json["can_launch"] is False

    launch = request(
        "/api/threads/start",
        method="POST",
        body=json.dumps({
            "url": "https://example.com",
            "auth": "I AM AUTHORIZED TO TEST THIS TARGET",
            "mode": "VibeAgent",
            "model": "laguna-s-2.1",
        }).encode("utf-8"),
    )
    assert launch["status"] == 503

    os.environ["VIBE_DASHBOARD_USER"] = "admin"
    os.environ["VIBE_DASHBOARD_PASSWORD"] = "unit-test-password"
    protected = request("/")
    assert protected["status"] == 401
    assert "WWW-Authenticate" in protected["headers"]
    basic = base64.b64encode(b"admin:unit-test-password").decode("ascii")
    logged_in = request("/", authorization="Basic " + basic)
    assert logged_in["status"] == 200

    print("[PASS] Vercel WSGI adapter: read-only preview, fail-closed launches, and dashboard auth")
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    finally:
        for name in (
            "VIBE_DASHBOARD_PASSWORD",
            "VIBE_DASHBOARD_USER",
            "VIBE_AGENT_WORKER_URL",
            "VIBE_AGENT_WORKER_TOKEN",
        ):
            os.environ.pop(name, None)
