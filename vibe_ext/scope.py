"""Exact-origin authorization for new network-facing extension commands."""
import json
from pathlib import Path
from urllib.parse import urlsplit

LOCAL_HOSTS = {"localhost", "127.0.0.1", "::1"}


def origin_for(url):
    parsed = urlsplit(url)
    if parsed.scheme not in ("http", "https"):
        raise ValueError("Only HTTP and HTTPS URLs are supported")
    if not parsed.hostname or parsed.username or parsed.password:
        raise ValueError("A target must have a host and no embedded credentials")
    if parsed.fragment:
        raise ValueError("Remove URL fragments")
    try:
        port = parsed.port or (443 if parsed.scheme == "https" else 80)
    except ValueError as exc:
        raise ValueError("Invalid target port") from exc
    host = parsed.hostname.lower().rstrip(".")
    if not host or "*" in host or "\\" in host:
        raise ValueError("Invalid target host")
    # Canonicalize explicit/default ports so a scope file can be unambiguous.
    bracketed = "[{}]".format(host) if ":" in host else host
    return "{}://{}:{}".format(parsed.scheme, bracketed, port)


def require_scope(url, scope_path=None):
    origin = origin_for(url)
    parsed = urlsplit(url)
    if parsed.hostname.lower().rstrip(".") in LOCAL_HOSTS:
        return origin
    if not scope_path:
        raise ValueError("Non-loopback targets require --scope with exact authorized origins")
    with Path(scope_path).open(encoding="utf-8") as handle:
        config = json.load(handle)
    targets = config.get("authorized_origins")
    if not isinstance(targets, list) or not all(isinstance(x, str) for x in targets):
        raise ValueError("Scope file requires authorized_origins: [HTTP(S) origin, ...]")
    allowed = {origin_for(x) for x in targets}
    if origin not in allowed:
        raise ValueError("Target origin is not in the exact authorized scope")
    return origin

