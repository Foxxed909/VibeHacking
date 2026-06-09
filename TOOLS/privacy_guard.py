import os
import re
import urllib.parse


ENV_PRIVACY_MODE = "VIBE_PRIVACY_MODE"
ENV_DNS_PROBES = "VIBE_ALLOW_DNS_PROBES"

_FALSEY = {"0", "false", "off", "no", "disabled"}
_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

_URL_RE = re.compile(r"https?://[^\s\"'<>)]*", re.IGNORECASE)
_EMAIL_RE = re.compile(r"\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b", re.IGNORECASE)
_IPV4_RE = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])")
_IPV6_RE = re.compile(r"\b(?:[0-9a-f]{0,4}:){2,}[0-9a-f:]{0,4}\b", re.IGNORECASE)
_MAC_RE = re.compile(r"\b(?:[0-9a-f]{2}[:-]){5}[0-9a-f]{2}\b", re.IGNORECASE)
_WINDOWS_USER_RE = re.compile(r"C:\\Users\\[^\\\s]+", re.IGNORECASE)
_SECRET_LINE_RE = re.compile(
    r"(?i)\b(authorization|cookie|set-cookie|x-api-key|api[_ -]?key|token|secret|password)\s*[:=]\s*[^\s,;]+"
)
_AUTH_HEADER_RE = re.compile(r"(?i)\bauthorization\s*[:=]\s*(?:bearer|basic)?\s*[^\s,;]+")
_BEARER_RE = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")
_BASIC_RE = re.compile(r"(?i)\bbasic\s+[A-Za-z0-9._~+/=-]+")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]*\b")
_API_KEY_RE = re.compile(r"\b(?:sk-proj-[A-Za-z0-9_-]{16,}|sk-[A-Za-z0-9_-]{16,}|AIza[A-Za-z0-9_-]{20,})\b")
_SENSITIVE_SEGMENT_RE = re.compile(
    r"(?i)^[a-z0-9_-]{24,}$|^[0-9a-f]{8}-[0-9a-f-]{27,}$|^[A-Za-z0-9+/=_-]{32,}$"
)

SENSITIVE_QUERY_KEYS = {
    "access_token",
    "api_key",
    "apikey",
    "auth",
    "code",
    "email",
    "key",
    "password",
    "secret",
    "session",
    "sid",
    "token",
}


def privacy_enabled():
    return os.environ.get(ENV_PRIVACY_MODE, "on").strip().lower() not in _FALSEY


def dns_probes_allowed():
    return os.environ.get(ENV_DNS_PROBES, "").strip().lower() in {"1", "true", "on", "yes"}


def privacy_user_agent(tool_name="VibeHacking"):
    return f"{tool_name}/1.0 authorized-security-test"


def _sanitize_query(query):
    if not query:
        return ""
    pairs = urllib.parse.parse_qsl(query, keep_blank_values=True)
    scrubbed = []
    for key, value in pairs:
        if key.lower() in SENSITIVE_QUERY_KEYS:
            scrubbed.append((key, "<redacted>"))
        else:
            scrubbed.append((key, _sanitize_path_segment(value)))
    return urllib.parse.urlencode(scrubbed)


def _sanitize_path_segment(segment):
    if not segment:
        return segment
    if _EMAIL_RE.search(segment) or _IPV4_RE.search(segment) or _SENSITIVE_SEGMENT_RE.match(segment):
        return "<id>"
    return segment


def _sanitize_path(path):
    parts = path.split("/")
    return "/".join(_sanitize_path_segment(part) for part in parts)


def _sanitize_url(match):
    raw = match.group(0)
    trail = ""
    while raw and raw[-1] in ".,;":
        trail = raw[-1] + trail
        raw = raw[:-1]
    parsed = urllib.parse.urlsplit(raw)
    if not parsed.scheme or not parsed.netloc:
        return raw + trail
    path = _sanitize_path(parsed.path or "/")
    query = _sanitize_query(parsed.query)
    rebuilt = urllib.parse.urlunsplit((parsed.scheme, "<host>", path, query, ""))
    return rebuilt + trail


def sanitize_text(value):
    if not privacy_enabled() or value is None:
        return "" if value is None else str(value)

    text = str(value)
    text = _URL_RE.sub(_sanitize_url, text)
    text = _AUTH_HEADER_RE.sub("Authorization=<redacted>", text)
    text = _BEARER_RE.sub("Bearer <redacted>", text)
    text = _BASIC_RE.sub("Basic <redacted>", text)
    text = _SECRET_LINE_RE.sub(lambda m: f"{m.group(1)}=<redacted>", text)
    text = _JWT_RE.sub("<jwt>", text)
    text = _API_KEY_RE.sub("<api-key>", text)
    text = _EMAIL_RE.sub("<email>", text)
    text = _WINDOWS_USER_RE.sub(lambda _m: r"C:\Users\<user>", text)
    text = _MAC_RE.sub("<mac>", text)
    text = _IPV6_RE.sub("<ip>", text)
    text = _IPV4_RE.sub("<ip>", text)
    text = text.replace(_ROOT, "<workspace>")
    return text


def sanitize_data(value):
    if isinstance(value, str):
        return sanitize_text(value)
    if isinstance(value, dict):
        return {sanitize_text(k): sanitize_data(v) for k, v in value.items()}
    if isinstance(value, list):
        return [sanitize_data(item) for item in value]
    if isinstance(value, tuple):
        return tuple(sanitize_data(item) for item in value)
    return value


def privacy_summary_lines():
    state = "ON" if privacy_enabled() else "OFF"
    dns_state = "allowed" if dns_probes_allowed() else "blocked by default"
    return [
        f"Privacy guard: {state}",
        f"Extra DNS recon probes: {dns_state}",
        "Local Vibe logs/session files redact URLs, IPs, emails, auth headers, cookies, tokens, MACs, and Windows user paths.",
        "HTTP clients use a generic authorized-test User-Agent instead of a tester device/browser fingerprint.",
        "Limit: the target server, hosting provider, ISP/VPN, and DNS resolver can still see network metadata outside this app.",
        f"Set {ENV_PRIVACY_MODE}=off only for local debugging when exact artifacts are needed.",
        f"Set {ENV_DNS_PROBES}=1 only when explicit DNS recon is approved for the target.",
    ]
