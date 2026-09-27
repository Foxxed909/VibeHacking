import sys
import urllib.request
import urllib.parse
import ipaddress
import json
import os
import datetime
import time

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

DEFAULT_TARGET_BASE = (
    os.environ.get("VIBE_BASE_URL") or "http://127.0.0.1:3456"
).rstrip("/")

LOCAL_HOST_LITERALS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}


def normalize_host(raw):
    host = (raw or "").strip()
    if not host or host.startswith("#") or any(ch in host for ch in "*?"):
        return ""
    if "://" in host:
        try:
            host = urllib.parse.urlparse(host).hostname or ""
        except ValueError:
            return ""
    host = host.split("/")[0].strip().lower()
    if "@" in host:
        host = host.split("@")[-1]
    if host.count(":") == 1:
        host = host.split(":")[0]
    return host


def is_local_or_private(host):
    host = (host or "").strip().lower().strip("[]")
    if not host:
        return False
    if host in LOCAL_HOST_LITERALS:
        return True
    if host.endswith(".localhost") or host.endswith(".internal"):
        return True
    try:
        ip = ipaddress.ip_address(host)
    except ValueError:
        return False
    return not ip.is_global


LOCKED_MANIFEST = os.path.join(_root, "vb", "locked", "manifest.json")


def locked_tools(manifest_path=None):
    path = manifest_path or LOCKED_MANIFEST
    try:
        with open(path, "r", encoding="utf-8") as handle:
            data = json.load(handle)
    except (OSError, ValueError):
        return {}
    locked = data.get("locked_tools") or {}
    return {name: (meta or {}).get("reason", "high-impact authorized-testing tool")
            for name, meta in locked.items()}


def _locked_gate(names, reasons=None, assume_yes=False, log_path=None):
    names = [n for n in names if n]
    reasons = reasons or {}

    def _log(allowed, detail):
        if not log_path:
            return
        try:
            os.makedirs(os.path.dirname(log_path), exist_ok=True)
            stamp = time.strftime("%Y-%m-%d %H:%M:%S")
            with open(log_path, "a", encoding="utf-8") as handle:
                handle.write(f"{stamp}\ttools={','.join(names)}\t"
                             f"allowed={str(allowed).lower()}\tdetail={detail}\n")
        except OSError:
            pass

    if not names:
        return set()

    phrase = "I OWN THIS TARGET"
    if assume_yes:
        _log(True, "flag")
        return set(names)
    if os.environ.get("VIBE_LOCKED_ACK") == phrase:
        _log(True, "env_ack")
        return set(names)

    if not sys.stdin.isatty():
        print(f"[-] {len(names)} locked tool(s) requested in a non-interactive session.")
        print(f"    Re-run with an explicit opt-in (--allow-locked / "
              f"VIBE_LOCKED_ACK='{phrase}') on a target you own.")
        _log(False, "non_interactive")
        return set()

    print("=" * 64)
    print("LOCKED AUTHORIZED-ONLY TOOL" + ("S" if len(names) > 1 else ""))
    for name in names:
        print(f"Tool   : {name}")
        print(f"Reason : {reasons.get(name, 'high-impact authorized-testing tool')}")
    print("Run these only on systems you own or have written permission to test.")
    print("=" * 64)
    sys.stdout.flush()
    try:
        answer = input(f"Type '{phrase}' to proceed, anything else to skip: ")
    except (EOFError, KeyboardInterrupt):
        _log(False, "aborted")
        return set()
    allowed = answer.strip() == phrase
    _log(allowed, "typed_confirmation" if allowed else "declined")
    return set(names) if allowed else set()


def confirm_locked_tool(tool, reason="", assume_yes=False, log_path=None):
    return tool in _locked_gate([tool], {tool: reason}, assume_yes=assume_yes,
                                log_path=log_path)


def confirm_locked_tools(tools, reasons=None, assume_yes=False, log_path=None):
    return _locked_gate(list(tools), reasons, assume_yes=assume_yes, log_path=log_path)


def _canonical_header(name):
    if not isinstance(name, str) or not name or not name.islower():
        return name
    return "-".join(part.capitalize() for part in name.split("-"))


def _cookies_to_header(cookies):
    if isinstance(cookies, str):
        return cookies
    if isinstance(cookies, (list, tuple)):
        parts = [f"{c.get('name')}={c.get('value')}" for c in cookies
                 if isinstance(c, dict) and c.get("name")]
        return "; ".join(parts)
    return ""


def auth_context():
    ctx = {}
    path = os.environ.get("VIBE_AUTH_FILE")
    if path and os.path.exists(path):
        try:
            with open(path, "r", encoding="utf-8") as f:
                ctx = json.load(f)
        except (OSError, ValueError):
            ctx = {}
    cookie = (os.environ.get("VIBE_COOKIE")
              or ctx.get("cookie")
              or _cookies_to_header(ctx.get("cookies")))
    ua = os.environ.get("VIBE_UA") or ctx.get("user_agent") or ""
    extra = dict(ctx.get("headers") or {})
    env_hdr = os.environ.get("VIBE_HEADERS")
    if env_hdr:
        try:
            extra.update(json.loads(env_hdr))
        except ValueError:
            pass
    return cookie, ua, extra


def auth_headers():
    cookie, ua, extra = auth_context()
    headers = dict(extra)
    if cookie:
        headers["Cookie"] = cookie
    if ua:
        headers["User-Agent"] = ua
    return headers


def auth_active():
    cookie, ua, extra = auth_context()
    return bool(cookie or extra)


class _AuthHandler(urllib.request.BaseHandler):
    handler_order = 900

    def _apply(self, req):
        cookie, ua, extra = auth_context()
        if cookie and not req.has_header("Cookie"):
            req.add_unredirected_header("Cookie", cookie)
        if ua:
            try:
                req.remove_header("User-agent")
            except (AttributeError, KeyError):
                pass
            req.add_unredirected_header("User-agent", ua)
        for key, value in extra.items():
            req.add_unredirected_header(_canonical_header(key), value)
        return req

    def http_request(self, req):
        return self._apply(req)

    https_request = http_request


AuthHandler = _AuthHandler
urllib.request.install_opener(urllib.request.build_opener(_AuthHandler))


class _CaseInsensitiveHeaders(dict):
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

        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)
        session_dir = os.path.dirname(os.path.abspath(self.session_file))
        if session_dir and not os.path.exists(session_dir):
            os.makedirs(session_dir)

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
        try:
            print(formatted_msg)
            sys.stdout.flush()
        except (BrokenPipeError, ValueError):
            pass

        filename = f"{self.name.lower()}_session.log"
        with open(os.path.join(self.log_dir, filename), "a", encoding="utf-8") as f:
            f.write(formatted_msg + "\n")

    def banner(self):
        print("================================")
        print(f" 🛡️ {self.name.upper()} v{self.version}")
        print(f" {self.description}")
        print("================================")
        sys.stdout.flush()

    def save_session(self, data):
        with open(self.session_file, 'w', encoding='utf-8') as f:
            json.dump(sanitize_data(data), f, indent=4)

    def load_session(self):
        if os.path.exists(self.session_file):
            try:
                with open(self.session_file, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

    def baseline_probe(self, base_url, timeout=5):
        token = "vibe-baseline-%s" % datetime.datetime.now().strftime("%H%M%S%f")
        url = base_url.rstrip("/") + "/" + token
        status, body, _ = self.safe_request(url, method="GET")
        body = body or ""
        return {
            "url": url,
            "status": status,
            "length": len(body),
            "body": body,
            "catch_all": status == 200,
        }

    def is_catch_all(self, base_url):
        return self.baseline_probe(base_url).get("catch_all", False)

    @staticmethod
    def matches_baseline(body, baseline):
        if not baseline:
            return False
        return (body or "") == baseline.get("body", "")

    def safe_request(self, url, method='GET', data=None, headers=None):
        if headers is None:
            headers = {}
        else:
            headers = dict(headers)

        if privacy_enabled():
            headers['User-Agent'] = privacy_user_agent(self.name)
            headers.setdefault('DNT', '1')
            headers.setdefault('Sec-GPC', '1')
        else:
            headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8'

        _cookie, _ua, _extra = auth_context()
        if _cookie:
            headers.setdefault('Cookie', _cookie)
        if _ua:
            headers['User-Agent'] = _ua
        for _k, _v in _extra.items():
            headers.setdefault(_k, _v)

        try:
            body = json.dumps(data).encode('utf-8') if data else None
            if body and 'Content-Type' not in headers:
                headers['Content-Type'] = 'application/json'

            req = urllib.request.Request(url, method=method, data=body, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as response:
                return response.getcode(), response.read().decode('utf-8', errors='ignore'), _CaseInsensitiveHeaders(response.info())
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode('utf-8', errors='ignore'), _CaseInsensitiveHeaders(e.headers)
        except Exception as e:
            return 0, str(e), {}
