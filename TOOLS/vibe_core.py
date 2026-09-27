import sys
import urllib.request
import urllib.parse
import json
import os
import datetime

from privacy_guard import privacy_enabled, privacy_user_agent, sanitize_data, sanitize_text

for stream in (sys.stdout, sys.stderr):
    if hasattr(stream, "reconfigure"):
        stream.reconfigure(encoding="utf-8", errors="replace")

_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read_version():
    try:
        with open(os.path.join(_root, "VERSION"), "r", encoding="utf-8") as f:
            return f.read().strip() or "1.0.0"
    except OSError:
        return "1.0.0"


FRAMEWORK_VERSION = _read_version()


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
            try:
                os.makedirs(self.log_dir)
            except OSError:
                pass
        session_dir = os.path.dirname(os.path.abspath(self.session_file))
        if session_dir and not os.path.exists(session_dir):
            try:
                os.makedirs(session_dir)
            except OSError:
                pass

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
        try:
            os.makedirs(self.log_dir, exist_ok=True)
            with open(os.path.join(self.log_dir, filename), "a", encoding="utf-8") as f:
                f.write(formatted_msg + "\n")
        except OSError:
            pass

    def banner(self):
        print("================================")
        print(f" 🛡️ {self.name.upper()} v{self.version}")
        print(f" {self.description}")
        print("================================")
        sys.stdout.flush()

    def save_session(self, data):
        try:
            with open(self.session_file, 'w') as f:
                json.dump(sanitize_data(data), f, indent=4)
        except OSError:
            pass

    def load_session(self):
        if os.path.exists(self.session_file):
            try:
                with open(self.session_file, 'r') as f:
                    return json.load(f)
            except (json.JSONDecodeError, OSError):
                return {}
        return {}

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


def _norm_body(content: str) -> str:
    if not content:
        return ""
    return " ".join(content.split())[:4000]


def baseline_probe(tool: "VibeTool", base_url: str):
    base = base_url.rstrip("/")
    root_status, root_body, _ = tool.safe_request(base + "/", method="GET")
    ctrl_status, ctrl_body, _ = tool.safe_request(
        base + "/__vibe_baseline_control_9f3a2c1e__", method="GET"
    )
    return root_status, root_body or "", ctrl_status, ctrl_body or ""


def is_catch_all(root_body: str, control_body: str, candidate_body: str) -> bool:
    r = _norm_body(root_body)
    c = _norm_body(control_body)
    x = _norm_body(candidate_body)
    if not x:
        return False
    if c and x == c:
        return True
    if r and x == r and ("<!doctype html" in x.lower() or "<html" in x.lower()):
        return True
    if r and ("<!doctype html" in r.lower() or "<html" in r.lower()):
        if x.startswith(r[:200]) or r.startswith(x[:200]):
            return True
    return False


def matches_baseline(candidate_body: str, root_body: str, control_body: str) -> bool:
    return is_catch_all(root_body, control_body, candidate_body)


def looks_like_html_shell(content: str) -> bool:
    if not content:
        return False
    low = content[:500].lower()
    return "<!doctype html" in low or ("<html" in low and "<head" in low)
