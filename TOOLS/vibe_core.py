import sys
import urllib.request
import urllib.parse
import json
import os
import datetime

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


class VibeTool:
    def __init__(self, name, description):
        self.name = name
        self.description = description
        self.version = FRAMEWORK_VERSION
        self.session_file = os.path.join(_root, "vibe_session.json")
        self.log_dir = os.path.join(_root, "logs")

        if not os.path.exists(self.log_dir):
            os.makedirs(self.log_dir)

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
        formatted_msg = f"[{timestamp}] {prefix} {message}"
        print(formatted_msg)

        filename = f"{self.name.lower()}_session.log"
        with open(os.path.join(self.log_dir, filename), "a", encoding="utf-8") as f:
            f.write(formatted_msg + "\n")

        sys.stdout.flush()

    def banner(self):
        print("================================")
        print(f" 🛡️ {self.name.upper()} v{self.version}")
        print(f" {self.description}")
        print("================================")
        sys.stdout.flush()

    def save_session(self, data):
        with open(self.session_file, 'w') as f:
            json.dump(data, f, indent=4)

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

        headers['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'
        headers['Accept'] = 'text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8'

        try:
            body = json.dumps(data).encode('utf-8') if data else None
            if body and 'Content-Type' not in headers:
                headers['Content-Type'] = 'application/json'

            req = urllib.request.Request(url, method=method, data=body, headers=headers)
            with urllib.request.urlopen(req, timeout=10) as response:
                return response.getcode(), response.read().decode('utf-8', errors='ignore'), dict(response.info())
        except urllib.error.HTTPError as e:
            return e.code, e.read().decode('utf-8', errors='ignore'), dict(e.headers)
        except Exception as e:
            return 0, str(e), {}
