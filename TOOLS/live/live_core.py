import sys
import os
import time
import ssl
import urllib.request
import urllib.error
import socket
import json

# Allow importing vibe_core from parent TOOLS/ directory
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from vibe_core import VibeTool

__version__ = "1.0.0"


class LiveTool(VibeTool):
    """Remote-safe base class. Adds per-request delay and optional SSL bypass."""

    def __init__(self, name, description, delay=0.7):
        super().__init__(name, description)
        self.delay = delay
        self.verify_ssl = True

    def safe_request(self, url, method='GET', data=None, headers=None, timeout=10):
        if self.delay > 0:
            time.sleep(self.delay)

        if headers is None:
            headers = {}

        headers.setdefault('User-Agent',
            'Mozilla/5.0 (Windows NT 10.0; Win64; x64) '
            'AppleWebKit/537.36 (KHTML, like Gecko) '
            'Chrome/120.0.0.0 Safari/537.36')
        headers.setdefault('Accept',
            'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8')

        try:
            body = json.dumps(data).encode('utf-8') if data else None
            if body and 'Content-Type' not in headers:
                headers['Content-Type'] = 'application/json'

            req = urllib.request.Request(url, method=method, data=body, headers=headers)

            if not self.verify_ssl:
                ctx = ssl.create_default_context()
                ctx.check_hostname = False
                ctx.verify_mode = ssl.CERT_NONE
                opener = urllib.request.build_opener(urllib.request.HTTPSHandler(context=ctx))
                with opener.open(req, timeout=timeout) as response:
                    return response.getcode(), response.read().decode('utf-8', errors='ignore'), dict(response.info())
            else:
                with urllib.request.urlopen(req, timeout=timeout) as response:
                    return response.getcode(), response.read().decode('utf-8', errors='ignore'), dict(response.info())

        except urllib.error.HTTPError as e:
            return e.code, e.read().decode('utf-8', errors='ignore'), dict(e.headers)
        except urllib.error.URLError as e:
            return 0, f"[connection-error] {e.reason}", {}
        except socket.timeout:
            return 0, "[timeout] request timed out", {}
        except Exception as e:
            return 0, f"[error] {e}", {}
