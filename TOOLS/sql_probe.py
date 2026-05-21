import sys
import os
import argparse
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool

__version__ = "1.0.0"

DB_ERROR_SIGS = [
    # MySQL
    "you have an error in your sql syntax",
    "mysql_fetch_array()",
    "mysql_num_rows()",
    "supplied argument is not a valid mysql",
    # PostgreSQL
    "pg_query()",
    "unterminated quoted string at or near",
    "syntax error at or near",
    # SQLite
    "sqlite_master",
    "no such column",
    "unrecognized token",
    # MSSQL
    "unclosed quotation mark after the character string",
    "incorrect syntax near",
    "microsoft ole db provider",
    "odbc sql server driver",
    # Generic
    "sql syntax",
    "sqlstate",
    "ora-01756",
]

PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR 1=1--",
    '" OR 1=1--',
    "1; DROP TABLE users--",
    "' UNION SELECT NULL--",
    "1' AND SLEEP(0)--",
]

TEST_PARAMS = ["id", "q", "search", "user", "page", "name", "query"]


class SQLProbe(VibeTool):
    def __init__(self):
        super().__init__("SQLProbe", "SQL Injection Scanner")

    def _check_response(self, status, body, param, payload):
        body_lower = body.lower()
        for sig in DB_ERROR_SIGS:
            if sig in body_lower:
                self.log(f"DB ERROR LEAK on param '{param}' payload={repr(payload)} sig={repr(sig)}", "crit")
                return True
        if status == 500:
            self.log(f"500 Server Error on param '{param}' payload={repr(payload)} — possible crash", "warn")
        return False

    def run(self, url):
        self.banner()
        self.log(f"Target: {url}")
        base = url.rstrip("/")
        hits = 0

        for param in TEST_PARAMS:
            for payload in PAYLOADS:
                # GET: inject as query param
                encoded = urllib.parse.quote(payload, safe="")
                test_url = f"{base}?{param}={encoded}"
                status, body, _ = self.safe_request(test_url)
                if self._check_response(status, body, param, payload):
                    hits += 1

                # POST: inject as JSON body field
                post_data = {param: payload}
                status, body, _ = self.safe_request(base, method="POST", data=post_data)
                if self._check_response(status, body, f"{param}(POST)", payload):
                    hits += 1

        self.log("=" * 32)
        if hits > 0:
            self.log(f"{hits} potential SQL injection indicator(s) found", "crit")
        else:
            self.log("No SQL error signatures detected — target appears resilient", "pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SQLProbe - SQL Injection Scanner")
    parser.add_argument("--url", required=True, help="Target base URL (e.g. http://localhost:3456)")
    parser.add_argument("-v", "--version", action="version", version=f"SQLProbe {__version__}")
    args = parser.parse_args()
    SQLProbe().run(args.url)
