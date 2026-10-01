import sys
import os
import argparse
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool


class Axios(VibeTool):
    def __init__(self):
        super().__init__("Axios", "IDOR / ID Exposure Scanner")

    @staticmethod
    def _looks_like_object_record(body):
        body_l = (body or "").lower()
        return any(
            marker in body_l
            for marker in ('"id"', '"username"', '"email"', '"role"', '"user"', '"account"', '"owner"')
        )

    def _probe_base(self, base_url, start_id, end_id, mode="path"):
        leaks = []
        seen_bodies = set()

        for user_id in range(start_id, end_id + 1):
            if mode == "query":
                sep = "&" if "?" in base_url else "?"
                target = f"{base_url.rstrip('/')}{sep}id={user_id}"
            else:
                target = f"{base_url.rstrip('/')}/{user_id}"

            self.log(f"Probing ID {user_id} ({mode}): {target}")
            status, content, headers = self.safe_request(target, method='GET')

            if status == 200:
                if self.is_waf_challenge(status, content, headers) or self.is_soft_404(status, content):
                    continue
                if self._looks_like_object_record(content):
                    self.log(f"IDOR — ID {user_id} returned object record without authorization (200 OK)", "crit")
                    leaks.append(user_id)
                    seen_bodies.add((content or "")[:200])
                else:
                    self.log(f"ID {user_id} returned 200 OK (non-record content)", "info")
            elif status in (401, 403):
                self.log(f"ID {user_id} blocked ({status}) — properly protected", "pass")
            elif status == 404:
                self.log(f"ID {user_id} not found ({status})", "info")
            elif status == 0:
                self.log(f"Connection issue: {content}", "fail")
                break
            else:
                self.log(f"ID {user_id} — unexpected response ({status})", "warn")

        return leaks

    def run(self, base_url, start_id, end_id):
        self.banner()
        self.calibrate_soft_404(base_url)
        self.log(f"Scanning {base_url} for IDOR [{start_id}–{end_id}]")

        parsed = urllib.parse.urlparse(base_url)
        leaks = self._probe_base(base_url, start_id, end_id, mode="path")

        # Also test ?id=<n> query-parameter IDOR (and /api/user?id=<n> when pointed at root)
        if not leaks:
            query_target = base_url
            if (parsed.path or "/") in ("/", ""):
                query_target = f"{base_url.rstrip('/')}/api/user"
            query_leaks = self._probe_base(query_target, start_id, end_id, mode="query")
            leaks.extend(query_leaks)

        self.log("=" * 32)
        if leaks:
            self.log(f"{len(leaks)} IDOR vulnerability/vulnerabilities found — exposed IDs: {leaks}", "crit")
        else:
            self.log("No IDOR vulnerabilities found in range", "pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Axios - IDOR / ID Exposure Scanner")
    parser.add_argument("--url", required=True, help="Base endpoint to enumerate (e.g. http://localhost:3456/api/user)")
    parser.add_argument("--start", type=int, default=1, help="Starting ID (default: 1)")
    parser.add_argument("--end", type=int, default=10, help="Ending ID (default: 10)")
    parser.add_argument('-v', '--version', action='version', version='Axios 1.0.0')
    args = parser.parse_args()

    Axios().run(args.url, args.start, args.end)
