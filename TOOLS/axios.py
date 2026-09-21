import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool, FRAMEWORK_VERSION


class Axios(VibeTool):
    def __init__(self):
        super().__init__("Axios", "IDOR / ID Exposure Scanner")

    def run(self, base_url, start_id, end_id):
        self.banner()
        self.log(f"Scanning {base_url}/[{start_id}–{end_id}]")

        leaks = []

        # Catch-all guard: if a path that cannot exist answers 200, every ID in
        # the range will "leak" and the whole scan is a false positive.
        baseline = self.baseline_probe(base_url)
        if baseline.get("catch_all"):
            self.log("Target answers 200 for a nonexistent path (catch-all route). "
                     "Only responses that differ from that baseline count as exposed IDs.", "warn")

        for user_id in range(start_id, end_id + 1):
            target = f"{base_url.rstrip('/')}/{user_id}"
            self.log(f"Probing ID {user_id}")

            status, content, _ = self.safe_request(target, method='GET')

            if status == 200 and self.matches_baseline(content, baseline):
                self.log(f"ID {user_id}: 200 but identical to the catch-all baseline — not a leak")
            elif status == 200:
                self.log(f"IDOR — ID {user_id} returned data without authorization (200 OK)", "crit")
                leaks.append(user_id)
            elif status in (401, 403):
                self.log(f"ID {user_id} blocked ({status}) — properly protected", "pass")
            elif status == 404:
                self.log(f"ID {user_id} not found ({status})", "warn")
            elif status == 0:
                self.log(f"Connection issue: {content}", "fail")
            else:
                self.log(f"ID {user_id} — unexpected response ({status})", "warn")

        self.log("=" * 32)
        if leaks:
            self.log(f"{len(leaks)} IDOR vulnerability/vulnerabilities found — exposed IDs: {leaks}", "crit")
        else:
            self.log("No IDOR vulnerabilities found in range", "pass")
        if baseline.get("catch_all"):
            self.log("Note: confirm each exposed ID manually — the target serves a catch-all route.", "warn")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Axios - IDOR / ID Exposure Scanner")
    parser.add_argument("--url", required=True, help="Base endpoint to enumerate (e.g. http://localhost:3456/api/user)")
    parser.add_argument("--start", type=int, default=1, help="Starting ID (default: 1)")
    parser.add_argument("--end", type=int, default=10, help="Ending ID (default: 10)")
    parser.add_argument('-v', '--version', action='version', version=f"Axios {FRAMEWORK_VERSION}")
    args = parser.parse_args()

    Axios().run(args.url, args.start, args.end)
