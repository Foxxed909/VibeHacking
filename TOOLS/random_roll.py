import sys
import os
import argparse
import random
import string

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool


class RandomRoll(VibeTool):
    def __init__(self):
        super().__init__("Random Roll", "Password Policy Auditor")

    def _generate_password(self, length, weak=False):
        charset = string.ascii_lowercase if weak else string.ascii_letters + string.digits + "!@#$%^&*"
        return ''.join(random.choice(charset) for _ in range(length))

    def run(self, url, username, attempts, check_weak):
        self.banner()
        self.log(f"Hammering endpoint: {url}")

        weak_accepted = 0
        total = 0

        for i in range(attempts):
            pwd = self._generate_password(
                length=random.randint(4, 16),
                weak=check_weak
            )
            payload = {"username": f"{username}_{i}", "password": pwd}
            self.log(f"Rolling {payload['username']} with pwd: {pwd}")

            status, _, _ = self.safe_request(url, method='POST', data=payload)

            if status == 201:
                if len(pwd) < 8 or pwd.isalpha():
                    self.log(f"Weak password accepted — policy is broken", "crit")
                    weak_accepted += 1
                else:
                    self.log(f"Strong account created ({status})", "pass")
            elif status == 429:
                self.log(f"Rate limited ({status}) — throttling defense works", "pass")
                break
            elif status in (400, 403):
                self.log(f"Weak password rejected ({status})", "pass")
            elif status == 0:
                self.log(f"Connection issue", "fail")
                break
            else:
                self.log(f"Unexpected response ({status})", "warn")

            total += 1

        self.log("=" * 32)
        if weak_accepted > 0:
            self.log(f"{weak_accepted} policy bypass(es) out of {total} attempt(s)", "crit")
        else:
            self.log(f"Policy held across {total} attempt(s)", "pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Random Roll - Password Policy Auditor")
    parser.add_argument("--url", required=True, help="Registration endpoint (e.g. http://localhost:3456/api/register)")
    parser.add_argument("--user", default="vibe_test", help="Base username for test accounts")
    parser.add_argument("--attempts", type=int, default=10, help="Number of attempts")
    parser.add_argument("--check-weak", action="store_true", help="Deliberately generate weak passwords")
    parser.add_argument('-v', '--version', action='version', version='Random Roll 1.0.0')
    args = parser.parse_args()

    RandomRoll().run(args.url, args.user, args.attempts, args.check_weak)
