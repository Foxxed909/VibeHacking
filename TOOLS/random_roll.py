import sys
import os
import argparse
import random
import string

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool, FRAMEWORK_VERSION


class RandomRoll(VibeTool):
    def __init__(self):
        super().__init__("Random Roll", "Password Policy Auditor")

    def _generate_password(self, length, weak=False):
        """Weak mode = lowercase-only and 4-7 chars; strong mode = 8+ mixed.

        The old code drew lengths from randint(4, 16) in *both* modes, so
        "strong" runs could emit 4-char passwords and then report its own
        generator as the target's broken policy.
        """
        if weak:
            charset = string.ascii_lowercase
            length = random.randint(4, 7)
        else:
            charset = string.ascii_letters + string.digits + "!@#$%^&*"
            length = max(8, length)
        return ''.join(random.choice(charset) for _ in range(length))

    def run(self, url, username, attempts, check_weak):
        self.banner()
        self.log(f"Hammering endpoint: {url}")

        weak_accepted = 0
        total = 0

        for i in range(attempts):
            pwd = self._generate_password(length=8, weak=check_weak)
            payload = {"username": f"{username}_{i}", "password": pwd}
            # Never log the credential or its length class: session logs are
            # plaintext files that outlive the run.
            self.log(f"Rolling {payload['username']} "
                     f"(password: {len(pwd)} chars, hidden)")

            status, _, _ = self.safe_request(url, method='POST', data=payload)

            if status in (200, 201):
                if len(pwd) < 8 or pwd.isalpha():
                    self.log("Weak password accepted — policy is broken", "crit")
                    weak_accepted += 1
                else:
                    self.log(f"Strong account created ({status})", "pass")
            elif status == 429:
                self.log(f"Rate limited ({status}) — throttling defense works", "pass")
                break
            elif status in (400, 403):
                self.log(f"Weak password rejected ({status})", "pass")
            elif status == 0:
                self.log("Connection issue", "fail")
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
    parser.add_argument('-v', '--version', action='version', version=f"Random Roll {FRAMEWORK_VERSION}")
    args = parser.parse_args()

    RandomRoll().run(args.url, args.user, args.attempts, args.check_weak)
