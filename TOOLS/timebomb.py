import sys
import os
import argparse
import time
import statistics

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool


class TimeBomb(VibeTool):
    def __init__(self):
        super().__init__("TimeBomb", "Timing Attack Detector")

    def _measure(self, url, payload, rounds):
        times = []
        for _ in range(rounds):
            start = time.perf_counter()
            self.safe_request(url, method='POST', data=payload)
            times.append((time.perf_counter() - start) * 1000)
        return times

    def run(self, url, rounds, threshold_ms):
        self.banner()
        self.log(f"Probing timing side-channels on: {url}")
        self.log(f"Rounds per probe: {rounds} | Leak threshold: {threshold_ms}ms")

        probes = {
            "Valid user / wrong password": {
                "email": "admin@localhost.com",
                "password": "definitly_wrong_xX99"
            },
            "Non-existent user": {
                "email": "vibe_ghost_404@fake.invalid",
                "password": "definitly_wrong_xX99"
            },
            "Empty credentials": {
                "email": "",
                "password": ""
            },
            "SQL injection in email": {
                "email": "' OR 1=1--",
                "password": "x"
            },
        }

        results = {}

        for label, payload in probes.items():
            self.log(f"Measuring: {label} ({rounds} rounds)")
            times = self._measure(url, payload, rounds)
            avg = statistics.mean(times)
            med = statistics.median(times)
            results[label] = {"avg": avg, "med": med, "times": times}
            self.log(f"  avg={avg:.1f}ms  median={med:.1f}ms  min={min(times):.1f}ms  max={max(times):.1f}ms", "info")

        self.log("=" * 32)
        self.log("Analyzing timing deltas between probes...")

        baseline_label = "Non-existent user"
        baseline = results[baseline_label]["med"]

        leaks = 0
        for label, data in results.items():
            if label == baseline_label:
                continue
            delta = abs(data["med"] - baseline)
            if delta > threshold_ms:
                self.log(
                    f"TIMING LEAK — '{label}' is {delta:.1f}ms {'slower' if data['med'] > baseline else 'faster'} "
                    f"than baseline — user enumeration or branching logic exposed", "crit"
                )
                leaks += 1
            else:
                self.log(f"'{label}' delta={delta:.1f}ms — within threshold", "pass")

        self.log("=" * 32)
        if leaks > 0:
            self.log(f"{leaks} timing side-channel(s) detected — constant-time comparison not enforced", "crit")
        else:
            self.log("No significant timing differences — responses appear constant-time", "pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TimeBomb - Timing Attack Detector")
    parser.add_argument("--url", required=True, help="Login/auth endpoint (e.g. http://localhost:3456/api/login)")
    parser.add_argument("--rounds", type=int, default=8, help="Measurement rounds per probe (default: 8)")
    parser.add_argument("--threshold", type=float, default=150.0, help="Timing leak threshold in ms (default: 150)")
    parser.add_argument('-v', '--version', action='version', version='TimeBomb 1.0.0')
    args = parser.parse_args()

    TimeBomb().run(args.url, args.rounds, args.threshold)
