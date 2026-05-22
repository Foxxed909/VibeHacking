import sys
import os
import argparse
import time
import statistics

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from live_core import LiveTool

__version__ = "1.0.0"


class LiveTimeBomb(LiveTool):
    def __init__(self, delay=0.5):
        super().__init__("LiveTimeBomb", "Remote Timing Attack Detector", delay=delay)

    def _measure(self, url, payload, rounds, field_email, field_pass, timeout):
        times = []
        for _ in range(rounds):
            start = time.perf_counter()
            self.safe_request(url, method='POST',
                              data={field_email: payload[0], field_pass: payload[1]},
                              timeout=timeout)
            times.append((time.perf_counter() - start) * 1000)
        return times

    def run(self, url, known_email, rounds, threshold_ms, field_email, field_pass, timeout):
        self.banner()
        self.log(f"Target: {url}")
        self.log(f"Rounds per probe: {rounds} | Threshold: {threshold_ms}ms")
        self.log(f"Form fields: {field_email} / {field_pass}")

        probes = {
            "Known user / wrong password":  (known_email,                    "vibe_wrong_pass_xX99!"),
            "Non-existent user":            ("vibe_ghost_404@fake.invalid",  "vibe_wrong_pass_xX99!"),
            "Empty credentials":            ("",                              ""),
            "SQLi in email field":          ("' OR 1=1--",                   "x"),
        }

        results = {}
        for label, (email, password) in probes.items():
            self.log(f"Measuring: {label} ({rounds} rounds)...")
            times = self._measure(url, (email, password), rounds, field_email, field_pass, timeout)
            avg = statistics.mean(times)
            med = statistics.median(times)
            results[label] = {"avg": avg, "med": med}
            self.log(f"  avg={avg:.1f}ms  median={med:.1f}ms  "
                     f"min={min(times):.1f}ms  max={max(times):.1f}ms", "info")

        self.log("=" * 32)
        baseline = results["Non-existent user"]["med"]
        leaks = 0
        for label, data in results.items():
            if label == "Non-existent user":
                continue
            delta = abs(data["med"] - baseline)
            direction = "slower" if data["med"] > baseline else "faster"
            if delta > threshold_ms:
                self.log(
                    f"TIMING LEAK — '{label}' is {delta:.1f}ms {direction} than baseline"
                    f" — user enumeration or branching logic exposed", "crit"
                )
                leaks += 1
            else:
                self.log(f"'{label}' delta={delta:.1f}ms — within threshold", "pass")

        self.log("=" * 32)
        if leaks:
            self.log(f"{leaks} timing side-channel(s) detected", "crit")
        else:
            self.log("No significant timing differences detected", "pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="LiveTimeBomb - Remote Timing Attack Detector")
    parser.add_argument("--url", required=True, help="Login/auth endpoint (e.g. https://app.com/api/login)")
    parser.add_argument("--email", required=True, help="A real known email address on the target app")
    parser.add_argument("--field-email", default="email", help="JSON field name for email (default: email)")
    parser.add_argument("--field-pass", default="password", help="JSON field name for password (default: password)")
    parser.add_argument("--rounds", type=int, default=6, help="Measurement rounds per probe (default: 6)")
    parser.add_argument("--threshold", type=float, default=150.0, help="Leak threshold in ms (default: 150)")
    parser.add_argument("--delay", type=float, default=0.5, help="Seconds between requests (default: 0.5)")
    parser.add_argument("--timeout", type=float, default=10.0, help="Per-request timeout in seconds (default: 10)")
    parser.add_argument("--no-verify", action="store_true", help="Skip SSL certificate verification")
    parser.add_argument("-v", "--version", action="version", version=f"LiveTimeBomb {__version__}")
    args = parser.parse_args()

    tool = LiveTimeBomb(delay=args.delay)
    tool.verify_ssl = not args.no_verify
    tool.run(args.url, args.email, args.rounds, args.threshold,
             args.field_email, args.field_pass, args.timeout)
