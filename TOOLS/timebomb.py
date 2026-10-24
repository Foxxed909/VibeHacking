import sys, os, argparse, statistics, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool


class TimeBomb(VibeTool):
    def __init__(self):
        super().__init__("TimeBomb", "Timing Attack Detector v2.0")

    def _measure(self, url, payload, rounds):
        """Sequential measurement for timing accuracy."""
        times = []
        for _ in range(rounds):
            t0 = time.perf_counter()
            self.safe_request(url, method='POST', data=payload, timeout=15)
            times.append((time.perf_counter() - t0) * 1000)
        return sorted(times)

    def _stats(self, times):
        if not times: return 0, 0, 0, 0
        return statistics.median(times), statistics.mean(times), statistics.stdev(times) if len(times) > 1 else 0, max(times)

    def _is_significant(self, delta_ms, stdev_a, stdev_b):
        """
        FIX: statistical significance gate — a timing delta is only a real finding
        if it exceeds 2x the pooled standard deviation. Without this, a 151ms delta
        with stdev=200ms was being reported as a confirmed leak when it was pure noise.
        """
        pooled = (stdev_a + stdev_b) / 2
        return delta_ms > max(2.0 * pooled, 30.0)

    def run(self, url, rounds, threshold_ms):
        self.banner()
        self.log(f"Probing timing side-channels on: {url}")
        self.log(f"Rounds: {rounds} | Threshold: {threshold_ms}ms | Significance: 2σ required")

        probes = {
            "Valid user / wrong password":  {"email": "admin@localhost.com",         "password": "definitly_wrong_xX99"},
            "Non-existent user":            {"email": "vibe_ghost_404@fake.invalid",  "password": "definitly_wrong_xX99"},
            "Empty credentials":            {"email": "",                             "password": ""},
            "SQL injection email":          {"email": "' OR 1=1--",                  "password": "x"},
            "SQLi SLEEP(3) probe":          {"email": "' OR SLEEP(3)--",              "password": "x"},
            "SQLi WAITFOR probe":           {"email": "'; WAITFOR DELAY '0:0:3'--",   "password": "x"},
        }

        results = {}
        for label, payload in probes.items():
            self.log(f"Measuring: {label} ({rounds} rounds)")
            times = self._measure(url, payload, rounds)
            med, avg, std, mx = self._stats(times)
            results[label] = {"med": med, "avg": avg, "std": std, "max": mx}
            self.log(f"  avg={avg:.1f}ms median={med:.1f}ms \u03c3={std:.1f}ms max={mx:.1f}ms")

        self.log("=" * 50)
        baseline = results["Non-existent user"]
        leaks = 0

        for label, data in results.items():
            if label == "Non-existent user": continue
            delta = abs(data["med"] - baseline["med"])
            sig   = self._is_significant(delta, data["std"], baseline["std"])
            direction = "slower" if data["med"] > baseline["med"] else "faster"

            if delta > threshold_ms and sig:
                self.log(f"TIMING LEAK — '{label}': {delta:.1f}ms {direction} than baseline (\u03b4/\u03c3={delta/max(data['std'],1):.1f}x)", "crit")
                self.record_finding(
                    title=f"Timing Side-Channel: '{label}'",
                    severity="medium", location=url,
                    evidence=f"'{label}' median={data['med']:.1f}ms \u03c3={data['std']:.1f}ms | baseline median={baseline['med']:.1f}ms \u03c3={baseline['std']:.1f}ms | delta={delta:.1f}ms (significant)",
                    recommendation="Use constant-time comparison (hmac.compare_digest). Avoid early-exit user lookups.",
                    cwe="CWE-208", owasp="A07:2021-Identification and Authentication Failures",
                )
                leaks += 1
            elif delta > threshold_ms:
                self.log(f"  '{label}' delta={delta:.1f}ms but \u03c3={data['std']:.1f}ms \u2014 NOT significant (noise)", "warn")
            else:
                self.log(f"  '{label}' delta={delta:.1f}ms \u03c3={data['std']:.1f}ms \u2014 within threshold", "pass")

        # Absolute threshold for SQLi time-based
        for label in ("SQLi SLEEP(3) probe", "SQLi WAITFOR probe"):
            if label in results and results[label]["med"] >= 2800:
                self.log(f"TIME-BASED SQLi CONFIRMED \u2014 '{label}' median={results[label]['med']:.0f}ms", "crit")
                self.record_finding(title=f"Time-Based SQL Injection ({label})", severity="critical", location=url,
                    evidence=f"Median: {results[label]['med']:.0f}ms with SLEEP payload",
                    recommendation="Use parameterized queries.", cwe="CWE-89", owasp="A03:2021-Injection")
                leaks += 1

        # Probe reset + 2FA
        for name, sub in [("password_reset", "/api/auth/reset"), ("otp_2fa", "/api/auth/verify")]:
            ep = url.replace("/api/login", sub).replace("/login", sub)
            if ep == url: continue
            self.log(f"Probing {name} timing...")
            t1 = self._measure(ep, {"email": "real@example.com", "token": "000000"}, max(4, rounds // 2))
            t2 = self._measure(ep, {"email": "ghost@fake.invalid", "token": "000000"}, max(4, rounds // 2))
            m1, _, s1, _ = self._stats(t1); m2, _, s2, _ = self._stats(t2)
            ep_delta = abs(m1 - m2)
            if ep_delta > threshold_ms and self._is_significant(ep_delta, s1, s2):
                self.log(f"  TIMING LEAK on {name}: delta={ep_delta:.1f}ms", "warn"); leaks += 1
            else:
                self.log(f"  {name}: delta={ep_delta:.1f}ms \u2014 OK", "pass")

        self.log("=" * 50)
        if leaks: self.log(f"{leaks} statistically significant timing side-channel(s) detected", "crit")
        else: self.log("No significant timing differences \u2014 responses appear constant-time", "pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TimeBomb v2.0 \u2014 Timing Attack Detector")
    parser.add_argument("--url", required=True)
    parser.add_argument("--rounds",    type=int,   default=20,    help="Rounds per probe (default: 20, raised from 8)")
    parser.add_argument("--threshold", type=float, default=100.0, help="Threshold ms (default: 100, lowered from 150)")
    parser.add_argument("-v", "--version", action="version", version="TimeBomb 2.0.0")
    args = parser.parse_args()
    TimeBomb().run(args.url, args.rounds, args.threshold)
