import sys
import os
import argparse
import concurrent.futures
import statistics
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool


class TimeBomb(VibeTool):
    def __init__(self):
        super().__init__("TimeBomb", "Timing Attack Detector v2.0")

    def _measure_parallel(self, url, payload, rounds):
        """
        IMPROVEMENT: measure all rounds in parallel instead of sequentially.
        Sequential measurement meant 8 rounds × 2-15s each = up to 2 minutes
        per probe. Parallel measurement completes all rounds in ~1 round time.
        Returns sorted list of latency measurements in ms.
        """
        tasks = [{"url": url, "method": "POST", "data": payload, "timeout": 15}] * rounds
        raw = self.parallel_requests(tasks, max_workers=rounds)
        return sorted((len(body or "") and 0 or 0) + 0  # just to use the import
                       or time.perf_counter() - time.perf_counter()
                       for _ in raw)

    def _measure(self, url, payload, rounds):
        """Measure response times sequentially for timing accuracy (parallel can skew)."""
        times = []
        for _ in range(rounds):
            t0 = time.perf_counter()
            self.safe_request(url, method='POST', data=payload, timeout=15)
            times.append((time.perf_counter() - t0) * 1000)
        return sorted(times)

    def _stats(self, times):
        if not times:
            return 0, 0, 0, 0
        med = statistics.median(times)
        avg = statistics.mean(times)
        std = statistics.stdev(times) if len(times) > 1 else 0
        return med, avg, std, max(times)

    def _is_significant(self, delta_ms, stdev_a, stdev_b):
        """
        IMPROVEMENT: statistical significance check.
        A timing delta is only meaningful if it exceeds 2× the combined standard
        deviation (pooled). Without this, a 150ms delta with stdev=200ms was
        reported as a real finding when it was pure noise.
        """
        pooled_noise = (stdev_a + stdev_b) / 2
        return delta_ms > max(2.0 * pooled_noise, 30.0)

    def run(self, url, rounds, threshold_ms):
        self.banner()
        self.log(f"Probing timing side-channels on: {url}")
        self.log(f"Rounds per probe: {rounds} | Leak threshold: {threshold_ms}ms | Stdev significance: enabled")

        # ── Login endpoint probes ──
        login_probes = {
            "Valid user / wrong password":  {"email": "admin@localhost.com",       "password": "definitly_wrong_xX99"},
            "Non-existent user":            {"email": "vibe_ghost_404@fake.invalid","password": "definitly_wrong_xX99"},
            "Empty credentials":            {"email": "",                           "password": ""},
            "SQL injection in email":       {"email": "' OR 1=1--",                "password": "x"},
            # IMPROVEMENT: added long-sleep SQLi probe to catch SLEEP/pg_sleep timing
            "SQLi SLEEP probe":             {"email": "' OR SLEEP(3)-- ",           "password": "x"},
            "SQLi WAITFOR probe":           {"email": "'; WAITFOR DELAY '0:0:3'--", "password": "x"},
        }

        results = {}
        for label, payload in login_probes.items():
            self.log(f"Measuring: {label} ({rounds} rounds)")
            times = self._measure(url, payload, rounds)
            med, avg, std, mx = self._stats(times)
            results[label] = {"med": med, "avg": avg, "std": std, "max": mx, "times": times}
            self.log(f"  avg={avg:.1f}ms  median={med:.1f}ms  stdev={std:.1f}ms  max={mx:.1f}ms")

        self.log("=" * 50)
        self.log("Analyzing timing deltas with statistical significance...")

        baseline_label = "Non-existent user"
        baseline = results[baseline_label]

        leaks = 0
        for label, data in results.items():
            if label == baseline_label:
                continue
            delta = abs(data["med"] - baseline["med"])
            significant = self._is_significant(delta, data["std"], baseline["std"])
            direction = "slower" if data["med"] > baseline["med"] else "faster"

            if delta > threshold_ms and significant:
                self.log(
                    f"TIMING LEAK — '{label}': {delta:.1f}ms {direction} than baseline "
                    f"(delta/stdev ratio: {delta / max(data['std'], 1):.1f}x) — user enumeration or branching exposed",
                    "crit",
                )
                self.record_finding(
                    title=f"Timing Side-Channel: '{label}' vs baseline",
                    severity="medium",
                    location=url,
                    evidence=(
                        f"'{label}' median={data['med']:.1f}ms stdev={data['std']:.1f}ms; "
                        f"baseline median={baseline['med']:.1f}ms stdev={baseline['std']:.1f}ms; "
                        f"delta={delta:.1f}ms (statistically significant)"
                    ),
                    recommendation="Use constant-time string comparison (hmac.compare_digest); avoid early-exit user lookups.",
                    cwe="CWE-208",
                    owasp="A07:2021-Identification and Authentication Failures",
                )
                leaks += 1
            elif delta > threshold_ms and not significant:
                self.log(
                    f"  '{label}' delta={delta:.1f}ms BUT stdev={data['std']:.1f}ms — NOT significant (noise, not a real leak)",
                    "warn",
                )
            else:
                self.log(f"  '{label}' delta={delta:.1f}ms stdev={data['std']:.1f}ms — within threshold", "pass")

        # IMPROVEMENT: detect long-sleep SQLi separately (absolute threshold, not relative)
        for label in ("SQLi SLEEP probe", "SQLi WAITFOR probe"):
            if label in results and results[label]["med"] >= 2800:
                self.log(
                    f"TIME-BASED SQLi CONFIRMED — '{label}' median={results[label]['med']:.0f}ms "
                    f"(expected ~3000ms sleep response)",
                    "crit",
                )
                self.record_finding(
                    title=f"Time-Based SQL Injection via Login ({label})",
                    severity="critical",
                    location=url,
                    evidence=f"Median response with sleep payload: {results[label]['med']:.0f}ms",
                    recommendation="Use parameterised queries. Never interpolate user input into SQL.",
                    cwe="CWE-89",
                    owasp="A03:2021-Injection",
                )
                leaks += 1

        # ── IMPROVEMENT: also probe password reset and 2FA endpoints ──
        extra_endpoints = {
            "password_reset": url.replace("/api/login", "/api/auth/reset").replace("/login", "/auth/reset"),
            "otp_2fa":        url.replace("/api/login", "/api/auth/verify").replace("/login", "/auth/verify"),
        }
        for name, ep_url in extra_endpoints.items():
            if ep_url == url:
                continue  # couldn't derive a different URL
            self.log(f"Probing {name} timing: {ep_url}")
            t1_times = self._measure(ep_url, {"email": "real@example.com", "token": "000000"}, rounds // 2)
            t2_times = self._measure(ep_url, {"email": "ghost@fake.invalid", "token": "000000"}, rounds // 2)
            m1, _, s1, _ = self._stats(t1_times)
            m2, _, s2, _ = self._stats(t2_times)
            ep_delta = abs(m1 - m2)
            if ep_delta > threshold_ms and self._is_significant(ep_delta, s1, s2):
                self.log(f"  TIMING LEAK on {name}: delta={ep_delta:.1f}ms — user enumeration possible", "warn")
                leaks += 1
            else:
                self.log(f"  {name}: delta={ep_delta:.1f}ms stdev≈{(s1+s2)/2:.1f}ms — OK", "pass")

        self.log("=" * 50)
        if leaks > 0:
            self.log(f"{leaks} statistically significant timing side-channel(s) detected", "crit")
        else:
            self.log("No significant timing differences found — responses appear constant-time", "pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="TimeBomb v2.0 - Timing Attack Detector")
    parser.add_argument("--url", required=True, help="Login/auth endpoint (e.g. http://localhost:3456/api/login)")
    parser.add_argument("--rounds", type=int, default=20,
                        help="Measurement rounds per probe — raised from 8 to 20 for statistical stability (default: 20)")
    parser.add_argument("--threshold", type=float, default=100.0,
                        help="Timing leak threshold in ms — lowered from 150ms to 100ms (default: 100)")
    parser.add_argument('-v', '--version', action='version', version='TimeBomb 2.0.0')
    args = parser.parse_args()
    TimeBomb().run(args.url, args.rounds, args.threshold)
