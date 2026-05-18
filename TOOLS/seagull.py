import sys
import os
import argparse
import re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool

_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Seagull(VibeTool):
    def __init__(self):
        super().__init__("Seagull", "Traffic Noise Filter")

    def run(self, log_file, clean_output):
        self.banner()
        self.log(f"Parsing: {log_file}")

        if not os.path.exists(log_file):
            self.log("Log file not found — run traffic through a local proxy first", "fail")
            return

        noise_patterns = [
            r'GET .*\.(css|js|png|jpg|svg|woff2)',
            r'GET /api/health',
            r'POST /api/telemetry',
        ]

        kept = 0
        filtered = 0

        try:
            with open(log_file, "r", encoding="utf-8") as f_in, \
                 open(clean_output, "w", encoding="utf-8") as f_out:
                for line in f_in:
                    if any(re.search(p, line) for p in noise_patterns):
                        filtered += 1
                        continue
                    f_out.write(line)
                    kept += 1

            self.log(f"Filtered {filtered} noise request(s)", "info")
            self.log(f"Isolated {kept} potential attack vector(s) → {clean_output}", "pass")

        except OSError as e:
            self.log(f"Operation failed: {e}", "fail")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seagull - Traffic Noise Filter")
    parser.add_argument("--log", default=os.path.join(_root, "logs", "raw_proxy_traffic.txt"), help="Raw proxy log file")
    parser.add_argument("--out", default=os.path.join(_root, "logs", "clean_attack_surface.txt"), help="Output file for filtered results")
    parser.add_argument('-v', '--version', action='version', version='Seagull 1.0.0')
    args = parser.parse_args()

    Seagull().run(args.log, args.out)
