import sys
import os
import subprocess
import argparse
import re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool


class Vox(VibeTool):
    def __init__(self):
        super().__init__("Vox", "WiFi Intruder Detector")

    def run(self):
        self.banner()
        self.log("Auditing active devices on the local segment...")

        try:
            result = subprocess.run(['arp', '-a'], capture_output=True, text=True, errors='replace')
        except FileNotFoundError:
            self.log("arp command not found", "fail")
            return

        devices = re.findall(
            r"(\d+\.\d+\.\d+\.\d+)\s+([a-f0-9-]+)\s+dynamic",
            result.stdout,
            re.IGNORECASE
        )

        if not devices:
            self.log("No active dynamic devices found in local segment", "warn")
            return

        self.log(f"Found {len(devices)} active device(s)\n")
        print(f"  {'Local IP':<20} | {'MAC Address':<20}")
        print("  " + "-" * 44)

        for ip, mac in devices:
            print(f"  {ip:<20} | {mac.upper():<20}")

        self.log("If you don't recognise a MAC above, someone may be on your network", "warn")
        self.log("Audit complete", "pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vox - WiFi Intruder Detector")
    parser.add_argument('-v', '--version', action='version', version='Vox 1.0.0')
    parser.parse_args()

    Vox().run()
