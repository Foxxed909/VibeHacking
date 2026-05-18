import sys
import os
import subprocess
import argparse
import re

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool


class VibeRecon(VibeTool):
    def __init__(self):
        super().__init__("Vibe Recon", "WiFi Environment Scout")

    def run(self):
        self.banner()
        self.log("Scanning nearby wireless environments...")

        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
                capture_output=True,
                text=True,
                errors='replace'
            )
        except FileNotFoundError:
            self.log("netsh not found — this tool requires Windows", "fail")
            return

        if result.returncode != 0:
            self.log("WiFi adapter is either OFF or not found", "fail")
            return

        networks = re.findall(
            r"SSID \d+ : (.+)\n\s+Network type\s+: .+\n\s+Authentication\s+: (.+)\n\s+Encryption\s+: .+(?:\n.+){0,5}\n\s+Signal\s+: (\d+)%",
            result.stdout
        )

        if not networks:
            self.log("No WiFi networks found in range", "warn")
            return

        self.log(f"Found {len(networks)} network(s)\n")
        print(f"  {'SSID':<25} | {'Auth':<12} | Signal")
        print("  " + "-" * 52)

        for ssid, auth, signal in networks:
            strength_bar = "█" * (int(signal) // 10) + "░" * (10 - int(signal) // 10)
            print(f"  {ssid[:24]:<25} | {auth:<12} | {signal}% {strength_bar}")

        self.log("Recon complete", "pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Vibe Recon - WiFi Environment Scout")
    parser.add_argument('-v', '--version', action='version', version='Vibe Recon 1.0.0')
    parser.parse_args()

    VibeRecon().run()
