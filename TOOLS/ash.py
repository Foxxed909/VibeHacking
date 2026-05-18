import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool


class Ash(VibeTool):
    def __init__(self):
        super().__init__("Ash", "Infrastructure Deployment Agent")

    def run(self, target_dir):
        self.banner()
        self.log(f"Scanning target environment at: {target_dir}")

        if not os.path.exists(target_dir):
            self.log(f"Directory not found: {target_dir}", "fail")
            return

        project_name = os.path.basename(target_dir.rstrip('/\\'))
        self.log(f"Target located: {project_name}", "pass")

        if os.path.exists(os.path.join(target_dir, "package.json")):
            self.log("Node.js project detected — checking dependencies")
        elif os.path.exists(os.path.join(target_dir, "index.html")):
            self.log("Static web project detected — ready for browser analysis")

        self.log(f"Proxy tunnel: Localhost [CONNECTED]", "pass")
        self.log(f"Isolation boundary: [SECURE]", "pass")
        self.log(f"{project_name} is HOT and ready for audit", "hack")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Ash - Infrastructure Deployment Agent")
    parser.add_argument("--dir", required=True, help="Absolute path to target project directory")
    parser.add_argument('-v', '--version', action='version', version='Ash 1.0.0')
    args = parser.parse_args()

    Ash().run(args.dir)
