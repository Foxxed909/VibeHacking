import sys
import os
import shutil
import argparse
import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool

_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class Backer(VibeTool):
    def __init__(self):
        super().__init__("Backer", "Session Data Backup Utility")

    def run(self, source_dir, backup_dir):
        self.banner()
        self.log(f"Backing up: {source_dir} → {backup_dir}")

        if not os.path.exists(source_dir):
            self.log(f"Source directory not found: {source_dir}", "fail")
            return

        os.makedirs(backup_dir, exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_path = os.path.join(backup_dir, f"vibe_backup_{timestamp}")

        try:
            shutil.copytree(source_dir, backup_path)
            self.log(f"Backup complete: {backup_path}", "pass")
        except OSError as e:
            self.log(f"Backup failed: {e}", "fail")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Backer - Session Data Backup Utility")
    parser.add_argument("--source", default=os.path.join(_root, "logs"), help="Directory to back up")
    parser.add_argument("--dest", default=os.path.join(_root, "backups"), help="Destination for backup")
    parser.add_argument('-v', '--version', action='version', version='Backer 1.0.0')
    args = parser.parse_args()

    Backer().run(args.source, args.dest)
