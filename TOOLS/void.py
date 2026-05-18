import sys
import os
import sqlite3
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool


class Void(VibeTool):
    def __init__(self):
        super().__init__("Void", "Environment Cleaner / Anti-Artifact Tool")

    def run(self, db_path):
        self.banner()
        self.log(f"Initiating purge on: {db_path}")

        if not os.path.exists(db_path):
            self.log(f"Database not found: {db_path}", "warn")
            self.log("Nothing to wipe — environment is already clean", "pass")
            return

        try:
            conn = sqlite3.connect(db_path)
            cur = conn.cursor()

            cur.execute("DELETE FROM users WHERE email LIKE '%@vibe_test.com'")
            users_removed = cur.rowcount
            self.log(f"Purged {users_removed} test user account(s)")

            cur.execute("DELETE FROM comments WHERE content LIKE '%<script>%'")
            payloads_removed = cur.rowcount
            cur.execute("DELETE FROM comments WHERE content LIKE '%OR 1=1%'")
            payloads_removed += cur.rowcount
            self.log(f"Scrubbed {payloads_removed} injected payload(s)")

            cur.execute("DELETE FROM sqlite_sequence WHERE name IN ('users', 'comments')")

            conn.commit()
            conn.close()

            self.log("Environment restored to baseline state", "pass")

        except sqlite3.Error as e:
            self.log(f"Database cleanup failed: {e}", "fail")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Void - Anti-Artifact Environment Cleaner")
    parser.add_argument("--db", required=True, help="Path to target app database (e.g. ../Projects/MyApp/db.sqlite)")
    parser.add_argument('-v', '--version', action='version', version='Void 1.0.0')
    args = parser.parse_args()

    Void().run(args.db)
