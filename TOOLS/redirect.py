import sys
import os
import argparse
import urllib.parse
import urllib.request
import urllib.error

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool


class Redirect(VibeTool):
    def __init__(self):
        super().__init__("Redirect", "Open Redirect Scanner")

    def run(self, url, canary):
        self.banner()
        self.log(f"Scanning for open redirects on: {url}")
        self.log(f"Canary URL: {canary}")

        params = [
            'next', 'redirect', 'url', 'return', 'returnTo',
            'redirect_uri', 'dest', 'destination', 'go', 'goto',
            'continue', 'forward', 'location', 'target', 'redir',
        ]

        vulns = 0

        for param in params:
            query = urllib.parse.urlencode({param: canary})
            target = f"{url.rstrip('/')}?{query}"

            try:
                opener = urllib.request.build_opener(urllib.request.HTTPRedirectHandler())
                req = urllib.request.Request(target, headers={
                    'User-Agent': 'Mozilla/5.0 VibeHacking/1.0'
                })

                redirected_to = None
                original_open = opener.open

                class TrackingHandler(urllib.request.HTTPRedirectHandler):
                    def redirect_request(self_, req, fp, code, msg, hdrs, newurl):
                        nonlocal redirected_to
                        redirected_to = newurl
                        return None

                tracking_opener = urllib.request.build_opener(TrackingHandler())

                try:
                    with tracking_opener.open(req, timeout=5) as res:
                        body = res.read(512).decode('utf-8', errors='ignore')
                        location = res.url
                except urllib.error.HTTPError as e:
                    location = e.headers.get('Location', '')
                    body = ''

                actual_location = redirected_to or location or ''

                if canary in actual_location:
                    self.log(f"OPEN REDIRECT via ?{param}= — redirects to {actual_location}", "crit")
                    vulns += 1
                elif canary in body:
                    self.log(f"Canary reflected in body via ?{param}= — possible client-side redirect", "warn")
                    vulns += 1
                else:
                    self.log(f"?{param}= — no redirect", "pass")

            except Exception as e:
                self.log(f"?{param}= — error: {e}", "fail")

        self.log("=" * 32)
        if vulns > 0:
            self.log(f"{vulns} open redirect vector(s) found — phishing risk", "crit")
        else:
            self.log("No open redirects found", "pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Redirect - Open Redirect Scanner")
    parser.add_argument("--url", required=True, help="Target base URL (e.g. http://localhost:3456/login)")
    parser.add_argument("--canary", default="https://evil.com", help="External URL to inject as redirect target")
    parser.add_argument('-v', '--version', action='version', version='Redirect 1.0.0')
    args = parser.parse_args()

    Redirect().run(args.url, args.canary)
