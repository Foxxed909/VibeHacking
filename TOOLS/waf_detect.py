import sys
import os
import argparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool

__version__ = "1.0.0"

WAF_PAYLOADS = [
    "<script>alert(1)</script>",
    "' OR 1=1--",
    "../../../etc/passwd",
    "{{7*7}}",
    "\x00null",
]

WAF_HEADER_SIGS = {
    "CF-RAY": "Cloudflare",
    "cf-ray": "Cloudflare",
    "X-Sucuri-ID": "Sucuri",
    "x-sucuri-id": "Sucuri",
    "X-CDN": "Generic CDN WAF",
    "x-cdn": "Generic CDN WAF",
    "X-Amzn-Requestid": "AWS WAF",
    "x-amzn-requestid": "AWS WAF",
    "X-Amz-Cf-Id": "AWS CloudFront WAF",
    "x-amz-cf-id": "AWS CloudFront WAF",
    "X-Cache": "Caching Proxy / WAF",
    "x-cache": "Caching Proxy / WAF",
}

WAF_SERVER_SIGS = {
    "cloudflare": "Cloudflare",
    "sucuri": "Sucuri",
    "mod_security": "ModSecurity",
    "modsecurity": "ModSecurity",
    "aws": "AWS WAF",
    "akamai": "Akamai",
    "imperva": "Imperva",
    "incapsula": "Imperva Incapsula",
}

WAF_BLOCK_CODES = {403, 406, 429, 503}


class WAFDetect(VibeTool):
    def __init__(self):
        super().__init__("WAFDetect", "WAF / Firewall Detector")

    def _vendor_from_headers(self, headers):
        for header, vendor in WAF_HEADER_SIGS.items():
            if header in headers:
                return vendor
        server = headers.get("Server", headers.get("server", "")).lower()
        for sig, vendor in WAF_SERVER_SIGS.items():
            if sig in server:
                return vendor
        return None

    def run(self, url):
        self.banner()
        self.log(f"Target: {url}")
        base = url.rstrip("/")

        # Baseline request to compare against
        base_status, _, base_headers = self.safe_request(base)
        vendor = self._vendor_from_headers(base_headers)
        if vendor:
            self.log(f"WAF/CDN detected via headers: {vendor}", "crit")

        blocked = 0
        for payload in WAF_PAYLOADS:
            test_url = f"{base}?q={payload}"
            status, body, headers = self.safe_request(test_url)
            detected = self._vendor_from_headers(headers)
            if status in WAF_BLOCK_CODES:
                label = detected or "Unknown WAF"
                self.log(f"Blocked ({status}) on payload {repr(payload)} — {label}", "warn")
                blocked += 1
            elif detected and detected != vendor:
                self.log(f"WAF header appeared on payload {repr(payload)}: {detected}", "warn")
                blocked += 1
            else:
                self.log(f"Payload passed through ({status}): {repr(payload)}", "info")

        self.log("=" * 32)
        if vendor or blocked > 0:
            label = vendor or "Generic WAF"
            self.log(f"WAF DETECTED — {label}. {blocked}/{len(WAF_PAYLOADS)} payloads blocked.", "crit")
        else:
            self.log("No WAF signatures found — target may be unprotected or WAF is transparent", "pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="WAFDetect - WAF / Firewall Detector")
    parser.add_argument("--url", required=True, help="Target base URL (e.g. http://localhost:3456)")
    parser.add_argument("-v", "--version", action="version", version=f"WAFDetect {__version__}")
    args = parser.parse_args()
    WAFDetect().run(args.url)
