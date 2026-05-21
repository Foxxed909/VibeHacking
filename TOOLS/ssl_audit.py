import sys
import os
import argparse
import ssl
import socket
import datetime
from urllib.parse import urlparse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool

__version__ = "1.0.0"

DEPRECATED_PROTOS = {}
for _attr, _label in (("TLSv1", "TLS 1.0"), ("TLSv1_1", "TLS 1.1")):
    try:
        DEPRECATED_PROTOS[getattr(ssl.TLSVersion, _attr)] = _label
    except AttributeError:
        pass


class SSLAudit(VibeTool):
    def __init__(self):
        super().__init__("SSLAudit", "SSL/TLS Security Auditor")

    def run(self, url):
        self.banner()
        parsed = urlparse(url)
        if parsed.scheme != "https":
            self.log(f"Target is not HTTPS ({url}) — skipping SSL audit", "warn")
            return

        host = parsed.hostname
        port = parsed.port or 443
        self.log(f"Auditing SSL/TLS for {host}:{port}")

        # Default context (validates cert)
        ctx = ssl.create_default_context()
        try:
            with socket.create_connection((host, port), timeout=10) as sock:
                with ctx.wrap_socket(sock, server_hostname=host) as ssock:
                    cert = ssock.getpeercert()
                    cipher = ssock.cipher()
                    proto = ssock.version()

            # Certificate validity
            not_after_str = cert.get("notAfter", "")
            if not_after_str:
                expiry = datetime.datetime.strptime(not_after_str, "%b %d %H:%M:%S %Y %Z")
                days_left = (expiry - datetime.datetime.utcnow()).days
                if days_left < 0:
                    self.log(f"Certificate EXPIRED {abs(days_left)} days ago!", "crit")
                elif days_left < 30:
                    self.log(f"Certificate expires in {days_left} days — renew soon", "warn")
                else:
                    self.log(f"Certificate valid for {days_left} more days", "pass")

            # Issuer — detect self-signed
            subject = dict(x[0] for x in cert.get("subject", []))
            issuer = dict(x[0] for x in cert.get("issuer", []))
            if subject == issuer:
                self.log("Self-signed certificate detected", "crit")
            else:
                self.log(f"Issuer: {issuer.get('organizationName', issuer.get('commonName', 'unknown'))}", "info")

            # TLS version
            self.log(f"TLS version in use: {proto}", "info")

            # Cipher suite
            cipher_name, cipher_proto, cipher_bits = cipher
            self.log(f"Cipher: {cipher_name} ({cipher_bits}-bit)", "info")
            if cipher_bits and cipher_bits < 128:
                self.log(f"Weak cipher strength: {cipher_bits}-bit", "crit")

        except ssl.SSLCertVerificationError as e:
            self.log(f"Certificate verification FAILED: {e}", "crit")
        except ssl.SSLError as e:
            self.log(f"SSL error: {e}", "fail")
        except Exception as e:
            self.log(f"Connection error: {e}", "fail")
            return

        # Test for deprecated TLS versions
        for tls_ver, label in DEPRECATED_PROTOS.items():
            try:
                old_ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                old_ctx.check_hostname = False
                old_ctx.verify_mode = ssl.CERT_NONE
                old_ctx.minimum_version = tls_ver
                old_ctx.maximum_version = tls_ver
                with socket.create_connection((host, port), timeout=5) as sock:
                    with old_ctx.wrap_socket(sock, server_hostname=host):
                        self.log(f"DEPRECATED {label} accepted by server", "crit")
            except ssl.SSLError:
                self.log(f"{label} correctly rejected", "pass")
            except Exception:
                self.log(f"{label} test inconclusive", "info")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SSLAudit - SSL/TLS Security Auditor")
    parser.add_argument("--url", required=True, help="Target HTTPS URL (e.g. https://example.com)")
    parser.add_argument("-v", "--version", action="version", version=f"SSLAudit {__version__}")
    args = parser.parse_args()
    SSLAudit().run(args.url)
