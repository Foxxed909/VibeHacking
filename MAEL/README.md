# MAEL / VibeHacking Security Divisions

Additive security-research modules for the existing VibeHacking repository.
Designed for authorized assessments, offline directory analysis, controlled
exploit-development practice, and an isolated local range.

No pip packages are required for MAEL. Python 3.9+ is recommended.
The existing VibeHacking command chain remains unchanged.

## 01 WEBSTRIKE — bounded web baseline

Read-only HTTP GET of a single explicitly supplied URL. Audits common
security headers and cookie attributes without printing authentication
tokens or cookie values. Does not crawl, follow redirects, submit forms,
run injection probes, or generate load.

```bash
python TOOLS/mael_suite.py web http://127.0.0.1:3456/
python TOOLS/mael_suite.py web https://owned.example --allow-public
```

For deeper work, use the existing `python vibe.py scan <url>`,
`TOOLS/openapi_scout.py`, `TOOLS/aukdoc.py`, and the rest of
`TOOLS/CATALOG.md`.

## 03 DOMAINOPS — offline Active Directory configuration analysis

Input is an exported/sanitized JSON snapshot. No domain authentication,
LDAP connection, spraying, credential collection, or lateral movement.

```bash
python TOOLS/mael_suite.py ad MAEL/examples/ad_snapshot.json
```

Schema (subset):

```json
{
  "domainPolicy": {"minPwdLength": 14, "lockoutThreshold": 5},
  "users": [{"samAccountName": "service-x", "userAccountControl": 65536,
             "msDS-AllowedToDelegateTo": []}],
  "computers": [{"samAccountName": "WEB01$", "userAccountControl": 4096}]
}
```

Exported ACL control-path analysis also supports `entryPrincipals`, `tierZero`,
and `controlEdges` with `from`, `to`, and `right` fields. Supported
rights are GenericAll, WriteDacl, WriteOwner, AddMember,
ForceChangePassword and DCSync. Paths are hypotheses inferred from
exported permissions, not evidence of successful privilege escalation.

Flags reviewed include password-not-required (0x20), disabled accounts (0x2),
password-never-expires (0x10000), Kerberos preauthentication disabled
(0x400000), unconstrained delegation (0x80000), and protocol transition
(0x1000000). Findings are a prioritization aid, not proof of exploitability.
Collect and redact AD exports using your existing approved inventory process.

## 04 EXPLOITLAB — local crash research

Builds one deliberately unsafe C parser with AddressSanitizer, runs a benign
input then an oversized input in a temporary directory, and returns crash
diagnostics. Requires gcc or clang on Linux/macOS (WSL supported).

```bash
python TOOLS/mael_suite.py crash
```

This is an instrumented learning target, not an exploit payload generator.

## 07 CYBERRANGE — isolated Docker training target

The existing NovaChat practice app runs in a private Docker network,
with the host port published ONLY on loopback. The container has dropped
Linux capabilities, no-new-privileges and resource ceilings.

```bash
docker compose -f MAEL/compose.yaml up --build -d
python TOOLS/mael_suite.py web http://127.0.0.1:3456/
python vibe.py scan http://127.0.0.1:3456/
docker compose -f MAEL/compose.yaml down
```

The lab is intentionally vulnerable. Do not publish the container or
remove its localhost binding. Docker Compose is optional; the existing
`python testapp/app.py` works for host-only local labs.

## Tests

```bash
python -m unittest MAEL.tests -v
python tests/smoke_test.py
```

## Machine-readable output

All three commands emit JSON suitable for reporting and downstream automation.
WEBSTRIKE only retains URL, HTTP status and metadata findings; DOMAINOPS
records account identifiers from your provided snapshot; EXPLOITLAB retains
only sanitizer diagnostics from a generated local process.
