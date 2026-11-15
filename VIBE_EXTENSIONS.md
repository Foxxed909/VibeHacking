# VibeHacking Expanded Labs — v0.1

New self-contained Python standard-library modules extending the existing
web-first VibeHacking toolkit.

## Start here

    python -m vibe_ext --help
    python -m vibe_ext lab guide
    python -m vibe_ext web http://127.0.0.1:3456/
    python -m vibe_ext ad lab/ad/sample_edges.csv --principal alice
    python -m vibe_ext exploit corpus /tmp/vh-corpus --count 12
    python -m vibe_ext exploit triage /path/to/asan.log

Editable installation also registers the vhx command:

    python -m pip install -e .
    vhx --help

## 01: Web offensive assessment
Existing TOOLS/ scanners handle broad black-box testing. The extension adds
a small deterministic baseline with one HTTP GET, no cross-origin redirects,
cookie-value redaction, scope validation, and JSON findings. Check actual
authorization logic and exploit hypotheses with separately approved workflows.

For non-local targets, create a scope.json:

    {"authorized_origins": ["https://your-app.example:443"]}

Then:

    vhx web https://your-app.example/ --scope scope.json

The scope file is an operational access-control input, not proof of legal
authorization; keep your engagement authorization separately.

## 03: Active Directory analysis
Consumes offline CSV with source,target,relationship columns. Produces
transitive membership/ACL paths to critical groups. Use approved directory
exports and verify object inheritance/effective rights before treating ACL
hypotheses as confirmed findings.

## 04: Exploit development
Supports compiler-sanitizer crash triage, stable deduplication signatures,
top-frame extraction and deterministic local fuzz-seed generation. Includes
a deliberately vulnerable C fixture in lab/native/crashme.c.

## 07: Pentest lab
Docker Compose packages the existing NovaChat training target onto localhost
with an isolated Docker network. Lab/README.md covers native and AD exercises.

## Quality gates
    python -m unittest discover -s tests -p 'test_vibe_ext.py'
    python tests/smoke_test.py

This is a starter extension, not a finished AD live agent, full fuzzing engine,
or automated exploitation platform. Existing tools remain unchanged.

