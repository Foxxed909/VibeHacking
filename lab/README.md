# VibeHacking isolated lab environments

## Web target
The existing deliberately vulnerable NovaChat fixture is packaged with Docker
Compose. Docker publishes it on the host loopback address only and connects it to
an isolated internal network (no external egress through that network).

    docker compose -f lab/compose.yaml up --build
    python -m vibe_ext web http://127.0.0.1:3456/
    docker compose -f lab/compose.yaml down

Never publish the training fixture on a public interface. This is a standalone
practice target, not a hardened production service.

## Native exploit-development lab
Compile the toy local buffer-overflow fixture with a sanitizer:

    cc -g -O1 -fno-omit-frame-pointer -fsanitize=address \
       -o lab/native/crashme lab/native/crashme.c
    python -m vibe_ext exploit corpus lab/native/corpus --count 20
    python -c "import sys;sys.stdout.buffer.write(b'A'*80+b'\n')" | \
       ./lab/native/crashme 2> crash.log
    python -m vibe_ext exploit triage crash.log

The fixture is local and intentionally flawed. Run it in a disposable VM or
container; avoid using elevated accounts. Compiler and OS instrumentation vary.

## Active Directory assessment lab
Start with a synthetic group-and-ACL edge export; no domain required:

    python -m vibe_ext ad lab/ad/sample_edges.csv --principal alice

For an authorized enterprise export, normalize group and ACL relationships to
source,target,relationship. Supported relationships: member_of, generic_all,
write_dacl, write_owner, add_member. This module analyzes CSV locally and never
authenticates to a domain controller.

For live AD validation, use a separate licensed Windows Server lab, dedicated
test domain, snapshots, and isolated virtual network. Manual confirmation is
required for candidate paths because inheritance and object permissions affect
effective access.

