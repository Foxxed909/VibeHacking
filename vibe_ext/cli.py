"""Unified VibeHacking expansion CLI, Python 3.8+."""
import argparse
import json
import sys

from .ad import analyze_edges
from .exploit import generate_corpus, triage_log
from .web import audit_url


def build_parser():
    parser = argparse.ArgumentParser(prog="vhx",
                                     description="VibeHacking expanded security lab modules")
    sub = parser.add_subparsers(dest="module", required=True)

    web = sub.add_parser("web", help="Scoped low-impact web configuration audit")
    web.add_argument("url")
    web.add_argument("--scope", help="JSON scope manifest for non-loopback origins")
    web.add_argument("--timeout", type=float, default=8)

    ad = sub.add_parser("ad", help="Offline AD group and ACL path audit")
    ad.add_argument("edges_csv")
    ad.add_argument("--principal", required=True)
    ad.add_argument("--critical", action="append",
                    help="Critical principal/group (repeat to override defaults)")

    exploit = sub.add_parser("exploit", help="Crash triage and test corpus")
    exploit_sub = exploit.add_subparsers(dest="action", required=True)
    crash = exploit_sub.add_parser("triage")
    crash.add_argument("log_file")
    corpus = exploit_sub.add_parser("corpus")
    corpus.add_argument("output_dir")
    corpus.add_argument("--count", type=int, default=20)

    lab = sub.add_parser("lab", help="Local lab launch guidance")
    lab.add_argument("action", choices=["guide"])
    return parser


def main(argv=None):
    args = build_parser().parse_args(argv)
    try:
        if args.module == "web":
            if not 0 < args.timeout <= 30:
                raise ValueError("timeout must be within (0, 30] seconds")
            result = audit_url(args.url, args.scope, args.timeout)
        elif args.module == "ad":
            result = analyze_edges(args.edges_csv, args.principal, args.critical)
        elif args.module == "exploit":
            if args.action == "triage":
                result = triage_log(args.log_file)
            else:
                result = generate_corpus(args.output_dir, args.count)
        else:
            result = {
                "web_lab": "docker compose -f lab/compose.yaml up --build",
                "web_target": "http://127.0.0.1:3456/",
                "native_lab": "See lab/README.md for ASan build and crash triage",
                "active_directory": "See lab/README.md for offline ACL path simulation",
            }
        print(json.dumps(result, indent=2))
        return 0
    except (OSError, ValueError, json.JSONDecodeError) as exc:
        print("vhx: {}".format(exc), file=sys.stderr)
        return 2


if __name__ == "__main__":
    sys.exit(main())

