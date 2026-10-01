#!/usr/bin/env python3
"""
openapi_scout.py — OpenAPI / Swagger / GraphQL / AI-Agent Schema & Introspection Auditor.

Discovers exposed machine-readable API specifications, parses undocumented routes
into the shared VibeHacking Attack-Surface Graph, and tests GraphQL endpoints for
introspection exposure and batch-query rate-limit bypasses.
"""
import argparse
import json
import os
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool

SCHEMA_PATHS = (
    "/openapi.json",
    "/swagger.json",
    "/api/openapi.json",
    "/api/swagger.json",
    "/v1/openapi.json",
    "/v2/api-docs",
    "/v3/api-docs",
    "/api-docs",
    "/swagger/v1/swagger.json",
    "/.well-known/openapi.json",
    "/.well-known/ai-plugin.json",
    "/.well-known/mcp.json",
    "/actuator",
    "/actuator/mappings",
    "/actuator/env",
)

GRAPHQL_PATHS = (
    "/graphql",
    "/api/graphql",
    "/v1/graphql",
    "/query",
)

INTROSPECTION_QUERY = {"query": "query { __schema { queryType { name } types { name kind } } }"}
BATCH_QUERY = [{"query": "{ __typename }"}, {"query": "{ __typename }"}, {"query": "{ __typename }"}]


class OpenApiScout(VibeTool):
    def __init__(self):
        super().__init__("OpenAPI Scout", "OpenAPI, GraphQL & Shadow-API Schema Auditor")

    def _parse_openapi(self, base_url, path, body):
        try:
            spec = json.loads(body)
        except Exception:
            return 0
        if not isinstance(spec, dict):
            return 0
        if not any(k in spec for k in ("openapi", "swagger", "paths", "schema_version", "tools")):
            return 0

        version = spec.get("openapi") or spec.get("swagger") or spec.get("schema_version") or "unknown"
        paths_obj = spec.get("paths", {})
        discovered = []
        unauthenticated_ops = []

        global_sec = spec.get("security", [])
        for route_path, methods in (paths_obj.items() if isinstance(paths_obj, dict) else []):
            full_route = f"{base_url.rstrip('/')}/{str(route_path).lstrip('/')}"
            discovered.append(full_route)
            if isinstance(methods, dict):
                for verb, op in methods.items():
                    if verb.lower() in ("get", "post", "put", "delete", "patch") and isinstance(op, dict):
                        op_sec = op.get("security", global_sec)
                        if not op_sec and verb.lower() in ("post", "put", "delete", "patch"):
                            unauthenticated_ops.append(f"{verb.upper()} {route_path}")

        self.log(
            f"EXPOSED SCHEMA: {path} (spec={version}, {len(discovered)} path(s) mapped)",
            "hack" if discovered else "warn",
        )
        self.record_finding(
            title=f"Exposed API Schema Specification at {path}",
            severity="medium" if not unauthenticated_ops else "high",
            location=f"{base_url.rstrip('/')}{path}",
            evidence=f"Specification version={version} exposes {len(discovered)} route(s) and {len(unauthenticated_ops)} state-changing op(s) without security definitions.",
            recommendation="Restrict OpenAPI/Swagger and actuator schemas to internal networks or authenticated developer portals in production.",
            cwe="CWE-200",
            owasp="API9:2023-Improper Inventory Management",
        )

        if discovered:
            self.update_surface(endpoints=discovered)
        return 1

    def _audit_graphql(self, base_url):
        issues = 0
        for gpath in GRAPHQL_PATHS:
            target = f"{base_url.rstrip('/')}{gpath}"
            status, body, headers = self.safe_request(target, method="POST", data=INTROSPECTION_QUERY, timeout=6)
            if status == 200 and body and "__schema" in body and "types" in body:
                if self.is_waf_challenge(status, body, headers) or self.is_soft_404(status, body):
                    continue
                self.log(f"GRAPHQL INTROSPECTION ENABLED at {gpath} — full schema downloadable", "crit")
                self.record_finding(
                    title=f"GraphQL Introspection Enabled in Production ({gpath})",
                    severity="high",
                    location=target,
                    evidence="POST query { __schema { types { name } } } returned complete schema type definitions.",
                    recommendation="Disable GraphQL introspection in production environments.",
                    cwe="CWE-200",
                    owasp="API9:2023-Improper Inventory Management",
                )
                self.update_surface(endpoints=[target])
                issues += 1

                # Check batching amplification
                b_status, b_body, _ = self.safe_request(target, method="POST", data=BATCH_QUERY, timeout=6)
                if b_status == 200 and (b_body or "").strip().startswith("[") and "__typename" in (b_body or ""):
                    self.log(f"GRAPHQL ARRAY BATCHING ENABLED at {gpath} — brute-force rate-limit bypass risk", "warn")
                    self.record_finding(
                        title=f"GraphQL Array Batching Allowed ({gpath})",
                        severity="medium",
                        location=target,
                        evidence="Server executed a batched array of 3 GraphQL operations in a single HTTP request.",
                        recommendation="Enforce per-operation rate limits and cap maximum batch size / query depth.",
                        cwe="CWE-770",
                        owasp="API4:2023-Unrestricted Resource Consumption",
                    )
                    issues += 1
        return issues

    def run(self, url):
        self.banner()
        parsed = urllib.parse.urlparse(url)
        base_url = f"{parsed.scheme}://{parsed.netloc}"
        self.log(f"Scouting OpenAPI, Swagger, GraphQL & AI-Agent schemas on: {base_url}")
        self.calibrate_soft_404(base_url)

        found = 0
        for path in SCHEMA_PATHS:
            target = f"{base_url.rstrip('/')}{path}"
            status, body, headers = self.safe_request(target, method="GET", timeout=5)
            if status == 200 and body:
                if self.is_waf_challenge(status, body, headers) or self.is_soft_404(status, body):
                    continue
                found += self._parse_openapi(base_url, path, body)

        found += self._audit_graphql(base_url)

        self.log("=" * 32)
        if found > 0:
            self.log(f"Schema audit complete — {found} exposed schema/GraphQL issue(s) identified", "hack")
        else:
            self.log("No exposed OpenAPI/Swagger specs or unguarded GraphQL introspection found", "pass")
        return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(
        description="OpenAPI Scout - OpenAPI, Swagger, GraphQL & AI-Agent Schema Auditor"
    )
    parser.add_argument("--url", required=True, help="Target base URL (e.g. http://localhost:3456)")
    parser.add_argument("-v", "--version", action="version", version="OpenAPI Scout 1.0.0")
    args = parser.parse_args()

    sys.exit(OpenApiScout().run(args.url))
