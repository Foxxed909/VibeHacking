#!/usr/bin/env python3
"""
mcp_probe.py — Model Context Protocol (MCP) server auditor (INTERNAL edition).

MCP servers expose *tools* (functions an AI agent can call) over JSON-RPC. The
bounty-grade bugs are: the server answers **without authentication**, it exposes
**dangerous tools** (shell/file/fetch/db) to whoever can reach it, or its **CORS**
lets any website drive it with the victim's credentials (the web equivalent of
the classic MCP DNS-rebinding bug).

It speaks real MCP: detects the transport/endpoint, then sends `initialize`,
`tools/list`, `resources/list`, `prompts/list`. The **auth-boundary test runs
with NO session on purpose** (a fresh opener, bypassing the toolkit's global
auth) — a valid JSON-RPC *result* there means anyone can call it, which is the
finding. With `--authed` (and a captured session) it repeats to show what your
account can actually reach. Confirms on real JSON-RPC results, not status codes.

    python TOOLS/mcp_probe.py --url https://mcp.your-app.example/
    python TOOLS/mcp_probe.py --url https://mcp.your-app.example/mcp --authed
"""
import argparse
import json
import os
import sys
import urllib.error
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool, auth_headers
from privacy_guard import privacy_user_agent

CANDIDATE_PATHS = ("", "/mcp", "/api/mcp", "/mcp/v1", "/rpc", "/jsonrpc",
                   "/message", "/messages", "/sse", "/stream", "/v1/mcp")

# Tool/resource name fragments that make an exposed capability high-impact.
DANGEROUS = ("exec", "shell", "command", "cmd", "run", "spawn", "subprocess", "eval",
             "file", "read", "write", "delete", "unlink", "fs", "path", "dir", "ls",
             "fetch", "http", "request", "url", "curl", "browse", "download",
             "sql", "query", "db", "database", "mongo", "redis",
             "secret", "key", "token", "env", "config", "credential", "password",
             "ssh", "deploy", "admin", "sudo", "root", "kube", "docker")

PROTO = "2025-06-18"


class MCPProbe(VibeTool):
    def __init__(self, url):
        super().__init__("MCP Probe", "Model Context Protocol Server Auditor")
        self.base = url.rstrip("/")
        self.endpoint = None
        self.findings = 0
        # A fresh opener with NO AuthHandler — used to test the unauth boundary
        # even when the toolkit has a global session configured.
        self._anon = urllib.request.build_opener()

    def _rpc(self, path, method, params, authed):
        payload = {"jsonrpc": "2.0", "id": 1, "method": method}
        if params is not None:
            payload["params"] = params
        headers = {
            "Content-Type": "application/json",
            "Accept": "application/json, text/event-stream",
            "User-Agent": privacy_user_agent("MCP Probe"),
        }
        if authed:
            headers.update(auth_headers())  # explicit session; unauth path sends none
        url = self.base + path
        req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                     method="POST", headers=headers)
        try:
            # Always the fresh no-auth opener; auth is controlled purely by headers
            # above, so the unauth boundary test is never contaminated by a global session.
            with self._anon.open(req, timeout=8) as r:
                return r.getcode(), self._parse(r.read(60000).decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            return e.code, self._parse(e.read(60000).decode("utf-8", "replace"))
        except Exception as e:
            return 0, {"_error": str(e)}

    @staticmethod
    def _parse(text):
        """Handle both plain JSON and SSE (data: {...}) MCP responses."""
        text = text.strip()
        if not text:
            return {}
        if text.startswith("{") or text.startswith("["):
            try:
                return json.loads(text)
            except ValueError:
                return {"_raw": text[:400]}
        # SSE frames
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("data:"):
                chunk = line[5:].strip()
                if chunk.startswith("{"):
                    try:
                        return json.loads(chunk)
                    except ValueError:
                        continue
        return {"_raw": text[:400]}

    @staticmethod
    def _ok(resp):
        """A genuine JSON-RPC success (not an error / auth rejection)."""
        return isinstance(resp, dict) and "result" in resp and "error" not in resp

    def _detect(self):
        for path in CANDIDATE_PATHS:
            code, resp = self._rpc(path, "initialize", {
                "protocolVersion": PROTO, "capabilities": {},
                "clientInfo": {"name": "vh-mcp-probe", "version": "1.0"}}, authed=False)
            is_mcp = isinstance(resp, dict) and (
                "jsonrpc" in resp or "result" in resp
                or (isinstance(resp.get("error"), dict) and "code" in resp["error"]))
            if is_mcp:
                # a JSON-RPC result OR any JSON-RPC-shaped error (incl. a 401
                # "unauthorized") both prove an MCP endpoint lives here
                self.endpoint = path
                srv = (resp.get("result", {}).get("serverInfo", {}) if self._ok(resp) else {})
                self.log(f"MCP endpoint: {self.base + (path or '/')}"
                         + (f"  ({srv.get('name','?')} {srv.get('version','')})" if srv else ""))
                return True
        return False

    def _enumerate(self, authed):
        tag = "AUTHED" if authed else "UNAUTH"
        init_code, init = self._rpc(self.endpoint, "initialize", {
            "protocolVersion": PROTO, "capabilities": {},
            "clientInfo": {"name": "vh-mcp-probe", "version": "1.0"}}, authed)

        if not authed and self._ok(init):
            self.log(f"[{tag}] initialize SUCCEEDED with no credentials — the MCP server "
                     "answers anonymous clients. Enumerating what's exposed…", "hack")
            self.findings += 1
        elif not authed:
            self.log(f"[{tag}] initialize rejected without auth "
                     f"(code {init_code}) — good, there's an auth gate.", "pass")
            return

        for method, key, label in (("tools/list", "tools", "tool"),
                                    ("resources/list", "resources", "resource"),
                                    ("prompts/list", "prompts", "prompt")):
            code, resp = self._rpc(self.endpoint, method, {}, authed)
            if not self._ok(resp):
                continue
            items = resp.get("result", {}).get(key, []) or []
            if not items:
                self.log(f"[{tag}] {method}: none exposed.")
                continue
            names = [it.get("name", "?") for it in items if isinstance(it, dict)]
            self.log(f"[{tag}] {method}: {len(names)} {label}(s) — {', '.join(names[:20])}")
            for nm in names:
                low = nm.lower()
                if any(d in low for d in DANGEROUS):
                    sev = "hack" if not authed else "crit"
                    self.log(f"    ⚠ DANGEROUS {label} reachable ({tag}): {nm!r}", sev)
                    self.findings += 1

    def _cors(self):
        evil = "https://evil.example"
        headers = {"Origin": evil, "Access-Control-Request-Method": "POST",
                   "User-Agent": privacy_user_agent("MCP Probe")}
        req = urllib.request.Request(self.base + self.endpoint, method="OPTIONS", headers=headers)
        try:
            with self._anon.open(req, timeout=8) as r:
                h = dict(r.headers)
        except urllib.error.HTTPError as e:
            h = dict(e.headers)
        except Exception:
            return
        aco = h.get("Access-Control-Allow-Origin", "")
        acc = (h.get("Access-Control-Allow-Credentials", "") or "").lower()
        if aco == evil and acc == "true":
            self.log("CORS: reflects arbitrary Origin AND allows credentials — any website can "
                     "drive this MCP server as the logged-in victim (DNS-rebinding-class).", "hack")
            self.findings += 1
        elif aco in ("*", evil):
            self.log(f"CORS: Access-Control-Allow-Origin={aco!r} (credentials={acc or 'unset'}) — "
                     "review; open origin on an MCP control plane is risky.", "warn")
        else:
            self.log("CORS: origin not reflected — good.", "pass")

    def run(self, authed):
        self.banner()
        self.log(f"Target: {self.base}")
        if not self._detect():
            self.log("No MCP JSON-RPC endpoint found on the common paths. If you know it, pass "
                     "it directly as --url (e.g. .../mcp).", "warn")
            return 1
        self._enumerate(authed=False)
        self._cors()
        if authed:
            if auth_headers():
                self.log("-" * 40)
                self.log("Repeating with your captured session (authed surface)…")
                self._enumerate(authed=True)
            else:
                self.log("--authed set but no session configured (VIBE_AUTH_FILE/VIBE_COOKIE). "
                         "Capture one with helpers/browser/grab_session.js first.", "warn")
        self.log("=" * 40)
        if self.findings:
            self.log(f"MCP SWEEP COMPLETE — {self.findings} issue(s). Confirm each and report with "
                     "the exact JSON-RPC request/response.", "hack")
        else:
            self.log("No MCP exposure confirmed — auth-gated, no dangerous anonymous tools, CORS sane.", "pass")
        return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="MCP Probe - Model Context Protocol server auditor")
    p.add_argument("--url", required=True, help="MCP server base URL (e.g. https://mcp.your-app.example/)")
    p.add_argument("--authed", action="store_true",
                   help="After the unauth boundary test, re-run using your captured session")
    p.add_argument("-v", "--version", action="version", version="MCP Probe 1.0.0")
    args = p.parse_args(argv)
    return MCPProbe(args.url).run(args.authed)


if __name__ == "__main__":
    raise SystemExit(main())
