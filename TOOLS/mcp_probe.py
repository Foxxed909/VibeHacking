#!/usr/bin/env python3
"""mcp_probe.py — Model Context Protocol (MCP) server auditor (INTERNAL).

Speaks real MCP (initialize, tools/list, resources/list, prompts/list),
tests the unauth boundary with a fresh opener, flags dangerous exposed tools,
and checks CORS for the DNS-rebinding-class origin reflection bug.

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
            headers.update(auth_headers())
        url = self.base + path
        req = urllib.request.Request(url, data=json.dumps(payload).encode(),
                                     method="POST", headers=headers)
        try:
            with self._anon.open(req, timeout=8) as r:
                return r.getcode(), self._parse(r.read(60000).decode("utf-8", "replace"))
        except urllib.error.HTTPError as e:
            return e.code, self._parse(e.read(60000).decode("utf-8", "replace"))
        except Exception as e:
            return 0, {"_error": str(e)}

    @staticmethod
    def _parse(text):
        text = text.strip()
        if not text:
            return {}
        if text.startswith("{") or text.startswith("["):
            try:
                return json.loads(text)
            except ValueError:
                return {"_raw": text[:400]}
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
            self.log(f"[{tag}] initialize SUCCEEDED with no credentials — "
                     "MCP server answers anonymous clients.", "hack")
            self.findings += 1
        elif not authed:
            self.log(f"[{tag}] initialize rejected (code {init_code}) — auth gate confirmed.", "pass")
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
                if any(d in nm.lower() for d in DANGEROUS):
                    self.log(f"    DANGEROUS {label} reachable ({tag}): {nm!r}",
                             "hack" if not authed else "crit")
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
            self.log("CORS: reflects arbitrary Origin AND allows credentials — "
                     "any website can drive this MCP server as the logged-in victim.", "hack")
            self.findings += 1
        elif aco in ("*", evil):
            self.log(f"CORS: ACAO={aco!r} credentials={acc or 'unset'} — review.", "warn")
        else:
            self.log("CORS: origin not reflected — good.", "pass")

    def run(self, authed):
        self.banner()
        self.log(f"Target: {self.base}")
        if not self._detect():
            self.log("No MCP endpoint found on common paths. Pass full path as --url.", "warn")
            return 1
        self._enumerate(authed=False)
        self._cors()
        if authed:
            if auth_headers():
                self.log("-" * 40)
                self.log("Repeating with captured session (authed surface)…")
                self._enumerate(authed=True)
            else:
                self.log("--authed set but no session configured (VIBE_AUTH_FILE/VIBE_COOKIE).", "warn")
        self.log("=" * 40)
        if self.findings:
            self.log(f"MCP SWEEP COMPLETE — {self.findings} issue(s)", "hack")
        else:
            self.log("No MCP exposure confirmed.", "pass")
        return 0


def main(argv=None):
    p = argparse.ArgumentParser(description="MCP Probe - MCP server auditor")
    p.add_argument("--url", required=True)
    p.add_argument("--authed", action="store_true")
    p.add_argument("-v", "--version", action="version", version="MCP Probe 1.0.0")
    args = p.parse_args(argv)
    return MCPProbe(args.url).run(args.authed)


if __name__ == "__main__":
    raise SystemExit(main())
