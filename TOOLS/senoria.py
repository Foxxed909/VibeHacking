#!/usr/bin/env python3
"""
senoria.py - Public web asset secret leak auditor.

Senoria is intentionally defensive: it crawls served pages/assets for exposed
API-key-like material, records evidence, and redacts the credential value. It
does not validate, spend, enrich, or try to use any discovered secret.
"""
import argparse
import concurrent.futures
import datetime
import hashlib
import html
import ipaddress
import json
import math
import os
import re
import sys
import threading
import time
import urllib.error
import urllib.parse
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from privacy_guard import privacy_enabled, privacy_user_agent, sanitize_text
from vibe_core import VibeTool


MAX_WORKERS = 80
MAX_PAGES = 600
DEFAULT_WORKERS = 24
DEFAULT_INSTANCES = 1
DEFAULT_TIMEOUT = 10.0
MAX_BODY_BYTES = 1_500_000

TEXT_EXTENSIONS = {
    "",
    ".asp",
    ".aspx",
    ".css",
    ".env",
    ".html",
    ".htm",
    ".js",
    ".json",
    ".jsx",
    ".map",
    ".mjs",
    ".php",
    ".rss",
    ".svelte",
    ".ts",
    ".tsx",
    ".txt",
    ".vue",
    ".webmanifest",
    ".xml",
    ".yaml",
    ".yml",
}

SKIP_EXTENSIONS = {
    ".7z",
    ".avi",
    ".bmp",
    ".br",
    ".eot",
    ".gif",
    ".gz",
    ".ico",
    ".jpeg",
    ".jpg",
    ".mov",
    ".mp3",
    ".mp4",
    ".ogg",
    ".otf",
    ".pdf",
    ".png",
    ".rar",
    ".svg",
    ".tar",
    ".ttf",
    ".wasm",
    ".wav",
    ".webp",
    ".woff",
    ".woff2",
    ".zip",
}

SEED_PATHS = [
    "/",
    "/robots.txt",
    "/sitemap.xml",
    "/manifest.json",
    "/site.webmanifest",
    "/asset-manifest.json",
    "/.well-known/security.txt",
    "/config.js",
    "/config.json",
    "/runtime-config.json",
    "/env.js",
    "/.env",
    "/.env.local",
    "/.env.production",
]

PLACEHOLDER_WORDS = {
    "changeme",
    "demo",
    "example",
    "fake",
    "placeholder",
    "replace",
    "sample",
    "test",
    "todo",
    "your",
}

SECRET_PATTERNS = [
    ("OpenAI API key", re.compile(r"\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{20,}\b"), "high"),
    ("OpenRouter API key", re.compile(r"\bsk-or-[A-Za-z0-9_-]{20,}\b"), "high"),
    ("Stripe live secret key", re.compile(r"\b(?:sk|rk)_live_[0-9A-Za-z]{20,}\b"), "critical"),
    ("Google API key", re.compile(r"\bAIza[0-9A-Za-z_-]{20,}\b"), "high"),
    ("AWS access key id", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b"), "high"),
    ("GitHub token", re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{30,}\b"), "high"),
    ("GitHub fine-grained token", re.compile(r"\bgithub_pat_[A-Za-z0-9_]{20,}_[A-Za-z0-9_]{20,}\b"), "high"),
    ("Slack token", re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{20,}\b"), "high"),
    ("SendGrid API key", re.compile(r"\bSG\.[A-Za-z0-9_-]{16,}\.[A-Za-z0-9_-]{16,}\b"), "high"),
    ("Mailgun API key", re.compile(r"\bkey-[0-9a-fA-F]{32}\b"), "high"),
    ("Twilio secret/key", re.compile(r"\bSK[0-9a-fA-F]{32}\b"), "high"),
    ("Heroku API key", re.compile(r"\bheroku_[0-9a-fA-F]{32}\b"), "high"),
    ("JWT", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b"), "medium"),
    (
        "Private key block",
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----[\s\S]{40,}?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.MULTILINE,
        ),
        "critical",
    ),
]

CONTEXTUAL_SECRET_RE = re.compile(
    r"""(?ix)
    (?P<name>
        [A-Z0-9_.-]*
        (?:api[_-]?key|access[_-]?token|auth[_-]?token|bearer|client[_-]?secret|
           private[_-]?key|secret[_-]?key|secret|token|password|passwd|pwd)
        [A-Z0-9_.-]*
    )
    \s*[:=]\s*
    (?P<quote>["']?)
    (?P<value>[A-Za-z0-9._~+/=$-]{16,240})
    (?P=quote)
    """
)

AUTH_HEADER_RE = re.compile(r"(?i)\bAuthorization\s*[:=]\s*Bearer\s+([A-Za-z0-9._~+/=-]{20,})")
URL_TOKEN_RE = re.compile(r"(?i)(?:[?&](?:api_key|apikey|access_token|token|secret|key)=)([A-Za-z0-9._~+/=-]{16,})")

LINK_PATTERNS = [
    re.compile(r"""(?i)\b(?:href|src|action)\s*=\s*["']([^"'#<>]+)["']"""),
    re.compile(r"""(?i)\b(?:fetch|importScripts)\s*\(\s*["'`]([^"'`]+)["'`]"""),
    re.compile(r"""(?i)\baxios\.\w+\s*\(\s*["'`]([^"'`]+)["'`]"""),
    re.compile(r"""(?i)\bnew\s+URL\s*\(\s*["'`]([^"'`]+)["'`]"""),
    re.compile(r"""(?i)\bfrom\s+["'`]([^"'`]+)["'`]"""),
    re.compile(r"""(?i)\bimport\s*\(\s*["'`]([^"'`]+)["'`]"""),
    re.compile(r"""(?i)url\(\s*["']?([^"')]+)["']?\s*\)"""),
    re.compile(r"""(?i)\bhttps?://[^\s"'<>\\)]+"""),
]

SOURCE_MAP_RE = re.compile(r"(?im)//[#@]\s*sourceMappingURL=([^\s]+)")


def _expand_url_tokens(argv):
    expanded = []
    for arg in argv:
        lowered = arg.lower()
        if lowered.startswith("-url:") or lowered.startswith("--url:"):
            expanded.extend(["--url", arg.split(":", 1)[1]])
        elif lowered.startswith("-url=") or lowered.startswith("--url="):
            expanded.extend(["--url", arg.split("=", 1)[1]])
        else:
            expanded.append(arg)
    return expanded


def _normalize_target(raw):
    value = (raw or "").strip()
    if not value:
        return ""
    if value.lower().startswith("url:"):
        value = value.split(":", 1)[1].strip()
    parsed = urllib.parse.urlparse(value)
    if parsed.scheme in {"http", "https"} and parsed.netloc:
        return value
    if value.startswith("//"):
        return "https:" + value
    host_hint = value.split("/", 1)[0].lower()
    if host_hint.startswith("localhost") or host_hint.startswith("127.") or host_hint.startswith("[::1]"):
        return "http://" + value
    return "https://" + value


def _canonical_url(url):
    parsed = urllib.parse.urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.netloc:
        return ""
    path = parsed.path or "/"
    return urllib.parse.urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), path, parsed.query, ""))


def _origin(url):
    parsed = urllib.parse.urlsplit(url)
    return (parsed.scheme.lower(), parsed.netloc.lower())


def _is_local_or_private(url):
    host = (urllib.parse.urlsplit(url).hostname or "").strip().lower()
    if host in {"localhost", "::1"}:
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_private or ip.is_link_local
    except ValueError:
        return host.endswith(".local") or host.endswith(".localhost")


def _extension(url):
    path = urllib.parse.urlsplit(url).path
    return os.path.splitext(path.lower())[1]


def _looks_textual(url, content_type):
    ctype = (content_type or "").lower()
    if any(item in ctype for item in ("text/", "javascript", "json", "xml", "yaml", "x-www-form-urlencoded")):
        return True
    ext = _extension(url)
    if ext in SKIP_EXTENSIONS:
        return False
    return ext in TEXT_EXTENSIONS


def _shannon_entropy(value):
    if not value:
        return 0.0
    counts = {}
    for char in value:
        counts[char] = counts.get(char, 0) + 1
    total = float(len(value))
    return -sum((count / total) * math.log(count / total, 2) for count in counts.values())


def _is_placeholder(value):
    lowered = value.lower()
    if len(set(value)) <= 4:
        return True
    if any(word in lowered for word in PLACEHOLDER_WORDS):
        return True
    if re.fullmatch(r"[0-9]+", value):
        return True
    return False


def _fingerprint(secret):
    return hashlib.sha256(secret.encode("utf-8", errors="ignore")).hexdigest()[:16]


def _redact(secret):
    compact = " ".join(secret.strip().split())
    if len(compact) <= 10:
        return "<redacted>"
    return f"{compact[:6]}...{compact[-4:]} ({len(compact)} chars)"


def _line_number(text, index):
    return text.count("\n", 0, index) + 1


def _snippet(text, start, end):
    left = max(0, start - 80)
    right = min(len(text), end + 80)
    snippet = text[left:right].replace("\r", " ").replace("\n", " ")
    return re.sub(r"\s+", " ", snippet).strip()


def _utc_stamp():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


class Senoria(VibeTool):
    def __init__(self):
        super().__init__("Senoria", "Public Web Asset Secret Leak Auditor")
        self.findings = []
        self.finding_keys = set()
        self.show_keys = False
        self.visited = set()
        self.queued = set()
        self.lock = threading.Lock()

    def _fetch(self, url, timeout):
        headers = {"Accept": "text/html,application/javascript,application/json,text/plain,*/*;q=0.5"}
        if privacy_enabled():
            headers["User-Agent"] = privacy_user_agent("Senoria")
            headers["DNT"] = "1"
            headers["Sec-GPC"] = "1"
        else:
            headers["User-Agent"] = "Senoria/1.0 authorized-security-test"
        try:
            req = urllib.request.Request(url, headers=headers)
            if _is_local_or_private(url):
                opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))
                response_ctx = opener.open(req, timeout=timeout)
            else:
                response_ctx = urllib.request.urlopen(req, timeout=timeout)
            with response_ctx as response:
                raw = response.read(MAX_BODY_BYTES + 1)
                truncated = len(raw) > MAX_BODY_BYTES
                if truncated:
                    raw = raw[:MAX_BODY_BYTES]
                charset = response.headers.get_content_charset() or "utf-8"
                body = raw.decode(charset, errors="replace")
                return response.getcode(), body, dict(response.headers), truncated, ""
        except urllib.error.HTTPError as exc:
            raw = exc.read(MAX_BODY_BYTES + 1)
            body = raw[:MAX_BODY_BYTES].decode("utf-8", errors="replace")
            return exc.code, body, dict(exc.headers), len(raw) > MAX_BODY_BYTES, ""
        except Exception as exc:
            return 0, "", {}, False, str(exc)

    def _record_value(self, url, text, start, end, secret, kind, severity, confidence, name=""):
        secret = html.unescape(secret).strip().strip('"\'')
        if not secret or _is_placeholder(secret):
            return

        fp = _fingerprint(secret)
        key = (fp, url, start)
        if key in self.finding_keys:
            return

        self.finding_keys.add(key)
        window = text[max(0, start - 160): min(len(text), end + 160)].lower()
        notes = []
        if any(marker in window for marker in ("credit", "quota", "billing", "usage", "balance")):
            notes.append("credit/billing language nearby")
        if name:
            notes.append(f"context={name[:80]}")

        finding = {
            "kind": kind,
            "severity": severity,
            "confidence": confidence,
            "url": sanitize_text(url),
            "line": _line_number(text, start),
            "redacted": _redact(secret),
            "fingerprint": fp,
            "evidence": sanitize_text(_snippet(text, start, end).replace(secret, _redact(secret))),
            "notes": notes,
        }
        if self.show_keys:
            finding["secret"] = secret
        self.findings.append(finding)
        self.log(
            f"{kind} at {url} line {finding['line']} -> {finding['redacted']} fp={fp}",
            "hack" if severity in {"critical", "high"} else "warn",
        )
        if self.show_keys:
            print(f"    [KEY] {kind}: {secret}", flush=True)

    def _record(self, url, text, match, kind, severity, confidence, name=""):
        groups = match.groupdict()
        if groups.get("value"):
            secret = groups["value"]
            start = match.start("value")
            end = match.end("value")
        else:
            secret = match.group(0)
            start = match.start()
            end = match.end()
        self._record_value(url, text, start, end, secret, kind, severity, confidence, name=name)

    def _scan_text(self, url, text):
        for kind, pattern, severity in SECRET_PATTERNS:
            for match in pattern.finditer(text):
                self._record(url, text, match, kind, severity, "pattern")

        for match in CONTEXTUAL_SECRET_RE.finditer(text):
            value = html.unescape(match.group("value")).strip().strip('"\'')
            if _is_placeholder(value):
                continue
            if _shannon_entropy(value) < 3.2 and len(value) < 28:
                continue
            name = match.group("name")
            self._record(url, text, match, "Contextual secret value", "medium", "context+entropy", name=name)

        for match in AUTH_HEADER_RE.finditer(text):
            self._record_value(
                url,
                text,
                match.start(1),
                match.end(1),
                match.group(1),
                "Bearer token",
                "high",
                "authorization-header",
            )

        for match in URL_TOKEN_RE.finditer(text):
            self._record_value(
                url,
                text,
                match.start(1),
                match.end(1),
                match.group(1),
                "Token in URL query",
                "medium",
                "query-parameter",
            )

    def _extract_links(self, current, body, root_origin):
        links = set()
        for pattern in LINK_PATTERNS:
            for raw in pattern.findall(body):
                candidate = raw[0] if isinstance(raw, tuple) else raw
                candidate = html.unescape(candidate).strip()
                if not candidate or candidate.startswith(("data:", "blob:", "mailto:", "tel:", "javascript:")):
                    continue
                resolved = _canonical_url(urllib.parse.urljoin(current, candidate))
                if resolved and _origin(resolved) == root_origin:
                    links.add(resolved)

        for match in SOURCE_MAP_RE.finditer(body):
            resolved = _canonical_url(urllib.parse.urljoin(current, match.group(1).strip()))
            if resolved and _origin(resolved) == root_origin:
                links.add(resolved)

        if _extension(current) in {".js", ".mjs"}:
            map_url = _canonical_url(current + ".map")
            if map_url and _origin(map_url) == root_origin:
                links.add(map_url)

        return links

    def _write_report(self, target, max_pages, workers):
        reports_dir = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "reports")
        os.makedirs(reports_dir, exist_ok=True)
        report_path = os.path.join(reports_dir, "senoria_findings.json")
        payload = {
            "tool": "senoria",
            "generated_at": _utc_stamp(),
            "target": sanitize_text(target),
            "visited": len(self.visited),
            "max_pages": max_pages,
            "workers": workers,
            "raw_secrets_stored": self.show_keys,
            "findings": self.findings,
        }
        with open(report_path, "w", encoding="utf-8") as handle:
            json.dump(payload, handle, indent=2)
        return report_path

    def run(
        self,
        target,
        instances=DEFAULT_INSTANCES,
        workers=DEFAULT_WORKERS,
        max_pages=None,
        timeout=DEFAULT_TIMEOUT,
        show_keys=False,
    ):
        self.banner()
        base_url = _canonical_url(_normalize_target(target))
        if not base_url:
            self.log("No valid scan target supplied.", "fail")
            return 2
        if show_keys and not _is_local_or_private(base_url):
            self.log("--show-keys is local/private only; public/domain scans stay redacted.", "warn")
            show_keys = False
        self.show_keys = bool(show_keys)

        instances = max(1, min(int(instances or 1), 20))
        workers = max(1, min(int(workers or DEFAULT_WORKERS), MAX_WORKERS))
        page_budget = max_pages if max_pages is not None else max(60, instances * 50)
        page_budget = max(1, min(int(page_budget), MAX_PAGES))
        root_origin = _origin(base_url)

        if self.show_keys:
            self.log("Scope: same-origin local/private assets; raw matched keys will be shown in console/report.")
        else:
            self.log("Scope: same-origin public web assets only; discovered secrets are redacted.")
        self.log(f"Target: {base_url}")
        self.log(f"Instances: {instances} | Workers: {workers} | Page budget: {page_budget}")

        seeds = [_canonical_url(base_url)]
        for path in SEED_PATHS:
            seed = _canonical_url(urllib.parse.urljoin(base_url, path))
            if seed not in seeds:
                seeds.append(seed)

        queue = []
        seed_backlog = []
        for index, seed in enumerate(filter(None, seeds)):
            if _origin(seed) != root_origin or _extension(seed) in SKIP_EXTENSIONS:
                continue
            if index == 0:
                self.queued.add(seed)
                queue.append(seed)
            else:
                seed_backlog.append(seed)

        started = time.monotonic()
        with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as executor:
            pending = {}
            while (queue or seed_backlog or pending) and len(self.visited) < page_budget:
                if not queue and not pending and seed_backlog:
                    while seed_backlog and len(queue) < workers and len(self.visited) + len(pending) + len(queue) < page_budget:
                        seed = seed_backlog.pop(0)
                        if seed not in self.queued and seed not in self.visited:
                            self.queued.add(seed)
                            queue.append(seed)

                while queue and len(pending) < workers and len(self.visited) + len(pending) < page_budget:
                    url = queue.pop(0)
                    pending[executor.submit(self._fetch, url, timeout)] = url

                if not pending:
                    break

                done, _not_done = concurrent.futures.wait(
                    pending,
                    timeout=0.2,
                    return_when=concurrent.futures.FIRST_COMPLETED,
                )
                for future in done:
                    url = pending.pop(future)
                    with self.lock:
                        self.visited.add(url)
                    status, body, headers, truncated, error = future.result()
                    if error:
                        self.log(f"[{status}] {url} ({error[:80]})", "warn")
                        continue

                    content_type = headers.get("Content-Type", "")
                    if not _looks_textual(url, content_type):
                        continue

                    if status in (200, 201, 202, 203, 206, 301, 302, 307, 308, 401, 403):
                        self._scan_text(url, body)
                        if truncated:
                            self.log(f"Truncated large response before scanning: {url}", "warn")
                        for link in sorted(self._extract_links(url, body, root_origin), reverse=True):
                            if link not in self.queued and link not in self.visited and _extension(link) not in SKIP_EXTENSIONS:
                                self.queued.add(link)
                                queue.insert(0, link)

        elapsed = time.monotonic() - started
        report_path = self._write_report(base_url, page_budget, workers)
        with open(self.session_file, "w", encoding="utf-8") as handle:
            json.dump(
                {
                    "target": sanitize_text(base_url),
                    "last_senoria": _utc_stamp(),
                    "senoria_findings": len(self.findings),
                },
                handle,
                indent=4,
            )

        self.log("=" * 32)
        if self.findings:
            self.log(f"Potential leaked secret(s): {len(self.findings)} across {len(self.visited)} fetched asset(s)", "hack")
        else:
            self.log(f"No API-key-like leaks found across {len(self.visited)} fetched asset(s)", "pass")
        self.log(f"Report: {report_path}")
        self.log(f"Elapsed: {elapsed:.1f}s")
        return 0


def _choose_target(args):
    if args.url:
        return args.url
    if isinstance(args.scan, str) and args.scan:
        return args.scan
    if args.target:
        return args.target
    return ""


def main(argv=None):
    parser = argparse.ArgumentParser(
        description="Senoria - same-origin public asset scanner for leaked API keys and tokens"
    )
    parser.add_argument("target", nargs="?", help="Target URL/domain (localhost, localhost:3000, or https://site.com)")
    parser.add_argument("--scan", nargs="?", const=True, default=None, help="Scan target URL/domain")
    parser.add_argument("--url", "-u", default="", help="Target URL/domain; also accepts -url:https://site.com")
    parser.add_argument("--i", "-i", "--instances", dest="instances", type=int, default=DEFAULT_INSTANCES,
                        help="Crawl budget multiplier, 1-20 (default: 1)")
    parser.add_argument("-w", "--workers", type=int, default=DEFAULT_WORKERS,
                        help=f"Parallel fetch workers, capped at {MAX_WORKERS} (default: {DEFAULT_WORKERS})")
    parser.add_argument("--max-pages", type=int, default=None,
                        help=f"Maximum same-origin assets/pages to fetch, capped at {MAX_PAGES}")
    parser.add_argument("--timeout", type=float, default=DEFAULT_TIMEOUT, help="Per-request timeout in seconds")
    parser.add_argument(
        "--show-keys",
        action="store_true",
        help="Show and store raw matched keys for localhost/private targets only",
    )
    parser.add_argument("--fail-on-findings", action="store_true", help="Exit 1 when potential leaks are found")
    parser.add_argument("-v", "--version", action="version", version="Senoria 1.0.0")
    args = parser.parse_args(_expand_url_tokens(argv or sys.argv[1:]))

    target = _choose_target(args)
    if not target:
        parser.error("supply a target with --scan <url>, --url <url>, or a positional URL")

    tool = Senoria()
    rc = tool.run(
        target,
        instances=args.instances,
        workers=args.workers,
        max_pages=args.max_pages,
        timeout=args.timeout,
        show_keys=args.show_keys,
    )
    if args.fail_on_findings and tool.findings:
        return 1
    return rc


if __name__ == "__main__":
    sys.exit(main())
