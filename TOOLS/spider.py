import sys
import os
import argparse
import re
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from vibe_core import VibeTool


class Spider(VibeTool):
    def __init__(self):
        super().__init__("Spider", "Attack Surface Crawler")

    def _extract_links(self, base, html):
        links = set()

        href_tags = re.findall(r'href=["\']([^"\'#>]+)["\']', html, re.IGNORECASE)
        src_tags  = re.findall(r'src=["\']([^"\'#>]+)["\']', html, re.IGNORECASE)
        action    = re.findall(r'action=["\']([^"\'#>]+)["\']', html, re.IGNORECASE)
        fetch_api = re.findall(r"""fetch\s*\(\s*['"`]([^'"`]+)['"`]""", html)
        axios_api = re.findall(r"""axios\.\w+\s*\(\s*['"`]([^'"`]+)['"`]""", html)

        for raw in href_tags + src_tags + action + fetch_api + axios_api:
            resolved = urllib.parse.urljoin(base, raw)
            links.add(resolved)

        return links

    def _is_same_origin(self, base, url):
        b = urllib.parse.urlparse(base)
        u = urllib.parse.urlparse(url)
        return b.scheme == u.scheme and b.netloc == u.netloc

    def run(self, url, depth):
        self.banner()
        self.log(f"Crawling from: {url} (depth {depth})")

        visited   = set()
        queue     = [(url, 0)]
        surface   = []
        forms     = []

        while queue:
            current, level = queue.pop(0)

            if current in visited or level > depth:
                continue
            if not self._is_same_origin(url, current):
                continue

            visited.add(current)
            self.log(f"[depth {level}] Crawling: {current}")

            status, body, headers = self.safe_request(current, method='GET')

            content_type = headers.get('Content-Type', '')
            entry = {
                "url": current,
                "status": status,
                "type": content_type.split(';')[0].strip(),
                "depth": level,
            }
            surface.append(entry)

            if status == 200 and 'html' in content_type.lower():
                found_forms = re.findall(
                    r'<form[^>]*action=["\']([^"\']*)["\'][^>]*method=["\'](\w+)["\']',
                    body, re.IGNORECASE
                )
                for action, method in found_forms:
                    resolved = urllib.parse.urljoin(current, action)
                    forms.append((method.upper(), resolved))
                    self.log(f"  Form found: {method.upper()} {resolved}", "hack")

                links = self._extract_links(current, body)
                for link in links:
                    if link not in visited:
                        queue.append((link, level + 1))

        self.log("=" * 32)
        self.log(f"Crawl complete — {len(visited)} URL(s) discovered")

        print()
        print("  ATTACK SURFACE MAP")
        print("  " + "-" * 60)
        for e in sorted(surface, key=lambda x: x['url']):
            flag = "[🔴]" if e['status'] >= 500 else "[🟢]" if e['status'] == 200 else "[🟡]"
            print(f"  {flag} {e['status']}  {e['url']}")

        if forms:
            print()
            print("  FORMS (potential POST endpoints)")
            print("  " + "-" * 60)
            for method, action in sorted(set(forms)):
                print(f"  [📝] {method:<5}  {action}")

        self.log(f"Total unique routes: {len(surface)} | Forms: {len(set(forms))}", "pass")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Spider - Attack Surface Crawler")
    parser.add_argument("--url", required=True, help="Starting URL (e.g. http://localhost:3456)")
    parser.add_argument("--depth", type=int, default=2, help="Crawl depth (default: 2)")
    parser.add_argument('-v', '--version', action='version', version='Spider 1.0.0')
    args = parser.parse_args()

    Spider().run(args.url, args.depth)
