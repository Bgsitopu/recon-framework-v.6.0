"""
Endpoint discovery:
  - HTML href/src/action extraction
  - robots.txt & sitemap.xml parsing
  - Regex-based API endpoint detection
  - Hidden input fields
"""
import re
from bs4 import BeautifulSoup
from core.config import Config
from core.session import fetch, make_session
from core.logger import get_logger
from utils.helpers import normalize_url, resolve_url, tag_severity

log = get_logger("endpoint")

# Regex patterns for API-style endpoints in JS/HTML
API_PATTERNS = [
    r'["\'](/api/[^\s"\'<>]+)["\']',
    r'["\'](/v\d+/[^\s"\'<>]+)["\']',
    r'["\']([^\s"\'<>]*(?:endpoint|graphql|rest|rpc)[^\s"\'<>]*)["\']',
    r'fetch\(["\']([^"\']+)["\']',
    r'axios\.[a-z]+\(["\']([^"\']+)["\']',
    r'XMLHttpRequest.*open\(["\'][A-Z]+["\'],\s*["\']([^"\']+)["\']',
]


def _parse_robots(text: str, base: str) -> list[str]:
    paths = []
    for line in text.splitlines():
        line = line.strip()
        if line.lower().startswith(("disallow:", "allow:")):
            path = line.split(":", 1)[1].strip()
            if path and path != "/":
                paths.append(resolve_url(base, path))
    return paths


def _parse_sitemap(text: str) -> list[str]:
    return re.findall(r"<loc>([^<]+)</loc>", text)


def _extract_html_links(html: str, base: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    links = set()
    for tag in soup.find_all(["a", "form", "script", "link", "img", "iframe"]):
        for attr in ("href", "src", "action", "data-src"):
            val = tag.get(attr, "")
            if val and not val.startswith(("mailto:", "tel:", "javascript:", "#")):
                links.add(resolve_url(base, val))
    return list(links)


def _extract_api_endpoints(text: str, base: str) -> list[str]:
    found = set()
    for pat in API_PATTERNS:
        for m in re.findall(pat, text, re.IGNORECASE):
            if m.startswith("/"):
                found.add(resolve_url(base, m))
            elif m.startswith("http"):
                found.add(m)
    return list(found)


async def run(cfg: Config) -> dict:
    base = normalize_url(cfg.target)
    log.info(f"[endpoint] Discovering endpoints: {base}")
    endpoints = set()

    async with make_session(cfg) as session:
        # Main page
        _, html, _ = await fetch(session, base, cfg)
        endpoints.update(_extract_html_links(html, base))
        endpoints.update(_extract_api_endpoints(html, base))

        # robots.txt
        _, robots, _ = await fetch(session, f"{base}/robots.txt", cfg)
        endpoints.update(_parse_robots(robots, base))

        # sitemap.xml
        _, sitemap, _ = await fetch(session, f"{base}/sitemap.xml", cfg)
        endpoints.update(_parse_sitemap(sitemap))

    tagged = [
        {"url": ep, "severity": tag_severity(ep, cfg.severity_keywords)}
        for ep in sorted(endpoints) if ep.startswith("http")
    ]
    log.info(f"[endpoint] Found {len(tagged)} endpoints")
    return {"base": base, "endpoints": tagged}
