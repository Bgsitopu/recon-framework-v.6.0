"""Shared utility helpers."""
import re
import tldextract
from urllib.parse import urljoin, urlparse


def normalize_url(url: str) -> str:
    if not url.startswith(("http://", "https://")):
        url = "https://" + url
    return url.rstrip("/")


def get_domain(url: str) -> str:
    ext = tldextract.extract(url)
    return f"{ext.domain}.{ext.suffix}" if ext.suffix else ext.domain


def get_base_url(url: str) -> str:
    p = urlparse(normalize_url(url))
    return f"{p.scheme}://{p.netloc}"


def resolve_url(base: str, path: str) -> str:
    return urljoin(base, path)


def extract_urls_from_text(text: str, base_url: str = "") -> list[str]:
    """Extract all href/src/action URLs from raw text."""
    patterns = [
        r'href=["\']([^"\']+)["\']',
        r'src=["\']([^"\']+)["\']',
        r'action=["\']([^"\']+)["\']',
        r'url\(["\']?([^"\')\s]+)["\']?\)',
    ]
    urls = []
    for pat in patterns:
        for match in re.findall(pat, text, re.IGNORECASE):
            if base_url:
                match = resolve_url(base_url, match)
            urls.append(match)
    return list(set(urls))


def tag_severity(path: str, severity_map: dict) -> str:
    path_lower = path.lower()
    for level in ("critical", "high", "medium", "low"):
        for kw in severity_map.get(level, []):
            if kw in path_lower:
                return level
    return "info"
