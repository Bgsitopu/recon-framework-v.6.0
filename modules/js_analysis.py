"""
JavaScript analysis:
  - Discover all .js files from HTML
  - Extract: API keys, tokens, secrets, URLs, Firebase config, hardcoded creds
"""
import re
from bs4 import BeautifulSoup
from core.config import Config
from core.session import fetch, make_session
from core.logger import get_logger
from utils.helpers import normalize_url, resolve_url

log = get_logger("js_analysis")

SECRET_PATTERNS = {
    "api_key":        r'(?:api[_-]?key|apikey)\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']',
    "secret":         r'(?:secret|client_secret)\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']',
    "token":          r'(?:token|access_token|auth_token)\s*[=:]\s*["\']([A-Za-z0-9_\-\.]{20,})["\']',
    "password":       r'(?:password|passwd|pwd)\s*[=:]\s*["\']([^"\']{6,})["\']',
    "aws_key":        r'AKIA[0-9A-Z]{16}',
    "aws_secret":     r'(?:aws_secret|aws_secret_access_key)\s*[=:]\s*["\']([A-Za-z0-9/+=]{40})["\']',
    "firebase":       r'firebase[^\{]*\{[^\}]*apiKey\s*:\s*["\']([^"\']+)["\']',
    "google_oauth":   r'[0-9]+-[0-9A-Za-z_]{32}\.apps\.googleusercontent\.com',
    "jwt":            r'eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+',
    "private_key":    r'-----BEGIN (?:RSA |EC )?PRIVATE KEY-----',
    "url_with_creds": r'https?://[^:@\s]+:[^@\s]+@[^\s"\']+',
    "internal_url":   r'https?://(?:localhost|127\.0\.0\.1|10\.\d+\.\d+\.\d+|192\.168\.\d+\.\d+)[^\s"\']*',
}


def _find_js_urls(html: str, base: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    urls = []
    for tag in soup.find_all("script", src=True):
        src = tag["src"]
        if src.endswith(".js") or ".js?" in src:
            urls.append(resolve_url(base, src))
    return list(set(urls))


def _scan_js(content: str) -> dict:
    findings = {}
    for name, pattern in SECRET_PATTERNS.items():
        matches = re.findall(pattern, content, re.IGNORECASE)
        if matches:
            findings[name] = list(set(matches))
    return findings


async def run(cfg: Config) -> dict:
    base = normalize_url(cfg.target)
    log.info(f"[js_analysis] Analyzing JS files: {base}")
    all_findings = []

    async with make_session(cfg) as session:
        _, html, _ = await fetch(session, base, cfg)
        js_urls = _find_js_urls(html, base)
        log.info(f"[js_analysis] Found {len(js_urls)} JS files")

        for js_url in js_urls:
            _, content, _ = await fetch(session, js_url, cfg)
            if not content:
                continue
            findings = _scan_js(content)
            if findings:
                all_findings.append({"file": js_url, "findings": findings})
                log.warning(f"[js_analysis] Secrets in {js_url}: {list(findings.keys())}")

    return {"base": base, "js_files": len(js_urls), "findings": all_findings}
