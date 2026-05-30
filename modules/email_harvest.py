"""
Email Harvester v7.0
- Extract emails from HTML, JS, WHOIS, contact pages
- MX record validation (only keep emails from domains with valid MX)
- Stricter false positive filtering
- Obfuscation deobfuscation
"""
import re
import dns.resolver
from bs4 import BeautifulSoup
from core.config import Config
from core.session import fetch, make_session
from core.logger import get_logger
from utils.helpers import normalize_url, get_domain, resolve_url

log = get_logger("email_harvest")

EMAIL_RE = re.compile(
    r"[a-zA-Z0-9._%+\-]{1,64}@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,10}",
    re.IGNORECASE
)
OBFUSCATED_RE = re.compile(
    r"([a-zA-Z0-9._%+\-]+)\s*[\[\(]?\s*(?:at|@)\s*[\]\)]?\s*"
    r"([a-zA-Z0-9.\-]+)\s*[\[\(]?\s*(?:dot|\.)\s*[\]\)]?\s*([a-zA-Z]{2,10})",
    re.IGNORECASE
)

# Domains/patterns that are almost always false positives
FP_DOMAINS = {
    "example.com", "test.com", "domain.com", "email.com", "yourdomain.com",
    "yoursite.com", "sentry.io", "wixpress.com", "schema.org", "w3.org",
    "jquery.com", "google.com", "facebook.com", "twitter.com", "github.com",
    "cloudflare.com", "amazonaws.com", "microsoft.com", "apple.com",
    "placeholder.com", "sample.com", "foo.com", "bar.com", "baz.com",
}
FP_PATTERNS = [
    r"^[a-z]+@[a-z]+\.(png|jpg|gif|svg|css|js|php|html)$",  # file extensions
    r"^\d+@",           # starts with digits only
    r"@\d+\.\d+",       # IP-like domain
    r"\.{2,}",          # double dots
]

CONTACT_PATHS = ["/contact", "/contact-us", "/about", "/about-us", "/team", "/support", "/help"]

_mx_cache: dict[str, bool] = {}


def _has_mx(domain: str) -> bool:
    if domain in _mx_cache:
        return _mx_cache[domain]
    try:
        dns.resolver.resolve(domain, "MX", lifetime=4)
        _mx_cache[domain] = True
        return True
    except Exception:
        _mx_cache[domain] = False
        return False


def _is_valid_email(email: str, target_domain: str) -> bool:
    email = email.lower().strip()
    if len(email) > 254:
        return False
    # FP domain check
    domain_part = email.split("@", 1)[1] if "@" in email else ""
    if domain_part in FP_DOMAINS:
        return False
    # FP pattern check
    for pat in FP_PATTERNS:
        if re.search(pat, email, re.IGNORECASE):
            return False
    # Must have valid-looking domain
    if not re.match(r"^[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,10}$", domain_part):
        return False
    return True


def _extract_emails(text: str, target_domain: str) -> set[str]:
    emails = set(EMAIL_RE.findall(text))
    for m in OBFUSCATED_RE.finditer(text):
        emails.add(f"{m.group(1)}@{m.group(2)}.{m.group(3)}")
    return {e.lower() for e in emails if _is_valid_email(e, target_domain)}


def _find_js_urls(html: str, base: str) -> list[str]:
    soup = BeautifulSoup(html, "html.parser")
    return list({
        resolve_url(base, tag["src"])
        for tag in soup.find_all("script", src=True)
        if ".js" in tag.get("src", "")
    })


async def run(cfg: Config) -> dict:
    base = normalize_url(cfg.target)
    domain = get_domain(base)
    log.info(f"[email_harvest] Harvesting: {base}")

    all_emails: set[str] = set()
    sources: dict[str, list[str]] = {}

    async with make_session(cfg) as session:
        _, html, _ = await fetch(session, base, cfg)
        found = _extract_emails(html, domain)
        if found:
            sources["main_page"] = list(found)
            all_emails.update(found)

        for path in CONTACT_PATHS:
            _, page_html, _ = await fetch(session, base + path, cfg)
            if page_html:
                found = _extract_emails(page_html, domain)
                if found:
                    sources[path] = list(found)
                    all_emails.update(found)

        js_urls = _find_js_urls(html, base)
        for js_url in js_urls[:8]:
            _, js_content, _ = await fetch(session, js_url, cfg)
            if js_content:
                found = _extract_emails(js_content, domain)
                if found:
                    sources[js_url] = list(found)
                    all_emails.update(found)

        # WHOIS via hackertarget
        try:
            import aiohttp
            async with session.get(
                f"https://api.hackertarget.com/whois/?q={domain}",
                timeout=aiohttp.ClientTimeout(total=10), ssl=False
            ) as r:
                whois_text = await r.text()
            found = _extract_emails(whois_text, domain)
            if found:
                sources["whois"] = list(found)
                all_emails.update(found)
        except Exception:
            pass

    # MX validation: only keep emails whose domain has MX record
    import asyncio as _asyncio
    loop = _asyncio.get_event_loop()
    sem = _asyncio.Semaphore(20)

    async def check_mx(email):
        d = email.split("@")[1]
        async with sem:
            return email, await loop.run_in_executor(None, _has_mx, d)

    mx_results = await _asyncio.gather(*[check_mx(e) for e in all_emails])
    validated = {e for e, ok in mx_results if ok}

    on_domain  = sorted(e for e in validated if domain in e)
    off_domain = sorted(e for e in validated if domain not in e)
    rejected   = len(all_emails) - len(validated)

    log.info(f"[email_harvest] {len(validated)} valid ({len(on_domain)} on-domain, {rejected} rejected by MX)")
    return {
        "target": base,
        "total": len(validated),
        "on_domain": on_domain,
        "off_domain": off_domain,
        "sources": sources,
        "mx_rejected": rejected,
    }
