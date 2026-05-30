"""
Cloud Discovery v8.0
Detects exposed cloud assets: AWS S3, CloudFront, Azure Blob/CDN,
Google Cloud Storage, DigitalOcean Spaces, Backblaze B2.
Validates findings via HTTP probe.
"""
import re
import aiohttp
from core.config import Config
from core.session import fetch, make_session
from core.logger import get_logger, ModuleTimer
from utils.helpers import normalize_url, get_domain

log = get_logger("cloud_discovery")

# (provider, pattern, url_template_or_None)
CLOUD_PATTERNS: list[tuple[str, str]] = [
    ("AWS S3",          r'([a-z0-9][a-z0-9\-\.]{2,62})\.s3\.amazonaws\.com'),
    ("AWS S3",          r's3\.amazonaws\.com/([a-z0-9][a-z0-9\-\.]{2,62})'),
    ("AWS S3",          r's3-[a-z0-9\-]+\.amazonaws\.com/([a-z0-9][a-z0-9\-\.]{2,62})'),
    ("AWS CloudFront",  r'([a-z0-9]+)\.cloudfront\.net'),
    ("Azure Blob",      r'([a-z0-9][a-z0-9\-]{2,62})\.blob\.core\.windows\.net'),
    ("Azure CDN",       r'([a-z0-9][a-z0-9\-]{2,62})\.azureedge\.net'),
    ("Azure Static",    r'([a-z0-9][a-z0-9\-]{2,62})\.z\d+\.web\.core\.windows\.net'),
    ("GCS",             r'([a-z0-9][a-z0-9\-\.]{2,62})\.storage\.googleapis\.com'),
    ("GCS",             r'storage\.googleapis\.com/([a-z0-9][a-z0-9\-\.]{2,62})'),
    ("DO Spaces",       r'([a-z0-9][a-z0-9\-]{2,62})\.[a-z0-9\-]+\.digitaloceanspaces\.com'),
    ("Backblaze B2",    r'([a-z0-9][a-z0-9\-\.]{2,62})\.s3\.us-[a-z0-9\-]+\.backblazeb2\.com'),
    ("Cloudflare R2",   r'([a-z0-9][a-z0-9\-\.]{2,62})\.r2\.cloudflarestorage\.com'),
    ("Fastly",          r'([a-z0-9][a-z0-9\-\.]{2,62})\.global\.ssl\.fastly\.net'),
]

# Status codes that indicate public/misconfigured bucket
EXPOSED_STATUSES = {200, 206}
EXISTS_STATUSES  = {200, 206, 403, 301, 302}


def _extract_cloud_refs(text: str) -> list[tuple[str, str]]:
    """Return list of (provider, full_url_or_hostname) from text."""
    found = []
    for provider, pattern in CLOUD_PATTERNS:
        for m in re.finditer(pattern, text, re.IGNORECASE):
            found.append((provider, m.group(0)))
    return found


async def _probe(url: str, session) -> tuple[int, bool]:
    """Return (status, is_listable). is_listable = bucket listing exposed."""
    if not url.startswith("http"):
        url = "https://" + url
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=8),
                               ssl=False, allow_redirects=True) as r:
            body = await r.text(errors="replace")
            listable = bool(re.search(r'<ListBucketResult|<EnumerationResults|"kind":"storage#objects"', body))
            return r.status, listable
    except Exception:
        return 0, False


async def run(cfg: Config, prior_results: dict | None = None) -> dict:
    base   = normalize_url(cfg.target)
    domain = get_domain(base)
    prior  = prior_results or {}

    with ModuleTimer("cloud_discovery"):
        # Collect text sources to scan
        sources: list[str] = []

        async with make_session(cfg) as session:
            _, html, _ = await fetch(session, base, cfg)
            sources.append(html)

            # JS files
            for f in prior.get("js_analysis", {}).get("findings", []):
                js_url = f.get("file", "")
                if js_url:
                    _, js_text, _ = await fetch(session, js_url, cfg)
                    sources.append(js_text)

        # Also scan subdomain list and endpoint URLs as text
        for sub in prior.get("subdomain", {}).get("subdomains", []):
            sources.append(sub)
        for ep in prior.get("endpoint", {}).get("endpoints", []):
            sources.append(ep.get("url", "") if isinstance(ep, dict) else ep)

        # Extract all cloud references
        seen: set[str] = set()
        raw_findings: list[dict] = []
        for text in sources:
            for provider, ref in _extract_cloud_refs(text):
                if ref not in seen:
                    seen.add(ref)
                    raw_findings.append({"provider": provider, "ref": ref})

        # Probe each finding
        validated: list[dict] = []
        async with aiohttp.ClientSession() as session:
            import asyncio
            sem = asyncio.Semaphore(20)

            async def probe_one(finding: dict):
                ref = finding["ref"]
                url = ref if ref.startswith("http") else f"https://{ref}"
                async with sem:
                    status, listable = await _probe(url, session)
                if status in EXISTS_STATUSES:
                    risk = "critical" if listable else \
                           "high"     if status in EXPOSED_STATUSES else "medium"
                    validated.append({
                        "provider": finding["provider"],
                        "url": url,
                        "status": status,
                        "listable": listable,
                        "risk": risk,
                    })

            await asyncio.gather(*[probe_one(f) for f in raw_findings])

        # Deduplicate by URL
        seen_urls: set[str] = set()
        deduped = []
        for v in validated:
            if v["url"] not in seen_urls:
                seen_urls.add(v["url"])
                deduped.append(v)

        by_provider: dict[str, list] = {}
        for v in deduped:
            by_provider.setdefault(v["provider"], []).append(v)

        log.info(f"[cloud_discovery] {len(deduped)} cloud assets found "
                 f"({sum(1 for v in deduped if v['listable'])} listable)")
        return {
            "total": len(deduped),
            "assets": deduped,
            "by_provider": {k: len(v) for k, v in by_provider.items()},
            "exposed": [v for v in deduped if v["listable"]],
        }
