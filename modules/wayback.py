"""Wayback Machine v10.0 — parallel sources, merge+dedup, 24h cache, per-source counts."""
from __future__ import annotations
import asyncio
import json
import time
import aiohttp
from core.config import Config
from core.logger import get_logger
from utils.helpers import get_domain, normalize_url, tag_severity

log = get_logger("wayback")

# Simple in-process 24h cache: domain → (timestamp, result_dict)
_CACHE: dict[str, tuple[float, dict]] = {}
_CACHE_TTL = 86400  # 24 hours


async def _get(session: aiohttp.ClientSession, url: str, timeout: int,
               label: str) -> tuple[int, str]:
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=timeout)) as r:
            return r.status, await r.text()
    except asyncio.TimeoutError:
        log.warning(f"[wayback] {label} timeout")
        return -1, ""
    except Exception as e:
        log.warning(f"[wayback] {label} error: {type(e).__name__}: {e}")
        return -2, ""


async def _fetch_wayback(domain: str, session: aiohttp.ClientSession, timeout: int) -> list[str]:
    url = (f"http://web.archive.org/cdx/search/cdx"
           f"?url=*.{domain}/*&output=text&fl=original&collapse=urlkey&limit=2000")
    for attempt in range(1, 4):
        status, text = await _get(session, url, timeout, f"Wayback attempt {attempt}/3")
        if status == 200 and text.strip():
            urls = [u.strip() for u in text.splitlines() if u.strip().startswith("http")]
            log.info(f"[wayback] Wayback CDX: {len(urls)} URLs")
            return urls
        if status in (429, 503):
            await asyncio.sleep(10 * attempt)
        elif status < 0 and attempt < 3:
            await asyncio.sleep(2 ** attempt)
    return []


async def _fetch_otx(domain: str, session: aiohttp.ClientSession, timeout: int) -> list[str]:
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/url_list?limit=500"
    status, text = await _get(session, url, timeout, "OTX")
    if status != 200 or not text.strip():
        return []
    try:
        data = json.loads(text)
        urls = [e.get("url", "") for e in data.get("url_list", []) if e.get("url")]
        log.info(f"[wayback] OTX: {len(urls)} URLs")
        return urls
    except Exception:
        return []


async def _fetch_commoncrawl(domain: str, session: aiohttp.ClientSession, timeout: int) -> list[str]:
    url = (f"https://index.commoncrawl.org/CC-MAIN-2024-10-index"
           f"?url=*.{domain}&output=text&fl=url&limit=500")
    status, text = await _get(session, url, timeout, "CommonCrawl")
    if status != 200 or not text.strip():
        return []
    urls = [u.strip() for u in text.splitlines() if u.strip().startswith("http")]
    log.info(f"[wayback] CommonCrawl: {len(urls)} URLs")
    return urls


async def run(cfg: Config) -> dict:
    domain = get_domain(normalize_url(cfg.target))
    log.info(f"[wayback] Fetching archived URLs for: {domain}")

    # 24h cache check
    cached = _CACHE.get(domain)
    if cached and (time.time() - cached[0]) < _CACHE_TTL:
        log.info(f"[wayback] Cache hit for {domain}")
        return cached[1]

    connector = aiohttp.TCPConnector(ssl=False)
    async with aiohttp.ClientSession(connector=connector) as session:
        # Run all 3 sources in parallel
        wb_urls, otx_urls, cc_urls = await asyncio.gather(
            _fetch_wayback(domain, session, cfg.timeout),
            _fetch_otx(domain, session, cfg.timeout),
            _fetch_commoncrawl(domain, session, cfg.timeout),
        )

    source_counts = {
        "wayback":     len(wb_urls),
        "otx":         len(otx_urls),
        "commoncrawl": len(cc_urls),
    }

    # Merge + deduplicate preserving order
    seen: set[str] = set()
    merged: list[str] = []
    for u in wb_urls + otx_urls + cc_urls:
        if u.startswith("http") and u not in seen:
            seen.add(u)
            merged.append(u)

    tagged = [{"url": u, "severity": tag_severity(u, cfg.severity_keywords)}
              for u in merged]

    log.info(
        f"[wayback] Wayback={source_counts['wayback']} OTX={source_counts['otx']} "
        f"CommonCrawl={source_counts['commoncrawl']} → unique={len(tagged)}"
    )

    result = {
        "domain":        domain,
        "urls":          tagged,
        "total":         len(tagged),
        "success":       len(tagged) > 0,
        "source_counts": source_counts,
        # legacy fields preserved for backward compat
        "source_used":      "parallel",
        "fallback_sources": [],
        "error_reason":     "" if tagged else "All sources returned no results",
    }

    # Store in 24h cache
    _CACHE[domain] = (time.time(), result)
    return result
