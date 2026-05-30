"""
Subdomain enumeration v9.0
- Wildcard DNS detection & false-positive filtering
- Source tagging: crt.sh, hackertarget, dns-brute
- Dedup + resolve validation (A record)
- Reports: total, validated, wildcard-filtered
"""
from __future__ import annotations
import asyncio
import os
import random
import string
import dns.resolver
import aiohttp
from dataclasses import dataclass, field
from core.config import Config
from core.session import make_session
from core.logger import get_logger
from utils.helpers import get_domain

log = get_logger("subdomain")


@dataclass
class SubdomainEntry:
    subdomain: str
    ip: str
    sources: list[str] = field(default_factory=list)
    wildcard_filtered: bool = False


# ── Wildcard detection ────────────────────────────────────────────────────────

def _random_label(n: int = 12) -> str:
    return "".join(random.choices(string.ascii_lowercase, k=n))


def _resolve_a(host: str) -> str | None:
    try:
        answers = dns.resolver.resolve(host, "A", lifetime=3)
        return str(answers[0])
    except Exception:
        return None


def _resolve_cname(host: str) -> str | None:
    try:
        answers = dns.resolver.resolve(host, "CNAME", lifetime=3)
        return str(answers[0])
    except Exception:
        return None


def _detect_wildcard(domain: str, probes: int = 5) -> tuple[bool, set[str]]:
    """
    Generate `probes` random subdomains. If ≥3 resolve, wildcard is active.
    Returns (is_wildcard, set_of_wildcard_ips).
    """
    wildcard_ips: set[str] = set()
    resolved_count = 0
    for _ in range(probes):
        label = _random_label()
        ip = _resolve_a(f"{label}.{domain}")
        if ip:
            resolved_count += 1
            wildcard_ips.add(ip)
    is_wildcard = resolved_count >= 3
    return is_wildcard, wildcard_ips


# ── Passive sources ───────────────────────────────────────────────────────────

async def _crtsh(domain: str, session: aiohttp.ClientSession) -> list[str]:
    url = f"https://crt.sh/?q=%.{domain}&output=json"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=20), ssl=False) as r:
            data = await r.json(content_type=None)
            return list({e["name_value"].strip().lstrip("*.") for e in data if "name_value" in e})
    except Exception:
        return []


async def _hackertarget(domain: str, session: aiohttp.ClientSession) -> list[str]:
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15), ssl=False) as r:
            text = await r.text()
            return [line.split(",")[0] for line in text.splitlines() if "," in line]
    except Exception:
        return []


async def _otx(domain: str, session: aiohttp.ClientSession) -> list[str]:
    url = f"https://otx.alienvault.com/api/v1/indicators/domain/{domain}/passive_dns"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=15), ssl=False) as r:
            data = await r.json(content_type=None)
            return list({e["hostname"] for e in data.get("passive_dns", [])
                         if e.get("hostname", "").endswith(f".{domain}")})
    except Exception:
        return []


async def _bufferover(domain: str, session: aiohttp.ClientSession) -> list[str]:
    url = f"https://dns.bufferover.run/dns?q=.{domain}"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as r:
            data = await r.json(content_type=None)
            results = data.get("FDNS_A", []) or []
            return list({e.split(",")[1] for e in results if "," in e
                         and e.split(",")[1].endswith(f".{domain}")})
    except Exception:
        return []


async def _threatcrowd(domain: str, session: aiohttp.ClientSession) -> list[str]:
    url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as r:
            data = await r.json(content_type=None)
            return [s for s in data.get("subdomains", [])
                    if isinstance(s, str) and s.endswith(f".{domain}")]
    except Exception:
        return []


async def _rapiddns(domain: str, session: aiohttp.ClientSession) -> list[str]:
    url = f"https://rapiddns.io/subdomain/{domain}?full=1"
    try:
        async with session.get(url, timeout=aiohttp.ClientTimeout(total=10), ssl=False) as r:
            text = await r.text()
            import re
            return list(set(re.findall(rf'[\w\-\.]+\.{re.escape(domain)}', text)))
    except Exception:
        return []


# ── DNS brute-force ───────────────────────────────────────────────────────────

async def _brute(domain: str, wordlist: str) -> list[str]:
    if not os.path.exists(wordlist):
        return []
    with open(wordlist) as f:
        words = [w.strip() for w in f if w.strip()]

    found: list[str] = []
    loop = asyncio.get_event_loop()
    sem = asyncio.Semaphore(80)

    async def check(word: str) -> None:
        sub = f"{word}.{domain}"
        async with sem:
            ip = await loop.run_in_executor(None, _resolve_a, sub)
            if ip:
                found.append(sub)

    await asyncio.gather(*[check(w) for w in words])
    return found


# ── Validation ────────────────────────────────────────────────────────────────

async def _resolve_all(candidates: dict[str, set]) -> dict[str, str | None]:
    """Resolve all candidate subdomains concurrently."""
    loop = asyncio.get_event_loop()
    sem = asyncio.Semaphore(60)
    resolved: dict[str, str | None] = {}

    async def resolve_one(sub: str) -> None:
        async with sem:
            resolved[sub] = await loop.run_in_executor(None, _resolve_a, sub)

    await asyncio.gather(*[resolve_one(s) for s in candidates])
    return resolved


# ── Main ──────────────────────────────────────────────────────────────────────

async def run(cfg: Config) -> dict:
    domain = get_domain(cfg.target)
    log.info(f"[subdomain] Enumerating: {domain}")

    # Step 1: Wildcard detection (blocking, fast)
    loop = asyncio.get_event_loop()
    is_wildcard, wildcard_ips = await loop.run_in_executor(None, _detect_wildcard, domain)
    if is_wildcard:
        log.warning(f"[subdomain] Wildcard DNS detected! IPs: {wildcard_ips}")

    # Step 2: Passive enumeration — all sources in parallel
    async with make_session(cfg) as session:
        crtsh_list, ht_list, otx_list, buf_list, tc_list, rd_list = await asyncio.gather(
            _crtsh(domain, session),
            _hackertarget(domain, session),
            _otx(domain, session),
            _bufferover(domain, session),
            _threatcrowd(domain, session),
            _rapiddns(domain, session),
        )

    # Step 3: DNS brute-force
    brute_list = await _brute(domain, cfg.dns_wordlist)

    # Step 4: Merge with source tags
    tagged: dict[str, set] = {}
    for s in crtsh_list:
        tagged.setdefault(s, set()).add("crt.sh")
    for s in ht_list:
        tagged.setdefault(s, set()).add("hackertarget")
    for s in otx_list:
        tagged.setdefault(s, set()).add("otx")
    for s in buf_list:
        tagged.setdefault(s, set()).add("bufferover")
    for s in tc_list:
        tagged.setdefault(s, set()).add("threatcrowd")
    for s in rd_list:
        tagged.setdefault(s, set()).add("rapiddns")
    for s in brute_list:
        tagged.setdefault(s, set()).add("dns-brute")

    # Step 5: Resolve all
    resolved = await _resolve_all(tagged)

    # Step 6: Build entries, filter wildcards
    entries: list[dict] = []
    wildcard_filtered: list[str] = []
    total_discovered = len(tagged)

    for sub, sources in sorted(tagged.items()):
        ip = resolved.get(sub)
        if not ip:
            continue
        # Wildcard filter: skip if IP matches a known wildcard IP
        if is_wildcard and ip in wildcard_ips:
            wildcard_filtered.append(sub)
            log.debug(f"[subdomain] Wildcard-filtered: {sub} → {ip}")
            continue
        entries.append({
            "subdomain": sub,
            "ip": ip,
            "sources": sorted(sources),
            "wildcard_filtered": False,
        })

    subdomains = [e["subdomain"] for e in entries]

    log.info(
        f"[subdomain] total={total_discovered} validated={len(entries)} "
        f"wildcard_filtered={len(wildcard_filtered)} wildcard_dns={is_wildcard}"
    )
    return {
        "domain": domain,
        "subdomains": subdomains,
        "entries": entries,
        "total_discovered": total_discovered,
        "total_validated": len(entries),
        "wildcard_filtered_count": len(wildcard_filtered),
        "wildcard_filtered": wildcard_filtered,
        "wildcard_dns": is_wildcard,
        "wildcard_ips": sorted(wildcard_ips),
        "sources": {
            "crt.sh":      len(crtsh_list),
            "hackertarget":len(ht_list),
            "otx":         len(otx_list),
            "bufferover":  len(buf_list),
            "threatcrowd": len(tc_list),
            "rapiddns":    len(rd_list),
            "dns-brute":   len(brute_list),
        },
    }
