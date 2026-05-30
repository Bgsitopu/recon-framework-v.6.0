"""
WHOIS, DNS records, and IP geolocation.
"""
import asyncio
import socket
import dns.resolver
import aiohttp
from core.config import Config
from core.logger import get_logger
from utils.helpers import get_domain, normalize_url

log = get_logger("whois_dns")

DNS_TYPES = ["A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA"]


def _dns_records(domain: str) -> dict:
    records = {}
    for rtype in DNS_TYPES:
        try:
            answers = dns.resolver.resolve(domain, rtype, lifetime=5)
            records[rtype] = [str(r) for r in answers]
        except Exception:
            pass
    return records


async def _geoip(ip: str, session) -> dict:
    try:
        async with session.get(
            f"http://ip-api.com/json/{ip}?fields=country,regionName,city,isp,org,as",
            timeout=aiohttp.ClientTimeout(total=8), ssl=False
        ) as r:
            return await r.json(content_type=None)
    except Exception:
        return {}


async def _whois_api(domain: str, session) -> str:
    try:
        async with session.get(
            f"https://www.whoisxmlapi.com/whoisserver/WhoisService?domainName={domain}&outputFormat=json",
            timeout=aiohttp.ClientTimeout(total=10), ssl=False
        ) as r:
            data = await r.json(content_type=None)
            rec = data.get("WhoisRecord", {})
            return rec.get("rawText", "")[:2000]
    except Exception:
        return ""


async def run(cfg: Config) -> dict:
    domain = get_domain(normalize_url(cfg.target))
    log.info(f"[whois_dns] Querying: {domain}")

    loop = asyncio.get_event_loop()
    dns_records = await loop.run_in_executor(None, _dns_records, domain)

    # Resolve IP
    try:
        ip = socket.gethostbyname(domain)
    except Exception:
        ip = ""

    import aiohttp as _aiohttp
    async with _aiohttp.ClientSession() as session:
        geo, whois_raw = await asyncio.gather(
            _geoip(ip, session) if ip else asyncio.sleep(0, result={}),
            _whois_api(domain, session),
        )

    result = {
        "domain": domain,
        "ip": ip,
        "dns": dns_records,
        "geolocation": geo,
        "whois_raw": whois_raw,
    }
    log.info(f"[whois_dns] IP: {ip} | DNS types: {list(dns_records.keys())}")
    return result
