"""
core/validator.py v9.1 — P4: False-positive reduction engine.
Validates: login panels, SSL findings, WAF findings, vuln findings, cloud assets, params.
Only confirmed findings labeled 'confirmed'; unverified → 'suspected' or 'informational'.
"""
from __future__ import annotations
import asyncio, re
import dns.resolver
import aiohttp
from core.config import Config
from core.logger import get_logger

log = get_logger("validator")


def _resolve_a(host: str) -> str | None:
    try:
        return str(dns.resolver.resolve(host, "A", lifetime=3)[0])
    except Exception:
        return None

def _has_login_form(html: str) -> bool:
    return bool(re.search(r'<input[^>]+type=["\']password["\']', html, re.IGNORECASE))

async def _fetch(session: aiohttp.ClientSession, url: str, timeout: int) -> tuple[int, str]:
    try:
        async with session.get(url, ssl=False, allow_redirects=True,
                               timeout=aiohttp.ClientTimeout(total=timeout),
                               headers={"User-Agent": "Mozilla/5.0 ReconBot/9.1"}) as r:
            return r.status, await r.text(errors="replace")
    except Exception:
        return 0, ""


async def validate_login_panels(panels: list[dict], cfg: Config) -> list[dict]:
    """Re-verify each panel. Remove unreachable; label form presence."""
    if not panels:
        return panels
    connector = aiohttp.TCPConnector(ssl=False, limit=20)
    async with aiohttp.ClientSession(connector=connector) as session:
        sem = asyncio.Semaphore(10)
        async def check(p: dict) -> dict | None:
            async with sem:
                status, html = await _fetch(session, p["url"], cfg.timeout)
                if status not in (200, 401, 403):
                    log.debug(f"[validator] Panel removed (HTTP {status}): {p['url']}")
                    return None
                return {**p, "has_login_form": _has_login_form(html),
                        "verified": True, "validation_status": "confirmed"}
        results = await asyncio.gather(*[check(p) for p in panels])
    verified = [r for r in results if r]
    log.info(f"[validator] Login panels: {len(verified)}/{len(panels)} verified, "
             f"{len(panels)-len(verified)} removed as FP")
    return verified


async def validate_subdomains(entries: list[dict]) -> list[dict]:
    """Re-resolve each subdomain. Remove those that no longer resolve."""
    if not entries:
        return entries
    loop = asyncio.get_event_loop()
    sem  = asyncio.Semaphore(60)
    async def check(e: dict) -> dict | None:
        async with sem:
            ip = await loop.run_in_executor(None, _resolve_a, e["subdomain"])
            if not ip:
                log.debug(f"[validator] Subdomain removed (no DNS): {e['subdomain']}")
                return None
            return {**e, "ip": ip, "verified": True, "validation_status": "confirmed"}
    results = await asyncio.gather(*[check(e) for e in entries])
    verified = [r for r in results if r]
    log.info(f"[validator] Subdomains: {len(verified)}/{len(entries)} verified, "
             f"{len(entries)-len(verified)} removed as FP")
    return verified


async def validate_cloud_assets(assets: list[dict], cfg: Config) -> list[dict]:
    """Re-check cloud assets. Remove unreachable."""
    if not assets:
        return assets
    connector = aiohttp.TCPConnector(ssl=False, limit=20)
    async with aiohttp.ClientSession(connector=connector) as session:
        sem = asyncio.Semaphore(10)
        async def check(a: dict) -> dict | None:
            async with sem:
                status, _ = await _fetch(session, a["url"], cfg.timeout)
                if status == 0:
                    log.debug(f"[validator] Cloud asset removed (unreachable): {a['url']}")
                    return None
                return {**a, "verified_status": status, "validation_status": "confirmed"}
        results = await asyncio.gather(*[check(a) for a in assets])
    verified = [r for r in results if r]
    log.info(f"[validator] Cloud assets: {len(verified)}/{len(assets)} verified")
    return verified


async def validate_cve_paths(cve_paths: list[dict], cfg: Config) -> list[dict]:
    """Re-verify confirmed CVE paths. Downgrade if no longer accessible."""
    if not cve_paths:
        return cve_paths
    connector = aiohttp.TCPConnector(ssl=False, limit=20)
    async with aiohttp.ClientSession(connector=connector) as session:
        sem = asyncio.Semaphore(10)
        async def check(cve: dict) -> dict:
            if not cve.get("confirmed"):
                return {**cve, "validation_status": "informational"}
            async with sem:
                status, _ = await _fetch(session, cve["url"], cfg.timeout)
                if status != 200:
                    log.debug(f"[validator] CVE path downgraded (HTTP {status}): {cve['url']}")
                    return {**cve, "confirmed": False,
                            "validation_status": "suspected",
                            "confidence": max(0, cve.get("confidence", 80) - 40)}
                return {**cve, "validation_status": "confirmed"}
        results = list(await asyncio.gather(*[check(c) for c in cve_paths]))
    still = sum(1 for c in results if c.get("confirmed"))
    log.info(f"[validator] CVE paths: {still}/{len(cve_paths)} still confirmed after re-check")
    return results


def validate_waf_findings(waf_list: list[dict]) -> list[dict]:
    """
    Label WAF findings by confidence:
    ≥85 → confirmed, 70-84 → suspected, <70 → informational.
    """
    out = []
    for w in waf_list:
        conf = w.get("confidence", 0)
        status = "confirmed" if conf >= 85 else "suspected" if conf >= 70 else "informational"
        out.append({**w, "validation_status": status})
    return out


def validate_ssl_findings(findings: list[dict], chain_valid: bool, self_signed: bool) -> list[dict]:
    """
    P1/P4: Ensure SSL findings are internally consistent.
    Remove 'self-signed' finding if chain_valid=True (contradiction guard).
    """
    cleaned = []
    for f in findings:
        issue = f.get("issue", "").lower()
        # Guard: never report self-signed when chain is valid
        if "self-signed" in issue and chain_valid:
            log.warning(f"[validator] Removed contradictory SSL finding: '{f['issue']}' "
                        f"(chain_valid=True)")
            continue
        # Guard: never report chain failure when self_signed is the cause — already reported
        if "chain validation failed" in issue and self_signed:
            continue
        cleaned.append({**f, "validation_status": f.get("validation_status", "confirmed")})
    return cleaned


async def run_all_validations(results: dict, cfg: Config) -> dict:
    """Run all FP-reduction validations. Returns updated results dict."""
    login_data = results.get("login_finder") or {}
    sub_data   = results.get("subdomain") or {}
    cloud_data = results.get("cloud_discovery") or {}
    vuln_data  = results.get("vuln_scan") or {}
    ssl_data   = results.get("ssl_check") or {}
    tech_data  = results.get("tech_detect") or {}

    v_panels, v_entries, v_assets, v_cves = await asyncio.gather(
        validate_login_panels(login_data.get("panels", []), cfg),
        validate_subdomains(sub_data.get("entries", [])),
        validate_cloud_assets(cloud_data.get("assets", []), cfg),
        validate_cve_paths(vuln_data.get("cve_paths", []), cfg),
    )

    # SSL finding consistency check (P1/P4)
    ssl_findings = validate_ssl_findings(
        ssl_data.get("findings", []),
        chain_valid=ssl_data.get("chain_valid", False),
        self_signed=ssl_data.get("self_signed", False),
    )

    # WAF confidence labeling (P4/P5)
    waf_raw = tech_data.get("waf_findings", [])
    waf_validated = validate_waf_findings(waf_raw)

    # Write back
    if login_data:
        results["login_finder"] = {**login_data, "panels": v_panels}
    if sub_data:
        results["subdomain"] = {**sub_data, "entries": v_entries,
                                "subdomains": [e["subdomain"] for e in v_entries],
                                "total_validated": len(v_entries)}
    if cloud_data:
        results["cloud_discovery"] = {**cloud_data, "assets": v_assets,
                                      "total": len(v_assets)}
    if vuln_data:
        results["vuln_scan"] = {**vuln_data, "cve_paths": v_cves}
    if ssl_data:
        results["ssl_check"] = {**ssl_data, "findings": ssl_findings}
    if tech_data and waf_validated:
        results["tech_detect"] = {**tech_data, "waf_findings": waf_validated}

    log.info("[validator] All FP-reduction validations complete")
    return results
