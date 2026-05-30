"""
Screenshot Intelligence v9.0
- Captures: homepage, login panels, admin interfaces, high-value endpoints
- Full-size + thumbnail generation
- Page title + HTTP status per capture
- Gallery metadata for HTML dashboard
"""
from __future__ import annotations
import asyncio
import os
import re
from dataclasses import dataclass, field
from core.config import Config
from core.logger import get_logger, ModuleTimer
from utils.helpers import normalize_url

log = get_logger("screenshot")

_PROOT_ARGS = [
    "--no-sandbox", "--disable-setuid-sandbox",
    "--disable-dev-shm-usage", "--disable-gpu", "--single-process",
]
_DEFAULT_ARGS = ["--no-sandbox", "--disable-setuid-sandbox"]

MAX_RETRIES = 3
THUMB_WIDTH = 240
THUMB_HEIGHT = 160

# High-value path patterns to screenshot
HIGH_VALUE_PATTERNS = re.compile(
    r"/(admin|administrator|dashboard|panel|manage|backend|cpanel|"
    r"login|signin|auth|wp-admin|phpmyadmin|adminer|console|"
    r"api|swagger|graphiql|actuator|monitor|status)",
    re.IGNORECASE,
)


@dataclass
class ScreenshotResult:
    url: str
    category: str          # homepage / login / admin / endpoint / custom
    path: str = ""
    thumb: str = ""
    title: str = ""
    status: int = 0
    error: str = ""
    attempt: int = 1


def _is_proot() -> bool:
    if not os.path.exists("/proc/1/exe"):
        return True
    try:
        with open("/proc/1/cmdline", "rb") as f:
            return b"proot" in f.read()
    except Exception:
        return True


def _slug(url: str) -> str:
    return re.sub(r"[^\w\-]", "_", url.replace("https://", "").replace("http://", ""))[:80]


def _categorize(url: str, base: str) -> str:
    if url.rstrip("/") == base.rstrip("/"):
        return "homepage"
    path = url.split("?")[0].lower()
    if any(k in path for k in ("login", "signin", "auth", "wp-login")):
        return "login"
    if any(k in path for k in ("admin", "administrator", "dashboard", "panel", "manage", "backend", "cpanel")):
        return "admin"
    return "endpoint"


async def _capture_one(url: str, category: str, out_dir: str, browser) -> ScreenshotResult:
    slug = _slug(url)
    full_path  = os.path.join(out_dir, f"{slug}.png")
    thumb_path = os.path.join(out_dir, f"{slug}_thumb.png")
    result = ScreenshotResult(url=url, category=category)

    for attempt in range(1, MAX_RETRIES + 1):
        result.attempt = attempt
        try:
            page = await browser.new_page(viewport={"width": 1280, "height": 900})
            resp = await page.goto(url, timeout=25000, wait_until="domcontentloaded")
            result.title  = await page.title()
            result.status = resp.status if resp else 0
            await page.screenshot(path=full_path, full_page=False)
            await page.close()
            result.path = full_path

            # Thumbnail
            try:
                page2 = await browser.new_page(
                    viewport={"width": THUMB_WIDTH, "height": THUMB_HEIGHT}
                )
                await page2.goto(url, timeout=15000, wait_until="domcontentloaded")
                await page2.screenshot(path=thumb_path, full_page=False)
                await page2.close()
                result.thumb = thumb_path
            except Exception:
                pass

            return result
        except Exception as e:
            if attempt == MAX_RETRIES:
                result.error = str(e)[:120]
                return result
            await asyncio.sleep(2)

    result.error = "max retries exceeded"
    return result


async def run(cfg: Config, prior_results: dict | None = None) -> dict:
    if not cfg.screenshot:
        return {"skipped": True, "reason": "screenshot disabled"}

    out_dir = os.path.join(cfg.output_dir, "screenshots")
    os.makedirs(out_dir, exist_ok=True)

    prior = prior_results or {}
    base  = normalize_url(cfg.target)

    # Collect URLs by category
    url_map: dict[str, str] = {base: "homepage"}

    # Login panels
    for panel in prior.get("login_finder", {}).get("panels", [])[:8]:
        url_map[panel["url"]] = "login"

    # Admin interfaces from dir_discovery
    for item in prior.get("dir_discovery", {}).get("found", []):
        url = item.get("url", "")
        if url and HIGH_VALUE_PATTERNS.search(url) and url not in url_map:
            url_map[url] = _categorize(url, base)

    # High-value endpoints
    for ep in prior.get("endpoint", {}).get("endpoints", []):
        url = ep.get("url", ep) if isinstance(ep, dict) else ep
        sev = ep.get("severity", "") if isinstance(ep, dict) else ""
        if sev in ("critical", "high") and url not in url_map:
            url_map[url] = "endpoint"

    try:
        from playwright.async_api import async_playwright
    except ImportError:
        log.warning("[screenshot] Playwright not installed")
        return {"skipped": True, "reason": "playwright not installed"}

    with ModuleTimer("screenshot"):
        launch_args = _PROOT_ARGS if _is_proot() else _DEFAULT_ARGS
        captures: list[ScreenshotResult] = []
        try:
            async with async_playwright() as p:
                browser = await p.chromium.launch(headless=True, args=launch_args)
                sem = asyncio.Semaphore(3)

                async def bounded(url: str, cat: str) -> ScreenshotResult:
                    async with sem:
                        return await _capture_one(url, cat, out_dir, browser)

                captures = list(await asyncio.gather(
                    *[bounded(u, c) for u, c in url_map.items()]
                ))
                await browser.close()
        except Exception as e:
            log.error(f"[screenshot] Browser launch failed: {e}")
            return {"skipped": True, "reason": str(e)}

    ok  = [r for r in captures if r.path]
    err = [r for r in captures if r.error]
    log.info(f"[screenshot] {len(ok)} captured, {len(err)} failed")

    # Gallery metadata grouped by category
    gallery: dict[str, list[dict]] = {}
    for r in captures:
        gallery.setdefault(r.category, []).append({
            "url": r.url, "path": r.path, "thumb": r.thumb,
            "title": r.title, "status": r.status,
            "error": r.error,
        })

    return {
        "captures": [r.__dict__ for r in captures],
        "gallery": gallery,
        "success": len(ok),
        "failed": len(err),
        "out_dir": out_dir,
    }
