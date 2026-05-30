"""Directory discovery v9.0 — P4: jitter, UA rotation, 429 backoff, rate limiting."""
from __future__ import annotations
import asyncio
import os
import random
import aiohttp
from core.config import Config
from core.logger import get_logger
from utils.helpers import normalize_url, tag_severity
from utils.user_agents import random_ua

log = get_logger("dir_discovery")

SENSITIVE_FILES = [
    ".env", ".env.local", ".env.production", ".git/config", ".htaccess",
    "web.config", "config.php", "wp-config.php", "database.yml",
    "backup.zip", "backup.tar.gz", "dump.sql", "db.sql",
    "admin/", "administrator/", "phpmyadmin/", "adminer.php",
    "server-status", "server-info", "phpinfo.php", "info.php",
]


def _build_paths(wordlist: str, extensions: list[str]) -> list[str]:
    paths = list(SENSITIVE_FILES)
    if not os.path.exists(wordlist):
        return paths
    with open(wordlist) as f:
        words = [w.strip() for w in f if w.strip() and not w.startswith("#")]
    for word in words:
        paths.append(word)
        for ext in extensions:
            paths.append(f"{word}.{ext}")
    return paths


async def run(cfg: Config) -> dict:
    base = normalize_url(cfg.target)
    log.info(f"[dir_discovery] Brute-forcing: {base}")

    # ── Jitter config ──────────────────────────────────────────────────────
    # Spec: low=50-200ms, medium=200-700ms, high=700-1500ms
    _JITTER_RANGES = {"off": (0.0, 0.0), "low": (0.05, 0.2),
                      "medium": (0.2, 0.7), "high": (0.7, 1.5)}
    raw_level = getattr(cfg, "dir_jitter", "off") or "off"
    jitter_level = raw_level if raw_level in _JITTER_RANGES else "off"
    if raw_level not in _JITTER_RANGES:
        log.warning(f"[dir_discovery] Invalid dir_jitter={raw_level!r}, falling back to 'off'")

    if jitter_level != "off":
        jitter_min, jitter_max = _JITTER_RANGES[jitter_level]
    else:
        jitter_min = getattr(cfg, "dir_jitter_min", 0.2 if cfg.stealth else 0.0)
        jitter_max = getattr(cfg, "dir_jitter_max", 1.5 if cfg.stealth else 0.0)
        if jitter_min or jitter_max:
            jitter_level = "custom"

    stats: dict = {
        "requests": 0, "delays_applied": 0, "rate_limit_events": 0,
        "avg_delay_s": 0.0, "jitter_level": jitter_level,
        "avg_response_time": 0.0, "requests_per_sec": 0.0,
        "blocked_count": 0, "retry_count": 0,
    }

    try:
        paths = _build_paths(cfg.wordlist, cfg.extensions)
        if not paths:
            return {"base": base, "found": [], "stats": stats}

        if cfg.stealth:
            random.shuffle(paths)

        found: list[dict] = []
        backoff_until: list[float] = [0.0]
        # 403 adaptive throttle: track consecutive 403s
        consec_403: list[int] = [0]
        throttle_extra: list[float] = [0.0]
        total_response_time: list[float] = [0.0]
        scan_start = asyncio.get_event_loop().time()

        connector = aiohttp.TCPConnector(ssl=False, limit=cfg.threads)
        async with aiohttp.ClientSession(connector=connector) as session:
            sem = asyncio.Semaphore(cfg.threads)

            async def check(path: str) -> dict | None:
                url = f"{base}/{path.lstrip('/')}"
                async with sem:
                    now = asyncio.get_event_loop().time()
                    if backoff_until[0] > now:
                        await asyncio.sleep(backoff_until[0] - now)

                    # Jitter + adaptive 403 throttle
                    delay = random.uniform(jitter_min, jitter_max) if (jitter_min or jitter_max) else 0.0
                    delay += throttle_extra[0]
                    if delay > 0:
                        await asyncio.sleep(delay)
                        stats["delays_applied"] += 1
                        n = stats["delays_applied"]
                        stats["avg_delay_s"] = (stats["avg_delay_s"] * (n - 1) + delay) / n

                    headers = {"User-Agent": random_ua()}
                    stats["requests"] += 1
                    req_start = asyncio.get_event_loop().time()

                    for attempt in range(1, 4):
                        try:
                            async with session.get(
                                url, headers=headers, ssl=False,
                                allow_redirects=True,
                                timeout=aiohttp.ClientTimeout(total=cfg.timeout),
                            ) as r:
                                elapsed = asyncio.get_event_loop().time() - req_start
                                total_response_time[0] += elapsed
                                n = stats["requests"]
                                stats["avg_response_time"] = total_response_time[0] / n

                                if r.status == 429:
                                    stats["rate_limit_events"] += 1
                                    stats["blocked_count"] += 1
                                    backoff = 10 * attempt
                                    backoff_until[0] = asyncio.get_event_loop().time() + backoff
                                    log.warning(f"[dir_discovery] HTTP 429 — backing off {backoff}s")
                                    await asyncio.sleep(backoff)
                                    headers = {"User-Agent": random_ua()}
                                    continue

                                if r.status == 403:
                                    consec_403[0] += 1
                                    # Adaptive: after 5 consecutive 403s, add throttle
                                    if consec_403[0] >= 5:
                                        throttle_extra[0] = min(throttle_extra[0] + 0.1, 2.0)
                                        stats["blocked_count"] += 1
                                        log.debug(f"[dir_discovery] 403 throttle → {throttle_extra[0]:.1f}s extra")
                                else:
                                    # Gradually recover: reduce throttle on non-403
                                    if consec_403[0] > 0:
                                        consec_403[0] = max(0, consec_403[0] - 1)
                                    if throttle_extra[0] > 0:
                                        throttle_extra[0] = max(0.0, throttle_extra[0] - 0.02)

                                if r.status in (200, 201, 204, 301, 302, 403, 401):
                                    return {
                                        "url": url, "status": r.status,
                                        "size": r.headers.get("content-length", "?"),
                                        "severity": tag_severity(path, cfg.severity_keywords),
                                        "response_time": round(elapsed, 3),
                                    }
                                return None
                        except (aiohttp.ClientError, asyncio.TimeoutError):
                            if attempt == 3:
                                return None
                            stats["retry_count"] += 1
                            await asyncio.sleep(1.5 ** attempt)
                    return None

            results = await asyncio.gather(*[check(p) for p in paths])
            found = [r for r in results if r]

        elapsed_total = asyncio.get_event_loop().time() - scan_start
        stats["requests_per_sec"] = round(stats["requests"] / elapsed_total, 2) if elapsed_total > 0 else 0.0
        stats["avg_response_time"] = round(stats["avg_response_time"], 3)

    except Exception as exc:
        log.error(f"[dir_discovery] Module error (isolated): {exc}")
        return {"base": base, "found": [], "stats": stats, "error": str(exc)}

    log.info(
        f"[dir_discovery] found={len(found)} requests={stats['requests']} "
        f"avg_response={stats['avg_response_time']}s rps={stats['requests_per_sec']} "
        f"jitter={jitter_level} delays={stats['delays_applied']} "
        f"blocked={stats['blocked_count']} retries={stats['retry_count']} "
        f"rate_limit_events={stats['rate_limit_events']}"
    )
    return {"base": base, "found": found, "stats": stats}
