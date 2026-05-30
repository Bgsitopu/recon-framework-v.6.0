"""
core/session.py v9.0
P9: Performance & Scale
- Shared aiohttp session pool (singleton per Config)
- Request deduplication (in-flight cache)
- Adaptive retry with exponential backoff
- DNS result caching via ReconCache
- HTTP response caching
"""
from __future__ import annotations
import asyncio
import hashlib
import random
import aiohttp
from aiohttp import ClientSession, TCPConnector
from core.config import Config
from utils.user_agents import random_ua

# In-flight dedup: url → asyncio.Future
_in_flight: dict[str, asyncio.Future] = {}
# Shared session pool: keyed by (proxy, threads)
_session_pool: dict[tuple, ClientSession] = {}
_pool_lock = asyncio.Lock()


def _build_headers() -> dict:
    return {
        "User-Agent": random_ua(),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": "en-US,en;q=0.5",
        "Accept-Encoding": "gzip, deflate",
        "Connection": "keep-alive",
        "DNT": "1",
    }


def _cache_key(url: str, method: str = "GET") -> str:
    return hashlib.md5(f"{method}:{url}".encode()).hexdigest()


async def get_shared_session(cfg: Config) -> ClientSession:
    """Return (or create) a shared session for this config profile."""
    key = (cfg.proxy, cfg.threads)
    async with _pool_lock:
        if key not in _session_pool or _session_pool[key].closed:
            connector = TCPConnector(
                ssl=False,
                limit=cfg.threads,
                limit_per_host=min(cfg.threads, 20),
                ttl_dns_cache=300,
                enable_cleanup_closed=True,
            )
            _session_pool[key] = ClientSession(connector=connector)
        return _session_pool[key]


async def close_all_sessions() -> None:
    async with _pool_lock:
        for s in _session_pool.values():
            if not s.closed:
                await s.close()
        _session_pool.clear()


async def fetch(
    session: ClientSession,
    url: str,
    cfg: Config,
    method: str = "GET",
    use_cache: bool = True,
    diag_module: str = "",   # optional: module name for diagnostics recording
    **kwargs,
) -> tuple[int, str, dict]:
    """
    Fetch with:
    - HTTP response caching
    - In-flight deduplication
    - Adaptive retry with exponential backoff
    - Stealth delay
    - Diagnostics: records retries and timeouts when diag_module is set
    Returns (status, text, headers). On failure: (0, "", {}).
    """
    if cfg.stealth and (cfg.delay_min or cfg.delay_max):
        await asyncio.sleep(random.uniform(cfg.delay_min, cfg.delay_max))

    # Cache lookup
    if use_cache and method == "GET":
        try:
            from core.cache import get_cache
            cache = get_cache()
            cached = await cache.http.get(_cache_key(url))
            if cached is not None:
                return cached
        except Exception:
            pass

    # In-flight dedup
    key = _cache_key(url, method)
    if key in _in_flight:
        try:
            return await asyncio.shield(_in_flight[key])
        except Exception:
            return 0, "", {}

    loop = asyncio.get_event_loop()
    future: asyncio.Future = loop.create_future()
    _in_flight[key] = future

    result = (0, "", {})
    try:
        _diag_mod = None
        if diag_module:
            try:
                from core.diagnostics import get_diagnostics
                _diag_mod = get_diagnostics().module(diag_module)
            except Exception:
                pass

        for attempt in range(cfg.retries):
            try:
                async with session.request(
                    method, url,
                    headers=_build_headers(),
                    timeout=aiohttp.ClientTimeout(total=cfg.timeout),
                    ssl=False,
                    allow_redirects=True,
                    **kwargs,
                ) as resp:
                    text = await resp.text(errors="replace")
                    result = (resp.status, text, dict(resp.headers))
                    break
            except asyncio.TimeoutError:
                if _diag_mod:
                    _diag_mod.timeout_count += 1
                if attempt == cfg.retries - 1:
                    result = (0, "", {})
                else:
                    if _diag_mod:
                        _diag_mod.retries += 1
                    await asyncio.sleep(1.5 ** attempt)
            except aiohttp.ClientError:
                if attempt == cfg.retries - 1:
                    result = (0, "", {})
                else:
                    if _diag_mod:
                        _diag_mod.retries += 1
                    await asyncio.sleep(1.5 ** attempt)
            except Exception:
                result = (0, "", {})
                break

        # Store in cache
        if use_cache and method == "GET" and result[0] > 0:
            try:
                from core.cache import get_cache
                await get_cache().http.set(_cache_key(url), result)
            except Exception:
                pass

        future.set_result(result)
    except Exception as e:
        if not future.done():
            future.set_exception(e)
        result = (0, "", {})
    finally:
        _in_flight.pop(key, None)

    return result


def make_session(cfg: Config) -> ClientSession:
    """Create a new per-call session (for modules that manage their own lifecycle)."""
    connector = TCPConnector(
        ssl=False,
        limit=cfg.threads,
        limit_per_host=min(cfg.threads, 20),
        ttl_dns_cache=300,
    )
    return ClientSession(connector=connector)
