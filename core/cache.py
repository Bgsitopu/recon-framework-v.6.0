"""
core/cache.py v8.0 — In-memory TTL cache for DNS, HTTP responses, Wayback results.
Thread-safe via asyncio. No external dependencies.
"""
import asyncio
import time
from typing import Any, Optional


class TTLCache:
    """Simple in-memory cache with per-entry TTL."""

    def __init__(self, default_ttl: int = 300):
        self._store: dict[str, tuple[Any, float]] = {}  # key → (value, expires_at)
        self._default_ttl = default_ttl
        self._lock = asyncio.Lock()

    async def get(self, key: str) -> Optional[Any]:
        async with self._lock:
            entry = self._store.get(key)
            if entry and time.monotonic() < entry[1]:
                return entry[0]
            if entry:
                del self._store[key]
            return None

    async def set(self, key: str, value: Any, ttl: Optional[int] = None) -> None:
        async with self._lock:
            expires = time.monotonic() + (ttl if ttl is not None else self._default_ttl)
            self._store[key] = (value, expires)

    async def clear(self) -> None:
        async with self._lock:
            self._store.clear()

    def size(self) -> int:
        return len(self._store)


class ReconCache:
    """Namespaced caches for each data type used in recon."""

    def __init__(self, ttl_dns: int = 300, ttl_http: int = 60, ttl_wayback: int = 3600):
        self.dns     = TTLCache(ttl_dns)
        self.http    = TTLCache(ttl_http)
        self.wayback = TTLCache(ttl_wayback)
        self.tech    = TTLCache(3600)   # tech fingerprints rarely change

    def stats(self) -> dict:
        return {
            "dns":     self.dns.size(),
            "http":    self.http.size(),
            "wayback": self.wayback.size(),
            "tech":    self.tech.size(),
        }


# Global singleton — created once per process
_cache: Optional[ReconCache] = None


def get_cache(cfg=None) -> ReconCache:
    global _cache
    if _cache is None:
        if cfg:
            _cache = ReconCache(cfg.cache_ttl_dns, cfg.cache_ttl_http, cfg.cache_ttl_wayback)
        else:
            _cache = ReconCache()
    return _cache
