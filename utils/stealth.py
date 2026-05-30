"""Stealth helpers: randomized headers, delays, crawl patterns."""
import asyncio
import random
from utils.user_agents import random_ua


REFERERS = [
    "https://www.google.com/",
    "https://www.bing.com/",
    "https://duckduckgo.com/",
    "https://www.reddit.com/",
    "",
]


def stealth_headers() -> dict:
    return {
        "User-Agent": random_ua(),
        "Referer": random.choice(REFERERS),
        "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        "Accept-Language": random.choice(["en-US,en;q=0.9", "en-GB,en;q=0.8", "fr-FR,fr;q=0.7"]),
        "Cache-Control": random.choice(["no-cache", "max-age=0", ""]),
        "DNT": str(random.randint(0, 1)),
    }


async def random_delay(min_s: float = 0.5, max_s: float = 3.0):
    await asyncio.sleep(random.uniform(min_s, max_s))


def shuffle_paths(paths: list) -> list:
    """Randomize crawl order to avoid pattern detection."""
    shuffled = paths.copy()
    random.shuffle(shuffled)
    return shuffled
