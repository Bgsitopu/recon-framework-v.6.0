"""
Parameter Discovery v8.0
Collects URL parameters from HTML, JS, robots.txt, sitemap, endpoints, Wayback.
Groups by endpoint, risk-scores sensitive parameter names.
"""
import re
from urllib.parse import urlparse, parse_qs
from core.config import Config
from core.session import fetch, make_session
from core.logger import get_logger, ModuleTimer
from utils.helpers import normalize_url

log = get_logger("parameter_discovery")

# Parameters considered sensitive and their risk level
SENSITIVE_PARAMS: dict[str, str] = {
    # Critical — direct injection / auth bypass targets
    "token": "critical", "access_token": "critical", "api_key": "critical",
    "apikey": "critical", "secret": "critical", "password": "critical",
    "passwd": "critical", "auth": "critical", "jwt": "critical",
    # High — redirect / SSRF / path traversal
    "redirect": "high", "redirect_uri": "high", "redirect_url": "high",
    "next": "high", "url": "high", "return": "high", "returnurl": "high",
    "goto": "high", "dest": "high", "destination": "high",
    "file": "high", "path": "high", "filepath": "high", "dir": "high",
    "include": "high", "page": "high", "template": "high",
    # Medium — enumeration / injection
    "id": "medium", "user": "medium", "userid": "medium", "user_id": "medium",
    "username": "medium", "email": "medium", "account": "medium",
    "query": "medium", "search": "medium", "q": "medium", "keyword": "medium",
    "callback": "medium", "jsonp": "medium", "format": "medium",
    "type": "medium", "action": "medium", "cmd": "medium", "exec": "medium",
    "debug": "medium", "test": "medium", "admin": "medium",
    # Low — informational
    "lang": "low", "locale": "low", "currency": "low", "sort": "low",
    "order": "low", "page": "low", "limit": "low", "offset": "low",
    "ref": "low", "source": "low", "utm_source": "low",
}

# Regex to find params in JS/HTML source
_PARAM_RE = re.compile(
    r'[?&]([a-zA-Z_][a-zA-Z0-9_\-]{0,40})=',
)
_JS_PARAM_RE = re.compile(
    r'["\']([a-zA-Z_][a-zA-Z0-9_\-]{0,40})["\']:\s*(?:params|query|data|body)',
    re.IGNORECASE,
)


def _extract_from_url(url: str) -> dict[str, list[str]]:
    """Extract params from a URL's query string."""
    try:
        qs = parse_qs(urlparse(url).query)
        return {k: v for k, v in qs.items()}
    except Exception:
        return {}


def _extract_from_text(text: str) -> set[str]:
    """Extract parameter names from raw HTML/JS text."""
    params = set(_PARAM_RE.findall(text))
    params.update(_JS_PARAM_RE.findall(text))
    return params


def _risk(param: str) -> str:
    return SENSITIVE_PARAMS.get(param.lower(), "info")


def _build_param_map(url_list: list) -> dict[str, dict]:
    """
    Build {endpoint: {param: {risk, count}}} from a list of URL strings or dicts.
    """
    param_map: dict[str, dict] = {}
    for item in url_list:
        url = item.get("url", item) if isinstance(item, dict) else item
        if not isinstance(url, str) or "?" not in url:
            continue
        base = url.split("?")[0]
        params = _extract_from_url(url)
        if not params:
            continue
        ep = param_map.setdefault(base, {})
        for p in params:
            if p not in ep:
                ep[p] = {"risk": _risk(p), "count": 0}
            ep[p]["count"] += 1
    return param_map


async def run(cfg: Config, prior_results: dict | None = None) -> dict:
    base = normalize_url(cfg.target)
    prior = prior_results or {}

    with ModuleTimer("parameter_discovery"):
        all_params: set[str] = set()
        param_map: dict[str, dict] = {}

        # 1. From already-discovered endpoints
        endpoints = prior.get("endpoint", {}).get("endpoints", [])
        wayback   = prior.get("wayback", {}).get("urls", [])
        pm = _build_param_map(endpoints + wayback)
        for ep, params in pm.items():
            param_map.setdefault(ep, {}).update(params)
            all_params.update(params.keys())

        async with make_session(cfg) as session:
            # 2. Main page + robots + sitemap
            for path in ["", "/robots.txt", "/sitemap.xml"]:
                _, text, _ = await fetch(session, base + path, cfg)
                found = _extract_from_text(text)
                all_params.update(found)

            # 3. JS files from prior js_analysis
            js_findings = prior.get("js_analysis", {}).get("findings", [])
            for f in js_findings:
                js_url = f.get("file", "")
                if js_url:
                    _, js_text, _ = await fetch(session, js_url, cfg)
                    all_params.update(_extract_from_text(js_text))

        # Risk summary
        by_risk: dict[str, list] = {"critical": [], "high": [], "medium": [], "low": [], "info": []}
        for p in all_params:
            by_risk[_risk(p)].append(p)

        # Flatten endpoint param list for reporting
        endpoint_params = [
            {"endpoint": ep, "params": list(params.keys()),
             "sensitive": [p for p in params if _risk(p) in ("critical","high","medium")]}
            for ep, params in sorted(param_map.items())
            if params
        ]

        log.info(f"[parameter_discovery] {len(all_params)} params across {len(param_map)} endpoints")
        return {
            "total_params": len(all_params),
            "all_params": sorted(all_params),
            "by_risk": by_risk,
            "endpoint_params": endpoint_params[:200],
        }
