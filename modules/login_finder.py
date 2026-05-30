"""
Login panel finder:
  - Probes common login/admin paths
  - Detects login forms in HTML
  - Categorizes by technology
"""
import re
from core.config import Config
from core.session import fetch, make_session
from core.logger import get_logger
from utils.helpers import normalize_url

log = get_logger("login_finder")

LOGIN_PATHS = [
    "login", "admin", "admin/login", "administrator", "wp-admin", "wp-login.php",
    "user/login", "account/login", "signin", "auth/login", "panel", "cpanel",
    "dashboard", "manage", "management", "backend", "control", "portal",
    "login.php", "login.aspx", "login.jsp", "login.html", "admin.php",
    "phpmyadmin", "adminer", "adminer.php", "webmail", "roundcube",
]

TECH_HINTS = {
    "WordPress":  [r"wp-login", r"wordpress"],
    "phpMyAdmin": [r"phpmyadmin", r"pma_"],
    "cPanel":     [r"cpanel", r"whm"],
    "Joomla":     [r"joomla", r"com_users"],
    "Drupal":     [r"drupal", r"user/login"],
    "Django":     [r"django", r"csrfmiddlewaretoken"],
    "Laravel":    [r"laravel", r"_token"],
}


def _has_login_form(html: str) -> bool:
    return bool(re.search(r'<input[^>]+type=["\']password["\']', html, re.IGNORECASE))


def _detect_tech(html: str) -> str:
    for tech, patterns in TECH_HINTS.items():
        if any(re.search(p, html, re.IGNORECASE) for p in patterns):
            return tech
    return "generic"


async def run(cfg: Config) -> dict:
    base = normalize_url(cfg.target)
    log.info(f"[login_finder] Scanning: {base}")
    panels = []

    async with make_session(cfg) as session:
        for path in LOGIN_PATHS:
            url = f"{base}/{path}"
            status, html, _ = await fetch(session, url, cfg)
            if status in (200, 401, 403) and html:
                has_form = _has_login_form(html)
                tech = _detect_tech(html)
                panels.append({
                    "url": url,
                    "status": status,
                    "has_login_form": has_form,
                    "technology": tech,
                })
                if has_form:
                    log.warning(f"[login_finder] Login panel: {url} [{tech}]")

    log.info(f"[login_finder] Found {len(panels)} panels")
    return {"base": base, "panels": panels}
