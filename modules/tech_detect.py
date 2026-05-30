"""
Technology detection v10.0
- Multi-signal weighted evidence accumulation
- Minimum confidence threshold (50%) to suppress noise
- Evidence string per finding
- Version fingerprinting, outdated detection, CVE correlation
"""
from __future__ import annotations
import re
from dataclasses import dataclass, field
from core.config import Config
from core.session import fetch, make_session
from core.logger import get_logger
from utils.helpers import normalize_url

log = get_logger("tech_detect")


@dataclass
class TechFinding:
    name: str
    version: str | None = None
    confidence: int = 0
    detection_method: str = ""
    evidence: list[str] = field(default_factory=list)
    outdated: bool = False
    cves: list[str] = field(default_factory=list)


# Minimum confidence to include a finding in output
MIN_CONFIDENCE = 50

# Multi-signal signature table:
# (tech_name, pattern, source, weight, label)
# source: "header" | "html" | "cookie"
# weight: contribution to confidence (signals accumulate, capped at 100)
SIGNALS: list[tuple[str, str, str, int, str]] = [

    # ── Web Servers ──────────────────────────────────────────────────────────
    ("Nginx",       r"nginx/([\d\.]+)",                    "header", 90, "Server header"),
    ("Nginx",       r"<hr>.*nginx|nginx error page",       "html",   40, "Error page"),
    ("Apache",      r"Apache/([\d\.]+)",                   "header", 90, "Server header"),
    ("Apache",      r"<address>Apache",                    "html",   40, "Error page"),
    ("IIS",         r"Microsoft-IIS/([\d\.]+)",            "header", 90, "Server header"),
    ("IIS",         r"iisstart\.png|iis-85\.png",          "html",   40, "IIS default page"),
    ("LiteSpeed",   r"LiteSpeed",                          "header", 90, "Server header"),
    ("LiteSpeed",   r"x-litespeed-cache",                  "header", 50, "Cache header"),
    ("Caddy",       r"Caddy",                              "header", 90, "Server header"),
    ("OpenResty",   r"openresty/([\d\.]+)",                "header", 90, "Server header"),
    ("Tomcat",      r"Apache-Coyote|Tomcat/([\d\.]+)",     "header", 90, "Server header"),
    ("Tomcat",      r"Apache Tomcat|coyoteconnector",      "html",   40, "Error page"),
    ("Gunicorn",    r"gunicorn/([\d\.]+)",                 "header", 90, "Server header"),
    ("uWSGI",       r"uwsgi-file|uWSGI",                   "header", 80, "Server header"),
    ("JBoss",       r"JBossWeb/([\d\.]+)",                 "header", 90, "Server header"),
    ("WebLogic",    r"weblogic/([\d\.]+)|x-weblogic",      "header", 90, "Server header"),
    ("GlassFish",   r"glassfish/([\d\.]+)",                "header", 90, "Server header"),
    ("Tengine",     r"tengine/([\d\.]+)",                  "header", 90, "Server header"),

    # ── PHP ──────────────────────────────────────────────────────────────────
    ("PHP",         r"PHP/([\d\.]+)",                      "header", 90, "X-Powered-By header"),
    ("PHP",         r"PHPSESSID",                          "cookie", 60, "PHPSESSID cookie"),
    ("PHP",         r"\.php(?:\?|\")",                     "html",   30, "PHP URLs in page"),

    # ── CMS ──────────────────────────────────────────────────────────────────
    ("WordPress",   r"/wp-content/",                       "html",   70, "wp-content path"),
    ("WordPress",   r"/wp-includes/",                      "html",   70, "wp-includes path"),
    ("WordPress",   r"WordPress ([\d\.]+)",                "html",   80, "Generator meta tag"),
    ("WordPress",   r"wp-json",                            "html",   50, "REST API path"),
    ("WordPress",   r"wordpress",                          "html",   40, "WordPress mention"),
    ("WordPress",   r"wordpress_[a-z]",                    "cookie", 80, "WordPress cookie"),

    ("Drupal",      r"Drupal\.settings",                   "html",   80, "Drupal.settings JS"),
    ("Drupal",      r"/sites/default/files/",              "html",   70, "Drupal files path"),
    ("Drupal",      r"drupal",                             "html",   40, "Drupal mention"),
    ("Drupal",      r"X-Generator: Drupal",                "header", 90, "X-Generator header"),
    ("Drupal",      r"Drupal\.version",                    "html",   80, "Drupal version JS"),

    ("Joomla",      r"/components/com_",                   "html",   70, "Joomla component path"),
    ("Joomla",      r"joomla",                             "html",   50, "Joomla mention"),
    ("Joomla",      r"/media/jui/",                        "html",   70, "Joomla JUI path"),
    ("Joomla",      r"mosConfig_|joomla_[a-z]",            "cookie", 80, "Joomla cookie"),

    ("Ghost",       r"/ghost/api/",                        "html",   80, "Ghost API path"),
    ("Ghost",       r"ghost-url|content=\"Ghost",          "html",   70, "Ghost meta"),
    ("Ghost",       r"/assets/built/",                     "html",   40, "Ghost built assets"),

    ("Magento",     r"Mage\.Cookies|Magento_([\d\.]+)",    "html",   80, "Mage JS object"),
    ("Magento",     r"/skin/frontend/|/js/mage/",          "html",   70, "Magento paths"),
    ("Shopify",     r"cdn\.shopify\.com",                  "html",   90, "Shopify CDN"),
    ("Shopify",     r"Shopify\.theme",                     "html",   80, "Shopify JS object"),
    ("Wix",         r"wixstatic\.com",                     "html",   90, "Wix static CDN"),
    ("Squarespace", r"static\.squarespace\.com",           "html",   90, "Squarespace CDN"),
    ("Webflow",     r"webflow\.com",                       "html",   90, "Webflow CDN"),

    # ── Frontend Frameworks ───────────────────────────────────────────────────
    # React — multiple strong signals
    ("React",       r"__REACT_DEVTOOLS_GLOBAL_HOOK__",     "html",   85, "React DevTools hook"),
    ("React",       r"data-reactroot|data-reactid",        "html",   85, "React DOM attributes"),
    ("React",       r"react(?:\.production\.min|\.development)\.js", "html", 80, "React bundle"),
    ("React",       r"/_next/static|__NEXT_DATA__",        "html",   70, "Next.js (implies React)"),
    ("React",       r"react-dom",                          "html",   60, "react-dom reference"),
    ("React",       r"\"react\":",                         "html",   50, "React in bundle map"),
    ("React",       r"createElement\s*\(",                 "html",   30, "createElement call"),

    # Next.js
    ("Next.js",     r"__NEXT_DATA__",                      "html",   90, "__NEXT_DATA__ object"),
    ("Next.js",     r"/_next/static",                      "html",   85, "Next.js static path"),
    ("Next.js",     r"/_next/chunks",                      "html",   80, "Next.js chunks"),
    ("Next.js",     r"next/dist/client",                   "html",   75, "Next.js client dist"),
    ("Next.js",     r"x-nextjs-page|x-powered-by.*next",  "header", 90, "Next.js header"),

    # Vue
    ("Vue",         r"__vue_app__|__VUE__",                "html",   85, "Vue app instance"),
    ("Vue",         r"vue(?:\.runtime)?(?:\.esm)?(?:\.min)?\.js", "html", 75, "Vue bundle"),
    ("Vue",         r"data-v-[a-f0-9]{8}",                "html",   80, "Vue scoped CSS attr"),
    ("Vue",         r"v-bind:|v-on:|v-model=",             "html",   70, "Vue directives"),
    ("Vue",         r"\"vue\":",                           "html",   50, "Vue in bundle map"),

    # Nuxt.js
    ("Nuxt.js",     r"__NUXT__",                           "html",   90, "__NUXT__ object"),
    ("Nuxt.js",     r"/_nuxt/",                            "html",   85, "Nuxt static path"),
    ("Nuxt.js",     r"nuxt-link|<nuxt>",                   "html",   70, "Nuxt components"),
    ("Nuxt.js",     r"x-powered-by.*nuxt",                 "header", 90, "Nuxt header"),

    # Angular
    ("Angular",     r"ng-version=",                        "html",   90, "ng-version attribute"),
    ("Angular",     r"angular(?:\.min)?\.js",              "html",   75, "Angular bundle"),
    ("Angular",     r"\[_nghost-|_ngcontent-",             "html",   85, "Angular host/content attrs"),
    ("Angular",     r"ng-app=|ng-controller=",             "html",   70, "AngularJS directives"),
    ("Angular",     r"platformBrowserDynamic|bootstrapModule", "html", 60, "Angular bootstrap"),

    # Svelte
    ("Svelte",      r"__svelte_[a-z0-9]+",                "html",   85, "Svelte internal attr"),
    ("Svelte",      r"svelte/internal|svelte-",            "html",   75, "Svelte bundle ref"),
    ("Svelte",      r"class=\"s-[a-zA-Z0-9_-]+\"",        "html",   70, "Svelte scoped class"),

    # jQuery / Bootstrap
    ("jQuery",      r"jquery(?:\.min)?\.js",               "html",   70, "jQuery script tag"),
    ("jQuery",      r"jQuery v([\d\.]+)",                  "html",   80, "jQuery version comment"),
    ("jQuery",      r"jquery/([\d\.]+)/jquery",            "html",   75, "jQuery CDN URL"),
    ("Bootstrap",   r"bootstrap(?:\.min)?\.(?:css|js)",    "html",   70, "Bootstrap asset"),
    ("Bootstrap",   r"bootstrap@([\d\.]+)",                "html",   75, "Bootstrap CDN version"),

    # ── Backend Frameworks ────────────────────────────────────────────────────
    # Laravel
    ("Laravel",     r"laravel_session",                    "cookie", 85, "laravel_session cookie"),
    ("Laravel",     r"XSRF-TOKEN",                         "cookie", 70, "XSRF-TOKEN cookie"),
    ("Laravel",     r"laravel",                            "html",   40, "Laravel mention"),
    ("Laravel",     r"X-Powered-By: PHP",                  "header", 30, "PHP (Laravel indicator)"),

    # Django
    ("Django",      r"csrfmiddlewaretoken",                "html",   85, "CSRF middleware token"),
    ("Django",      r"csrftoken",                          "cookie", 80, "csrftoken cookie"),
    ("Django",      r"django",                             "html",   40, "Django mention"),
    ("Django",      r"__admin_media_prefix__",             "html",   80, "Django admin"),

    # Flask
    ("Flask",       r"Werkzeug/([\d\.]+)",                 "header", 90, "Werkzeug header"),
    ("Flask",       r"session=\.",                         "cookie", 60, "Flask session cookie"),
    ("Flask",       r"flask",                              "html",   40, "Flask mention"),

    # Express.js
    ("Express",     r"X-Powered-By: Express",              "header", 90, "X-Powered-By header"),
    ("Express",     r"connect\.sid",                       "cookie", 70, "connect.sid cookie"),
    ("Express",     r"express",                            "html",   30, "Express mention"),

    # ASP.NET
    ("ASP.NET",     r"X-AspNet-Version: ([\d\.]+)",        "header", 90, "X-AspNet-Version header"),
    ("ASP.NET",     r"X-Powered-By: ASP\.NET",             "header", 85, "X-Powered-By header"),
    ("ASP.NET",     r"__VIEWSTATE",                        "html",   80, "__VIEWSTATE field"),
    ("ASP.NET",     r"__EVENTVALIDATION",                  "html",   75, "__EVENTVALIDATION field"),
    ("ASP.NET",     r"ASP\.NET_SessionId",                 "cookie", 80, "ASP.NET session cookie"),

    # Spring Boot
    ("Spring Boot", r"JSESSIONID",                         "cookie", 70, "JSESSIONID cookie"),
    ("Spring Boot", r"X-Application-Context",              "header", 85, "X-Application-Context"),
    ("Spring Boot", r"\"_links\".*\"self\"",               "html",   70, "Spring HATEOAS links"),
    ("Spring Boot", r"Whitelabel Error Page",              "html",   90, "Spring error page"),

    # Rails
    ("Rails",       r"authenticity_token",                 "html",   80, "Rails CSRF token"),
    ("Rails",       r"X-Runtime",                          "header", 70, "X-Runtime header"),
    ("Rails",       r"_rails_session|_session_id",         "cookie", 80, "Rails session cookie"),

    # FastAPI
    ("FastAPI",     r"/openapi\.json",                     "html",   75, "OpenAPI JSON path"),
    ("FastAPI",     r"/docs#/",                            "html",   70, "FastAPI docs path"),
    ("FastAPI",     r"fastapi",                            "html",   50, "FastAPI mention"),

    # ── CDN / Cloud ───────────────────────────────────────────────────────────
    ("Cloudflare",  r"cf-ray",                             "header", 90, "CF-Ray header"),
    ("Cloudflare",  r"cf_clearance|__cf_bm",               "cookie", 85, "Cloudflare cookie"),
    ("Cloudflare",  r"cloudflare",                         "header", 70, "Cloudflare header"),
    ("AWS CloudFront", r"X-Amz-Cf-Id",                    "header", 90, "CloudFront header"),
    ("AWS CloudFront", r"cloudfront\.net",                 "html",   70, "CloudFront domain"),
    ("Vercel",      r"x-vercel-id",                        "header", 90, "x-vercel-id header"),
    ("Netlify",     r"x-nf-request-id",                    "header", 90, "Netlify header"),
    ("Fastly",      r"x-fastly-request-id",                "header", 90, "Fastly header"),
    ("Fastly",      r"x-served-by.*cache",                 "header", 70, "Fastly cache header"),
    ("Akamai",      r"x-akamai-transformed|akamaighost",   "header", 90, "Akamai header"),
    ("Azure CDN",   r"x-azure-ref|x-fd-healthprobe",       "header", 90, "Azure CDN header"),
    ("Varnish",     r"x-varnish",                          "header", 85, "X-Varnish header"),
    ("Varnish",     r"via:.*varnish",                      "header", 75, "Via: Varnish"),

    # ── Analytics ─────────────────────────────────────────────────────────────
    ("Google Analytics", r"google-analytics\.com/analytics\.js", "html", 90, "GA analytics.js"),
    ("Google Analytics", r"gtag\('config',\s*'G-",        "html",   90, "GA4 gtag config"),
    ("Google Analytics", r"gtag\('config',\s*'UA-",       "html",   90, "UA gtag config"),
    ("Google Analytics", r"UA-\d{4,}-\d+",                "html",   80, "UA tracking ID"),
    ("Google Analytics", r"G-[A-Z0-9]{8,}",               "html",   80, "GA4 measurement ID"),
    ("Google Tag Manager", r"googletagmanager\.com/gtm\.js", "html", 90, "GTM script"),
    ("Google Tag Manager", r"GTM-[A-Z0-9]+",              "html",   85, "GTM container ID"),

    # ── Payment ───────────────────────────────────────────────────────────────
    ("Stripe",      r"js\.stripe\.com",                    "html",   90, "Stripe JS CDN"),
    ("Stripe",      r"pk_live_[A-Za-z0-9]+",              "html",   95, "Stripe live key"),
    ("Stripe",      r"pk_test_[A-Za-z0-9]+",              "html",   80, "Stripe test key"),
    ("PayPal",      r"paypalobjects\.com",                 "html",   90, "PayPal CDN"),

    # ── Security ──────────────────────────────────────────────────────────────
    ("reCAPTCHA",   r"google\.com/recaptcha",              "html",   90, "reCAPTCHA script"),
    ("reCAPTCHA",   r"grecaptcha\.execute",                "html",   85, "reCAPTCHA v3 call"),
    ("hCaptcha",    r"hcaptcha\.com",                      "html",   90, "hCaptcha script"),

    # ── E-commerce ────────────────────────────────────────────────────────────
    ("WooCommerce", r"/wc-api/|woocommerce",               "html",   80, "WooCommerce path/mention"),
    ("PrestaShop",  r"prestashop",                         "html",   70, "PrestaShop mention"),
    ("PrestaShop",  r"id_product=\d+",                     "html",   60, "PrestaShop product URL"),
    ("OpenCart",    r"route=common/home",                  "html",   80, "OpenCart route"),
]


WAF_SIGNATURES: dict[str, list[str]] = {
    "Cloudflare":  [r"cloudflare", r"cf-ray", r"cf_clearance"],
    "Akamai":      [r"akamai", r"ak_bmsc", r"akamaighost"],
    "Imperva":     [r"incapsula", r"visid_incap"],
    "Sucuri":      [r"sucuri", r"x-sucuri-id"],
    "F5 BIG-IP":   [r"bigipserver", r"f5-trafficshield"],
    "ModSecurity": [r"mod_security", r"modsecurity"],
    "AWS WAF":     [r"awswaf", r"x-amzn-waf"],
    "Wordfence":   [r"wordfence", r"wfwaf-authcookie"],
    "Fortinet":    [r"fortigate", r"fortiwebcookie"],
}

OUTDATED_THRESHOLDS: dict[str, tuple[int, int]] = {
    "PHP":       (8, 1),
    "Apache":    (2, 4),
    "Nginx":     (1, 24),
    "WordPress": (6, 4),
    "jQuery":    (3, 6),
    "Bootstrap": (5, 0),
    "Flask":     (3, 0),
    "IIS":       (10, 0),
}

CVE_HINTS: dict[str, dict[str, list[str]]] = {
    "PHP": {
        "7.4": ["CVE-2021-21703", "CVE-2022-31625"],
        "7.3": ["CVE-2020-7068", "CVE-2021-21703"],
        "5":   ["CVE-2016-7124", "CVE-2015-8994"],
    },
    "Apache": {
        "2.2": ["CVE-2017-7679", "CVE-2017-9798"],
        "2.4": ["CVE-2021-41773", "CVE-2021-42013"],
    },
    "Nginx": {
        "1.18": ["CVE-2021-23017"],
        "1.16": ["CVE-2019-20372"],
    },
    "WordPress": {
        "5": ["CVE-2022-21661", "CVE-2022-21662"],
        "4": ["CVE-2019-17671", "CVE-2020-28032"],
    },
}


def _is_outdated(name: str, version: str) -> bool:
    threshold = OUTDATED_THRESHOLDS.get(name)
    if not threshold or not version:
        return False
    parts = version.split(".")
    try:
        major = int(parts[0]) if parts else 0
        minor = int(parts[1]) if len(parts) > 1 else 0
        req_major, req_minor = threshold
        if major < req_major:
            return True
        if major == req_major and minor < req_minor:
            return True
    except ValueError:
        pass
    return False


def _get_cves(name: str, version: str) -> list[str]:
    if not version:
        return []
    tech_cves = CVE_HINTS.get(name, {})
    major = version.split(".")[0]
    major_minor = ".".join(version.split(".")[:2])
    return tech_cves.get(major_minor, tech_cves.get(major, []))


def _detect_all(html: str, headers: dict, cookies: str) -> list[TechFinding]:
    """
    Multi-signal weighted accumulation.
    Each matching signal adds its weight to the tech's confidence pool.
    Confidence is capped at 100. Findings below MIN_CONFIDENCE are dropped.
    """
    header_str = " ".join(f"{k.lower()}: {v}" for k, v in headers.items())
    html_body  = html[:80000]

    # Accumulator: name → {confidence, version, evidence, best_method}
    acc: dict[str, dict] = {}

    for name, pattern, source, weight, label in SIGNALS:
        target = (header_str if source == "header"
                  else cookies  if source == "cookie"
                  else html_body)
        m = re.search(pattern, target, re.IGNORECASE)
        if not m:
            continue

        version = m.group(1) if m.lastindex and m.lastindex >= 1 else None
        snippet = m.group(0)[:60].strip()
        evidence_str = f"[{source}] {label}: {snippet!r}"

        if name not in acc:
            acc[name] = {"confidence": 0, "version": None,
                         "evidence": [], "best_method": source}

        entry = acc[name]
        # Accumulate confidence — each new signal adds weight, capped at 100
        entry["confidence"] = min(100, entry["confidence"] + weight)
        entry["evidence"].append(evidence_str)
        if version and not entry["version"]:
            entry["version"] = version
        # Prefer header > cookie > html for detection_method label
        method_rank = {"header": 3, "cookie": 2, "html": 1}
        if method_rank.get(source, 0) > method_rank.get(entry["best_method"], 0):
            entry["best_method"] = source

    results: list[TechFinding] = []
    for name, entry in acc.items():
        if entry["confidence"] < MIN_CONFIDENCE:
            continue
        version = entry["version"]
        results.append(TechFinding(
            name=name,
            version=version,
            confidence=entry["confidence"],
            detection_method=entry["best_method"],
            evidence=entry["evidence"],
            outdated=_is_outdated(name, version or ""),
            cves=_get_cves(name, version or ""),
        ))

    return sorted(results, key=lambda f: -f.confidence)


async def run(cfg: Config) -> dict:
    url = normalize_url(cfg.target)
    log.info(f"[tech_detect] Scanning: {url}")

    async with make_session(cfg) as session:
        status, html, headers = await fetch(session, url, cfg)

    cookies = headers.get("Set-Cookie", headers.get("set-cookie", ""))
    cookies_all = "; ".join(
        v for k, v in headers.items() if k.lower() == "set-cookie"
    ) or cookies

    findings = _detect_all(html, headers, cookies_all)

    from core.waf_detect import detect_wafs
    waf_results  = detect_wafs(html, headers, cookies_all)
    waf_names    = [w.name for w in waf_results]
    waf_findings = [
        {"name": w.name, "confidence": w.confidence,
         "evidence": w.evidence, "detection_methods": w.detection_methods,
         "validation_status": "confirmed" if w.confidence >= 85 else "suspected"}
        for w in waf_results
    ]
    waf_debug = {
        "signatures_checked": detect_wafs.signatures_checked,
        "matched_count":      detect_wafs.matched_count,
    }

    tech_names = [f.name for f in findings]
    outdated   = [f for f in findings if f.outdated]

    log.info(
        f"[tech_detect] {len(findings)} techs detected | "
        f"{len(outdated)} outdated | WAF: {waf_names}"
    )

    return {
        "url":    url,
        "status": status,
        "technologies": tech_names,
        "tech_findings": [
            {
                "name":             f.name,
                "version":          f.version,
                "confidence":       f.confidence,
                "detection_method": f.detection_method,
                "evidence":         f.evidence,
                "outdated":         f.outdated,
                "cves":             f.cves,
            }
            for f in findings
        ],
        "outdated_count": len(outdated),
        "waf":            waf_names,
        "waf_findings":   waf_findings,
        "waf_debug":      waf_debug,
        "server":         headers.get("Server", headers.get("server", "unknown")),
        "x_powered_by":   headers.get("X-Powered-By", headers.get("x-powered-by", "")),
        "headers":        dict(headers),
    }
