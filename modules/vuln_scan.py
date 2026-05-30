"""
Vulnerability Scanner v9.0
- Security Header Analyzer v2: CSP/HSTS scoring, COEP/COOP/CORP, posture score
- Evidence-validated CVE path probing
- CORS, clickjacking, version disclosure, dangerous methods
- Every finding: title, severity, confidence, evidence, affected_asset, remediation
"""
from __future__ import annotations
import re
import aiohttp
from dataclasses import dataclass, field
from core.config import Config
from core.session import fetch, make_session
from core.logger import get_logger, ModuleTimer
from utils.helpers import normalize_url

log = get_logger("vuln_scan")


@dataclass
class VulnFinding:
    title: str
    severity: str
    confidence: str          # confirmed / likely / speculative
    evidence: str
    affected_asset: str
    remediation: str
    cve_id: str = ""
    verification_status: str = "confirmed"
    detection_source: str = "header_analysis"
    validation_status: str = "confirmed"


# ── Security Header Analyzer v2 ───────────────────────────────────────────────

# (header, severity, explanation, remediation, score_weight)
SECURITY_HEADERS: list[tuple[str, str, str, str, int]] = [
    ("Content-Security-Policy",        "high",   "Prevents XSS by restricting resource origins.",
     "Add: Content-Security-Policy: default-src 'self'; script-src 'self'", 20),
    ("Strict-Transport-Security",      "medium", "Forces HTTPS, prevents SSL stripping.",
     "Add: Strict-Transport-Security: max-age=31536000; includeSubDomains", 15),
    ("X-Frame-Options",                "medium", "Prevents clickjacking via iframe embedding.",
     "Add: X-Frame-Options: DENY", 10),
    ("X-Content-Type-Options",         "medium", "Prevents MIME-type sniffing.",
     "Add: X-Content-Type-Options: nosniff", 10),
    ("Referrer-Policy",                "low",    "Controls referrer info leakage.",
     "Add: Referrer-Policy: strict-origin-when-cross-origin", 5),
    ("Permissions-Policy",             "low",    "Restricts browser feature access.",
     "Add: Permissions-Policy: geolocation=(), microphone=(), camera=()", 5),
    ("Cross-Origin-Embedder-Policy",   "medium", "Prevents loading cross-origin resources without permission.",
     "Add: Cross-Origin-Embedder-Policy: require-corp", 10),
    ("Cross-Origin-Opener-Policy",     "medium", "Isolates browsing context, prevents Spectre attacks.",
     "Add: Cross-Origin-Opener-Policy: same-origin", 10),
    ("Cross-Origin-Resource-Policy",   "medium", "Prevents other origins from loading this resource.",
     "Add: Cross-Origin-Resource-Policy: same-origin", 10),
    ("X-XSS-Protection",               "low",    "Legacy XSS filter for older browsers.",
     "Add: X-XSS-Protection: 1; mode=block", 5),
]

MAX_HEADER_SCORE = sum(w for *_, w in SECURITY_HEADERS)


def _score_csp(csp: str) -> tuple[int, list[str]]:
    """Score CSP quality 0-100, return (score, issues)."""
    if not csp:
        return 0, ["CSP header missing"]
    issues = []
    score = 60  # base for having CSP
    if "unsafe-inline" in csp:
        score -= 20; issues.append("unsafe-inline weakens XSS protection")
    if "unsafe-eval" in csp:
        score -= 15; issues.append("unsafe-eval allows eval() execution")
    if "*" in csp and "default-src" in csp:
        score -= 20; issues.append("wildcard in default-src")
    if "default-src" in csp:
        score += 15
    if "script-src" in csp:
        score += 10
    if "nonce-" in csp or "sha256-" in csp:
        score += 15; issues = [i for i in issues if "unsafe-inline" not in i]
    return max(0, min(100, score)), issues


def _score_hsts(hsts: str) -> tuple[int, list[str]]:
    """Score HSTS quality 0-100."""
    if not hsts:
        return 0, ["HSTS header missing"]
    issues = []
    score = 50
    m = re.search(r"max-age=(\d+)", hsts)
    if m:
        age = int(m.group(1))
        if age >= 31536000:
            score += 30
        elif age >= 2592000:
            score += 15; issues.append(f"max-age {age}s < recommended 31536000")
        else:
            issues.append(f"max-age {age}s too short")
    if "includeSubDomains" in hsts:
        score += 15
    if "preload" in hsts:
        score += 5
    return min(100, score), issues


def _analyze_headers(headers: dict) -> dict:
    hdr_lower = {k.lower(): v for k, v in headers.items()}
    missing = []
    present = []
    score_earned = 0

    for hdr, sev, explanation, remediation, weight in SECURITY_HEADERS:
        val = hdr_lower.get(hdr.lower(), "")
        if val:
            present.append({"header": hdr, "value": val})
            score_earned += weight
        else:
            missing.append({
                "header": hdr, "severity": sev,
                "explanation": explanation, "remediation": remediation,
                "confidence": 99,
                "detection_source": "header_analysis",
                "validation_status": "confirmed",
                "evidence": f"{hdr} header absent from response",
            })

    posture_score = int(score_earned / MAX_HEADER_SCORE * 100)

    csp_val  = hdr_lower.get("content-security-policy", "")
    hsts_val = hdr_lower.get("strict-transport-security", "")
    csp_score,  csp_issues  = _score_csp(csp_val)
    hsts_score, hsts_issues = _score_hsts(hsts_val)

    # Referrer-Policy validation
    rp = hdr_lower.get("referrer-policy", "")
    rp_issues = []
    if rp in ("unsafe-url", "no-referrer-when-downgrade", ""):
        rp_issues.append(f"Referrer-Policy '{rp or 'missing'}' leaks full URL to third parties")

    # Permissions-Policy validation
    pp = hdr_lower.get("permissions-policy", "")
    pp_issues = []
    for feature in ("geolocation", "camera", "microphone"):
        if feature not in pp:
            pp_issues.append(f"Permissions-Policy does not restrict '{feature}'")

    # Individual Cross-Origin policy findings (P5)
    co_findings = []
    for hdr, policy, remediation in [
        ("Cross-Origin-Embedder-Policy",  "require-corp",  "Add: Cross-Origin-Embedder-Policy: require-corp"),
        ("Cross-Origin-Opener-Policy",    "same-origin",   "Add: Cross-Origin-Opener-Policy: same-origin"),
        ("Cross-Origin-Resource-Policy",  "same-origin",   "Add: Cross-Origin-Resource-Policy: same-origin"),
    ]:
        val = hdr_lower.get(hdr.lower(), "")
        if not val:
            co_findings.append({
                "issue": f"Missing {hdr}",
                "severity": "medium",
                "confidence": 99,
                "evidence": f"{hdr} header absent",
                "detection_source": "header_analysis",
                "validation_status": "confirmed",
                "remediation": remediation,
            })

    return {
        "missing_headers": missing,
        "present_headers": present,
        "posture_score": posture_score,
        "csp_score": csp_score,
        "csp_issues": csp_issues,
        "hsts_score": hsts_score,
        "hsts_issues": hsts_issues,
        "referrer_policy_issues": rp_issues,
        "permissions_policy_issues": pp_issues,
        "co_findings": co_findings,
    }


# ── CVE Paths ─────────────────────────────────────────────────────────────────

CVE_PATHS: list[tuple[str, str, str, list[str], str]] = [
    # (path, description, severity, evidence_patterns, cve_id)
    ("/.git/HEAD",           "Exposed Git repository",              "critical", [r"ref:\s*refs/heads/"], ""),
    ("/.git/config",         "Exposed Git config",                  "critical", [r"\[core\]"], ""),
    ("/.env",                "Exposed .env file",                   "critical", [r"(?:APP_KEY|DB_|SECRET|TOKEN)\s*="], ""),
    ("/.htpasswd",           "Exposed .htpasswd credentials",       "critical", [r":\$(?:apr1|2y|1)\$"], ""),
    ("/wp-json/wp/v2/users", "WordPress user enumeration",          "high",     [r'"id"\s*:\s*\d+'], "CVE-2017-5487"),
    ("/xmlrpc.php",          "WordPress XMLRPC enabled",            "medium",   [r"XML-RPC server accepts"], "CVE-2020-28032"),
    ("/server-status",       "Apache mod_status exposed",           "high",     [r"Apache Server Status"], ""),
    ("/actuator",            "Spring Boot Actuator exposed",        "critical", [r'"_links"'], "CVE-2022-22965"),
    ("/actuator/env",        "Spring Boot Actuator /env",           "critical", [r'"activeProfiles"'], "CVE-2022-22965"),
    ("/actuator/heapdump",   "Spring Boot heapdump exposed",        "critical", [], "CVE-2022-22965"),
    ("/.DS_Store",           "macOS .DS_Store exposed",             "medium",   [], ""),
    ("/config.json",         "Config file exposed",                 "high",     [r'(?:password|secret|key|token)'], ""),
    ("/api/swagger.json",    "Swagger API docs exposed",            "medium",   [r'"swagger"'], ""),
    ("/openapi.json",        "OpenAPI spec exposed",                "medium",   [r'"openapi"'], ""),
    ("/graphql",             "GraphQL endpoint exposed",            "medium",   [r'"data"'], ""),
    ("/graphiql",            "GraphiQL IDE exposed",                "medium",   [r"graphiql"], ""),
    ("/console",             "Web console exposed",                 "high",     [r"(?:console|terminal|shell)"], ""),
    ("/manager/html",        "Tomcat Manager exposed",              "critical", [r"Tomcat Web Application Manager"], "CVE-2020-1938"),
    ("/phpinfo.php",         "phpinfo() exposed",                   "high",     [r"PHP Version"], ""),
    ("/adminer.php",         "Adminer DB tool exposed",             "critical", [r"adminer"], ""),
    ("/phpmyadmin/",         "phpMyAdmin exposed",                  "critical", [r"phpMyAdmin"], "CVE-2020-26934"),
    ("/backup.sql",          "SQL backup exposed",                  "critical", [r"(?:CREATE TABLE|INSERT INTO)"], ""),
    ("/debug",               "Debug endpoint exposed",              "high",     [r"(?:debug|traceback|exception)"], ""),
    ("/web.config",          "web.config exposed",                  "critical", [r"<configuration>"], ""),
    ("/crossdomain.xml",     "Flash crossdomain policy",            "medium",   [r"allow-access-from"], ""),
]

DANGEROUS_METHODS = ["PUT", "DELETE", "TRACE", "CONNECT"]

VERSION_PATTERNS = [
    (r"Apache/([\d\.]+)",        "Apache"),
    (r"nginx/([\d\.]+)",         "Nginx"),
    (r"PHP/([\d\.]+)",           "PHP"),
    (r"OpenSSL/([\d\.]+\w?)",    "OpenSSL"),
    (r"WordPress ([\d\.]+)",     "WordPress"),
    (r"Microsoft-IIS/([\d\.]+)", "IIS"),
    (r"Jetty/([\d\.]+)",         "Jetty"),
    (r"Tomcat/([\d\.]+)",        "Tomcat"),
]


def _check_cors(headers: dict, target: str) -> VulnFinding | None:
    acao = headers.get("Access-Control-Allow-Origin",
                       headers.get("access-control-allow-origin", ""))
    acac = headers.get("Access-Control-Allow-Credentials", "").lower()
    if acao == "*":
        return VulnFinding(
            title="CORS wildcard misconfiguration",
            severity="medium", confidence="confirmed",
            evidence=f"Access-Control-Allow-Origin: *",
            affected_asset=target,
            remediation="Restrict CORS to trusted origins. Never use wildcard with credentials.",
        )
    if acao and acac == "true":
        return VulnFinding(
            title="CORS reflects origin with credentials",
            severity="high", confidence="confirmed",
            evidence=f"ACAO: {acao}, ACAC: true",
            affected_asset=target,
            remediation="Validate Origin server-side. Do not reflect arbitrary origins.",
        )
    return None


def _check_clickjacking(headers: dict, target: str) -> VulnFinding | None:
    xfo = headers.get("X-Frame-Options", headers.get("x-frame-options", ""))
    csp = headers.get("Content-Security-Policy", headers.get("content-security-policy", ""))
    if not xfo and "frame-ancestors" not in csp.lower():
        return VulnFinding(
            title="Clickjacking — no frame protection",
            severity="medium", confidence="confirmed",
            evidence="X-Frame-Options absent, CSP frame-ancestors absent",
            affected_asset=target,
            remediation="Add X-Frame-Options: DENY or CSP: frame-ancestors 'none'",
        )
    return None


def _detect_versions(headers: dict, html: str, target: str) -> list[VulnFinding]:
    combined = " ".join(str(v) for v in headers.values()) + " " + html[:8000]
    findings = []
    for pattern, name in VERSION_PATTERNS:
        m = re.search(pattern, combined, re.IGNORECASE)
        if m:
            findings.append(VulnFinding(
                title=f"Version disclosure: {name} {m.group(1)}",
                severity="low", confidence="confirmed",
                evidence=m.group(0),
                affected_asset=target,
                remediation=f"Remove {name} version from response headers/body.",
            ))
    return findings


def _confirm(body: str, patterns: list[str]) -> tuple[bool, str]:
    if not patterns:
        return True, body[:100].strip()
    for pat in patterns:
        m = re.search(pat, body, re.IGNORECASE)
        if m:
            start = max(0, m.start() - 30)
            return True, body[start:start + 120].strip()
    return False, ""


async def _check_methods(session: aiohttp.ClientSession, url: str, cfg: Config) -> list[str]:
    dangerous = []
    for method in DANGEROUS_METHODS:
        try:
            async with session.request(method, url, ssl=False,
                                       timeout=aiohttp.ClientTimeout(total=cfg.timeout)) as r:
                if r.status not in (405, 501, 400, 403):
                    dangerous.append(method)
        except Exception:
            pass
    return dangerous


async def run(cfg: Config) -> dict:
    base = normalize_url(cfg.target)

    with ModuleTimer("vuln_scan"):
        async with make_session(cfg) as session:
            status, html, headers = await fetch(session, base, cfg)

            header_analysis = _analyze_headers(headers)
            clickjacking    = _check_clickjacking(headers, base)
            version_disc    = _detect_versions(headers, html, base)

            # CORS probe
            cors_finding: VulnFinding | None = None
            try:
                async with session.get(
                    base, ssl=False,
                    headers={"Origin": "https://evil-recon.com"},
                    timeout=aiohttp.ClientTimeout(total=cfg.timeout)
                ) as r:
                    cors_finding = _check_cors(dict(r.headers), base)
            except Exception:
                pass

            dangerous_methods = await _check_methods(session, base, cfg)

            # CVE path probing
            cve_paths: list[dict] = []
            for path, desc, severity, evidence_patterns, cve_id in CVE_PATHS:
                url = base.rstrip("/") + path
                s, body, _ = await fetch(session, url, cfg)
                if s == 200:
                    confirmed, snippet = _confirm(body, evidence_patterns)
                    if confirmed:
                        cve_paths.append({
                            "url": url, "status": s,
                            "title": desc, "description": desc,
                            "severity": severity,
                            "confidence": "confirmed",
                            "evidence": snippet[:200],
                            "evidence_source": url,
                            "affected_asset": base,
                            "cve_id": cve_id,
                            "verification_status": "confirmed",
                            "confirmed": True,
                            "remediation": f"Restrict access to {path}",
                        })
                        log.warning(f"[vuln_scan] CONFIRMED {desc} → {url}")
                elif s == 403:
                    cve_paths.append({
                        "url": url, "status": s,
                        "title": desc + " (access denied)",
                        "description": desc + " (access denied — resource may exist)",
                        "severity": "low",
                        "confidence": "speculative",
                        "evidence": "HTTP 403 response",
                        "evidence_source": url,
                        "affected_asset": base,
                        "cve_id": cve_id,
                        "verification_status": "unconfirmed",
                        "confirmed": False,
                        "remediation": f"Verify {path} is not accessible",
                    })

        confirmed_count = sum(1 for c in cve_paths if c.get("confirmed"))
        log.info(
            f"[vuln_scan] posture={header_analysis['posture_score']}/100 "
            f"missing_headers={len(header_analysis['missing_headers'])} "
            f"confirmed_cves={confirmed_count}"
        )

        return {
            "target": base,
            # Header analysis v2
            "missing_headers":            header_analysis["missing_headers"],
            "present_headers":            header_analysis["present_headers"],
            "posture_score":              header_analysis["posture_score"],
            "csp_score":                  header_analysis["csp_score"],
            "csp_issues":                 header_analysis["csp_issues"],
            "hsts_score":                 header_analysis["hsts_score"],
            "hsts_issues":                header_analysis["hsts_issues"],
            "referrer_policy_issues":     header_analysis["referrer_policy_issues"],
            "permissions_policy_issues":  header_analysis["permissions_policy_issues"],
            "co_findings":                header_analysis["co_findings"],
            # Findings
            "cors":               cors_finding.__dict__ if cors_finding else None,
            "clickjacking":       clickjacking.__dict__ if clickjacking else None,
            "version_disclosure": [v.__dict__ for v in version_disc],
            "dangerous_methods":  dangerous_methods,
            "cve_paths":          cve_paths,
        }
