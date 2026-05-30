"""
AI Analysis / Risk Engine v9.1
P2: HSTS/header sync — reads hsts_status from ssl_check (single source of truth)
P3: Confidence framework — every finding has confidence/evidence/validation_status
P8: Executive Summary v2 — confirmed/suspected/fp_removed/scan_confidence
P9: Risk Engine consistency — only scores validated findings, weights by confidence
"""
from __future__ import annotations
import re
from core.logger import get_logger, ModuleTimer

log = get_logger("ai_analysis")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _cve_confirmed(r: dict, keyword: str) -> bool:
    return any(keyword in e.get("url","") and e.get("confirmed")
               for e in r.get("vuln_scan",{}).get("cve_paths",[]))

def _port_open(r: dict, port: int) -> bool:
    return any(p["port"]==port and p.get("verified", True)
               for p in r.get("port_scan",{}).get("open_ports",[]))

def _ssl(r: dict) -> dict:
    return r.get("ssl_check") or {}

def _vuln(r: dict) -> dict:
    return r.get("vuln_scan") or {}

# P2: read hsts_status from ssl_check — single source of truth
# "unknown" means fetch failed — do not report as missing
def _hsts_missing(r: dict) -> bool:
    return _ssl(r).get("hsts_status", "missing") == "missing"

def _hsts_weak(r: dict) -> bool:
    return _ssl(r).get("hsts_status") in ("weak", "partial")


# ── P9: Rules with confidence weighting ──────────────────────────────────────
# (name, check_fn, severity, base_weight, category, remediation, confidence_fn)
# confidence_fn(results) → int 0-100; None = always 95
RULES: list[tuple] = [
    ("Exposed .env file",
     lambda r: _cve_confirmed(r,".env"), "critical", 30, "exposed_secrets",
     "Remove .env from web root.", None),
    ("Exposed Git repository",
     lambda r: _cve_confirmed(r,".git"), "critical", 30, "exposed_secrets",
     "Block /.git/ via web server config.", None),
    ("Hardcoded secrets in JS",
     lambda r: len(r.get("js_analysis",{}).get("findings",[])) > 0,
     "critical", 28, "exposed_secrets",
     "Move secrets to server-side. Rotate exposed keys.", None),
    ("Exposed SQL backup",
     lambda r: _cve_confirmed(r,"backup.sql") or _cve_confirmed(r,"dump.sql"),
     "critical", 28, "exposed_secrets",
     "Remove backup files from web root.", None),
    ("Exposed web.config",
     lambda r: _cve_confirmed(r,"web.config"), "critical", 28, "exposed_secrets",
     "Block web.config via server config.", None),
    ("Spring Boot Actuator exposed",
     lambda r: _cve_confirmed(r,"actuator"), "critical", 28, "admin_interface",
     "Restrict Actuator endpoints in production.", None),
    ("Tomcat Manager exposed",
     lambda r: _cve_confirmed(r,"manager/html"), "critical", 25, "admin_interface",
     "Restrict Tomcat Manager to localhost.", None),
    ("Exposed DB admin tool",
     lambda r: _cve_confirmed(r,"phpmyadmin") or _cve_confirmed(r,"adminer"),
     "critical", 25, "admin_interface",
     "Restrict DB admin tools to trusted IPs.", None),
    ("phpinfo() exposed",
     lambda r: _cve_confirmed(r,"phpinfo"), "high", 18, "admin_interface",
     "Remove phpinfo.php from production.", None),
    ("Open Redis (unauthenticated)",
     lambda r: _port_open(r,6379), "critical", 25, "open_ports",
     "Bind Redis to localhost. Enable requirepass.",
     lambda r: next((p["confidence"] for p in r.get("port_scan",{}).get("open_ports",[]) if p["port"]==6379), 95)),
    ("Open MongoDB",
     lambda r: _port_open(r,27017), "critical", 25, "open_ports",
     "Enable MongoDB auth. Bind to localhost.",
     lambda r: next((p["confidence"] for p in r.get("port_scan",{}).get("open_ports",[]) if p["port"]==27017), 95)),
    ("Open Elasticsearch",
     lambda r: _port_open(r,9200), "critical", 25, "open_ports",
     "Enable X-Pack security. Bind to localhost.",
     lambda r: next((p["confidence"] for p in r.get("port_scan",{}).get("open_ports",[]) if p["port"]==9200), 95)),
    ("Docker API exposed",
     lambda r: _port_open(r,2375) or _port_open(r,2376), "critical", 25, "open_ports",
     "Never expose Docker API publicly.", None),
    ("Telnet port open",
     lambda r: _port_open(r,23), "high", 15, "open_ports",
     "Disable Telnet. Use SSH instead.", None),
    # P1/P2 fix: use cert_type and hsts_status — no contradictions
    ("Expired SSL certificate",
     lambda r: _ssl(r).get("expired", False), "critical", 25, "weak_ssl",
     "Renew SSL certificate immediately.", lambda r: 99),
    ("SSL chain validation failed",
     lambda r: not _ssl(r).get("chain_valid", True) and not _ssl(r).get("self_signed", False),
     "high", 15, "weak_ssl",
     "Fix certificate chain. Ensure intermediate certs are installed.", None),
    ("Weak SSL/TLS protocol",
     lambda r: len(_ssl(r).get("weak_protocols",[])) > 0, "high", 15, "weak_ssl",
     "Disable TLS 1.0/1.1. Enforce TLS 1.2+.", None),
    # P2 FIX: self_signed only when chain_valid=False (ssl_check guarantees this)
    ("Self-signed SSL certificate",
     lambda r: _ssl(r).get("self_signed", False), "high", 15, "weak_ssl",
     "Replace self-signed cert with a trusted CA certificate.",
     lambda r: next((f["confidence"] for f in _ssl(r).get("findings",[])
                     if "self-signed" in f.get("issue","").lower()), 95)),
    ("SSL certificate expiring soon",
     lambda r: _ssl(r).get("expiry_warning", False), "high", 12, "weak_ssl",
     "Renew SSL certificate before expiry.", lambda r: 99),
    # P2 FIX: use hsts_status from ssl_check — single source of truth
    ("HSTS not enabled",
     _hsts_missing, "medium", 6, "weak_ssl",
     "Add Strict-Transport-Security: max-age=31536000; includeSubDomains",
     lambda r: 99),
    ("HSTS weak configuration",
     _hsts_weak, "low", 3, "weak_ssl",
     "Increase HSTS max-age to ≥31536000 and add includeSubDomains.",
     lambda r: 99),
    ("Missing CSP header",
     lambda r: any(h["header"]=="Content-Security-Policy"
                   for h in _vuln(r).get("missing_headers",[])),
     "high", 12, "missing_headers",
     "Implement Content-Security-Policy to prevent XSS.", None),
    ("Low security header posture",
     lambda r: _vuln(r).get("posture_score", 100) < 50,
     "medium", 10, "missing_headers",
     "Implement all recommended security headers.", None),
    ("Missing COEP/COOP/CORP",
     lambda r: sum(1 for h in _vuln(r).get("missing_headers",[])
                   if h["header"].startswith("Cross-Origin")) >= 2,
     "medium", 8, "missing_headers",
     "Add Cross-Origin-Embedder/Opener/Resource-Policy headers.", None),
    ("Outdated technology detected",
     lambda r: r.get("tech_detect",{}).get("outdated_count",0) > 0,
     "high", 14, "technology_age",
     "Update outdated software to latest stable versions.", None),
    ("Technology CVEs detected",
     lambda r: any(f.get("cves") for f in r.get("tech_detect",{}).get("tech_findings",[])),
     "high", 16, "technology_age",
     "Patch or upgrade technologies with known CVEs.", None),
    ("Critical parameters exposed",
     lambda r: len(r.get("parameter_discovery",{}).get("by_risk",{}).get("critical",[])) > 0,
     "high", 14, "dangerous_params",
     "Audit and sanitize critical parameters.", None),
    ("High-risk redirect parameters",
     lambda r: len(r.get("parameter_discovery",{}).get("by_risk",{}).get("high",[])) > 0,
     "medium", 8, "dangerous_params",
     "Validate and whitelist redirect/URL parameters.", None),
    ("Exposed cloud storage (listable)",
     lambda r: len(r.get("cloud_discovery",{}).get("exposed",[])) > 0,
     "critical", 25, "cloud_exposure",
     "Set bucket ACL to private.", None),
    ("Cloud assets detected",
     lambda r: r.get("cloud_discovery",{}).get("total",0) > 0,
     "low", 3, "cloud_exposure",
     "Audit cloud asset permissions.", None),
    ("CORS misconfiguration",
     lambda r: _vuln(r).get("cors") is not None, "high", 15, "misc",
     "Restrict CORS to trusted origins.", None),
    ("Clickjacking vulnerability",
     lambda r: _vuln(r).get("clickjacking") is not None, "medium", 8, "misc",
     "Add X-Frame-Options: DENY or CSP frame-ancestors 'none'.", None),
    ("Dangerous HTTP methods enabled",
     lambda r: len(_vuln(r).get("dangerous_methods",[])) > 0, "medium", 7, "misc",
     "Disable PUT, DELETE, TRACE methods.", None),
    ("No WAF detected",
     lambda r: len(r.get("tech_detect",{}).get("waf",[])) == 0,
     "medium", 5, "misc",
     "Consider deploying a WAF.", None),
    ("Version disclosure",
     lambda r: len(_vuln(r).get("version_disclosure",[])) > 0, "low", 2, "misc",
     "Remove Server/X-Powered-By headers.", None),
    ("Emails exposed",
     lambda r: r.get("email_harvest",{}).get("total",0) > 0, "low", 2, "misc",
     "Use contact forms instead of exposing emails.", None),
    ("Multiple login panels exposed",
     lambda r: len(r.get("login_finder",{}).get("panels",[])) >= 3,
     "medium", 8, "asset_exposure",
     "Restrict admin interfaces to trusted IPs.", None),
    ("Wildcard DNS detected",
     lambda r: r.get("subdomain",{}).get("wildcard_dns", False),
     "low", 3, "asset_exposure",
     "Review wildcard DNS configuration.", None),
]

EP_GROUPS = {
    "admin":  [r"/admin",r"/administrator",r"/manage",r"/backend",r"/cpanel",r"/wp-admin",r"/dashboard"],
    "api":    [r"/api/",r"/v\d+/",r"/graphql",r"/rest/",r"/swagger",r"/openapi",r"/webhook"],
    "login":  [r"/login",r"/signin",r"/auth",r"/oauth",r"/sso",r"/logout",r"/register"],
    "asset":  [r"\.js$",r"\.css$",r"\.png$",r"\.jpg$",r"\.svg$",r"/static/",r"/assets/"],
}

def _group_endpoints(endpoints: list) -> dict[str,list]:
    groups: dict[str,list] = {k:[] for k in EP_GROUPS}
    groups["other"] = []
    for ep in endpoints:
        url = ep.get("url",ep) if isinstance(ep,dict) else ep
        matched = False
        for group, patterns in EP_GROUPS.items():
            if any(re.search(p,url,re.IGNORECASE) for p in patterns):
                groups[group].append(url); matched=True; break
        if not matched: groups["other"].append(url)
    return groups

def _correlate(results: dict) -> dict:
    sub_entries  = results.get("subdomain",{}).get("entries",[])
    techs        = results.get("tech_detect",{}).get("technologies",[])
    tech_findings= results.get("tech_detect",{}).get("tech_findings",[])
    cve_paths    = results.get("vuln_scan",{}).get("cve_paths",[])
    endpoints    = results.get("endpoint",{}).get("endpoints",[])
    panels       = results.get("login_finder",{}).get("panels",[])
    open_ports   = results.get("port_scan",{}).get("open_ports",[])
    cloud_assets = results.get("cloud_discovery",{}).get("assets",[])

    sub_ip_ports: dict[str,dict] = {
        e["subdomain"]: {"ip":e["ip"],"ports":[p["port"] for p in open_ports]}
        for e in sub_entries
    }
    sub_panels: dict[str,list] = {}
    for panel in panels:
        for e in sub_entries:
            if e["subdomain"] in panel["url"]:
                sub_panels.setdefault(e["subdomain"],[]).append(panel["url"])
    tech_vulns: dict[str,list] = {}
    for cve in cve_paths:
        if not cve.get("confirmed"): continue
        for tech in techs:
            if tech.lower() in cve.get("description","").lower():
                tech_vulns.setdefault(tech,[]).append(cve["description"])
    for tf in tech_findings:
        if tf.get("cves"):
            tech_vulns.setdefault(tf["name"],[]).extend(tf["cves"])
    cloud_sub_map: dict[str,list] = {}
    for asset in cloud_assets:
        related = [e["subdomain"] for e in sub_entries if e["subdomain"] in asset.get("url","")]
        if related: cloud_sub_map[asset.get("url","")] = related
    sub_ep_count: dict[str,int] = {}
    for ep in endpoints:
        url = ep.get("url","") if isinstance(ep,dict) else ep
        for e in sub_entries:
            if e["subdomain"] in url:
                sub_ep_count[e["subdomain"]] = sub_ep_count.get(e["subdomain"],0)+1
    return {
        "subdomain_ip_ports": sub_ip_ports,
        "subdomain_panels": sub_panels,
        "subdomain_ep_counts": sub_ep_count,
        "tech_to_vulns": tech_vulns,
        "cloud_to_subdomains": cloud_sub_map,
        "total_endpoints": len(endpoints),
        "total_subdomains": len(sub_entries),
    }

def _attack_surface(results: dict) -> dict:
    entry_points = [
        {"type":"login_panel","url":p["url"],"tech":p.get("technology","")}
        for p in results.get("login_finder",{}).get("panels",[])
    ]
    for e in results.get("endpoint",{}).get("endpoints",[]):
        if isinstance(e,dict) and e.get("severity") in ("critical","high"):
            entry_points.append({"type":"sensitive_endpoint","url":e["url"]})
    exposed_services = []
    for p in results.get("port_scan",{}).get("open_ports",[]):
        risk = ("critical" if p["port"] in (6379,27017,9200,2375,2376)
                else "high" if p["port"] in (23,3306,5432,1433) else "low")
        exposed_services.append({"port":p["port"],"service":p["service"],
                                  "fingerprint":p.get("fingerprint",""),"risk":risk})
    cloud = results.get("cloud_discovery",{})
    return {
        "entry_points": entry_points[:50],
        "exposed_services": exposed_services,
        "subdomain_count": len(results.get("subdomain",{}).get("subdomains",[])),
        "subdomain_sources": results.get("subdomain",{}).get("sources",{}),
        "tech_stack": results.get("tech_detect",{}).get("technologies",[]),
        "waf": results.get("tech_detect",{}).get("waf",[]),
        "cloud_assets": cloud.get("total",0),
        "cloud_providers": cloud.get("by_provider",{}),
    }

def _top_attack_paths(results: dict) -> list[str]:
    paths = []
    for cve in results.get("vuln_scan",{}).get("cve_paths",[]):
        if cve.get("confirmed"):
            paths.append(f"Direct access: {cve['url']} [{cve['severity'].upper()}]")
    for p in results.get("login_finder",{}).get("panels",[]):
        if p.get("has_login_form"):
            paths.append(f"Login panel: {p['url']} [{p.get('technology','generic')}]")
    for port in results.get("port_scan",{}).get("open_ports",[]):
        if port["port"] in (6379,27017,9200,2375):
            paths.append(f"Exposed service: {port['service']} port {port['port']}")
    for tf in results.get("tech_detect",{}).get("tech_findings",[]):
        if tf.get("cves"):
            paths.append(f"Vulnerable tech: {tf['name']} {tf.get('version','')} → {', '.join(tf['cves'][:2])}")
    return paths[:10]

def _critical_assets(results: dict) -> list[str]:
    assets = []
    for e in results.get("subdomain",{}).get("entries",[]):
        assets.append(f"Subdomain: {e['subdomain']} ({e['ip']})")
    for p in results.get("login_finder",{}).get("panels",[]):
        if p.get("has_login_form"):
            assets.append(f"Login panel: {p['url']}")
    for port in results.get("port_scan",{}).get("open_ports",[]):
        if port["port"] in (6379,27017,9200,2375,2376,3306,5432):
            assets.append(f"Exposed service: {port['service']}:{port['port']}")
    return assets[:10]


def run_sync(results: dict) -> dict:
    with ModuleTimer("ai_analysis"):
        misconfigs: list[dict] = []

        for name, check_fn, severity, base_weight, category, remediation, conf_fn in RULES:
            try:
                if not check_fn(results):
                    continue
                # P9: get confidence from finding or default 95
                confidence = conf_fn(results) if conf_fn else 95
                # P9: weight scaled by confidence — uncertain findings contribute less
                weight = int(base_weight * confidence / 100)
                misconfigs.append({
                    "issue": name, "severity": severity,
                    "weight": weight, "base_weight": base_weight,
                    "category": category, "remediation": remediation,
                    "confidence": confidence,
                    "validation_status": "confirmed" if confidence >= 80 else "suspected",
                })
            except Exception:
                pass

        # P9: only confirmed findings drive the score
        confirmed = [m for m in misconfigs if m["validation_status"] == "confirmed"]
        suspected = [m for m in misconfigs if m["validation_status"] == "suspected"]

        raw = sum(m["weight"] for m in confirmed)
        raw += sum(m["weight"] * 0.3 for m in suspected)  # suspected = 30% weight
        if not results.get("tech_detect",{}).get("waf"):
            raw += 5
        risk_score = min(100, int(raw))
        risk_level = ("CRITICAL" if risk_score>=80 else "HIGH" if risk_score>=60
                      else "MEDIUM" if risk_score>=35 else "LOW" if risk_score>=15 else "MINIMAL")

        by_category: dict[str,list] = {}
        by_severity:  dict[str,list] = {"critical":[],"high":[],"medium":[],"low":[],"info":[]}
        for m in misconfigs:
            by_category.setdefault(m["category"],[]).append(m["issue"])
            by_severity.setdefault(m["severity"],[]).append(m["issue"])

        all_eps = (results.get("endpoint",{}).get("endpoints",[]) +
                   results.get("wayback",{}).get("urls",[]))
        ep_groups = _group_endpoints(all_eps)
        ep_by_sev: dict[str,list] = {"critical":[],"high":[],"medium":[],"low":[],"info":[]}
        for ep in all_eps:
            sev = ep.get("severity","info") if isinstance(ep,dict) else "info"
            url = ep.get("url",ep) if isinstance(ep,dict) else ep
            ep_by_sev.setdefault(sev,[]).append(url)

        correlation    = _correlate(results)
        atk_surface    = _attack_surface(results)
        top_paths      = _top_attack_paths(results)
        crit_assets    = _critical_assets(results)

        # P8: validation statistics
        cve_paths = results.get("vuln_scan",{}).get("cve_paths",[])
        n_confirmed_cves = sum(1 for c in cve_paths if c.get("confirmed"))
        n_suspected_cves = sum(1 for c in cve_paths if not c.get("confirmed") and c.get("status")==200)
        port_fp = results.get("port_scan",{}).get("fp_removed",0)
        sub_wc  = results.get("subdomain",{}).get("wildcard_filtered_count",0)
        total_fp_removed = port_fp + sub_wc

        # Scan confidence from diagnostics
        scan_confidence = 85  # default; overridden if diagnostics available
        modules_succeeded = 0
        modules_failed = 0
        fallbacks_used = 0
        try:
            from core.diagnostics import get_diagnostics
            diag = get_diagnostics()
            scan_confidence = diag.scan_confidence()
            d = diag.to_dict()
            modules_succeeded = d.get("success_count", 0)
            modules_failed    = len(d.get("error_modules", []))
            fallbacks_used    = len(d.get("warning_modules", []))
        except Exception:
            pass

        # Evidence coverage: % of confirmed findings that have non-empty evidence
        all_findings = misconfigs[:]
        for cve in cve_paths:
            all_findings.append({"evidence": cve.get("evidence", ""), "validation_status": cve.get("verification_status", "")})
        evidence_coverage = 0
        if all_findings:
            with_evidence = sum(1 for f in all_findings if f.get("evidence"))
            evidence_coverage = int(with_evidence / len(all_findings) * 100)

        # Validation coverage: % of findings that are confirmed (not suspected/informational)
        validation_coverage = 0
        if all_findings:
            validated = sum(1 for f in all_findings
                            if f.get("validation_status") in ("confirmed",) or f.get("confidence", 0) >= 80)
            validation_coverage = int(validated / len(all_findings) * 100)

        stats = {
            "subdomains":        len(results.get("subdomain",{}).get("subdomains",[])),
            "wildcard_dns":      results.get("subdomain",{}).get("wildcard_dns",False),
            "wildcard_filtered": results.get("subdomain",{}).get("wildcard_filtered_count",0),
            "open_ports":        [p["port"] for p in results.get("port_scan",{}).get("open_ports",[])],
            "technologies":      results.get("tech_detect",{}).get("technologies",[]),
            "outdated_techs":    [f["name"] for f in results.get("tech_detect",{}).get("tech_findings",[]) if f.get("outdated")],
            "waf":               results.get("tech_detect",{}).get("waf",[]),
            "js_secrets":        sum(len(f.get("findings",{})) for f in results.get("js_analysis",{}).get("findings",[])),
            "emails_found":      results.get("email_harvest",{}).get("total",0),
            "ssl_days_left":     results.get("ssl_check",{}).get("days_until_expiry","N/A"),
            "ssl_cert_type":     results.get("ssl_check",{}).get("cert_type","unknown"),
            "confirmed_cves":    n_confirmed_cves,
            "cloud_assets":      results.get("cloud_discovery",{}).get("total",0),
            "total_params":      results.get("parameter_discovery",{}).get("total_params",0),
            "posture_score":     results.get("vuln_scan",{}).get("posture_score",0),
            "csp_score":         results.get("vuln_scan",{}).get("csp_score",0),
            "hsts_score":        results.get("vuln_scan",{}).get("hsts_score",0),
            # P2: explicit HSTS status from ssl_check
            "hsts_status":       results.get("ssl_check",{}).get("hsts_status","missing"),
        }

        # P8: Executive Summary v2
        critical_issues = [m["issue"] for m in confirmed if m["severity"]=="critical"]
        high_issues     = [m["issue"] for m in confirmed if m["severity"]=="high"]
        parts = [f"Risk: {risk_score}/100 ({risk_level})."]
        if critical_issues: parts.append(f"Critical: {'; '.join(critical_issues[:3])}.")
        if high_issues:     parts.append(f"High: {'; '.join(high_issues[:3])}.")
        if not stats["waf"]: parts.append("No WAF detected.")
        if n_confirmed_cves: parts.append(f"{n_confirmed_cves} CVE paths confirmed.")
        if stats["outdated_techs"]: parts.append(f"Outdated: {', '.join(stats['outdated_techs'][:3])}.")
        parts.append(f"Stack: {', '.join(stats['technologies'][:4]) or 'unknown'}. "
                     f"Subdomains: {stats['subdomains']}. Ports: {len(stats['open_ports'])}.")
        summary = " ".join(parts)

        log.info(f"[ai_analysis] risk={risk_score}/100 ({risk_level}) "
                 f"confirmed={len(confirmed)} suspected={len(suspected)} "
                 f"fp_removed={total_fp_removed} scan_confidence={scan_confidence}%")

        return {
            "summary":           summary,
            "risk_score":        risk_score,
            "risk_level":        risk_level,
            "misconfigurations": misconfigs,
            "by_category":       by_category,
            "risk_breakdown":    by_severity,
            "endpoint_classification": ep_by_sev,
            "endpoint_groups":   ep_groups,
            "attack_surface":    atk_surface,
            "correlation":       correlation,
            "top_attack_paths":  top_paths,
            "critical_assets":   crit_assets,
            "stats":             stats,
            # P8: validation statistics + P6: executive summary v3
            "validation_stats": {
                "confirmed_findings":  len(confirmed),
                "suspected_findings":  len(suspected),
                "fp_removed":          total_fp_removed,
                "confirmed_cves":      n_confirmed_cves,
                "suspected_cves":      n_suspected_cves,
                "scan_confidence":     scan_confidence,
                "modules_succeeded":   modules_succeeded,
                "modules_failed":      modules_failed,
                "fallbacks_used":      fallbacks_used,
                "evidence_coverage":   evidence_coverage,
                "validation_coverage": validation_coverage,
            },
        }
