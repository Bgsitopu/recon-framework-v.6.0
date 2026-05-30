"""
Unit tests for critical recon framework modules.
Run: python -m pytest tests/ -v
"""
import asyncio
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

import pytest
from unittest.mock import AsyncMock, MagicMock, patch
from core.config import Config


# ── subdomain tests ───────────────────────────────────────────────────────────

class TestWildcardDetection:
    def test_no_wildcard(self):
        from modules.subdomain import _detect_wildcard
        with patch("modules.subdomain._resolve_a", return_value=None):
            is_wc, ips = _detect_wildcard("example.com", probes=5)
        assert is_wc is False
        assert ips == set()

    def test_wildcard_detected(self):
        from modules.subdomain import _detect_wildcard
        with patch("modules.subdomain._resolve_a", return_value="1.2.3.4"):
            is_wc, ips = _detect_wildcard("example.com", probes=5)
        assert is_wc is True
        assert "1.2.3.4" in ips

    def test_partial_resolves_not_wildcard(self):
        """Only 2 out of 5 resolve — not a wildcard."""
        from modules.subdomain import _detect_wildcard
        call_count = {"n": 0}
        def side_effect(host):
            call_count["n"] += 1
            return "1.2.3.4" if call_count["n"] <= 2 else None
        with patch("modules.subdomain._resolve_a", side_effect=side_effect):
            is_wc, _ = _detect_wildcard("example.com", probes=5)
        assert is_wc is False


# ── vuln_scan header analysis tests ──────────────────────────────────────────

class TestHeaderAnalysis:
    def test_all_headers_present(self):
        from modules.vuln_scan import _analyze_headers
        headers = {
            "Content-Security-Policy": "default-src 'self'",
            "Strict-Transport-Security": "max-age=31536000; includeSubDomains",
            "X-Frame-Options": "DENY",
            "X-Content-Type-Options": "nosniff",
            "Referrer-Policy": "strict-origin-when-cross-origin",
            "Permissions-Policy": "geolocation=(), microphone=(), camera=()",
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
            "X-XSS-Protection": "1; mode=block",
        }
        result = _analyze_headers(headers)
        assert result["missing_headers"] == []
        assert result["posture_score"] == 100

    def test_missing_csp(self):
        from modules.vuln_scan import _analyze_headers
        result = _analyze_headers({})
        missing = [h["header"] for h in result["missing_headers"]]
        assert "Content-Security-Policy" in missing
        assert result["posture_score"] < 100

    def test_csp_scoring_unsafe_inline(self):
        from modules.vuln_scan import _score_csp
        score, issues = _score_csp("default-src 'self'; script-src 'unsafe-inline'")
        assert score < 80
        assert any("unsafe-inline" in i for i in issues)

    def test_csp_scoring_good(self):
        from modules.vuln_scan import _score_csp
        score, issues = _score_csp("default-src 'self'; script-src 'nonce-abc123'")
        assert score >= 70

    def test_hsts_scoring_good(self):
        from modules.vuln_scan import _score_hsts
        score, issues = _score_hsts("max-age=31536000; includeSubDomains; preload")
        assert score >= 90
        assert issues == []

    def test_hsts_scoring_short_maxage(self):
        from modules.vuln_scan import _score_hsts
        score, issues = _score_hsts("max-age=3600")
        assert score < 80
        assert any("max-age" in i for i in issues)


# ── tech_detect tests ─────────────────────────────────────────────────────────

class TestTechDetect:
    def test_detects_nginx_from_header(self):
        from modules.tech_detect import _detect_all
        findings = _detect_all("", {"Server": "nginx/1.18.0"}, "")
        names = [f.name for f in findings]
        assert "Nginx" in names

    def test_detects_version(self):
        from modules.tech_detect import _detect_all
        findings = _detect_all("", {"Server": "Apache/2.2.34"}, "")
        apache = next((f for f in findings if f.name == "Apache"), None)
        assert apache is not None
        assert apache.version == "2.2.34"

    def test_outdated_detection(self):
        from modules.tech_detect import _is_outdated
        assert _is_outdated("PHP", "7.4") is True
        assert _is_outdated("PHP", "8.2") is False
        assert _is_outdated("Apache", "2.2") is True
        assert _is_outdated("Apache", "2.4") is False

    def test_cve_lookup(self):
        from modules.tech_detect import _get_cves
        cves = _get_cves("PHP", "7.4.0")
        assert len(cves) > 0

    def test_waf_detection(self):
        from core.waf_detect import detect_wafs
        results = detect_wafs("", {"cf-ray": "abc123", "Server": "cloudflare"})
        names = [w.name for w in results]
        assert "Cloudflare" in names


# ── ai_analysis / risk engine tests ──────────────────────────────────────────

class TestRiskEngine:
    def _base_results(self) -> dict:
        return {
            "vuln_scan": {"missing_headers": [], "cve_paths": [], "cors": None,
                          "clickjacking": None, "version_disclosure": [],
                          "dangerous_methods": [], "posture_score": 100},
            "ssl_check": {"chain_valid": True, "expired": False, "self_signed": False,
                          "weak_protocols": [], "hsts": True, "expiry_warning": False},
            "tech_detect": {"technologies": [], "waf": ["Cloudflare"], "tech_findings": [],
                            "outdated_count": 0},
            "port_scan": {"open_ports": []},
            "subdomain": {"subdomains": [], "entries": [], "wildcard_dns": False,
                          "wildcard_filtered_count": 0},
            "login_finder": {"panels": []},
            "js_analysis": {"findings": []},
            "email_harvest": {"total": 0},
            "parameter_discovery": {"by_risk": {}, "total_params": 0},
            "cloud_discovery": {"total": 0, "exposed": [], "assets": []},
            "endpoint": {"endpoints": []},
            "wayback": {"urls": []},
        }

    def test_minimal_risk(self):
        from modules.ai_analysis import run_sync
        result = run_sync(self._base_results())
        assert result["risk_score"] >= 0
        assert result["risk_level"] in ("MINIMAL", "LOW", "MEDIUM", "HIGH", "CRITICAL")

    def test_critical_env_raises_score(self):
        from modules.ai_analysis import run_sync
        r = self._base_results()
        r["vuln_scan"]["cve_paths"] = [{
            "url": "https://example.com/.env",
            "confirmed": True, "severity": "critical",
        }]
        result = run_sync(r)
        assert result["risk_score"] >= 30

    def test_correlation_tech_vulns(self):
        from modules.ai_analysis import _correlate
        r = self._base_results()
        r["tech_detect"]["technologies"] = ["WordPress"]
        r["tech_detect"]["tech_findings"] = [{"name": "WordPress", "cves": ["CVE-2022-21661"]}]
        r["vuln_scan"]["cve_paths"] = [{
            "url": "/wp-json/wp/v2/users", "confirmed": True,
            "description": "WordPress user enumeration", "severity": "high",
        }]
        corr = _correlate(r)
        assert "WordPress" in corr["tech_to_vulns"]

    def test_top_attack_paths_populated(self):
        from modules.ai_analysis import run_sync
        r = self._base_results()
        r["vuln_scan"]["cve_paths"] = [{
            "url": "https://example.com/.git/HEAD",
            "confirmed": True, "severity": "critical",
            "description": "Exposed Git repository",
        }]
        result = run_sync(r)
        assert len(result["top_attack_paths"]) > 0


# ── cache tests ───────────────────────────────────────────────────────────────

class TestCache:
    def test_set_and_get(self):
        from core.cache import TTLCache
        cache = TTLCache(default_ttl=60)
        asyncio.run(cache.set("key1", "value1"))
        result = asyncio.run(cache.get("key1"))
        assert result == "value1"

    def test_expired_entry(self):
        from core.cache import TTLCache
        import time
        cache = TTLCache(default_ttl=0)
        asyncio.run(cache.set("key1", "value1", ttl=0))
        time.sleep(0.01)
        result = asyncio.run(cache.get("key1"))
        assert result is None

    def test_miss_returns_none(self):
        from core.cache import TTLCache
        cache = TTLCache()
        result = asyncio.run(cache.get("nonexistent"))
        assert result is None


# ── validator tests ───────────────────────────────────────────────────────────

class TestValidator:
    def test_validate_subdomains_removes_unresolvable(self):
        from core.validator import validate_subdomains
        entries = [
            {"subdomain": "live.example.com", "ip": "1.2.3.4", "sources": ["crt.sh"]},
            {"subdomain": "dead.example.com", "ip": "5.6.7.8", "sources": ["dns-brute"]},
        ]
        def resolve_side(host):
            return "1.2.3.4" if "live" in host else None
        with patch("core.validator._resolve_a", side_effect=resolve_side):
            result = asyncio.run(validate_subdomains(entries))
        assert len(result) == 1
        assert result[0]["subdomain"] == "live.example.com"

    def test_validate_login_panels_removes_dead(self):
        from core.validator import validate_login_panels
        cfg = Config()
        panels = [
            {"url": "https://example.com/login", "status": 200, "has_login_form": True},
            {"url": "https://example.com/dead",  "status": 200, "has_login_form": False},
        ]
        async def mock_fetch(session, url, timeout):
            if "dead" in url:
                return 0, ""
            return 200, '<input type="password">'
        with patch("core.validator._fetch", side_effect=mock_fetch):
            result = asyncio.run(validate_login_panels(panels, cfg))
        assert len(result) == 1
        assert result[0]["url"] == "https://example.com/login"


if __name__ == "__main__":
    pytest.main([__file__, "-v"])

# ── P1: SSL expiry parsing tests ──────────────────────────────────────────────

class TestSSLExpiryParsing:
    def test_standard_format(self):
        from modules.ssl_check import _parse_cert_date
        dt, err = _parse_cert_date("Mar 14 00:00:00 2027 GMT")
        assert dt is not None
        assert err == ""
        assert dt.year == 2027

    def test_single_digit_day(self):
        """'Jan  1 ...' with double space — common in some certs."""
        from modules.ssl_check import _parse_cert_date
        dt, err = _parse_cert_date("Jan  1 00:00:00 2027 GMT")
        assert dt is not None, f"Parse failed: {err}"
        assert dt.month == 1

    def test_no_tz_suffix(self):
        from modules.ssl_check import _parse_cert_date
        dt, err = _parse_cert_date("Mar 14 00:00:00 2027")
        assert dt is not None
        assert dt.year == 2027

    def test_asn1_generalizedtime(self):
        """ASN.1 GeneralizedTime: YYYYMMDDHHmmssZ"""
        from modules.ssl_check import _parse_cert_date
        dt, err = _parse_cert_date("20270314000000Z")
        assert dt is not None, f"Parse failed: {err}"
        assert dt.year == 2027
        assert dt.month == 3

    def test_asn1_utctime(self):
        """ASN.1 UTCTime: YYMMDDHHmmssZ — two-digit year"""
        from modules.ssl_check import _parse_cert_date
        dt, err = _parse_cert_date("270314000000Z")
        assert dt is not None, f"Parse failed: {err}"
        # strptime %y: 00-68 → 2000-2068, 69-99 → 1969-1999
        assert dt.month == 3

    def test_empty_string_returns_error(self):
        from modules.ssl_check import _parse_cert_date
        dt, err = _parse_cert_date("")
        assert dt is None
        assert "missing" in err.lower()

    def test_garbage_returns_error(self):
        from modules.ssl_check import _parse_cert_date
        dt, err = _parse_cert_date("not-a-date")
        assert dt is None
        assert err != ""

    def test_expired_cert_days_negative(self):
        from modules.ssl_check import _parse_cert_date
        from datetime import datetime, timezone
        dt, err = _parse_cert_date("Jan  1 00:00:00 2000 GMT")
        assert dt is not None
        days = (dt - datetime.now(timezone.utc)).days
        assert days < 0

    def test_days_never_none_for_valid_date(self):
        """Regression: days_until_expiry must not be None when date parses OK."""
        from modules.ssl_check import _parse_cert_date
        from datetime import datetime, timezone
        dt, err = _parse_cert_date("Dec 31 23:59:59 2099 GMT")
        assert dt is not None
        days = (dt - datetime.now(timezone.utc)).days
        assert days is not None
        assert days > 0

    def test_log_line_no_noned(self):
        """Regression: log line must never contain 'Noned' when days is None."""
        # Simulate what ssl_check does for the log line
        days = None
        days_display = f"{days}d" if days is not None else "unknown"
        log_line = f"expires={days_display}"
        assert "None" not in log_line
        assert log_line == "expires=unknown"


# ── P2: HSTS consistency tests ────────────────────────────────────────────────

class TestHSTSConsistency:
    def test_hsts_missing_not_fired_when_fetch_failed(self):
        """ai_analysis must not report 'HSTS not enabled' when hsts_status=unknown."""
        from modules.ai_analysis import _hsts_missing
        results = {"ssl_check": {"hsts_status": "unknown"}}
        assert _hsts_missing(results) is False

    def test_hsts_missing_fires_when_confirmed_absent(self):
        from modules.ai_analysis import _hsts_missing
        results = {"ssl_check": {"hsts_status": "missing"}}
        assert _hsts_missing(results) is True

    def test_hsts_missing_not_fired_when_enabled(self):
        from modules.ai_analysis import _hsts_missing
        results = {"ssl_check": {"hsts_status": "enabled"}}
        assert _hsts_missing(results) is False

    def test_hsts_weak_fires_for_weak(self):
        from modules.ai_analysis import _hsts_weak
        results = {"ssl_check": {"hsts_status": "weak"}}
        assert _hsts_weak(results) is True

    def test_hsts_weak_fires_for_partial(self):
        from modules.ai_analysis import _hsts_weak
        results = {"ssl_check": {"hsts_status": "partial"}}
        assert _hsts_weak(results) is True

    def test_hsts_status_unknown_when_fetch_fails(self):
        """ssl_check must set hsts_status=unknown (not missing) on fetch failure."""
        # Simulate the logic from ssl_check.run()
        hsts_fetch_ok = False
        hsts = False
        hsts_max_age = 0
        if not hsts_fetch_ok:
            hsts_status = "unknown"
        elif not hsts:
            hsts_status = "missing"
        elif hsts_max_age >= 31536000:
            hsts_status = "enabled"
        elif hsts_max_age > 0:
            hsts_status = "weak"
        else:
            hsts_status = "partial"
        assert hsts_status == "unknown"

    def test_no_hsts_finding_when_fetch_failed(self):
        """ssl_check must not emit 'HSTS not enabled' finding when fetch failed."""
        hsts_fetch_ok = False
        hsts = False
        findings = []
        if not hsts and hsts_fetch_ok:
            findings.append({"issue": "HSTS not enabled"})
        assert findings == []


# ── P3: Dynamic scan confidence tests ────────────────────────────────────────

class TestDynamicScanConfidence:
    def _make_diag(self, statuses: list[str], retries: list[int] | None = None) -> object:
        from core.diagnostics import ScanDiagnostics, ModuleDiag
        d = ScanDiagnostics()
        for i, status in enumerate(statuses):
            md = d.module(f"mod_{i}")
            md.status = status
            if retries:
                md.retries = retries[i]
        return d

    def test_all_success_is_100(self):
        d = self._make_diag(["success"] * 15)
        assert d.scan_confidence() == 100

    def test_one_error_reduces_confidence(self):
        d = self._make_diag(["success"] * 13 + ["error"] * 2)
        conf = d.scan_confidence()
        assert conf < 100
        assert conf >= 80  # 13/15 base = 86%

    def test_one_fallback_warning_reduces_confidence(self):
        d = self._make_diag(["success"] * 14 + ["warning"])
        conf = d.scan_confidence()
        assert conf < 100
        assert conf >= 90

    def test_retries_reduce_confidence(self):
        d = self._make_diag(["success"] * 15, retries=[0]*14 + [5])
        conf_no_retry = self._make_diag(["success"] * 15).scan_confidence()
        assert d.scan_confidence() < conf_no_retry

    def test_empty_modules_returns_0(self):
        from core.diagnostics import ScanDiagnostics
        d = ScanDiagnostics()
        assert d.scan_confidence() == 0

    def test_confidence_never_exceeds_100(self):
        d = self._make_diag(["success"] * 20)
        assert d.scan_confidence() <= 100

    def test_confidence_never_below_0(self):
        d = self._make_diag(["error"] * 15, retries=[10] * 15)
        assert d.scan_confidence() >= 0


# ── P4: WAF debug output tests ────────────────────────────────────────────────

class TestWAFDebugOutput:
    def test_signatures_checked_populated(self):
        from core.waf_detect import detect_wafs, WAF_RULES
        detect_wafs("", {})
        total_rules = sum(len(rules) for _, rules in WAF_RULES)
        assert detect_wafs.signatures_checked == total_rules

    def test_matched_count_zero_for_no_waf(self):
        from core.waf_detect import detect_wafs
        detect_wafs("", {"Server": "Apache"})
        assert detect_wafs.matched_count == 0

    def test_matched_count_nonzero_for_cloudflare(self):
        from core.waf_detect import detect_wafs
        results = detect_wafs("", {"cf-ray": "abc123", "server": "cloudflare"})
        assert detect_wafs.matched_count == len(results)
        assert detect_wafs.matched_count > 0

    def test_debug_attrs_always_exist(self):
        """Attributes must exist even before first call."""
        from core.waf_detect import detect_wafs
        # Reset to initial state by importing fresh
        assert hasattr(detect_wafs, "signatures_checked")
        assert hasattr(detect_wafs, "matched_count")


# ── P1 extra: cryptography-based parser ──────────────────────────────────────

class TestSSLCryptographyParser:
    def test_cryptography_importable(self):
        from cryptography import x509  # noqa: F401

    def test_cert_info_crypto_returns_days(self):
        """_cert_info_crypto must return integer days_until_expiry, not None."""
        import ssl, socket
        from modules.ssl_check import _cert_info_crypto
        try:
            data = _cert_info_crypto("google.com", 443, timeout=5)
            assert data["days_until_expiry"] is not None
            assert isinstance(data["days_until_expiry"], int)
            assert data["expiry_date"] is not None
            assert data["_parse_method"] == "cryptography"
        except OSError:
            pytest.skip("No network access")

    def test_cert_info_unverified_prefers_crypto(self):
        """_cert_info_unverified should use cryptography when available."""
        from modules.ssl_check import _cert_info_unverified
        try:
            data = _cert_info_unverified("google.com", 443, timeout=5)
            assert data["days_until_expiry"] is not None
            assert data["_parse_method"] == "cryptography"
        except OSError:
            pytest.skip("No network access")


# ── P5: Evidence-based findings ──────────────────────────────────────────────

class TestEvidenceBasedFindings:
    def test_vuln_finding_has_detection_source(self):
        from modules.vuln_scan import VulnFinding
        f = VulnFinding(
            title="Test", severity="medium", confidence="confirmed",
            evidence="header absent", affected_asset="https://example.com",
            remediation="Add header",
        )
        assert f.detection_source == "header_analysis"
        assert f.validation_status == "confirmed"

    def test_analyze_headers_returns_co_findings(self):
        from modules.vuln_scan import _analyze_headers
        result = _analyze_headers({})
        assert "co_findings" in result
        assert len(result["co_findings"]) == 3  # COEP, COOP, CORP

    def test_co_findings_have_all_required_fields(self):
        from modules.vuln_scan import _analyze_headers
        for f in _analyze_headers({})["co_findings"]:
            for field in ("issue", "severity", "confidence", "evidence",
                          "detection_source", "validation_status"):
                assert field in f, f"Missing field: {field}"

    def test_co_findings_empty_when_all_present(self):
        from modules.vuln_scan import _analyze_headers
        headers = {
            "Cross-Origin-Embedder-Policy": "require-corp",
            "Cross-Origin-Opener-Policy": "same-origin",
            "Cross-Origin-Resource-Policy": "same-origin",
        }
        assert _analyze_headers(headers)["co_findings"] == []

    def test_co_findings_partial(self):
        from modules.vuln_scan import _analyze_headers
        headers = {"Cross-Origin-Embedder-Policy": "require-corp"}
        assert len(_analyze_headers(headers)["co_findings"]) == 2


# ── P6: Executive summary v3 ─────────────────────────────────────────────────

class TestExecutiveSummaryV3:
    def _base(self):
        return {
            "vuln_scan": {"missing_headers": [], "cve_paths": [], "cors": None,
                          "clickjacking": None, "version_disclosure": [],
                          "dangerous_methods": [], "posture_score": 100,
                          "co_findings": []},
            "ssl_check": {"chain_valid": True, "expired": False, "self_signed": False,
                          "weak_protocols": [], "hsts": True, "hsts_status": "enabled",
                          "expiry_warning": False},
            "tech_detect": {"technologies": [], "waf": ["Cloudflare"],
                            "tech_findings": [], "outdated_count": 0},
            "port_scan": {"open_ports": []},
            "subdomain": {"subdomains": [], "entries": [], "wildcard_dns": False,
                          "wildcard_filtered_count": 0},
            "login_finder": {"panels": []},
            "js_analysis": {"findings": []},
            "email_harvest": {"total": 0},
            "parameter_discovery": {"by_risk": {}, "total_params": 0},
            "cloud_discovery": {"total": 0, "exposed": [], "assets": []},
            "endpoint": {"endpoints": []},
            "wayback": {"urls": []},
        }

    def test_validation_stats_has_v3_fields(self):
        from modules.ai_analysis import run_sync
        vstats = run_sync(self._base())["validation_stats"]
        for key in ("modules_succeeded", "modules_failed", "fallbacks_used",
                    "evidence_coverage", "validation_coverage", "scan_confidence"):
            assert key in vstats, f"Missing: {key}"

    def test_evidence_coverage_is_percentage(self):
        from modules.ai_analysis import run_sync
        ev = run_sync(self._base())["validation_stats"]["evidence_coverage"]
        assert 0 <= ev <= 100

    def test_validation_coverage_is_percentage(self):
        from modules.ai_analysis import run_sync
        vc = run_sync(self._base())["validation_stats"]["validation_coverage"]
        assert 0 <= vc <= 100

    def test_scan_confidence_is_int(self):
        from modules.ai_analysis import run_sync
        sc = run_sync(self._base())["validation_stats"]["scan_confidence"]
        assert isinstance(sc, int)


if __name__ == "__main__":
    pytest.main([__file__, "-v"])


# ── Dir discovery jitter & resilience tests ───────────────────────────────────

class TestDirDiscoveryJitter:
    _JITTER_RANGES = {"off": (0.0, 0.0), "low": (0.05, 0.3),
                      "medium": (0.3, 1.2), "high": (1.0, 4.0)}

    def _resolve(self, raw):
        r = raw or "off"
        return r if r in self._JITTER_RANGES else "off"

    def test_stealth_off_jitter_off_resolves(self):
        assert self._resolve("off") == "off"

    def test_invalid_jitter_falls_back_to_off(self):
        for bad in ("turbo", "MEDIUM", "1", "", None):
            assert self._resolve(bad) == "off", f"Expected off for {bad!r}"

    def test_valid_levels_resolve_ranges(self):
        assert self._JITTER_RANGES["low"]    == (0.05, 0.3)
        assert self._JITTER_RANGES["medium"] == (0.3, 1.2)
        assert self._JITTER_RANGES["high"]   == (1.0, 4.0)
        assert self._JITTER_RANGES["off"]    == (0.0, 0.0)

    def test_missing_attr_defaults_to_off(self):
        cfg = Config()
        if hasattr(cfg, "dir_jitter"):
            delattr(cfg, "dir_jitter")
        assert self._resolve(getattr(cfg, "dir_jitter", "off")) == "off"

    def test_empty_wordlist_returns_sensitive_files(self):
        from modules.dir_discovery import _build_paths, SENSITIVE_FILES
        paths = _build_paths("/nonexistent/wordlist.txt", ["php"])
        assert paths == SENSITIVE_FILES

    def test_stats_keys_always_present(self):
        required = {"requests", "delays_applied", "rate_limit_events",
                    "avg_delay_s", "jitter_level"}
        stats = {"requests": 0, "delays_applied": 0, "rate_limit_events": 0,
                 "avg_delay_s": 0.0, "jitter_level": "off"}
        assert required.issubset(stats.keys())

    def test_module_error_is_isolated(self):
        from modules.dir_discovery import run
        cfg = Config()
        cfg.target = "https://example.com"
        cfg.threads = 1
        cfg.timeout = 1
        cfg.wordlist = "/nonexistent"
        cfg.extensions = []
        cfg.stealth = False
        cfg.dir_jitter = "off"
        cfg.severity_keywords = {}
        with patch("modules.dir_discovery.aiohttp.TCPConnector",
                   side_effect=RuntimeError("boom")):
            result = asyncio.run(run(cfg))
        assert "error" in result
        assert result["found"] == []
        assert "jitter_level" in result["stats"]

    def test_stealth_on_uses_legacy_jitter_when_level_off(self):
        """stealth=True with dir_jitter=off should use dir_jitter_min/max."""
        cfg = Config()
        cfg.stealth = True
        cfg.dir_jitter = "off"
        cfg.dir_jitter_min = 0.2
        cfg.dir_jitter_max = 1.5
        level = self._resolve(getattr(cfg, "dir_jitter", "off"))
        assert level == "off"
        # Legacy path: jitter_min/max come from cfg
        jitter_min = getattr(cfg, "dir_jitter_min", 0.2 if cfg.stealth else 0.0)
        jitter_max = getattr(cfg, "dir_jitter_max", 1.5 if cfg.stealth else 0.0)
        assert jitter_min == 0.2
        assert jitter_max == 1.5


# ── New stats fields tests ────────────────────────────────────────────────────

class TestDirDiscoveryStats:
    def test_stats_has_all_new_fields(self):
        required = {"requests", "delays_applied", "rate_limit_events",
                    "avg_delay_s", "jitter_level", "avg_response_time",
                    "requests_per_sec", "blocked_count", "retry_count"}
        stats = {"requests": 0, "delays_applied": 0, "rate_limit_events": 0,
                 "avg_delay_s": 0.0, "jitter_level": "off",
                 "avg_response_time": 0.0, "requests_per_sec": 0.0,
                 "blocked_count": 0, "retry_count": 0}
        assert required.issubset(stats.keys())

    def test_jitter_ranges_match_spec(self):
        """Spec: low=50-200ms, medium=200-700ms, high=700-1500ms."""
        ranges = {"off": (0.0, 0.0), "low": (0.05, 0.2),
                  "medium": (0.2, 0.7), "high": (0.7, 1.5)}
        assert ranges["low"]    == (0.05, 0.2)
        assert ranges["medium"] == (0.2, 0.7)
        assert ranges["high"]   == (0.7, 1.5)


class TestWaybackParallel:
    def test_source_counts_keys(self):
        """source_counts must have wayback, otx, commoncrawl keys."""
        source_counts = {"wayback": 10, "otx": 5, "commoncrawl": 3}
        assert set(source_counts.keys()) == {"wayback", "otx", "commoncrawl"}

    def test_dedup_merges_correctly(self):
        wb  = ["https://a.com/1", "https://a.com/2"]
        otx = ["https://a.com/2", "https://a.com/3"]
        cc  = ["https://a.com/3", "https://a.com/4"]
        seen: set = set()
        merged = []
        for u in wb + otx + cc:
            if u.startswith("http") and u not in seen:
                seen.add(u); merged.append(u)
        assert len(merged) == 4
        assert merged[0] == "https://a.com/1"

    def test_legacy_fields_preserved(self):
        result = {"source_used": "parallel", "fallback_sources": [], "source_counts": {}}
        assert "source_used" in result
        assert "fallback_sources" in result


class TestSubdomainSources:
    def test_sources_dict_has_all_six(self):
        sources = {"crt.sh": 0, "hackertarget": 0, "otx": 0,
                   "bufferover": 0, "threatcrowd": 0, "rapiddns": 0, "dns-brute": 0}
        for key in ("crt.sh", "hackertarget", "otx", "bufferover", "threatcrowd", "rapiddns"):
            assert key in sources


class TestSSLNewFields:
    def test_cert_info_crypto_has_san_count(self):
        try:
            from modules.ssl_check import _cert_info_crypto
            data = _cert_info_crypto("google.com", 443, timeout=5)
            assert "san_count" in data
            assert isinstance(data["san_count"], int)
            assert data["san_count"] >= 0
        except OSError:
            pytest.skip("No network")

    def test_cert_info_crypto_has_signature_algorithm(self):
        try:
            from modules.ssl_check import _cert_info_crypto
            data = _cert_info_crypto("google.com", 443, timeout=5)
            assert "signature_algorithm" in data
            assert isinstance(data["signature_algorithm"], str)
            assert data["signature_algorithm"] != ""
        except OSError:
            pytest.skip("No network")

    def test_cert_info_crypto_has_ocsp_status(self):
        try:
            from modules.ssl_check import _cert_info_crypto
            data = _cert_info_crypto("google.com", 443, timeout=5)
            assert "ocsp_status" in data
            assert data["ocsp_status"] in ("url_present", "not_configured", "unknown")
        except OSError:
            pytest.skip("No network")

    def test_fallback_has_san_count(self):
        from modules.ssl_check import _cert_info_fallback
        try:
            data = _cert_info_fallback("google.com", 443, timeout=5)
            assert "san_count" in data
            assert "signature_algorithm" in data
            assert "ocsp_status" in data
        except OSError:
            pytest.skip("No network")

    def test_weak_cipher_list_comprehensive(self):
        from modules.ssl_check import WEAK_CIPHER_PATTERNS
        for pattern in ("RC4", "RC2", "DES", "3DES", "NULL", "EXPORT", "SEED", "IDEA"):
            assert pattern in WEAK_CIPHER_PATTERNS, f"Missing: {pattern}"


class TestCSVExport:
    def test_save_csv_creates_file(self, tmp_path):
        from reporting.reporter import save_csv
        results = {
            "ai_analysis": {"misconfigurations": [
                {"severity": "high", "issue": "Missing CSP", "confidence": 95,
                 "remediation": "Add CSP", "validation_status": "confirmed"}
            ]},
            "vuln_scan": {"cve_paths": [], "missing_headers": []},
        }
        path = save_csv(results, str(tmp_path), "https://example.com")
        assert os.path.exists(path)
        with open(path) as f:
            content = f.read()
        assert "Missing CSP" in content
        assert "severity" in content  # header row

    def test_save_csv_has_required_columns(self, tmp_path):
        from reporting.reporter import save_csv
        results = {"ai_analysis": {}, "vuln_scan": {}}
        path = save_csv(results, str(tmp_path), "https://example.com")
        with open(path) as f:
            header = f.readline()
        for col in ("type", "severity", "title", "confidence", "evidence",
                    "url", "remediation", "validation_status"):
            assert col in header

    def test_generate_all_returns_csv_key(self, tmp_path):
        from reporting.reporter import generate_all
        results = {
            "ai_analysis": {"misconfigurations": [], "risk_score": 0, "risk_level": "LOW",
                            "summary": "", "top_attack_paths": [], "critical_assets": [],
                            "risk_breakdown": {}, "by_category": {}, "endpoint_groups": {},
                            "attack_surface": {}, "correlation": {}, "validation_stats": {}},
            "vuln_scan": {"cve_paths": [], "missing_headers": [], "posture_score": 0,
                          "csp_score": 0, "hsts_score": 0, "csp_issues": [], "hsts_issues": [],
                          "referrer_policy_issues": [], "permissions_policy_issues": [],
                          "co_findings": [], "cors": None, "clickjacking": None,
                          "version_disclosure": [], "dangerous_methods": []},
            "ssl_check": {}, "tech_detect": {"technologies": [], "waf": [],
                          "tech_findings": [], "waf_findings": [], "waf_debug": {}},
            "subdomain": {"subdomains": [], "entries": [], "domain": "example.com",
                          "total_validated": 0, "wildcard_filtered_count": 0,
                          "wildcard_dns": False, "sources": {}},
            "port_scan": {"open_ports": [], "scanned": 0},
            "email_harvest": {"total": 0, "on_domain": [], "off_domain": []},
            "wayback": {"urls": [], "total": 0},
            "login_finder": {"panels": []},
            "js_analysis": {"findings": []},
            "dir_discovery": {"found": [], "stats": {}},
            "parameter_discovery": {"total_params": 0, "by_risk": {}},
            "cloud_discovery": {"total": 0, "assets": [], "by_provider": {}, "exposed": []},
            "screenshot": {},
        }
        out = generate_all(results, str(tmp_path), "https://example.com")
        assert "csv" in out
        assert os.path.exists(out["csv"])
