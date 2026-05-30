"""SSL/TLS Checker v10.0 — cryptography-based cert parsing, HSTS consistency, no contradictions."""
from __future__ import annotations
import asyncio, re, ssl, socket
from datetime import datetime, timezone
from core.config import Config
from core.logger import get_logger
from utils.helpers import get_domain, normalize_url

log = get_logger("ssl_check")
WEAK_CIPHER_PATTERNS = [
    "RC4", "RC2", "DES", "3DES", "MD5", "NULL", "EXPORT", "EXPORT40", "EXPORT56",
    "anon", "ADH", "AECDH", "aNULL", "eNULL", "LOW", "EXP", "SEED", "IDEA",
    "CAMELLIA128", "PSK", "SRP", "GOST",
]


# ── Certificate date parsing ──────────────────────────────────────────────────

def _parse_cert_date(date_str: str) -> tuple[datetime | None, str]:
    """
    Parse SSL certificate date strings. Returns (datetime_utc, error_reason).
    Handles: 'Jan 01 00:00:00 2027 GMT', ASN.1 GeneralizedTime/UTCTime, ISO 8601.
    """
    if not date_str:
        return None, "notAfter field missing from certificate"
    normalised = " ".join(date_str.split())
    # ASN.1 numeric formats — disambiguate by length before trying strptime
    asn1 = normalised.endswith("Z") and normalised.replace("Z", "").isdigit()
    if asn1:
        fmt = "%y%m%d%H%M%SZ" if len(normalised) == 13 else "%Y%m%d%H%M%SZ"
        try:
            dt = datetime.strptime(normalised, fmt).replace(tzinfo=timezone.utc)
            return dt, ""
        except ValueError as e:
            return None, f"ASN.1 parse error: {e}"
    formats = [
        "%b %d %H:%M:%S %Y %Z",
        "%b %d %H:%M:%S %Y",
        "%Y-%m-%dT%H:%M:%SZ",
    ]
    for fmt in formats:
        try:
            dt = datetime.strptime(normalised, fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt, ""
        except ValueError:
            continue
    return None, f"Unrecognised date format: {date_str!r}"


def _parse_dn(dn_list: list) -> dict:
    return {k: v for pair in dn_list for k, v in pair}


# ── Primary: cryptography-based cert extraction ───────────────────────────────

def _cert_info_crypto(host: str, port: int, timeout: float) -> dict:
    """Extract cert data using cryptography library (DER binary form). Most reliable."""
    from cryptography import x509 as cx509
    from cryptography.hazmat.backends import default_backend
    from cryptography.x509.oid import NameOID

    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as s:
            der         = s.getpeercert(binary_form=True)
            cipher_info = s.cipher()
            protocol    = s.version()

    cert = cx509.load_der_x509_certificate(der, default_backend())

    def _name_attr(name, oid):
        try:
            return name.get_attributes_for_oid(oid)[0].value
        except Exception:
            return ""

    subject_cn = _name_attr(cert.subject, NameOID.COMMON_NAME)
    subject_o  = _name_attr(cert.subject, NameOID.ORGANIZATION_NAME)
    subject_c  = _name_attr(cert.subject, NameOID.COUNTRY_NAME)
    issuer_cn  = _name_attr(cert.issuer,  NameOID.COMMON_NAME)
    issuer_o   = _name_attr(cert.issuer,  NameOID.ORGANIZATION_NAME)
    issuer_c   = _name_attr(cert.issuer,  NameOID.COUNTRY_NAME)

    # SANs
    try:
        san_ext = cert.extensions.get_extension_for_class(cx509.SubjectAlternativeName)
        sans = san_ext.value.get_values_for_type(cx509.DNSName)[:30]
    except Exception:
        sans = []

    # Signature algorithm
    try:
        sig_alg = cert.signature_hash_algorithm.name if cert.signature_hash_algorithm else "unknown"
        sig_alg_full = type(cert.signature_algorithm_oid).__name__ or sig_alg
        # Use OID dotted string for accuracy
        sig_algorithm = f"{sig_alg}"
    except Exception:
        sig_algorithm = "unknown"

    # OCSP status — check AIA extension for OCSP URL (actual stapling check is network-dependent)
    ocsp_url = ""
    ocsp_status = "unknown"
    try:
        from cryptography.x509.oid import ExtensionOID
        aia = cert.extensions.get_extension_for_oid(ExtensionOID.AUTHORITY_INFORMATION_ACCESS)
        from cryptography.x509 import AuthorityInformationAccessOID
        for access in aia.value:
            if access.access_method == AuthorityInformationAccessOID.OCSP:
                ocsp_url = access.access_location.value
                ocsp_status = "url_present"
                break
    except Exception:
        ocsp_status = "not_configured"

    # Validity dates — always available from cryptography
    try:
        not_after_dt  = cert.not_valid_after_utc
    except AttributeError:
        # older cryptography versions
        not_after_dt  = cert.not_valid_after.replace(tzinfo=timezone.utc)
    try:
        not_before_dt = cert.not_valid_before_utc
    except AttributeError:
        not_before_dt = cert.not_valid_before.replace(tzinfo=timezone.utc)

    days_left = (not_after_dt - datetime.now(timezone.utc)).days

    return {
        "protocol":          protocol,
        "cipher":            cipher_info[0] if cipher_info else "unknown",
        "cipher_bits":       cipher_info[2] if cipher_info else 0,
        "subject_cn":        subject_cn,
        "subject_o":         subject_o,
        "subject_c":         subject_c,
        "issuer_cn":         issuer_cn,
        "issuer_o":          issuer_o,
        "issuer_c":          issuer_c,
        "serial":            str(cert.serial_number),
        "not_before":        not_before_dt.strftime("%Y-%m-%d"),
        "not_after":         not_after_dt.strftime("%Y-%m-%d"),
        "days_until_expiry": days_left,
        "expiry_date":       not_after_dt.strftime("%Y-%m-%d"),
        "expiry_parse_error": "",
        "sans":              list(sans),
        "san_count":         len(sans),
        "signature_algorithm": sig_algorithm,
        "ocsp_url":          ocsp_url,
        "ocsp_status":       ocsp_status,
        "expired":           days_left < 0,
        "expiry_warning":    0 <= days_left <= 30,
        "_parse_method":     "cryptography",
    }


# ── Fallback: string-based cert extraction ────────────────────────────────────

def _cert_info_fallback(host: str, port: int, timeout: float) -> dict:
    """Fallback using ssl.CERT_REQUIRED (verified) to get populated getpeercert() dict."""
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_REQUIRED
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host) as s:
                cert        = s.getpeercert()
                cipher_info = s.cipher()
                protocol    = s.version()
    except ssl.SSLCertVerificationError:
        # Chain invalid — fall back to CERT_NONE but parse string dates
        ctx2 = ssl.create_default_context()
        ctx2.check_hostname = False
        ctx2.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx2.wrap_socket(sock, server_hostname=host) as s:
                cert        = s.getpeercert()
                cipher_info = s.cipher()
                protocol    = s.version()

    subject = _parse_dn(cert.get("subject", []))
    issuer  = _parse_dn(cert.get("issuer", []))
    sans    = [v for t, v in cert.get("subjectAltName", []) if t == "DNS"]
    not_after_str  = cert.get("notAfter", "")
    not_before_str = cert.get("notBefore", "")

    not_after_dt, date_error = _parse_cert_date(not_after_str)
    if not_after_dt is not None:
        days_left = (not_after_dt - datetime.now(timezone.utc)).days
        expiry_parse_error = ""
    else:
        days_left = None
        expiry_parse_error = date_error
        log.warning(f"[ssl_check] Fallback date parse failed: {date_error} | raw={not_after_str!r}")

    return {
        "protocol":          protocol,
        "cipher":            cipher_info[0] if cipher_info else "unknown",
        "cipher_bits":       cipher_info[2] if cipher_info else 0,
        "subject_cn":        subject.get("commonName", ""),
        "subject_o":         subject.get("organizationName", ""),
        "subject_c":         subject.get("countryName", ""),
        "issuer_cn":         issuer.get("commonName", ""),
        "issuer_o":          issuer.get("organizationName", ""),
        "issuer_c":          issuer.get("countryName", ""),
        "serial":            cert.get("serialNumber", ""),
        "not_before":        not_before_str,
        "not_after":         not_after_str,
        "days_until_expiry": days_left,
        "expiry_date":       not_after_dt.strftime("%Y-%m-%d") if not_after_dt else None,
        "expiry_parse_error": expiry_parse_error,
        "sans":              sans[:30],
        "san_count":         len(sans[:30]),
        "signature_algorithm": "unknown",
        "ocsp_url":          "",
        "ocsp_status":       "unknown",
        "expired":           days_left is not None and days_left < 0,
        "expiry_warning":    days_left is not None and 0 <= days_left <= 30,
        "_parse_method":     "fallback_string",
    }


def _cert_info_unverified(host: str, port: int, timeout: float) -> dict:
    """Try cryptography first, fall back to string parsing."""
    try:
        return _cert_info_crypto(host, port, timeout)
    except ImportError:
        log.warning("[ssl_check] cryptography not available, using string fallback")
    except Exception as e:
        log.warning(f"[ssl_check] cryptography parse failed ({e}), using string fallback")
    return _cert_info_fallback(host, port, timeout)


# ── Chain verification ────────────────────────────────────────────────────────

def _verify_chain(host: str, port: int, timeout: float) -> tuple[bool, str]:
    ctx = ssl.create_default_context()
    ctx.check_hostname = True
    ctx.verify_mode = ssl.CERT_REQUIRED
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True, ""
    except ssl.SSLCertVerificationError as e:
        return False, str(e)
    except Exception as e:
        return False, str(e)


def _is_self_signed(cert_data: dict) -> bool:
    return (
        cert_data["subject_cn"] == cert_data["issuer_cn"]
        and cert_data.get("subject_o", "X") == cert_data.get("issuer_o", "X")
    )


def _probe_weak_protocol(host: str, port: int, proto_name: str) -> bool:
    proto_const = getattr(ssl, proto_name, None)
    if not proto_const:
        return False
    try:
        ctx = ssl.SSLContext(proto_const)
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        with socket.create_connection((host, port), timeout=4) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True
    except Exception:
        return False


def _check_weak_protocols(host: str, port: int) -> list[str]:
    return [
        name.replace("PROTOCOL_", "").replace("_", ".")
        for name in ["PROTOCOL_TLSv1", "PROTOCOL_TLSv1_1"]
        if _probe_weak_protocol(host, port, name)
    ]


def _finding(issue: str, severity: str, confidence: int, evidence: str,
             validation_status: str = "confirmed") -> dict:
    return {
        "issue": issue, "severity": severity,
        "confidence": confidence, "evidence": evidence,
        "validation_status": validation_status,
        "detection_method": "certificate_analysis",
    }


# ── Main run ──────────────────────────────────────────────────────────────────

async def run(cfg: Config) -> dict:
    host = get_domain(normalize_url(cfg.target))
    log.info(f"[ssl_check] Checking {host}:443")
    loop = asyncio.get_event_loop()

    (chain_valid, chain_error), cert_data = await asyncio.gather(
        loop.run_in_executor(None, _verify_chain, host, 443, cfg.timeout),
        loop.run_in_executor(None, _cert_info_unverified, host, 443, cfg.timeout),
    )

    self_signed = (not chain_valid) and _is_self_signed(cert_data)
    weak_protocols = await loop.run_in_executor(None, _check_weak_protocols, host, 443)
    cipher_name    = cert_data.get("cipher", "")
    weak_ciphers   = [p for p in WEAK_CIPHER_PATTERNS if p.upper() in cipher_name.upper()]

    # HSTS — single source of truth; track fetch success
    hsts, hsts_value, hsts_max_age, hsts_fetch_ok = False, "", 0, False
    try:
        import aiohttp
        async with aiohttp.ClientSession() as session:
            async with session.get(f"https://{host}", ssl=False,
                                   timeout=aiohttp.ClientTimeout(total=cfg.timeout)) as r:
                hsts_value = r.headers.get("Strict-Transport-Security", "")
                hsts = bool(hsts_value)
                if hsts:
                    m = re.search(r"max-age=(\d+)", hsts_value)
                    hsts_max_age = int(m.group(1)) if m else 0
                hsts_fetch_ok = True
    except Exception:
        pass

    # cert_type — mutually exclusive
    if chain_valid:
        cert_type = "trusted_ca"
    elif self_signed:
        cert_type = "self_signed"
    elif chain_error:
        cert_type = "untrusted_ca"
    else:
        cert_type = "unknown"

    # HSTS status
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

    # Findings
    findings: list[dict] = []
    days = cert_data.get("days_until_expiry")

    if cert_data.get("expired"):
        findings.append(_finding("Certificate expired", "critical", 99,
                                 f"notAfter={cert_data['not_after']}"))
    if cert_data.get("expiry_warning"):
        findings.append(_finding(f"Certificate expires in {days} days", "high", 99,
                                 f"notAfter={cert_data['not_after']}"))
    if cert_data.get("expiry_parse_error"):
        findings.append(_finding(
            f"Could not parse expiry date: {cert_data['expiry_parse_error']}",
            "medium", 70, cert_data.get("not_after", ""), "suspected"))
    if self_signed:
        findings.append(_finding("Self-signed certificate", "high", 95,
                                 f"subject={cert_data['subject_cn']} issuer={cert_data['issuer_cn']}"))
    elif cert_type == "untrusted_ca":
        findings.append(_finding("Untrusted CA / chain error", "high", 90,
                                 chain_error[:120]))
    if not chain_valid:
        findings.append(_finding(f"Chain validation failed: {chain_error[:80]}", "high", 95,
                                 chain_error[:200]))
    for proto in weak_protocols:
        findings.append(_finding(f"Weak protocol supported: {proto}", "high", 90,
                                 f"TLS handshake succeeded with {proto}"))
    for c in weak_ciphers:
        findings.append(_finding(f"Weak cipher in use: {c}", "medium", 85,
                                 f"Negotiated cipher: {cipher_name}"))
    if not hsts and hsts_fetch_ok:
        findings.append(_finding("HSTS not enabled", "medium", 99,
                                 "Strict-Transport-Security header absent", "confirmed"))
    elif hsts and hsts_max_age < 31536000:
        findings.append(_finding(f"HSTS max-age too short ({hsts_max_age}s)", "low", 99,
                                 f"Strict-Transport-Security: {hsts_value}"))
    bits = cert_data.get("cipher_bits", 256)
    if isinstance(bits, int) and bits < 128:
        findings.append(_finding(f"Weak key size: {bits} bits", "high", 90,
                                 f"Cipher bits={bits}"))

    days_display = f"{days}d" if days is not None else "unknown"
    log.info(
        f"[ssl_check] cert_type={cert_type} chain={'OK' if chain_valid else 'FAIL'} "
        f"hsts={hsts_status} expires={days_display} "
        f"parse_method={cert_data.get('_parse_method','?')} findings={len(findings)}"
    )

    result = {
        **cert_data,
        "host": host, "port": 443,
        "cert_type": cert_type,
        "self_signed": self_signed,
        "chain_valid": chain_valid,
        "chain_error": chain_error,
        "hsts": hsts,
        "hsts_value": hsts_value,
        "hsts_max_age": hsts_max_age,
        "hsts_status": hsts_status,
        "weak_protocols": weak_protocols,
        "weak_ciphers": weak_ciphers,
        "findings": findings,
    }
    return result
