"""Port Scanner v9.0 — P7: verification phase, confidence scores."""
from __future__ import annotations
import asyncio, re, socket
import aiohttp
from core.config import Config
from core.logger import get_logger
from utils.helpers import get_domain, normalize_url

log = get_logger("port_scan")

PORT_SERVICES = {
    21:"FTP",22:"SSH",23:"Telnet",25:"SMTP",53:"DNS",80:"HTTP",110:"POP3",
    143:"IMAP",443:"HTTPS",445:"SMB",465:"SMTPS",587:"SMTP-Sub",993:"IMAPS",
    995:"POP3S",1433:"MSSQL",1521:"Oracle",2181:"Zookeeper",2375:"Docker",
    2376:"Docker-TLS",3000:"Dev-HTTP",3306:"MySQL",3389:"RDP",4848:"GlassFish",
    5000:"Flask/Dev",5432:"PostgreSQL",5601:"Kibana",5900:"VNC",6379:"Redis",
    6443:"K8s-API",7001:"WebLogic",8000:"HTTP-Alt",8080:"HTTP-Alt",8081:"HTTP-Alt",
    8443:"HTTPS-Alt",8888:"Jupyter",9000:"PHP-FPM",9090:"Prometheus",
    9200:"Elasticsearch",9300:"ES-Transport",11211:"Memcached",
    27017:"MongoDB",27018:"MongoDB-Shard",50000:"SAP",50070:"Hadoop-HDFS",
}
WEB_PORTS = {80,443,8080,8443,8000,8081,8888,3000,5000,5601,9090,9200}
_FP_PATTERNS = [r"(OpenSSH[_\s][\d\.]+)",r"(nginx/[\d\.]+)",r"(Apache/[\d\.]+)",
                r"(MySQL\s[\d\.]+)",r"(Redis\s[\d\.]+)",r"(SSH-[\d\.]+-[\w\.\-]+)"]

def _fingerprint(banner: str) -> str:
    for p in _FP_PATTERNS:
        m = re.search(p, banner, re.IGNORECASE)
        if m: return m.group(1)
    return (banner.splitlines()[0].strip()[:80]) if banner else ""

async def _grab_banner(reader, writer, host: str) -> str:
    try:
        writer.write(b"HEAD / HTTP/1.0\r\nHost: "+host.encode()+b"\r\n\r\n")
        await writer.drain()
        data = await asyncio.wait_for(reader.read(512), timeout=2.0)
        return data.decode(errors="replace").strip()[:200]
    except Exception:
        return ""

async def _http_title(host: str, port: int, timeout: float) -> str:
    scheme = "https" if port in (443,8443) else "http"
    try:
        async with aiohttp.ClientSession() as s:
            async with s.get(f"{scheme}://{host}:{port}/", ssl=False,
                             timeout=aiohttp.ClientTimeout(total=timeout),
                             allow_redirects=True) as r:
                text = await r.text(errors="replace")
                m = re.search(r"<title[^>]*>([^<]{1,120})</title>", text, re.IGNORECASE)
                return m.group(1).strip() if m else ""
    except Exception:
        return ""

async def _scan_port(host: str, port: int, timeout: float) -> dict | None:
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=timeout)
        service = PORT_SERVICES.get(port, "unknown")
        banner  = await _grab_banner(reader, writer, host)
        writer.close()
        try: await writer.wait_closed()
        except Exception: pass
        title = await _http_title(host, port, timeout) if port in WEB_PORTS else ""
        fp = _fingerprint(banner)
        # Determine detection method
        if fp:
            detection_method = "banner+fingerprint"
        elif title:
            detection_method = "http_title"
        else:
            detection_method = "tcp_connect"
        # Protocol: HTTPS ports use TLS
        protocol = "tcp"
        if port in (443, 8443, 465, 993, 995, 2376):
            protocol = "tcp/tls"
        return {"port": port, "protocol": protocol, "service": service,
                "banner": banner, "fingerprint": fp, "title": title,
                "state": "open", "detection_method": detection_method}
    except Exception:
        return None

async def _verify(host: str, port: int) -> bool:
    """Re-check port once to eliminate transient false positives."""
    try:
        reader, writer = await asyncio.wait_for(
            asyncio.open_connection(host, port), timeout=3.0)
        writer.close()
        try: await writer.wait_closed()
        except Exception: pass
        return True
    except Exception:
        return False

async def run(cfg: Config) -> dict:
    domain = get_domain(normalize_url(cfg.target))
    try: host = socket.gethostbyname(domain)
    except Exception: host = domain

    log.info(f"[port_scan] Scanning {host} — {len(cfg.ports)} ports")
    sem = asyncio.Semaphore(150)
    async def bounded(p):
        async with sem: return await _scan_port(host, p, timeout=2.5)

    raw = [r for r in await asyncio.gather(*[bounded(p) for p in cfg.ports]) if r]

    # Verification phase
    vsem = asyncio.Semaphore(50)
    async def do_verify(entry: dict) -> dict:
        async with vsem:
            ok = await _verify(host, entry["port"])
            return {**entry, "verified": ok,
                    "confidence": 95 if ok else 30,
                    "validation_status": "confirmed" if ok else "suspected"}

    verified = await asyncio.gather(*[do_verify(e) for e in raw])
    open_ports = sorted([p for p in verified if p["verified"]], key=lambda x: x["port"])
    fp_removed = len(raw) - len(open_ports)

    log.info(f"[port_scan] open={len(open_ports)} fp_removed={fp_removed} "
             f"ports={[p['port'] for p in open_ports]}")
    return {"host":host,"domain":domain,"scanned":len(cfg.ports),
            "open_ports":open_ports,"fp_removed":fp_removed}
