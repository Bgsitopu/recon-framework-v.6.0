"""Central configuration for the recon framework v8.0.
Includes scan profiles (fast/balanced/deep), cache settings, top-1000 ports.
"""
import os
from dataclasses import dataclass, field
from typing import Optional


def _is_proot() -> bool:
    if not os.path.exists("/proc/1/exe"):
        return True
    try:
        with open("/proc/1/cmdline", "rb") as f:
            return b"proot" in f.read()
    except Exception:
        return True


_DEFAULT_THREADS = 10 if _is_proot() else 50

TOP_1000_PORTS = [
    21, 22, 23, 25, 53, 80, 81, 88, 110, 111, 135, 139, 143, 179, 199,
    443, 444, 445, 465, 500, 512, 513, 514, 587, 593, 631, 636, 993, 995,
    1025, 1026, 1027, 1433, 1494, 1521, 1720, 1723, 1755, 1900,
    2000, 2001, 2049, 2100, 2121, 2181, 2222, 2375, 2376, 2379, 2380,
    3000, 3001, 3128, 3268, 3306, 3389, 3690,
    4000, 4040, 4443, 4444, 4567, 4848, 4899,
    5000, 5001, 5432, 5555, 5601, 5900, 5901,
    6000, 6379, 6443, 6667, 6969,
    7001, 7070, 7443, 7777,
    8000, 8001, 8008, 8009, 8080, 8081, 8082, 8083, 8084, 8085,
    8086, 8087, 8088, 8089, 8090, 8180, 8181, 8243, 8443, 8500,
    8600, 8888, 8899, 8983,
    9000, 9001, 9090, 9091, 9200, 9300, 9418,
    10000, 11211, 27017, 27018, 50000, 50070,
]

# Scan profile presets
PROFILES: dict[str, dict] = {
    "accuracy": {
        "threads": 20,
        "timeout": 20,
        "modules": [
            "subdomain", "tech_detect", "endpoint", "js_analysis",
            "dir_discovery", "login_finder", "whois_dns", "port_scan",
            "wayback", "vuln_scan", "ssl_check", "email_harvest",
            "screenshot", "parameter_discovery", "cloud_discovery",
        ],
        "ports": TOP_1000_PORTS,
        "description": "Accuracy-first: extra validation, multi-source, aggressive FP removal",
        "extra_validation": True,
        "multi_source": True,
        "port_verify_rounds": 3,
        "subdomain_probes": 10,
    },
    "fast": {
        "threads": 80,
        "timeout": 6,
        "modules": [
            "tech_detect", "vuln_scan", "ssl_check", "port_scan",
            "login_finder", "whois_dns",
        ],
        "ports": [21, 22, 23, 25, 80, 443, 445, 3306, 3389, 5432, 6379, 8080, 8443, 9200, 27017],
        "description": "Speed-first: core checks only, minimal ports",
    },
    "balanced": {
        "threads": 50,
        "timeout": 10,
        "modules": [
            "subdomain", "tech_detect", "endpoint", "js_analysis",
            "login_finder", "whois_dns", "port_scan", "vuln_scan",
            "ssl_check", "email_harvest", "parameter_discovery", "cloud_discovery",
        ],
        "ports": TOP_1000_PORTS[:200],
        "description": "Standard coverage: all key modules, top-200 ports",
    },
    "deep": {
        "threads": 30,
        "timeout": 15,
        "modules": [
            "subdomain", "tech_detect", "endpoint", "js_analysis",
            "dir_discovery", "login_finder", "whois_dns", "port_scan",
            "wayback", "vuln_scan", "ssl_check", "email_harvest",
            "screenshot", "parameter_discovery", "cloud_discovery",
        ],
        "ports": TOP_1000_PORTS,
        "description": "Maximum discovery: all modules, top-1000 ports, screenshots",
    },
}


@dataclass
class Config:
    target: str = ""
    output_dir: str = "reports"
    threads: int = field(default_factory=lambda: _DEFAULT_THREADS)
    timeout: int = 10
    retries: int = 3
    delay_min: float = 0.0
    delay_max: float = 0.0
    proxy: Optional[str] = None
    wordlist: str = "wordlists/common.txt"
    dns_wordlist: str = "wordlists/subdomains.txt"
    extensions: list = field(default_factory=lambda: [
        "php", "asp", "aspx", "jsp", "html", "js", "json", "xml",
        "txt", "bak", "env", "config",
    ])
    stealth: bool = False
    screenshot: bool = False
    profile: str = "balanced"
    modules: list = field(default_factory=lambda: list(PROFILES["balanced"]["modules"]))
    ports: list = field(default_factory=lambda: TOP_1000_PORTS[:200])
    # Cache settings
    cache_enabled: bool = True
    cache_ttl_dns: int = 300       # seconds
    cache_ttl_http: int = 60
    cache_ttl_wayback: int = 3600
    severity_keywords: dict = field(default_factory=lambda: {
        "critical": [".env", "id_rsa", "passwd", "shadow", "credentials",
                     "secret", "api_key", "token", "password", ".git"],
        "high":     ["admin", "backup", "config", "database", "db", "dump", "sql"],
        "medium":   ["login", "signin", "auth", "panel", "dashboard", "wp-admin"],
        "low":      ["robots.txt", "sitemap.xml", "readme", "changelog"],
    })

    # Accuracy benchmark mode (P12)
    accuracy_mode: bool = False
    port_verify_rounds: int = 1
    subdomain_probes: int = 5
    # Dir discovery jitter (independent of stealth)
    # Levels: "off" | "low" | "medium" | "high"
    dir_jitter: str = "off"
    dir_jitter_min: float = 0.0   # overridden by dir_jitter level at runtime
    dir_jitter_max: float = 0.0

    def apply_profile(self, name: str) -> None:
        """Apply a named scan profile to this config."""
        p = PROFILES.get(name)
        if not p:
            return
        self.profile             = name
        self.threads             = p["threads"]
        self.timeout             = p["timeout"]
        self.modules             = list(p["modules"])
        self.ports               = list(p["ports"])
        self.accuracy_mode       = p.get("extra_validation", False)
        self.port_verify_rounds  = p.get("port_verify_rounds", 1)
        self.subdomain_probes    = p.get("subdomain_probes", 5)
