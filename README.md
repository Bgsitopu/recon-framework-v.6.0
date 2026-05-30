# 🔍 Advanced Web Recon Framework

> Modular | Async | Stealth | AI-Powered | Python 3.11+ | Linux & Termux

A professional-grade web reconnaissance framework built for security researchers and penetration testers. Features async architecture, 10 specialized modules, AI-powered analysis, and a modern Rich terminal UI.

---

## ⚡ Quick Start

```bash
https://github.com/Bgsitopu/recon-framework
chmod +x install.sh && ./install.sh
python3 main.py -t https://example.com
```

---

## 🚀 Usage

```bash
# Enter Script menu
bash run.sh

# Full scan (all modules)
python3 main.py -t https://example.com

# Interactive mode (no args)
python3 main.py

# Specific modules only
python3 main.py -t https://example.com -m subdomain,tech_detect,port_scan

# Stealth mode with proxy
python3 main.py -t https://example.com --stealth --proxy http://127.0.0.1:8080

# With screenshots (requires playwright)
python3 main.py -t https://example.com --screenshot

# Custom output dir and threads
python3 main.py -t https://example.com -o /tmp/results --threads 30 --timeout 15
```

### All Options

| Flag | Description | Default |
|------|-------------|---------|
| `-t, --target` | Target URL | required |
| `-m, --modules` | Comma-separated module names | all |
| `-o, --output` | Output directory | `reports/` |
| `--threads` | Concurrent workers | 50 |
| `--timeout` | Request timeout (seconds) | 10 |
| `--stealth` | Random delays + rotating headers | off |
| `--screenshot` | Full-page screenshots via Playwright | off |
| `--proxy` | HTTP proxy URL | none |
| `--wordlist` | Custom directory wordlist | built-in |

---

## 📦 Modules

| Module | Description |
|--------|-------------|
| `subdomain` | Passive (crt.sh, HackerTarget) + DNS brute-force |
| `tech_detect` | Detect frameworks, CMS, WAF, server headers |
| `endpoint` | Extract endpoints from HTML, JS, robots.txt, sitemap |
| `js_analysis` | Download & scan JS files for secrets, API keys, tokens |
| `dir_discovery` | Async directory/file brute-force with sensitivity tagging |
| `screenshot` | Full-page screenshots via Playwright Chromium |
| `login_finder` | Find login/admin panels, detect technology |
| `whois_dns` | WHOIS, DNS records (A/MX/NS/TXT), IP geolocation |
| `port_scan` | Async TCP port scan with banner grabbing |
| `wayback` | Collect archived URLs from Wayback Machine CDX API |

---

## 🤖 AI Analysis

After all modules complete, the AI analyzer:
- Detects **misconfigurations** (exposed .env, open databases, no WAF, etc.)
- Classifies endpoints by **severity** (critical/high/medium/low/info)
- Generates a **risk score** (0–100)
- Produces a human-readable **summary**

---

## 📊 Reports

Three report formats are generated automatically:

| Format | Description |
|--------|-------------|
| `JSON` | Full structured data, machine-readable |
| `TXT` | Human-readable summary |
| `HTML` | Interactive dashboard with severity badges |

Reports saved to `reports/` (or custom `--output` dir).

---

## 🏗️ Architecture

```
recon_framework/
├── main.py                  # CLI entry point
├── core/
│   ├── config.py            # Central configuration dataclass
│   ├── logger.py            # Rich + file logging
│   ├── session.py           # aiohttp session factory + fetch with retry
│   └── queue_worker.py      # Async queue-based worker pool
├── modules/
│   ├── subdomain.py         # Subdomain enumeration
│   ├── tech_detect.py       # Technology & WAF detection
│   ├── endpoint.py          # Endpoint discovery
│   ├── js_analysis.py       # JavaScript secret scanning
│   ├── dir_discovery.py     # Directory brute-force
│   ├── screenshot.py        # Playwright screenshots
│   ├── login_finder.py      # Login panel detection
│   ├── whois_dns.py         # WHOIS, DNS, GeoIP
│   ├── port_scan.py         # Async port scanner
│   ├── wayback.py           # Wayback Machine collector
│   └── ai_analysis.py       # Rule-based AI analysis
├── utils/
│   ├── helpers.py           # URL utils, severity tagging
│   ├── user_agents.py       # UA rotation pool
│   ├── rate_limiter.py      # Token-bucket rate limiter
│   └── stealth.py           # Stealth headers, delays, shuffle
├── reporting/
│   └── reporter.py          # JSON / TXT / HTML report generator
├── wordlists/
│   ├── common.txt           # Directory wordlist
│   └── subdomains.txt       # Subdomain wordlist
├── reports/                 # Generated reports
├── logs/                    # Log files
├── requirements.txt
└── install.sh
```

---

## 🛡️ Stealth Mode

When `--stealth` is enabled:
- Random delay between requests (0.5–3.0s)
- Rotating User-Agent headers
- Randomized referer headers
- Shuffled crawl order (no sequential patterns)
- Proxy support via `--proxy`

---

## 📋 Requirements

- Python 3.11+
- Linux / Termux (Android)
- Internet connection for passive recon

### Dependencies
```
aiohttp, beautifulsoup4, dnspython, tldextract, rich, playwright, lxml
```

---

## ⚠️ Legal Disclaimer

This tool is intended for **authorized security testing only**. Only use against systems you own or have explicit written permission to test. Unauthorized use is illegal and unethical. The authors assume no liability for misuse.

---

## 🔧 Extending the Framework

Add a new module in 3 steps:

1. Create `modules/mymodule.py` with an `async def run(cfg: Config) -> dict` function
2. Import and add it to `MODULE_MAP` in `main.py`
3. Optionally add analysis logic in `modules/ai_analysis.py`
