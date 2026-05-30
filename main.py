#!/usr/bin/env python3
"""
Advanced Web Recon Framework v6.0
Smart TUI | Self-Diagnostic | AI-Powered | Vuln Scan | SSL Check | Email Harvest
"""
# ── Bootstrap: install missing packages BEFORE any other import ───────────────
import sys, subprocess, importlib

_REQUIRED = {
    "aiohttp":      "aiohttp",
    "bs4":          "beautifulsoup4",
    "dns":          "dnspython",
    "tldextract":   "tldextract",
    "rich":         "rich",
    "lxml":         "lxml",
}

def _is_proot() -> bool:
    """Detect proot/proot-distro environment."""
    import os
    if not os.path.exists("/proc/1/exe"):
        return True
    try:
        with open("/proc/1/cmdline", "rb") as f:
            return b"proot" in f.read()
    except Exception:
        return True


def _apt_install(pkg: str) -> bool:
    """Try to install a system package via apt (silent)."""
    try:
        r = subprocess.run(
            ["apt-get", "install", "-y", "--no-install-recommends", pkg],
            capture_output=True, timeout=120,
            env={**__import__("os").environ, "DEBIAN_FRONTEND": "noninteractive"},
        )
        return r.returncode == 0
    except Exception:
        return False


def _pip_install_one(pip_name: str) -> bool:
    """Install one pip package; try --break-system-packages then plain."""
    for extra in [["--break-system-packages"], []]:
        try:
            r = subprocess.run(
                [sys.executable, "-m", "pip", "install", pip_name, "-q"] + extra,
                capture_output=True, timeout=120,
            )
            if r.returncode == 0:
                return True
        except Exception:
            continue
    return False


# Packages that need system build-deps and their apt equivalents
_BUILD_DEPS = {
    "lxml":       ("libxml2-dev", "libxslt1-dev", "python3-lxml"),
    "dnspython":  (),
}


def _bootstrap():
    missing = []
    for imp, pip in _REQUIRED.items():
        try:
            importlib.import_module(imp)
        except ImportError:
            missing.append((imp, pip))
    if not missing:
        return

    print(f"[bootstrap] Installing: {', '.join(p for _, p in missing)}")

    for imp, pip in missing:
        # For packages with known build deps, try apt binary first
        if pip in _BUILD_DEPS:
            apt_pkgs = _BUILD_DEPS[pip]
            if apt_pkgs:
                # Try installing the python3-* apt binary package
                py_apt = next((p for p in apt_pkgs if p.startswith("python3-")), None)
                if py_apt and _apt_install(py_apt):
                    # Make it visible to current interpreter via apt-installed path
                    site = subprocess.run(
                        [sys.executable, "-c",
                         "import site; print(site.getsitepackages()[0])"],
                        capture_output=True, text=True
                    ).stdout.strip()
                    if site and site not in sys.path:
                        sys.path.insert(0, site)
                    try:
                        importlib.import_module(imp)
                        continue  # success via apt
                    except ImportError:
                        pass
                # Install build deps then pip install
                for dep in apt_pkgs:
                    if not dep.startswith("python3-"):
                        _apt_install(dep)

        ok = _pip_install_one(pip)
        if not ok:
            print(f"[bootstrap] WARNING: could not install {pip}")

        try:
            importlib.import_module(imp)
        except ImportError:
            pass

_bootstrap()
# ─────────────────────────────────────────────────────────────────────────────

import asyncio
import os
import signal
import json
from datetime import datetime

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt, Confirm
from rich.text import Text
from rich.rule import Rule
from rich.align import Align

from core.config import Config
from core.logger import get_logger
from core.doctor import run_diagnostics, print_report
from core.session_manager import (
    save_profile, load_profile, list_profiles, delete_profile,
    record_scan, get_history, clear_history,
)
from reporting.reporter import generate_all

# Lazy-load recon modules (imported here after bootstrap ensures deps exist)
def _load_modules():
    from modules import (
        subdomain, tech_detect, endpoint, js_analysis,
        dir_discovery, screenshot, login_finder,
        whois_dns, port_scan, wayback,
        vuln_scan, ssl_check, email_harvest,
    )
    from modules.parameter_discovery import run as param_run
    from modules.cloud_discovery import run as cloud_run
    from modules.ai_analysis import run_sync as ai_run
    return {
        "subdomain":            ("🌐", "Subdomain Enumeration",  subdomain.run),
        "tech_detect":          ("🔧", "Technology Detection",   tech_detect.run),
        "endpoint":             ("🔗", "Endpoint Discovery",     endpoint.run),
        "js_analysis":          ("📜", "JavaScript Analysis",    js_analysis.run),
        "dir_discovery":        ("📁", "Directory Discovery",    dir_discovery.run),
        "screenshot":           ("📸", "Screenshot Capture",     screenshot.run),
        "login_finder":         ("🔑", "Login Panel Finder",     login_finder.run),
        "whois_dns":            ("🌍", "WHOIS & DNS Info",       whois_dns.run),
        "port_scan":            ("🔌", "Port Scanner",           port_scan.run),
        "wayback":              ("⏳", "Wayback Machine",        wayback.run),
        "vuln_scan":            ("🛡", "Vulnerability Scan",     vuln_scan.run),
        "ssl_check":            ("🔒", "SSL/TLS Check",          ssl_check.run),
        "email_harvest":        ("📧", "Email Harvester",        email_harvest.run),
        "parameter_discovery":  ("🔎", "Parameter Discovery",   param_run),
        "cloud_discovery":      ("☁️ ", "Cloud Discovery",       cloud_run),
    }, ai_run


# ── Dependency graph for concurrent execution ─────────────────────────────────
# Modules in the same stage run concurrently via asyncio.gather().
# Each stage waits for the previous to complete.
# Modules that accept prior_results get them injected automatically.
_STAGES: list[list[str]] = [
    # Stage 0 — no dependencies, run first in parallel
    ["subdomain", "tech_detect", "whois_dns", "ssl_check", "port_scan"],
    # Stage 1 — needs stage 0 results (subdomain list, tech stack)
    ["endpoint", "js_analysis", "login_finder", "email_harvest", "wayback"],
    # Stage 2 — needs endpoints, JS, wayback
    ["dir_discovery", "vuln_scan", "parameter_discovery", "cloud_discovery"],
    # Stage 3 — needs everything above
    ["screenshot"],
]
# Modules that accept prior_results as second argument
_NEEDS_PRIOR = {"parameter_discovery", "cloud_discovery", "screenshot"}

console = Console()
log = get_logger("main")

# MODULE_MAP and ai_run are populated lazily on first use
MODULE_MAP: dict = {}
ai_run = None

def _ensure_modules():
    """Load recon modules on first use (after bootstrap has run)."""
    global MODULE_MAP, ai_run
    if not MODULE_MAP:
        MODULE_MAP, ai_run = _load_modules()

BANNER = """\
[bold cyan] ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗[/bold cyan]
[bold cyan] ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║[/bold cyan]
[bold cyan] ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║[/bold cyan]
[bold cyan] ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║[/bold cyan]
[bold cyan] ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║[/bold cyan]
[bold cyan] ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝[/bold cyan]
[bold yellow]   Advanced Web Recon Framework v7.0[/bold yellow]
[dim]   Source-Tagged · Evidence-Based · Top-1000 Ports · Attack Surface Mapping[/dim]"""

SEV_COLOR = {"critical": "red", "high": "orange3", "medium": "yellow", "low": "blue", "info": "dim"}


# ── UI Helpers ────────────────────────────────────────────────────────────────

def print_banner():
    console.print()
    console.print(Align.center(BANNER))
    console.print(Align.center(
        "[dim red]For authorized security testing only. Use responsibly.[/dim red]"
    ))
    console.print()


def _pick(prompt: str, choices: list[str], default: str = "") -> str:
    """Show numbered choices, return selected value."""
    for i, c in enumerate(choices, 1):
        console.print(f"  [cyan]{i}[/cyan]. {c}")
    raw = Prompt.ask(prompt, default=default)
    if raw.isdigit() and 1 <= int(raw) <= len(choices):
        return choices[int(raw) - 1]
    return raw


def _module_table(selected: list[str]) -> Table:
    t = Table(show_header=True, header_style="bold cyan", expand=False, box=None)
    t.add_column("#", width=3, style="dim")
    t.add_column("Key", width=14)
    t.add_column("Icon+Name", width=28)
    t.add_column("Selected", width=10)
    for i, (key, (icon, name, _)) in enumerate(MODULE_MAP.items(), 1):
        tick = "[green]✓[/green]" if key in selected else "[dim]·[/dim]"
        t.add_row(str(i), key, f"{icon} {name}", tick)
    return t


def _config_table(cfg: Config) -> Table:
    t = Table(show_header=False, box=None, expand=False, padding=(0, 2))
    t.add_column("Key", style="bold cyan", width=18)
    t.add_column("Value")
    t.add_row("Target",    f"[green]{cfg.target or '(not set)'}[/green]")
    t.add_row("Modules",   f"{len(cfg.modules)} selected")
    t.add_row("Threads",   str(cfg.threads))
    t.add_row("Timeout",   f"{cfg.timeout}s")
    t.add_row("Stealth",   "[green]ON[/green]" if cfg.stealth else "[dim]OFF[/dim]")
    t.add_row("Screenshot","[green]ON[/green]" if cfg.screenshot else "[dim]OFF[/dim]")
    t.add_row("Proxy",     cfg.proxy or "[dim]none[/dim]")
    t.add_row("Wordlist",  cfg.wordlist)
    t.add_row("Output",    cfg.output_dir)
    return t


# ── Sub-menus ─────────────────────────────────────────────────────────────────

def menu_select_modules(cfg: Config):
    """Interactive module toggle menu."""
    while True:
        console.print(Rule("[bold cyan]Module Selection[/bold cyan]"))
        console.print(_module_table(cfg.modules))
        console.print(
            "\n[dim]Enter module number to toggle, [bold]all[/bold] to select all, "
            "[bold]none[/bold] to clear, [bold]done[/bold] to confirm[/dim]"
        )
        raw = Prompt.ask("Action", default="done").strip().lower()
        if raw == "done":
            break
        elif raw == "all":
            cfg.modules = list(MODULE_MAP.keys())
        elif raw == "none":
            cfg.modules = []
        elif raw.isdigit():
            idx = int(raw) - 1
            keys = list(MODULE_MAP.keys())
            if 0 <= idx < len(keys):
                k = keys[idx]
                if k in cfg.modules:
                    cfg.modules.remove(k)
                else:
                    cfg.modules.append(k)
        else:
            # allow typing module name directly
            if raw in MODULE_MAP:
                if raw in cfg.modules:
                    cfg.modules.remove(raw)
                else:
                    cfg.modules.append(raw)


def menu_edit_config(cfg: Config):
    """Live config editor — edit any field."""
    while True:
        console.print(Rule("[bold cyan]Configuration Editor[/bold cyan]"))
        console.print(_config_table(cfg))
        console.print(
            "\n[dim]Options: [bold]target[/bold] · [bold]threads[/bold] · "
            "[bold]timeout[/bold] · [bold]stealth[/bold] · [bold]screenshot[/bold] · "
            "[bold]proxy[/bold] · [bold]wordlist[/bold] · [bold]output[/bold] · "
            "[bold]modules[/bold] · [bold]dirmode[/bold] · [bold]done[/bold][/dim]"
        )
        field = Prompt.ask("Edit field", default="done").strip().lower()

        if field == "done":
            break
        elif field == "target":
            cfg.target = Prompt.ask("Target URL").strip()
        elif field == "threads":
            cfg.threads = int(Prompt.ask("Threads", default=str(cfg.threads)))
        elif field == "timeout":
            cfg.timeout = int(Prompt.ask("Timeout (seconds)", default=str(cfg.timeout)))
        elif field == "stealth":
            cfg.stealth = Confirm.ask("Enable stealth mode?", default=cfg.stealth)
            if cfg.stealth:
                cfg.delay_min, cfg.delay_max = 0.5, 3.0
            else:
                cfg.delay_min = cfg.delay_max = 0.0
        elif field == "screenshot":
            cfg.screenshot = Confirm.ask("Enable screenshots?", default=cfg.screenshot)
        elif field == "proxy":
            v = Prompt.ask("Proxy URL (blank to clear)", default=cfg.proxy or "")
            cfg.proxy = v.strip() or None
        elif field == "wordlist":
            v = Prompt.ask("Wordlist path", default=cfg.wordlist)
            if os.path.exists(v):
                cfg.wordlist = v
            else:
                console.print(f"[red]File not found: {v}[/red]")
        elif field == "output":
            cfg.output_dir = Prompt.ask("Output directory", default=cfg.output_dir)
        elif field == "modules":
            menu_select_modules(cfg)
        elif field == "dirmode":
            console.print("  [cyan]1[/cyan]. full  — semua wordlist (lambat)")
            console.print("  [cyan]2[/cyan]. fast  — hanya sensitive files, tanpa wordlist")
            console.print("  [cyan]3[/cyan]. off   — skip dir_discovery")
            mode = Prompt.ask("Mode", default="1").strip()
            if mode in ("1","full"):
                if "dir_discovery" not in cfg.modules:
                    cfg.modules.append("dir_discovery")
                cfg.wordlist = "wordlists/common.txt"
                console.print("[green]Dir discovery: FULL[/green]")
            elif mode in ("2","fast"):
                if "dir_discovery" not in cfg.modules:
                    cfg.modules.append("dir_discovery")
                cfg.wordlist = "wordlists/sensitive_only.txt"
                # buat wordlist kecil jika belum ada
                if not os.path.exists(cfg.wordlist):
                    os.makedirs("wordlists", exist_ok=True)
                    with open(cfg.wordlist, "w") as f:
                        f.write("\n".join([
                            ".env",".git/config",".htpasswd","web.config","config.php",
                            "wp-config.php","backup.zip","dump.sql","phpinfo.php",
                            "admin","login","phpmyadmin","adminer.php","server-status",
                        ]))
                console.print("[yellow]Dir discovery: FAST (sensitive files only)[/yellow]")
            elif mode in ("3","off"):
                cfg.modules = [m for m in cfg.modules if m != "dir_discovery"]
                console.print("[dim]Dir discovery: OFF[/dim]")
        else:
            console.print(f"[red]Unknown field: {field}[/red]")


# ── Profile Menu ──────────────────────────────────────────────────────────────

def menu_profiles(cfg: Config):
    while True:
        console.print(Rule("[bold cyan]Profiles[/bold cyan]"))
        profiles = list_profiles()
        if profiles:
            t = Table(show_header=True, header_style="bold cyan", box=None)
            t.add_column("#", width=4, style="dim")
            t.add_column("Profile Name")
            for i, p in enumerate(profiles, 1):
                t.add_row(str(i), p)
            console.print(t)
        else:
            console.print("[dim]No saved profiles.[/dim]")

        console.print("\n[dim][bold]save[/bold] · [bold]load <name>[/bold] · "
                      "[bold]delete <name>[/bold] · [bold]back[/bold][/dim]")
        raw = Prompt.ask("Action", default="back").strip()

        if raw == "back":
            break
        elif raw == "save":
            name = Prompt.ask("Profile name").strip()
            if name:
                save_profile(name, cfg)
                console.print(f"[green]✓ Saved profile '{name}'[/green]")
        elif raw.startswith("load"):
            parts = raw.split(None, 1)
            name = parts[1] if len(parts) > 1 else (_pick("Select profile", profiles) if profiles else "")
            if name:
                loaded = load_profile(name)
                if loaded:
                    # copy fields into cfg
                    for attr in vars(loaded):
                        setattr(cfg, attr, getattr(loaded, attr))
                    console.print(f"[green]✓ Loaded profile '{name}'[/green]")
                else:
                    console.print(f"[red]Profile '{name}' not found.[/red]")
        elif raw.startswith("delete"):
            parts = raw.split(None, 1)
            name = parts[1] if len(parts) > 1 else (_pick("Select profile", profiles) if profiles else "")
            if name and Confirm.ask(f"Delete '{name}'?", default=False):
                delete_profile(name)
                console.print(f"[yellow]Deleted '{name}'[/yellow]")


# ── History Viewer ────────────────────────────────────────────────────────────

def menu_history():
    console.print(Rule("[bold cyan]Scan History[/bold cyan]"))
    history = get_history()
    if not history:
        console.print("[dim]No scan history yet.[/dim]")
        Prompt.ask("Press Enter to continue", default="")
        return

    t = Table(show_header=True, header_style="bold cyan", expand=True)
    t.add_column("#", width=4, style="dim")
    t.add_column("Timestamp", width=20)
    t.add_column("Target")
    t.add_column("Modules", width=8)
    t.add_column("Risk", width=6)
    t.add_column("Reports")

    for i, h in enumerate(reversed(history[-20:]), 1):
        risk = h.get("risk_score", "?")
        rc = "red" if isinstance(risk, int) and risk >= 70 else "yellow" if isinstance(risk, int) and risk >= 40 else "green"
        reports = " ".join(h.get("reports", {}).keys())
        t.add_row(
            str(i),
            h.get("timestamp", "")[:19],
            h.get("target", ""),
            str(len(h.get("modules", []))),
            f"[{rc}]{risk}[/{rc}]",
            reports,
        )
    console.print(t)

    raw = Prompt.ask("\n[dim]Enter # to view report path, [bold]clear[/bold] to wipe, Enter to go back[/dim]",
                     default="").strip()
    if raw == "clear":
        if Confirm.ask("Clear all history?", default=False):
            clear_history()
            console.print("[yellow]History cleared.[/yellow]")
    elif raw.isdigit():
        idx = len(history) - int(raw)
        if 0 <= idx < len(history):
            entry = history[idx]
            console.print(Panel(
                json.dumps(entry, indent=2),
                title=f"[cyan]{entry.get('target','')}[/cyan]",
                expand=False
            ))
            Prompt.ask("Press Enter to continue", default="")


# ── Results Viewer ────────────────────────────────────────────────────────────

def menu_view_results(results: dict):
    """Interactive results browser v6.0 — 10+ analysis features."""
    target = results.get("target", "")
    ai     = results.get("ai_analysis", {})

    MENU = [
        ("📋", "Raw Section Viewer",        "_view_raw"),
        ("⚠️ ", "Misconfigs + Remediation",  "_view_misconfigs"),
        ("🔒", "SSL/TLS Details",           "_view_ssl"),
        ("🔌", "Open Ports + Banners",      "_view_ports"),
        ("🌐", "Subdomains List",           "_view_subdomains"),
        ("📧", "Harvested Emails",          "_view_emails"),
        ("🔑", "Login Panels",              "_view_panels"),
        ("🔐", "JS Secrets",               "_view_js_secrets"),
        ("📁", "Dir Discovery (200/403)",   "_view_dirs"),
        ("🛡", "Vuln Scan Findings",        "_view_vulns"),
        ("🔗", "Endpoints by Severity",     "_view_endpoints"),
        ("🔍", "Search Across Results",     "_view_search"),
        ("📤", "Export Filtered CSV",       "_view_export_csv"),
        ("📊", "Risk Breakdown Chart",      "_view_risk_chart"),
    ]

    def _view_raw():
        keys = [k for k in results if k not in ("target","timestamp","config")]
        for i, k in enumerate(keys, 1):
            console.print(f"  [cyan]{i}[/cyan]. {k}")
        raw = Prompt.ask("Section #", default="0")
        if raw.isdigit() and 1 <= int(raw) <= len(keys):
            data = results[keys[int(raw)-1]]
            console.print(Panel(json.dumps(data, indent=2, default=str)[:5000],
                                title=keys[int(raw)-1], expand=False))

    def _view_misconfigs():
        misconfigs = ai.get("misconfigurations", [])
        if not misconfigs:
            console.print("[green]No misconfigurations found.[/green]")
            return
        t = Table(header_style="bold cyan", expand=True)
        t.add_column("Sev", width=10)
        t.add_column("Issue")
        t.add_column("Remediation", style="dim")
        for m in misconfigs:
            c = SEV_COLOR.get(m["severity"], "white")
            t.add_row(f"[{c}]{m['severity'].upper()}[/{c}]",
                      m["issue"], m.get("remediation",""))
        console.print(t)

    def _view_ssl():
        ssl = results.get("ssl_check", {})
        if not ssl:
            console.print("[dim]SSL module not run.[/dim]"); return
        t = Table(header_style="bold cyan", expand=False)
        t.add_column("Field", style="bold", width=22)
        t.add_column("Value")
        days = ssl.get("days_until_expiry")
        dc = "red" if isinstance(days,int) and days<0 else "yellow" if isinstance(days,int) and days<=30 else "green"
        days_display = str(days) if days is not None else "unknown"
        t.add_row("Subject CN",    ssl.get("subject_cn","N/A"))
        t.add_row("Issuer",        ssl.get("issuer_cn","N/A"))
        t.add_row("Protocol",      ssl.get("protocol","N/A"))
        t.add_row("Cipher",        f"{ssl.get('cipher','N/A')} ({ssl.get('cipher_bits','?')} bits)")
        t.add_row("Expires",       ssl.get("not_after","N/A"))
        t.add_row("Days Left",     f"[{dc}]{days_display}[/{dc}]")
        t.add_row("HSTS",          "✅" if ssl.get("hsts") else "❌")
        t.add_row("Self-signed",   "⚠️ YES" if ssl.get("self_signed") else "No")
        t.add_row("Weak Protocols",", ".join(ssl.get("weak_protocols",[])) or "None")
        t.add_row("SANs",          "\n".join(ssl.get("sans",[])[:10]))
        console.print(t)
        for f in ssl.get("findings",[]):
            c = SEV_COLOR.get(f["severity"],"white")
            console.print(f"  [{c}][{f['severity'].upper()}][/{c}] {f['issue']}")

    def _view_ports():
        ports = results.get("port_scan",{}).get("open_ports",[])
        if not ports:
            console.print("[dim]No open ports found.[/dim]"); return
        t = Table(header_style="bold cyan")
        t.add_column("Port", width=7)
        t.add_column("Service", width=14)
        t.add_column("Banner")
        for p in ports:
            t.add_row(str(p["port"]), p["service"], p.get("banner","") or "[dim]—[/dim]")
        console.print(t)

    def _view_subdomains():
        subs = results.get("subdomain",{}).get("subdomains",[])
        if not subs:
            console.print("[dim]No subdomains found.[/dim]"); return
        console.print(f"[bold]Found {len(subs)} subdomains:[/bold]")
        cols = 3
        rows_data = [subs[i:i+cols] for i in range(0, len(subs), cols)]
        t = Table(show_header=False, box=None, padding=(0,2))
        for _ in range(cols): t.add_column()
        for row in rows_data:
            t.add_row(*row, *[""]*(cols-len(row)))
        console.print(t)

    def _view_emails():
        em = results.get("email_harvest",{})
        if not em:
            console.print("[dim]Email harvest module not run.[/dim]"); return
        console.print(f"[bold]Total: {em.get('total',0)} emails[/bold]")
        if em.get("on_domain"):
            console.print("\n[cyan]On-domain:[/cyan]")
            for e in em["on_domain"]: console.print(f"  {e}")
        if em.get("off_domain"):
            console.print("\n[dim]Off-domain:[/dim]")
            for e in em["off_domain"]: console.print(f"  [dim]{e}[/dim]")

    def _view_panels():
        panels = results.get("login_finder",{}).get("panels",[])
        if not panels:
            console.print("[dim]No login panels found.[/dim]"); return
        t = Table(header_style="bold cyan", expand=True)
        t.add_column("URL")
        t.add_column("Status", width=8)
        t.add_column("Tech", width=14)
        t.add_column("Form", width=6)
        for p in panels:
            has = "[green]✓[/green]" if p.get("has_login_form") else "[dim]✗[/dim]"
            t.add_row(p["url"], str(p["status"]), p.get("technology","?"), has)
        console.print(t)

    def _view_js_secrets():
        findings = results.get("js_analysis",{}).get("findings",[])
        if not findings:
            console.print("[green]No JS secrets found.[/green]"); return
        for f in findings:
            console.print(f"\n[bold yellow]{f['file']}[/bold yellow]")
            for stype, vals in f.get("findings",{}).items():
                console.print(f"  [red]{stype}[/red]: {vals}")

    def _view_dirs():
        found = results.get("dir_discovery",{}).get("found",[])
        if not found:
            console.print("[dim]Nothing found.[/dim]"); return
        # Filter by status
        filt = Prompt.ask("Filter status (200/403/all)", default="all").strip()
        items = found if filt=="all" else [d for d in found if str(d.get("status",""))==filt]
        t = Table(header_style="bold cyan", expand=True)
        t.add_column("URL")
        t.add_column("Status", width=8)
        t.add_column("Severity", width=10)
        for d in items[:200]:
            c = SEV_COLOR.get(d.get("severity","info"),"white")
            t.add_row(d["url"], str(d["status"]),
                      f"[{c}]{d.get('severity','info')}[/{c}]")
        console.print(t)
        console.print(f"[dim]Showing {min(len(items),200)}/{len(items)} results[/dim]")

    def _view_vulns():
        vuln = results.get("vuln_scan",{})
        if not vuln:
            console.print("[dim]Vuln scan module not run.[/dim]"); return
        # CVE paths
        cve = vuln.get("cve_paths",[])
        if cve:
            console.print(f"\n[bold red]CVE Paths ({len(cve)}):[/bold red]")
            t = Table(header_style="bold cyan")
            t.add_column("Severity", width=10)
            t.add_column("URL")
            t.add_column("Description")
            t.add_column("Status", width=7)
            for c in cve:
                col = SEV_COLOR.get(c["severity"],"white")
                t.add_row(f"[{col}]{c['severity']}[/{col}]",
                          c["url"], c["description"], str(c["status"]))
            console.print(t)
        # Missing headers
        mh = vuln.get("missing_headers",[])
        if mh:
            console.print(f"\n[bold yellow]Missing Security Headers ({len(mh)}):[/bold yellow]")
            for h in mh: console.print(f"  [yellow]•[/yellow] {h['header']}")
        # CORS / Clickjacking
        if vuln.get("cors"):
            console.print(f"\n[red]CORS:[/red] {vuln['cors']['issue']}")
        if vuln.get("clickjacking"):
            console.print(f"[yellow]Clickjacking:[/yellow] {vuln['clickjacking']['issue']}")
        # Dangerous methods
        dm = vuln.get("dangerous_methods",[])
        if dm:
            console.print(f"\n[yellow]Dangerous HTTP Methods:[/yellow] {', '.join(dm)}")
        # Version disclosure
        vd = vuln.get("version_disclosure",[])
        if vd:
            console.print(f"\n[dim]Version Disclosure:[/dim]")
            for v in vd: console.print(f"  {v['software']} {v['version']}")

    def _view_endpoints():
        eps = results.get("endpoint",{}).get("endpoints",[])
        if not eps:
            console.print("[dim]No endpoints found.[/dim]"); return
        classified = ai.get("endpoint_classification",{})
        for sev in ("critical","high","medium","low","info"):
            items = classified.get(sev,[])
            if not items: continue
            c = SEV_COLOR.get(sev,"white")
            console.print(f"\n[{c}][{sev.upper()}] ({len(items)})[/{c}]")
            for url in items[:20]:
                console.print(f"  {url}")
            if len(items)>20:
                console.print(f"  [dim]... and {len(items)-20} more[/dim]")

    def _view_search():
        keyword = Prompt.ask("Search keyword").strip().lower()
        if not keyword: return
        hits = []
        raw = json.dumps(results, default=str).splitlines()
        for line in raw:
            if keyword in line.lower():
                hits.append(line.strip())
        console.print(f"\n[bold]Found {len(hits)} matches for '[cyan]{keyword}[/cyan]':[/bold]")
        for h in hits[:50]:
            console.print(f"  {h}")
        if len(hits)>50:
            console.print(f"  [dim]... and {len(hits)-50} more[/dim]")

    def _view_export_csv():
        import csv, io
        choices = {
            "1": ("subdomains",   results.get("subdomain",{}).get("subdomains",[])),
            "2": ("emails",       results.get("email_harvest",{}).get("on_domain",[]) +
                                  results.get("email_harvest",{}).get("off_domain",[])),
            "3": ("open_ports",   results.get("port_scan",{}).get("open_ports",[])),
            "4": ("login_panels", results.get("login_finder",{}).get("panels",[])),
            "5": ("dir_found",    results.get("dir_discovery",{}).get("found",[])),
            "6": ("endpoints",    results.get("endpoint",{}).get("endpoints",[])),
        }
        for k,(name,_) in choices.items():
            console.print(f"  [cyan]{k}[/cyan]. {name}")
        sel = Prompt.ask("Export which", default="1").strip()
        if sel not in choices: return
        name, data = choices[sel]
        if not data:
            console.print("[dim]No data to export.[/dim]"); return
        import os
        out_dir = results.get("config",{}).get("output_dir","reports") if isinstance(results.get("config"),dict) else "reports"
        os.makedirs(out_dir, exist_ok=True)
        slug = target.replace("https://","").replace("http://","").replace("/","_")
        path = os.path.join(out_dir, f"{slug}_{name}.csv")
        with open(path,"w",newline="",encoding="utf-8") as f:
            if data and isinstance(data[0], dict):
                w = csv.DictWriter(f, fieldnames=data[0].keys())
                w.writeheader(); w.writerows(data)
            else:
                w = csv.writer(f)
                w.writerows([[item] for item in data])
        console.print(f"[green]✓ Exported {len(data)} rows → {path}[/green]")

    def _view_risk_chart():
        misconfigs = ai.get("misconfigurations",[])
        counts = {"critical":0,"high":0,"medium":0,"low":0}
        for m in misconfigs:
            counts[m.get("severity","low")] = counts.get(m.get("severity","low"),0)+1
        risk = ai.get("risk_score",0)
        rc = "red" if risk>=70 else "yellow" if risk>=40 else "green"
        console.print(f"\n[bold]Risk Score: [{rc}]{risk}/100[/{rc}][/bold]\n")
        bar_width = 40
        for sev, col in [("critical","red"),("high","orange3"),("medium","yellow"),("low","blue")]:
            n = counts.get(sev,0)
            bar = "█" * min(n*4, bar_width)
            console.print(f"  [{col}]{sev:8}[/{col}] {bar} {n}")
        # Stats
        console.print()
        stats = ai.get("stats",{})
        t = Table(show_header=False, box=None, padding=(0,2))
        t.add_column(style="dim", width=20)
        t.add_column(style="bold")
        for k,v in stats.items():
            t.add_row(k, str(v))
        console.print(t)

    FN_MAP = {
        "_view_raw":        _view_raw,
        "_view_misconfigs": _view_misconfigs,
        "_view_ssl":        _view_ssl,
        "_view_ports":      _view_ports,
        "_view_subdomains": _view_subdomains,
        "_view_emails":     _view_emails,
        "_view_panels":     _view_panels,
        "_view_js_secrets": _view_js_secrets,
        "_view_dirs":       _view_dirs,
        "_view_vulns":      _view_vulns,
        "_view_endpoints":  _view_endpoints,
        "_view_search":     _view_search,
        "_view_export_csv": _view_export_csv,
        "_view_risk_chart": _view_risk_chart,
    }

    while True:
        console.print(Rule("[bold cyan]Results Browser v6.0[/bold cyan]"))
        console.print(f"  [dim]Target: {target}[/dim]\n")
        for i, (icon, label, _) in enumerate(MENU, 1):
            console.print(f"  [cyan]{i:2}[/cyan]. {icon} {label}")
        console.print("  [dim] 0. Back[/dim]\n")

        raw = Prompt.ask("[bold]Choose[/bold]", default="0").strip()
        if raw == "0" or raw.lower() == "back":
            break
        if raw.isdigit() and 1 <= int(raw) <= len(MENU):
            fn_key = MENU[int(raw)-1][2]
            console.print()
            try:
                FN_MAP[fn_key]()
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")
            Prompt.ask("\nPress Enter to continue", default="")


# ── Scan Engine ───────────────────────────────────────────────────────────────

async def run_recon(cfg: Config) -> dict:
    _ensure_modules()
    from core.cache import get_cache
    from core.diagnostics import reset_diagnostics
    get_cache(cfg)
    diag = reset_diagnostics()

    results: dict = {
        "target":    cfg.target,
        "timestamp": datetime.now().isoformat(),
        "profile":   cfg.profile,
        "config":    {"modules": cfg.modules, "stealth": cfg.stealth,
                      "threads": cfg.threads, "accuracy_mode": cfg.accuracy_mode},
    }

    # Track per-module status for live display
    mod_status: dict[str, str] = {}  # name → "pending"|"running"|"ok"|"err"

    def _status_line(mod_name: str, state: str) -> str:
        icon, label, _ = MODULE_MAP.get(mod_name, ("·", mod_name, None))
        sym = {"pending": "[dim]·[/dim]", "running": "[cyan]▶[/cyan]",
               "ok": "[green]✓[/green]", "err": "[red]✗[/red]"}.get(state, "·")
        return f"  {sym} [magenta]{label}[/magenta]"

    async def _run_one(mod_name: str) -> tuple[str, dict]:
        if mod_name not in MODULE_MAP:
            return mod_name, {"error": "unknown module"}
        icon, name, fn = MODULE_MAP[mod_name]
        md = diag.module(mod_name)
        md.start()
        try:
            if mod_name in _NEEDS_PRIOR:
                data = await fn(cfg, results)
            else:
                data = await fn(cfg)
            findings = (len(data.get("open_ports", data.get("subdomains",
                        data.get("panels", data.get("cve_paths", []))))) 
                        if isinstance(data, dict) else 0)
            fp = data.get("fp_removed", 0) if isinstance(data, dict) else 0
            md.finish(findings=findings, fp_removed=fp)
            return mod_name, data
        except Exception as e:
            md.fail(str(e))
            log.error(f"[{mod_name}] {e}", exc_info=True)
            return mod_name, {"error": str(e)}

    STAGE_NAMES = ["Reconnaissance", "Discovery", "Analysis", "Capture"]

    for stage_idx, stage_modules in enumerate(_STAGES):
        active = [m for m in stage_modules if m in cfg.modules]
        if not active:
            continue

        stage_label = STAGE_NAMES[stage_idx] if stage_idx < len(STAGE_NAMES) else f"Stage {stage_idx+1}"
        console.print(f"\n[bold cyan]  ── {stage_label} ──[/bold cyan]")

        # Show all as pending
        for m in active:
            console.print(_status_line(m, "pending"))

        # Run stage
        stage_results = await asyncio.gather(*[_run_one(m) for m in active])

        # Reprint with results (move up not possible in all terminals — just print summary line)
        ok  = sum(1 for _, d in stage_results if "error" not in d)
        err = len(stage_results) - ok
        status_parts = []
        for mod_name, data in stage_results:
            state = "err" if "error" in data else "ok"
            icon, label, _ = MODULE_MAP.get(mod_name, ("·", mod_name, None))
            sym = "[green]✓[/green]" if state == "ok" else "[red]✗[/red]"
            status_parts.append(f"{sym} [magenta]{label}[/magenta]")
            results[mod_name] = data

        console.print("  " + "  ".join(status_parts))

    # Validation pass
    console.print("\n[bold cyan]  ── Validation ──[/bold cyan]")
    try:
        from core.validator import run_all_validations
        results = await run_all_validations(results, cfg)
        if cfg.accuracy_mode:
            results = await run_all_validations(results, cfg)
        console.print("  [green]✓[/green] [magenta]Validation[/magenta]")
    except Exception as e:
        log.warning(f"[validator] Skipped: {e}")
        console.print("  [yellow]⚠[/yellow] [magenta]Validation[/magenta] [dim]skipped[/dim]")

    # AI Risk Engine
    console.print("\n[bold cyan]  ── Risk Engine ──[/bold cyan]")
    results["ai_analysis"] = ai_run(results)
    console.print("  [green]✓[/green] [magenta]AI Risk Engine[/magenta]")

    results["diagnostics"] = diag.to_dict()
    results["diagnostics"]["scan_confidence"] = diag.scan_confidence()
    return results


def print_summary(results: dict, report_paths: dict):
    from rich.columns import Columns

    ai   = results.get("ai_analysis", {})
    risk = ai.get("risk_score", 0)
    rlvl = ai.get("risk_level", "?")
    rc   = "red" if risk >= 70 else "yellow" if risk >= 40 else "green"

    ssl      = results.get("ssl_check", {})
    sub_data = results.get("subdomain", {})
    ports    = results.get("port_scan", {}).get("open_ports", [])
    vuln     = results.get("vuln_scan", {})
    tech     = results.get("tech_detect", {})
    vstats   = ai.get("validation_stats", {})
    diag_d   = results.get("diagnostics", {})
    confirmed_cves = sum(1 for c in vuln.get("cve_paths", []) if c.get("confirmed"))
    misconfigs     = ai.get("misconfigurations", [])
    scan_conf      = diag_d.get("scan_confidence", vstats.get("scan_confidence", "?"))

    console.print()
    console.rule(f"[bold {rc}]  SCAN COMPLETE  [/bold {rc}]")
    console.print()

    # ── Summary card ──────────────────────────────────────────────────────────
    summary = Table(box=None, show_header=False, padding=(0, 2), expand=False)
    summary.add_column(style="dim", width=20)
    summary.add_column(style="bold")

    _days = ssl.get("days_until_expiry")
    _dc   = "red" if isinstance(_days, int) and _days < 0 else \
            "yellow" if isinstance(_days, int) and _days <= 30 else "green"
    _days_str = f"[{_dc}]{_days}d[/{_dc}]" if _days is not None else "[dim]?[/dim]"

    summary.add_row("Risk Score",    f"[{rc}]{risk}/100  {rlvl}[/{rc}]")
    summary.add_row("Scan Confidence", f"[cyan]{scan_conf}%[/cyan]")
    summary.add_row("Technologies",  str(len(tech.get("technologies", []))))
    summary.add_row("WAF",           ", ".join(tech.get("waf", [])) or "[yellow]none[/yellow]")
    summary.add_row("Open Ports",    f"{len(ports)}")
    summary.add_row("Subdomains",    str(sub_data.get("total_validated", len(sub_data.get("subdomains", [])))))
    summary.add_row("Login Panels",  str(len(results.get("login_finder", {}).get("panels", []))))
    summary.add_row("Misconfigs",    f"{len(misconfigs)}  [dim]({sum(1 for m in misconfigs if m['severity']=='critical')} critical)[/dim]")
    summary.add_row("CVEs Confirmed",f"[{'red' if confirmed_cves else 'dim'}]{confirmed_cves}[/{'red' if confirmed_cves else 'dim'}]")
    summary.add_row("Header Posture",f"{vuln.get('posture_score', 0)}/100")
    summary.add_row("SSL Expiry",    _days_str)

    console.print(Panel(summary, title="[bold]Scan Summary[/bold]", expand=False, border_style="cyan"))

    # ── Technology table ──────────────────────────────────────────────────────
    tech_findings = tech.get("tech_findings", [])
    if tech_findings:
        console.print()
        t = Table(title="Technologies", header_style="bold cyan", box=None,
                  show_edge=True, padding=(0, 1), expand=False)
        t.add_column("Technology",  style="cyan",  width=22)
        t.add_column("Version",     style="dim",   width=12)
        t.add_column("Confidence",  width=10)
        t.add_column("Method",      style="dim",   width=8)
        for i, f in enumerate(tech_findings[:15]):
            conf = f["confidence"]
            cc = "green" if conf >= 80 else "yellow" if conf >= 60 else "dim"
            row_style = "" if i % 2 == 0 else "on grey7"
            t.add_row(
                f["name"],
                f.get("version") or "—",
                f"[{cc}]{conf}%[/{cc}]",
                f.get("detection_method", ""),
                style=row_style,
            )
        console.print(t)

    # ── Findings table ────────────────────────────────────────────────────────
    all_findings: list[tuple[str, str, str]] = []  # (severity, module, title)
    for m in misconfigs:
        all_findings.append((m["severity"], "risk", m["issue"]))
    for c in vuln.get("cve_paths", []):
        if c.get("confirmed"):
            all_findings.append((c["severity"], "vuln", c.get("title", c.get("description", ""))))
    for h in vuln.get("missing_headers", [])[:5]:
        all_findings.append((h["severity"], "headers", f"Missing {h['header']}"))

    if all_findings:
        console.print()
        ft = Table(title="Findings", header_style="bold cyan", box=None,
                   show_edge=True, padding=(0, 1), expand=False)
        ft.add_column("Severity", width=10)
        ft.add_column("Module",   width=10, style="dim")
        ft.add_column("Finding",  width=50)
        sev_order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}
        all_findings.sort(key=lambda x: sev_order.get(x[0], 5))
        for i, (sev, mod, title) in enumerate(all_findings[:20]):
            c = SEV_COLOR.get(sev, "white")
            row_style = "" if i % 2 == 0 else "on grey7"
            ft.add_row(f"[{c}]{sev.upper()}[/{c}]", mod, title, style=row_style)
        if len(all_findings) > 20:
            ft.add_row("[dim]...[/dim]", "", f"[dim]+{len(all_findings)-20} more[/dim]")
        console.print(ft)

    # ── Top attack paths ──────────────────────────────────────────────────────
    top_paths = ai.get("top_attack_paths", [])
    if top_paths:
        console.print()
        console.print("[bold red]  Top Attack Paths[/bold red]")
        for p in top_paths[:5]:
            console.print(f"  [red]→[/red] {p}")

    # ── Module status row ─────────────────────────────────────────────────────
    mod_data = diag_d.get("modules", {})
    if mod_data:
        console.print()
        parts = []
        for name, m in mod_data.items():
            s = m.get("status", "?")
            sym = "[green]✓[/green]" if s == "success" else \
                  "[red]✗[/red]"    if s == "error"   else \
                  "[yellow]⚠[/yellow]"
            rt = m.get("runtime_s", 0)
            parts.append(f"{sym} [dim]{name}[/dim] [dim cyan]{rt:.1f}s[/dim cyan]")
        # Print in rows of 3
        for i in range(0, len(parts), 3):
            console.print("  " + "   ".join(parts[i:i+3]))

    # ── Errors/warnings ───────────────────────────────────────────────────────
    if diag_d.get("error_modules"):
        console.print(f"\n  [red]✗ Failed: {', '.join(diag_d['error_modules'])}[/red]")
    if diag_d.get("warning_modules"):
        console.print(f"  [yellow]⚠ Warnings: {', '.join(diag_d['warning_modules'])}[/yellow]")

    # ── Report paths ──────────────────────────────────────────────────────────
    console.print()
    for fmt, path in report_paths.items():
        console.print(f"  [cyan]{fmt.upper():5}[/cyan] {path}")
    console.print()


# ── Main TUI Loop ─────────────────────────────────────────────────────────────

def _validate_config(cfg: Config) -> list[str]:
    """Return list of problems with current config."""
    issues = []
    if not cfg.target:
        issues.append("Target URL is not set")
    elif not cfg.target.startswith(("http://", "https://")):
        issues.append("Target must start with http:// or https://")
    if not cfg.modules:
        issues.append("No modules selected")
    if cfg.wordlist and not os.path.exists(cfg.wordlist):
        issues.append(f"Wordlist not found: {cfg.wordlist}")
    if cfg.proxy and not cfg.proxy.startswith(("http://", "https://", "socks5://")):
        issues.append("Proxy must start with http://, https://, or socks5://")
    return issues


_last_results: dict = {}


async def _run_and_store(cfg: Config):
    global _last_results
    _last_results = await run_recon(cfg)
    report_paths = generate_all(_last_results, cfg.output_dir, cfg.target)
    ai = _last_results.get("ai_analysis", {})
    record_scan(cfg.target, cfg.modules, ai.get("risk_score", 0), report_paths)
    print_summary(_last_results, report_paths)

    if Confirm.ask("\nBrowse results interactively?", default=False):
        menu_view_results(_last_results)


def main_menu():
    _ensure_modules()
    cfg = Config()
    cfg.modules = list(MODULE_MAP.keys())

    signal.signal(signal.SIGINT,  lambda s, f: (console.print("\n[yellow]Use 0 to exit.[/yellow]"),))
    signal.signal(signal.SIGTERM, lambda s, f: sys.exit(0))

    print_banner()

    console.print("[dim]Running startup diagnostics...[/dim]")
    checks = run_diagnostics(auto_fix=True)
    fails  = [c for c in checks if c.status == "fail"]
    if fails:
        console.print(f"[yellow]  ⚠ {len(fails)} issue(s) — run [bold]8[/bold] for details[/yellow]\n")
    else:
        console.print("[green]  ✓ System ready[/green]\n")

    MENU_ITEMS = [
        ("1", "Start Scan",        "full scan with all selected modules"),
        ("Q", "Quick Scan",        "skip dir_discovery & wayback"),
        ("2", "Set Target",        ""),
        ("3", "Edit Config",       "threads · timeout · stealth · proxy"),
        ("4", "Select Modules",    ""),
        ("P", "Scan Profile",      "fast / balanced / deep / accuracy"),
        ("5", "Profiles",          "save · load"),
        ("6", "History",           ""),
        ("7", "Browse Results",    "last scan"),
        ("8", "Diagnostics",       ""),
        ("0", "Exit",              ""),
    ]

    while True:
        # Status bar
        issues = _validate_config(cfg)
        rc_t   = "cyan" if cfg.target else "red"
        console.print(
            f"  [dim]target[/dim] [{rc_t}]{cfg.target or '(not set)'}[/{rc_t}]"
            f"  [dim]modules[/dim] [cyan]{len(cfg.modules)}[/cyan]"
            f"  [dim]profile[/dim] [cyan]{cfg.profile}[/cyan]"
            f"  [dim]stealth[/dim] {'[green]on[/green]' if cfg.stealth else '[dim]off[/dim]'}"
        )
        if issues:
            for iss in issues:
                console.print(f"  [red]✗ {iss}[/red]")
        console.print()

        for key, label, hint in MENU_ITEMS:
            hint_str = f"  [dim]{hint}[/dim]" if hint else ""
            console.print(f"  [cyan]{key:1}[/cyan]  {label}{hint_str}")

        console.print()
        choice = Prompt.ask("[bold cyan]>[/bold cyan]", default="1").strip()

        if choice == "0":
            console.print("[dim]bye.[/dim]")
            sys.exit(0)

        elif choice == "1":
            issues = _validate_config(cfg)
            if issues:
                for iss in issues: console.print(f"  [red]✗ {iss}[/red]")
                Prompt.ask("Enter to continue", default="")
                continue
            if not cfg.target.startswith(("http://", "https://")):
                cfg.target = "https://" + cfg.target
            console.print(
                f"\n  [cyan]target[/cyan]  {cfg.target}\n"
                f"  [cyan]modules[/cyan] {len(cfg.modules)}  "
                f"[cyan]threads[/cyan] {cfg.threads}  "
                f"[cyan]stealth[/cyan] {'on' if cfg.stealth else 'off'}\n"
            )
            asyncio.run(_run_and_store(cfg))

        elif choice.lower() == "q":
            issues = _validate_config(cfg)
            if issues:
                for iss in issues: console.print(f"  [red]✗ {iss}[/red]")
                Prompt.ask("Enter to continue", default="")
                continue
            if not cfg.target.startswith(("http://", "https://")):
                cfg.target = "https://" + cfg.target
            SLOW = {"dir_discovery", "wayback"}
            quick_modules = [m for m in cfg.modules if m not in SLOW]
            skipped = SLOW & set(cfg.modules)
            console.print(f"\n  [cyan]quick scan[/cyan]  skipping: [dim]{', '.join(skipped)}[/dim]\n")
            orig = cfg.modules
            cfg.modules = quick_modules
            asyncio.run(_run_and_store(cfg))
            cfg.modules = orig

        elif choice == "2":
            t = Prompt.ask("  Target").strip()
            if t:
                if not t.startswith(("http://", "https://")):
                    t = "https://" + t
                cfg.target = t

        elif choice == "3":
            menu_edit_config(cfg)

        elif choice == "4":
            menu_select_modules(cfg)

        elif choice.lower() == "p":
            from core.config import PROFILES
            console.print()
            for pname, pdata in PROFILES.items():
                active = " [green]←[/green]" if pname == cfg.profile else ""
                console.print(f"  [cyan]{pname:12}[/cyan] [dim]{pdata['description']}[/dim]{active}")
            sel = Prompt.ask("  Profile", choices=list(PROFILES.keys()), default=cfg.profile)
            cfg.apply_profile(sel)
            console.print(f"  [green]✓[/green] {sel}  {len(cfg.modules)} modules  {len(cfg.ports)} ports")

        elif choice == "5":
            menu_profiles(cfg)

        elif choice == "6":
            menu_history()

        elif choice == "7":
            if _last_results:
                menu_view_results(_last_results)
            else:
                console.print("  [dim]No results yet.[/dim]")
                Prompt.ask("Enter to continue", default="")

        elif choice == "8":
            console.print()
            checks = run_diagnostics(auto_fix=True)
            print_report(checks)
            Prompt.ask("\nEnter to continue", default="")

        else:
            console.print(f"  [dim]unknown: {choice}[/dim]")

        console.print()


# ── Entry Point ───────────────────────────────────────────────────────────────

if __name__ == "__main__":
    # Support --help / -t flags for non-interactive use
    if len(sys.argv) > 1:
        _ensure_modules()
        import argparse
        p = argparse.ArgumentParser(description="Advanced Web Recon Framework v7.0")
        p.add_argument("-t", "--target",    required=True)
        p.add_argument("-m", "--modules",   default="all")
        p.add_argument("-o", "--output",    default="reports")
        p.add_argument("--threads",         type=int, default=50)
        p.add_argument("--timeout",         type=int, default=10)
        p.add_argument("--stealth",         action="store_true")
        p.add_argument("--screenshot",      action="store_true")
        p.add_argument("--proxy",           default=None)
        p.add_argument("--wordlist",        default=None)
        args = p.parse_args()

        cfg = Config()
        cfg.target     = args.target if args.target.startswith("http") else "https://" + args.target
        cfg.output_dir = args.output
        cfg.threads    = args.threads
        cfg.timeout    = args.timeout
        cfg.stealth    = args.stealth
        cfg.screenshot = args.screenshot
        cfg.proxy      = args.proxy
        if args.wordlist:
            cfg.wordlist = args.wordlist
        cfg.modules = list(MODULE_MAP.keys()) if args.modules == "all" else [
            m.strip() for m in args.modules.split(",") if m.strip() in MODULE_MAP
        ]
        if cfg.stealth:
            cfg.delay_min, cfg.delay_max = 0.5, 3.0

        print_banner()
        asyncio.run(_run_and_store(cfg))
    else:
        main_menu()
