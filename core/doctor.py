"""
core/doctor.py v8.0 — Self-diagnostic with auto-fix.
Checks: Python version, pip packages, Playwright + browser binaries,
wordlists, writable dirs, system packages, network connectivity.
"""
import sys
import os
import subprocess
import importlib
import socket
from dataclasses import dataclass, field
from typing import Callable
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

REQUIRED_PACKAGES = {
    "aiohttp": "aiohttp", "bs4": "beautifulsoup4", "dns": "dnspython",
    "tldextract": "tldextract", "rich": "rich", "lxml": "lxml",
}
OPTIONAL_PACKAGES = {"playwright": "playwright"}

REQUIRED_WORDLISTS = ["wordlists/common.txt", "wordlists/subdomains.txt"]
REQUIRED_DIRS      = ["reports", "logs", "wordlists"]

CONNECTIVITY_HOSTS = [("8.8.8.8", 53), ("1.1.1.1", 53)]


@dataclass
class CheckResult:
    name: str
    status: str          # "ok" | "warn" | "fail"
    message: str
    fix: Callable | None = field(default=None, repr=False)
    fixed: bool = False


# ── Helpers ───────────────────────────────────────────────────────────────────

def _pip(pkg: str) -> bool:
    for extra in [["--break-system-packages"], []]:
        try:
            r = subprocess.run([sys.executable, "-m", "pip", "install", pkg, "-q"] + extra,
                               capture_output=True, timeout=90)
            if r.returncode == 0:
                return True
        except Exception:
            pass
    return False


def _is_proot() -> bool:
    if not os.path.exists("/proc/1/exe"):
        return True
    try:
        with open("/proc/1/cmdline", "rb") as f:
            return b"proot" in f.read()
    except Exception:
        return True


# ── Individual checks ─────────────────────────────────────────────────────────

def _check_python() -> CheckResult:
    v = sys.version_info
    ver = f"{v.major}.{v.minor}.{v.micro}"
    if v >= (3, 11):
        return CheckResult("Python Version", "ok", ver)
    if v >= (3, 9):
        return CheckResult("Python Version", "warn", f"{ver} (recommend 3.11+)")
    return CheckResult("Python Version", "fail", f"{ver} — need 3.9+")


def _check_env() -> CheckResult:
    if _is_proot():
        return CheckResult("Environment", "warn", "proot — screenshots & raw sockets limited")
    return CheckResult("Environment", "ok", "native Linux")


def _check_package(imp: str, pip_name: str, required: bool) -> CheckResult:
    try:
        mod = importlib.import_module(imp)
        ver = getattr(mod, "__version__", "?")
        return CheckResult(f"pkg:{pip_name}", "ok", f"installed ({ver})")
    except ImportError:
        status = "fail" if required else "warn"
        def fix():
            ok = _pip(pip_name)
            if ok and pip_name == "playwright":
                subprocess.run([sys.executable, "-m", "playwright", "install", "chromium", "--quiet"],
                               capture_output=True, timeout=180)
            return ok
        return CheckResult(f"pkg:{pip_name}", status, "not installed", fix=fix)


def _check_playwright_browser() -> CheckResult:
    """Verify Chromium binary is actually installed (not just the Python package)."""
    try:
        importlib.import_module("playwright")
    except ImportError:
        return CheckResult("Playwright Browser", "warn", "playwright package not installed")
    try:
        r = subprocess.run(
            [sys.executable, "-c",
             "from playwright.sync_api import sync_playwright; "
             "p=sync_playwright().start(); b=p.chromium.launch(); b.close(); p.stop(); print('ok')"],
            capture_output=True, text=True, timeout=30
        )
        if "ok" in r.stdout:
            return CheckResult("Playwright Browser", "ok", "Chromium binary available")
        def fix():
            r2 = subprocess.run([sys.executable, "-m", "playwright", "install", "chromium"],
                                capture_output=True, timeout=300)
            return r2.returncode == 0
        return CheckResult("Playwright Browser", "warn",
                           "Chromium not installed — screenshots disabled", fix=fix)
    except Exception as e:
        return CheckResult("Playwright Browser", "warn", f"check failed: {e}")


def _check_wordlist(path: str) -> CheckResult:
    if os.path.exists(path):
        lines = sum(1 for _ in open(path))
        return CheckResult(f"wordlist:{path}", "ok", f"{lines} entries")
    def fix():
        os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
        words = (
            ["www","mail","api","dev","staging","test","beta","admin","app","cdn",
             "static","media","blog","shop","portal","dashboard","auth","login","vpn","ftp"]
            if "subdomain" in path else
            ["admin","login","dashboard","api","backup","config","test","dev",
             ".env","wp-admin","phpmyadmin","uploads","static","assets","logs"]
        )
        with open(path, "w") as f:
            f.write("\n".join(words))
        return True
    return CheckResult(f"wordlist:{path}", "fail", "missing", fix=fix)


def _check_dirs() -> CheckResult:
    missing = [d for d in REQUIRED_DIRS if not os.path.isdir(d)]
    if not missing:
        return CheckResult("Output Directories", "ok", "all present")
    def fix():
        for d in missing:
            os.makedirs(d, exist_ok=True)
        return True
    return CheckResult("Output Directories", "fail", f"missing: {', '.join(missing)}", fix=fix)


def _check_write() -> CheckResult:
    try:
        os.makedirs("reports", exist_ok=True)
        test = "reports/.write_test"
        with open(test, "w") as f:
            f.write("x")
        os.remove(test)
        return CheckResult("Write Permission", "ok", "reports/ writable")
    except Exception as e:
        return CheckResult("Write Permission", "fail", str(e))


def _check_connectivity() -> CheckResult:
    for host, port in CONNECTIVITY_HOSTS:
        try:
            s = socket.create_connection((host, port), timeout=3)
            s.close()
            return CheckResult("Internet", "ok", f"reachable ({host}:{port})")
        except Exception:
            pass
    return CheckResult("Internet", "warn", "no connectivity — passive recon will fail")


def _check_system_pkg(pkg: str) -> CheckResult:
    """Check if a system binary/package is available."""
    try:
        r = subprocess.run(["which", pkg], capture_output=True, timeout=5)
        if r.returncode == 0:
            return CheckResult(f"sys:{pkg}", "ok", r.stdout.decode().strip())
        return CheckResult(f"sys:{pkg}", "warn", f"{pkg} not found in PATH")
    except Exception:
        return CheckResult(f"sys:{pkg}", "warn", "check failed")


# ── Public API ────────────────────────────────────────────────────────────────

def run_diagnostics(auto_fix: bool = True) -> list[CheckResult]:
    checks: list[CheckResult] = []

    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), transient=True) as prog:
        t = prog.add_task("Running diagnostics...", total=None)

        checks += [
            _check_env(),
            _check_python(),
            _check_connectivity(),
            _check_dirs(),
            _check_write(),
        ]
        for imp, pip in REQUIRED_PACKAGES.items():
            checks.append(_check_package(imp, pip, required=True))
        for imp, pip in OPTIONAL_PACKAGES.items():
            checks.append(_check_package(imp, pip, required=False))
        checks.append(_check_playwright_browser())
        for wl in REQUIRED_WORDLISTS:
            checks.append(_check_wordlist(wl))
        for pkg in ["curl", "git"]:
            checks.append(_check_system_pkg(pkg))

        prog.remove_task(t)

    if auto_fix:
        for c in checks:
            if c.status in ("fail", "warn") and c.fix:
                try:
                    if c.fix():
                        c.fixed = True
                        c.status = "ok"
                        c.message += " [auto-fixed]"
                except Exception as e:
                    c.message += f" (fix failed: {e})"

    return checks


def print_report(checks: list[CheckResult]) -> bool:
    table = Table(title="🩺 System Diagnostics v8.0", header_style="bold cyan", expand=False)
    table.add_column("Check", style="bold", min_width=28)
    table.add_column("Status", width=10)
    table.add_column("Details")

    icons = {"ok": "[green]✓ OK[/green]", "warn": "[yellow]⚠ WARN[/yellow]", "fail": "[red]✗ FAIL[/red]"}
    all_ok = True

    for c in checks:
        if c.status == "fail":
            all_ok = False
        fixed_tag = " [dim](fixed)[/dim]" if c.fixed else ""
        table.add_row(c.name, icons.get(c.status, c.status), c.message + fixed_tag)

    console.print(table)
    fails = [c for c in checks if c.status == "fail"]
    warns = [c for c in checks if c.status == "warn" and not c.fixed]

    if fails:
        console.print(f"\n[red]✗ {len(fails)} critical issue(s). Some modules may not work.[/red]")
    elif warns:
        console.print(f"\n[yellow]⚠ {len(warns)} warning(s). Reduced functionality.[/yellow]")
    else:
        console.print("\n[green]✓ All checks passed. Framework ready.[/green]")
    return all_ok
