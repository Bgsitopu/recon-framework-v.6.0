#!/usr/bin/env bash
# install.sh — Setup script for Advanced Web Recon Framework
set -e

echo "╔══════════════════════════════════════╗"
echo "║   Recon Framework — Installer        ║"
echo "╚══════════════════════════════════════╝"

# ── Detect environment ────────────────────────────────────────────────────────
IS_TERMUX=false
IS_PROOT=false

[[ -d "/data/data/com.termux" ]] && IS_TERMUX=true

# proot: /proc/1/exe tidak ada atau menunjuk ke proot, dan tidak ada systemd
if [[ ! -e "/proc/1/exe" ]] || grep -q "proot" /proc/1/cmdline 2>/dev/null || \
   [[ -f "/proc/version" ]] && grep -qi "android\|termux" /proc/version 2>/dev/null; then
    IS_PROOT=true
fi
# Fallback: cek apakah kita bisa akses /proc/sys/kernel/hostname (sering gagal di proot)
if [[ "$IS_PROOT" == "false" ]] && ! cat /proc/sys/kernel/hostname &>/dev/null; then
    IS_PROOT=true
fi

$IS_PROOT && echo "[*] proot environment detected"
$IS_TERMUX && echo "[*] Termux environment detected"

# ── APT flags (proot tidak support recommends install karena missing kernel features) ──
APT_FLAGS="-y"
$IS_PROOT && APT_FLAGS="-y --no-install-recommends"

# ── Python check ──────────────────────────────────────────────────────────────
if ! command -v python3 &>/dev/null; then
    echo "[!] Python3 not found."
    if $IS_TERMUX; then
        pkg install python -y
    else
        apt install $APT_FLAGS python3 python3-pip python3-venv python3-full 2>/dev/null || {
            echo "    Install Python 3.11+ from https://python.org"
            exit 1
        }
    fi
fi

PYTHON_VER=$(python3 -c "import sys; print(f'{sys.version_info.major}.{sys.version_info.minor}')")
echo "[+] Python $PYTHON_VER detected"

# ── Termux extras ─────────────────────────────────────────────────────────────
if $IS_TERMUX; then
    echo "[+] Termux: installing system deps..."
    pkg install -y clang libxml2 libxslt openssl python-pip
fi

# ── pip flags ─────────────────────────────────────────────────────────────────
# Ubuntu 23.04+ (PEP 668) memerlukan --break-system-packages di luar venv
PIP_FLAGS="--quiet"
python3 -c "import sys; exit(0 if sys.version_info >= (3,11) else 1)" 2>/dev/null && \
    PIP_FLAGS="$PIP_FLAGS --break-system-packages"

# ── Virtual environment ───────────────────────────────────────────────────────
echo "[+] Creating virtual environment..."
if ! python3 -m venv .venv 2>/dev/null; then
    apt install $APT_FLAGS python3-venv python3-full 2>/dev/null || true
    python3 -m venv .venv
fi

# ── Install Python deps ───────────────────────────────────────────────────────
echo "[+] Installing Python dependencies..."
.venv/bin/pip install --upgrade pip -q
.venv/bin/pip install -r requirements.txt -q

# ── Playwright (skip di proot karena tidak ada kernel namespace support) ──────
if $IS_PROOT; then
    echo "[!] proot detected — skipping Playwright browser install (screenshots disabled)"
    echo "    Playwright tetap terinstall tapi browser tidak bisa dijalankan di proot."
else
    echo "[+] Installing Playwright browsers (optional, skip with Ctrl+C)..."
    .venv/bin/python3 -m playwright install chromium 2>/dev/null || \
        echo "[!] Playwright install skipped (screenshots disabled)"
fi

# ── Wordlists ─────────────────────────────────────────────────────────────────
echo "[+] Creating default wordlists..."
.venv/bin/python3 - <<'PYEOF'
import os
os.makedirs("wordlists", exist_ok=True)

common = [
    "admin","login","dashboard","api","v1","v2","static","assets","uploads","files",
    "backup","config","test","dev","staging","old","new","temp","tmp","cache",
    "images","img","css","js","fonts","media","public","private","secret","hidden",
    "user","users","account","accounts","profile","settings","manage","management",
    "panel","control","console","portal","backend","frontend","app","application",
    "data","database","db","sql","logs","log","error","debug","info","status",
    "health","ping","metrics","monitor","docs","documentation","swagger","api-docs",
    "robots","sitemap","readme","changelog","license","install","setup","update",
    "wp-content","wp-includes","wp-admin","wp-login","xmlrpc","phpmyadmin","adminer",
    "server-status","server-info","phpinfo","info","test","demo","sample","example",
]
with open("wordlists/common.txt", "w") as f:
    f.write("\n".join(common))

subs = [
    "www","mail","ftp","smtp","pop","imap","webmail","remote","vpn","api","dev",
    "staging","test","beta","alpha","demo","app","mobile","m","cdn","static",
    "assets","media","img","images","video","blog","shop","store","portal","admin",
    "dashboard","panel","control","manage","support","help","docs","wiki","forum",
    "community","news","status","monitor","metrics","analytics","tracking","auth",
    "login","sso","oauth","id","accounts","user","users","profile","my","secure",
    "ssl","ns1","ns2","mx","mx1","mx2","smtp1","smtp2","pop3","imap4","exchange",
    "autodiscover","autoconfig","cpanel","whm","plesk","webdisk","ftp2","sftp",
    "git","svn","jenkins","ci","build","deploy","docker","k8s","kubernetes","db",
    "database","mysql","postgres","redis","mongo","elastic","kibana","grafana",
    "prometheus","vault","consul","nomad","terraform","ansible","puppet","chef",
]
with open("wordlists/subdomains.txt", "w") as f:
    f.write("\n".join(subs))

print("[+] Wordlists created: wordlists/common.txt, wordlists/subdomains.txt")
PYEOF

echo ""
echo "╔══════════════════════════════════════╗"
echo "║   Installation Complete! ✓           ║"
echo "╚══════════════════════════════════════╝"
echo ""
echo "Usage:"
echo "  .venv/bin/python3 main.py -t https://example.com"
echo "  .venv/bin/python3 main.py  # interactive mode"
echo "  .venv/bin/python3 main.py --help"
echo ""
echo "  # Or activate venv first:"
echo "  source .venv/bin/activate"
echo "  python3 main.py -t https://example.com"
