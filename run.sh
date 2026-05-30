#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

# ── Warna & helper ────────────────────────────────────────────────────────────
RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'
YELLOW='\033[1;33m'; BOLD='\033[1m'; RESET='\033[0m'

print_header() {
    clear
    echo -e "${CYAN}${BOLD}"
    echo "  ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗"
    echo "  ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║"
    echo "  ██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║"
    echo "  ██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║"
    echo "  ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║"
    echo "  ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝"
    echo -e "${RESET}${BOLD}         Advanced Web Recon Framework v6.0${RESET}"
    echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
    echo ""
}

spinner() {
    local pid=$1
    local msg="${2:-Loading...}"
    local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    local i=0
    tput civis 2>/dev/null || true
    while kill -0 "$pid" 2>/dev/null; do
        printf "  ${CYAN}%s${RESET}  %s" "${frames[$((i % 10))]}" "$msg"
        i=$((i + 1))
        sleep 0.1
        printf "\r\033[K"
    done
    tput cnorm 2>/dev/null || true
}

step_ok()   { echo -e "  ${GREEN}✔${RESET}  $1"; }
step_info() { echo -e "  ${CYAN}→${RESET}  $1"; }
step_warn() { echo -e "  ${YELLOW}⚠${RESET}  $1"; }

# ── Tampilkan header segera ───────────────────────────────────────────────────
print_header
step_info "Memulai framework..."
echo ""

# ── 1. System deps ────────────────────────────────────────────────────────────
IS_TERMUX=0
[ -n "$TERMUX_VERSION" ] || [ -d "/data/data/com.termux" ] && IS_TERMUX=1

(
    if [ "$IS_TERMUX" -eq 1 ]; then
        pkg install -y libxml2 libxslt clang make 2>/dev/null >/dev/null || true
    else
        DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
            libxml2-dev libxslt1-dev python3-lxml python3-venv python3-full \
            2>/dev/null >/dev/null || true
    fi
) &
spinner $! "Memeriksa dependensi sistem..."
wait $!
step_ok "Dependensi sistem siap"

# ── 2. Virtual environment ────────────────────────────────────────────────────
if [ ! -d .venv ]; then
    (
        if [ "$IS_TERMUX" -eq 1 ]; then
            python -m venv .venv 2>/dev/null || python3 -m venv .venv
        else
            python3 -m venv .venv
        fi
    ) &
    spinner $! "Membuat virtual environment..."
    wait $!
    step_ok "Virtual environment dibuat"
else
    step_ok "Virtual environment ditemukan"
fi

# ── 3. Python packages ────────────────────────────────────────────────────────
if ! .venv/bin/python -c "import aiohttp, bs4, dns, rich, lxml, tldextract" 2>/dev/null; then
    (
        if [ "$IS_TERMUX" -eq 1 ]; then
            # lxml susah di-compile di Termux, coba pkg dulu
            .venv/bin/pip install -q --no-cache-dir --timeout 120 \
                $(grep -v lxml requirements.txt | tr '\n' ' ') 2>/dev/null
            .venv/bin/pip install -q --no-cache-dir --timeout 120 lxml 2>/dev/null || \
                pkg install -y python-lxml 2>/dev/null >/dev/null || true
        else
            .venv/bin/pip install -q --no-cache-dir --timeout 120 -r requirements.txt 2>/dev/null
        fi
    ) &
    spinner $! "Menginstall dependensi Python..."
    wait $!
    step_ok "Paket Python terinstall"
else
    step_ok "Semua paket Python sudah tersedia"
fi

# ── 4. Launch ─────────────────────────────────────────────────────────────────
echo ""
echo -e "  ${YELLOW}━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━${RESET}"
step_info "Meluncurkan framework..."
echo ""
sleep 0.3

source .venv/bin/activate
exec python main.py "$@"
