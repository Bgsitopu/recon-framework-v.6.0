#!/usr/bin/env bash
set -e
cd "$(dirname "$0")"

# --- Loading spinner ---
spinner() {
    local pid=$1
    local msg="${2:-Loading...}"
    local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    local i=0
    tput civis 2>/dev/null || true
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r\033[36m%s\033[0m %s" "${frames[$((i % 10))]}" "$msg"
        i=$((i + 1))
        sleep 0.1
    done
    printf "\r\033[K"
    tput cnorm 2>/dev/null || true
}

# 1. System deps
(
    DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
        libxml2-dev libxslt1-dev python3-lxml python3-venv python3-full 2>/dev/null | \
        grep -E "^(Setting up|E:)" || true
) &
spinner $! "Memeriksa dependensi sistem..."
wait $!

# 2. Buat venv jika belum ada
if [ ! -d .venv ]; then
    python3 -m venv .venv &
    spinner $! "Membuat virtual environment..."
    wait $!
fi

# 3. Install pip deps (skip jika sudah lengkap)
(
    MISSING=$(.venv/bin/pip install --dry-run -q --no-cache-dir -r requirements.txt 2>&1 | grep "Would install" || true)
    if [ -n "$MISSING" ]; then
        .venv/bin/pip install -q --no-cache-dir --timeout 120 --upgrade pip
        .venv/bin/pip install -q --no-cache-dir --timeout 120 -r requirements.txt
    fi
) &
spinner $! "Memuat modul Python..."
wait $!

# 4. Jalankan
source .venv/bin/activate
exec python main.py "$@"
