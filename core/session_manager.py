"""
core/session_manager.py — Save/load config profiles and scan history.
Profiles stored as JSON in ~/.recon_framework/profiles/
Scan history stored in ~/.recon_framework/history.json
"""
import json
import os
from datetime import datetime
from dataclasses import asdict
from core.config import Config

_BASE_DIR = os.path.expanduser("~/.recon_framework")
_PROFILES_DIR = os.path.join(_BASE_DIR, "profiles")
_HISTORY_FILE = os.path.join(_BASE_DIR, "history.json")


def _ensure_dirs():
    os.makedirs(_PROFILES_DIR, exist_ok=True)


# ── Profiles ──────────────────────────────────────────────────────────────────

def save_profile(name: str, cfg: Config):
    _ensure_dirs()
    path = os.path.join(_PROFILES_DIR, f"{name}.json")
    with open(path, "w") as f:
        json.dump(asdict(cfg), f, indent=2)


def load_profile(name: str) -> Config | None:
    path = os.path.join(_PROFILES_DIR, f"{name}.json")
    if not os.path.exists(path):
        return None
    with open(path) as f:
        data = json.load(f)
    cfg = Config()
    for k, v in data.items():
        if hasattr(cfg, k):
            setattr(cfg, k, v)
    return cfg


def list_profiles() -> list[str]:
    _ensure_dirs()
    return [f[:-5] for f in os.listdir(_PROFILES_DIR) if f.endswith(".json")]


def delete_profile(name: str) -> bool:
    path = os.path.join(_PROFILES_DIR, f"{name}.json")
    if os.path.exists(path):
        os.remove(path)
        return True
    return False


# ── Scan History ──────────────────────────────────────────────────────────────

def _load_history() -> list[dict]:
    if not os.path.exists(_HISTORY_FILE):
        return []
    try:
        with open(_HISTORY_FILE) as f:
            return json.load(f)
    except Exception:
        return []


def _save_history(history: list[dict]):
    _ensure_dirs()
    with open(_HISTORY_FILE, "w") as f:
        json.dump(history[-100:], f, indent=2)  # keep last 100


def record_scan(target: str, modules: list[str], risk_score: int, report_paths: dict):
    history = _load_history()
    history.append({
        "timestamp": datetime.now().isoformat(),
        "target": target,
        "modules": modules,
        "risk_score": risk_score,
        "reports": report_paths,
    })
    _save_history(history)


def get_history() -> list[dict]:
    return _load_history()


def clear_history():
    if os.path.exists(_HISTORY_FILE):
        os.remove(_HISTORY_FILE)
