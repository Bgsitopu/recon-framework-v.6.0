"""
core/logger.py v8.0 — Structured per-module logging.
Tracks timestamps, execution duration, success/failure, exception traces, summary stats.
"""
import logging
import os
import time
from contextlib import contextmanager
from rich.logging import RichHandler
from rich.console import Console

console = Console()
_loggers: dict[str, logging.Logger] = {}


def get_logger(name: str = "recon") -> logging.Logger:
    if name in _loggers:
        return _loggers[name]
    os.makedirs("logs", exist_ok=True)
    logger = logging.getLogger(name)
    if logger.handlers:
        _loggers[name] = logger
        return logger
    logger.setLevel(logging.DEBUG)

    rich_h = RichHandler(console=console, show_path=False, markup=True,
                         log_time_format="[%H:%M:%S]")
    rich_h.setLevel(logging.INFO)

    file_h = logging.FileHandler(f"logs/{name}.log", encoding="utf-8")
    file_h.setLevel(logging.DEBUG)
    file_h.setFormatter(logging.Formatter(
        "%(asctime)s [%(levelname)-8s] [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S"
    ))

    logger.addHandler(rich_h)
    logger.addHandler(file_h)
    logger.propagate = False
    _loggers[name] = logger
    return logger


class ModuleTimer:
    """Context manager that logs module start/end with duration and status."""

    def __init__(self, module_name: str):
        self.name = module_name
        self.log  = get_logger(module_name)
        self._start: float = 0.0

    def __enter__(self) -> "ModuleTimer":
        self._start = time.perf_counter()
        self.log.info(f"[{self.name}] ▶ Starting")
        return self

    def __exit__(self, exc_type, exc_val, exc_tb):
        elapsed = time.perf_counter() - self._start
        if exc_type:
            self.log.error(f"[{self.name}] ✗ Failed in {elapsed:.1f}s — {exc_val}", exc_info=True)
        else:
            self.log.info(f"[{self.name}] ✓ Done in {elapsed:.1f}s")
        return False  # don't suppress exceptions

    def stat(self, key: str, value) -> None:
        self.log.debug(f"[{self.name}] stat:{key}={value}")
