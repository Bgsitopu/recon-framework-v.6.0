"""
core/diagnostics.py — P10: Scan Diagnostics Dashboard + P11: Smart Logging.
Tracks per-module: status, runtime, retries, cache hits/misses, failure reasons.
"""
from __future__ import annotations
import time
from dataclasses import dataclass, field
from typing import Literal

ModuleStatus = Literal["pending", "running", "success", "warning", "error", "skipped"]


@dataclass
class ModuleDiag:
    name: str
    status: ModuleStatus = "pending"
    start_time: float = 0.0
    end_time: float = 0.0
    runtime_s: float = 0.0
    retries: int = 0
    timeout_count: int = 0          # NEW: incremented on each asyncio.TimeoutError
    fallback_used: bool = False     # NEW: set True when a fallback provider is used
    cache_hits: int = 0
    cache_misses: int = 0
    findings_count: int = 0
    fp_removed: int = 0
    failure_reason: str = ""
    warnings: list[str] = field(default_factory=list)
    log_entries: list[str] = field(default_factory=list)

    def start(self) -> None:
        self.status = "running"
        self.start_time = time.perf_counter()

    def finish(self, findings: int = 0, fp_removed: int = 0) -> None:
        self.end_time = time.perf_counter()
        self.runtime_s = round(self.end_time - self.start_time, 2)
        self.findings_count = findings
        self.fp_removed = fp_removed
        if self.status == "running":
            self.status = "success"

    def fail(self, reason: str) -> None:
        self.end_time = time.perf_counter()
        self.runtime_s = round(self.end_time - self.start_time, 2)
        self.status = "error"
        self.failure_reason = reason

    def warn(self, msg: str) -> None:
        self.warnings.append(msg)
        if self.status == "success":
            self.status = "warning"

    def log(self, msg: str, source: str = "", confidence: int = 0,
            validation: str = "", retry: int = 0) -> None:
        """P11: structured log entry with detection source, confidence, validation."""
        parts = [msg]
        if source:      parts.append(f"source={source}")
        if confidence:  parts.append(f"confidence={confidence}%")
        if validation:  parts.append(f"validation={validation}")
        if retry:       parts.append(f"retry={retry}")
        self.log_entries.append(" | ".join(parts))

    def to_dict(self) -> dict:
        return {
            "name":           self.name,
            "status":         self.status,
            "runtime_s":      self.runtime_s,
            "retries":        self.retries,
            "timeout_count":  self.timeout_count,
            "fallback_used":  self.fallback_used,
            "cache_hits":     self.cache_hits,
            "cache_misses":   self.cache_misses,
            "findings_count": self.findings_count,
            "fp_removed":     self.fp_removed,
            "failure_reason": self.failure_reason,
            "warnings":       self.warnings,
        }


class ScanDiagnostics:
    """Central registry for all module diagnostics in a scan session."""

    def __init__(self) -> None:
        self._modules: dict[str, ModuleDiag] = {}

    def module(self, name: str) -> ModuleDiag:
        if name not in self._modules:
            self._modules[name] = ModuleDiag(name=name)
        return self._modules[name]

    def to_dict(self) -> dict:
        modules = {k: v.to_dict() for k, v in self._modules.items()}
        total_runtime = sum(v.runtime_s for v in self._modules.values())
        total_findings = sum(v.findings_count for v in self._modules.values())
        total_fp = sum(v.fp_removed for v in self._modules.values())
        errors   = [k for k, v in self._modules.items() if v.status == "error"]
        warnings = [k for k, v in self._modules.items() if v.status == "warning"]
        return {
            "modules":        modules,
            "total_runtime_s": round(total_runtime, 2),
            "total_findings":  total_findings,
            "total_fp_removed": total_fp,
            "error_modules":   errors,
            "warning_modules": warnings,
            "module_count":    len(self._modules),
            "success_count":   sum(1 for v in self._modules.values() if v.status == "success"),
        }

    def scan_confidence(self) -> int:
        """
        Dynamic scan confidence 0-100.
        - success=1.0, warning=0.7, fallback=0.5, error/skipped=0.0
        - Penalty: -2 per timeout (cap 20), -1 per retry (cap 10), -5 per fallback (cap 15)
        Breakdown logged at DEBUG level.
        """
        if not self._modules:
            return 0
        total = len(self._modules)
        ok    = sum(1 for v in self._modules.values() if v.status == "success")
        warn  = sum(1 for v in self._modules.values() if v.status == "warning")
        base  = (ok + warn * 0.7) / total * 100

        total_retries  = sum(v.retries for v in self._modules.values())
        total_timeouts = sum(v.timeout_count for v in self._modules.values())
        total_fallbacks= sum(1 for v in self._modules.values() if v.fallback_used)

        penalty = min(total_retries, 10) + min(total_timeouts * 2, 20) + min(total_fallbacks * 5, 15)
        confidence = max(0, min(100, int(base - penalty)))

        from core.logger import get_logger as _gl
        _gl("diagnostics").debug(
            f"[diagnostics] scan_confidence: base={base:.1f}% "
            f"ok={ok} warn={warn} errors={total-ok-warn} "
            f"retries={total_retries} timeouts={total_timeouts} fallbacks={total_fallbacks} "
            f"penalty={penalty} → {confidence}%"
        )
        return confidence


# Global singleton per scan session
_diag: ScanDiagnostics | None = None

def get_diagnostics() -> ScanDiagnostics:
    global _diag
    if _diag is None:
        _diag = ScanDiagnostics()
    return _diag

def reset_diagnostics() -> ScanDiagnostics:
    global _diag
    _diag = ScanDiagnostics()
    return _diag
