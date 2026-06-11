"""
m3mx tool — Full Analysis V2 OS detector.

Runs a short, ordered sequence of low-cost Volatility 3 probes against
the image and returns the most plausible OS tag plus enough metadata for
the future UI / logs. Probes are run via
:func:`app.fa2.volatility_runner.run_plugin`, so tests can mock the
runner without spinning up Volatility.

Critical rules:

* **Never crashes.** Every plugin failure is captured as a warning and
  the next probe is tried. If every probe fails, the function returns
  ``{"os": "unknown", …}`` with the warnings preserved.
* **Never invents values.** ``kernel`` and ``arch`` are only populated
  when a probe's output actually contains them — otherwise they stay
  empty strings. ``symbol_status`` is set from observed evidence.
* **Conservative confidence.** A single successful probe never yields
  confidence > 0.9 (we cannot rule out a corrupted dump with one row).
* **No upload side effects.** This module must only be called from the
  V2 Full Analysis route. Phase 2 does not wire it in.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Callable

from . import volatility_runner as runner

log = logging.getLogger("m3mx.fa2.os_detect")

# ---------------------------------------------------------------------------
# Result type
# ---------------------------------------------------------------------------

OS_CHOICES = ("windows", "linux", "mac", "unknown")
SYMBOL_STATES = ("ready", "partial", "missing", "unknown")


@dataclass
class DetectionResult:
    os: str = "unknown"
    confidence: float = 0.0
    detected_by: str = ""
    kernel: str = ""
    arch: str = ""
    symbol_status: str = "unknown"
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


# ---------------------------------------------------------------------------
# Probe table (in the order we try them)
# ---------------------------------------------------------------------------

# Each entry: (probe_plugin, target_os, signal_strength)
# signal_strength caps how high the probe's confidence can climb.
_PROBES: tuple[tuple[str, str, float], ...] = (
    ("windows.info",     "windows", 0.9),
    ("linux.banners",    "linux",   0.9),
    ("linux.pslist",     "linux",   0.7),    # secondary signal
    ("mac.banners",      "mac",     0.9),
    ("mac.pslist",       "mac",     0.7),
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_WINDOWS_KERNEL_RE = re.compile(r"NT(?:\s*Kernel)?\s*v?([\d.]+)", re.IGNORECASE)
_WINDOWS_ARCH_RE   = re.compile(r"\b(x64|x86|AMD64|Intel64|IA32)\b", re.IGNORECASE)
_LINUX_KERNEL_RE   = re.compile(r"Linux version (\S+)")
_LINUX_ARCH_RE     = re.compile(r"\b(x86_64|amd64|i[3-6]86|aarch64|arm64)\b")
# Restrict mac kernel capture to digits + dots so we don't accidentally
# scoop up the trailing colon from a banner like "Darwin Kernel Version 22.6.0:".
_MAC_KERNEL_RE     = re.compile(r"Darwin Kernel Version (\d+(?:\.\d+)*)")


def _flatten_rows(result: runner.RunnerResult) -> str:
    """Concatenate rows into a single haystack for regex inspection."""
    parts: list[str] = []
    for row in (result.rows or []):
        for cell in row:
            if cell:
                parts.append(str(cell))
    if not parts and result.output:
        parts.append(result.output)
    return " | ".join(parts)


def _extract_windows(text: str) -> tuple[str, str]:
    kernel = (_WINDOWS_KERNEL_RE.search(text) or [None, ""])[1] if text else ""
    if isinstance(kernel, re.Match):
        kernel = kernel.group(1)
    arch_match = _WINDOWS_ARCH_RE.search(text or "")
    arch = arch_match.group(1) if arch_match else ""
    return (kernel or "", arch)


def _extract_linux(text: str) -> tuple[str, str]:
    km = _LINUX_KERNEL_RE.search(text or "")
    am = _LINUX_ARCH_RE.search(text or "")
    return (km.group(1) if km else "", am.group(1) if am else "")


def _extract_mac(text: str) -> tuple[str, str]:
    km = _MAC_KERNEL_RE.search(text or "")
    return (km.group(1) if km else "", "")


def _symbol_status_for(result: runner.RunnerResult) -> str:
    """
    Infer how well Volatility's symbol resolution went from the probe
    error text. We are conservative — anything we cannot explain stays
    "unknown" rather than being optimistically reported as "ready".
    """
    if result.success and result.rows is not None and result.rows:
        return "ready"
    err = (result.error or "").lower()
    if not err:
        return "unknown"
    if "symbol" in err or "pdb" in err:
        return "missing"
    if "partial" in err or "translation layer" in err:
        return "partial"
    return "unknown"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

# A "run probe" callable so tests can inject a fake runner without
# monkey-patching the module. Default is the real runner.run_plugin.
ProbeCallable = Callable[[str, str, dict | None, int], runner.RunnerResult]


def detect_os(image_path: str | Path,
              vol_paths: dict | None = None,
              *,
              timeout: int = 60,
              probe_fn: ProbeCallable | None = None) -> DetectionResult:
    """
    Run probes against *image_path* and decide the OS. Never raises.

    Args:
        image_path: path to the memory image.
        vol_paths: optional ``{"vol3": …, "vol2": …}`` mapping; defaults
            to ``volatility_runner._vol3_binary`` discovery.
        timeout: per-probe timeout in seconds. Default 60 — probes are
            supposed to be cheap.
        probe_fn: dependency injection seam. Defaults to
            :func:`app.fa2.volatility_runner.run_plugin`. Tests pass a
            stub that returns canned :class:`RunnerResult` values.
    """
    probe = probe_fn or runner.run_plugin
    warnings: list[str] = []

    img = Path(image_path) if image_path else None
    if not img or not img.exists():
        warnings.append(f"image not found: {image_path!r}")
        return DetectionResult(
            os="unknown", confidence=0.0, detected_by="",
            warnings=warnings,
        )

    for plugin_name, target_os, ceiling in _PROBES:
        try:
            res = probe(str(img), plugin_name, vol_paths, timeout)
        except Exception as e:                                    # pragma: no cover
            warnings.append(f"{plugin_name} raised {type(e).__name__}: {e}")
            continue

        if not res.success:
            err = res.error or "probe failed"
            warnings.append(f"{plugin_name}: {err}")
            continue
        if not res.rows:
            # Plugin ran cleanly but produced no rows — almost certainly
            # the wrong OS. Note it and move on.
            warnings.append(f"{plugin_name}: probe ran but returned no rows")
            continue

        text = _flatten_rows(res)
        if target_os == "windows":
            kernel, arch = _extract_windows(text)
        elif target_os == "linux":
            kernel, arch = _extract_linux(text)
        else:
            kernel, arch = _extract_mac(text)

        # Confidence: clip the probe's ceiling by how much structured
        # detail we actually extracted.
        details = sum(bool(x) for x in (kernel, arch))
        if details >= 2:
            confidence = ceiling
        elif details == 1:
            confidence = round(ceiling * 0.85, 2)
        else:
            confidence = round(ceiling * 0.70, 2)

        return DetectionResult(
            os=target_os,
            confidence=max(0.0, min(1.0, confidence)),
            detected_by=plugin_name,
            kernel=kernel,
            arch=arch,
            symbol_status=_symbol_status_for(res),
            warnings=warnings,
        )

    # Every probe failed.
    return DetectionResult(
        os="unknown",
        confidence=0.0,
        detected_by="",
        kernel="", arch="",
        symbol_status="unknown",
        warnings=warnings or ["no probe succeeded"],
    )
