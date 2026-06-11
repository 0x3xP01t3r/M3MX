"""
m3mx tool — Full Analysis V2 safe Volatility runner.

A thin, *additive* wrapper around the Volatility 3 binary used only by
the V2 pipeline. It does **not** replace :func:`app.forensics.run_plugin`
and it does **not** touch Manual Analysis behaviour. The V2 pipeline
calls plugins by their full Volatility name (``windows.pslist``,
``linux.banners.Banners`` …) and parses CSV output independently from
``plugins.json``.

Design rules:

* Every helper is a free function.
* Subprocess invocation goes through :func:`_run_subprocess` so tests can
  monkey-patch a single seam.
* Nothing in this module ever raises into the caller. Failures return a
  structured result with ``success=False``.
* Discovery degrades gracefully — if ``vol -h`` cannot be parsed, we
  return an empty set and log a warning.
"""
from __future__ import annotations

import csv
import io
import logging
import re
import shutil
import subprocess
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Any, Iterable

log = logging.getLogger("m3mx.fa2.runner")

# ---------------------------------------------------------------------------
# Result wrapper
# ---------------------------------------------------------------------------

@dataclass
class RunnerResult:
    """Outcome of a single plugin invocation."""

    plugin: str                              # full Volatility plugin name
    success: bool = False
    elapsed: float = 0.0
    rows: list[list[str]] | None = None
    columns: list[str] | None = None
    output: str = ""                         # stdout (truncated)
    error: str = ""                          # short, single-line error
    command: str = ""                        # the exact command we ran
    timed_out: bool = False

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @property
    def row_count(self) -> int | None:
        return len(self.rows) if self.rows is not None else None


# ---------------------------------------------------------------------------
# Subprocess seam (mocked in tests)
# ---------------------------------------------------------------------------

@dataclass
class _CompletedProcess:
    """Mirror of subprocess.CompletedProcess that's easier to construct in tests."""
    returncode: int = 0
    stdout: str = ""
    stderr: str = ""
    timed_out: bool = False


def _run_subprocess(cmd: list[str], timeout: int) -> _CompletedProcess:
    """
    Wrapper around :func:`subprocess.run`. Returns a :class:`_CompletedProcess`
    on success, or one with ``timed_out=True`` / non-zero returncode on
    failure. Never raises.

    Tests monkey-patch this entire function so we never spawn real vol.
    """
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True,
            timeout=timeout, errors="replace",
        )
        return _CompletedProcess(
            returncode=proc.returncode,
            stdout=proc.stdout or "",
            stderr=proc.stderr or "",
        )
    except subprocess.TimeoutExpired as e:
        return _CompletedProcess(
            returncode=-1,
            stdout=(e.stdout.decode("utf-8", "replace") if isinstance(e.stdout, bytes)
                    else (e.stdout or "")),
            stderr=(e.stderr.decode("utf-8", "replace") if isinstance(e.stderr, bytes)
                    else (e.stderr or "")) or f"timeout after {timeout}s",
            timed_out=True,
        )
    except FileNotFoundError as e:
        return _CompletedProcess(returncode=-2, stderr=f"vol binary not found: {e}")
    except OSError as e:
        return _CompletedProcess(returncode=-3, stderr=f"subprocess OSError: {e}")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _vol3_binary(vol_paths: dict | None) -> str | None:
    """
    Return the Volatility 3 binary path, or None.

    Resolution rules:

    * ``vol_paths is None``  → search ``PATH`` for ``vol`` / ``volatility3`` / ``vol3``.
    * ``vol_paths`` provided → trust it verbatim. ``{"vol3": None}`` means
      "explicitly no Volatility available" and we honour that — this is
      what lets tests assert the missing-binary code path without being
      foiled by a real ``vol`` on the host PATH.
    """
    if vol_paths is not None:
        return vol_paths.get("vol3")
    for name in ("vol", "volatility3", "vol3"):
        found = shutil.which(name)
        if found:
            return found
    return None


def _parse_csv(text: str) -> tuple[list[str], list[list[str]]]:
    """Lightweight CSV parser — returns (columns, rows). Empty on failure."""
    if not text:
        return [], []
    try:
        rdr = csv.reader(io.StringIO(text))
        rows = [r for r in rdr if r]
    except csv.Error:
        return [], []
    if not rows:
        return [], []
    return rows[0], rows[1:]


def _short_error(stderr: str, stdout: str) -> str:
    """
    Volatility tends to dump a banner + traceback. Keep only the most
    informative line for the SSE / log payload.
    """
    for src in (stderr, stdout):
        for line in (src or "").splitlines():
            line = line.strip()
            if not line:
                continue
            # Skip the noisy Volatility framework banner.
            if line.startswith("Volatility 3 Framework"):
                continue
            if line.startswith("Progress:"):
                continue
            return line[:400]
    return ""


# ---------------------------------------------------------------------------
# Plugin execution
# ---------------------------------------------------------------------------

def run_plugin(image_path: str | Path,
               plugin: str,
               vol_paths: dict | None = None,
               timeout: int = 600,
               renderer: str = "csv") -> RunnerResult:
    """
    Execute a single Volatility 3 plugin by its full name (e.g.
    ``windows.pslist``) and return a :class:`RunnerResult`.

    Never raises. On any failure the returned object has
    ``success=False`` and a short ``error`` message.
    """
    img = str(Path(image_path).resolve()) if image_path else ""
    vol3 = _vol3_binary(vol_paths)
    if not vol3:
        return RunnerResult(plugin=plugin, success=False,
                            error="Volatility 3 binary not available")
    if not img or not Path(img).exists():
        return RunnerResult(plugin=plugin, success=False,
                            error=f"image not found: {image_path!r}")
    if not plugin or not isinstance(plugin, str):
        return RunnerResult(plugin=str(plugin), success=False,
                            error="invalid plugin name")

    cmd = [vol3, "-q", "-f", img, "-r", renderer, plugin]
    t0 = time.monotonic()
    proc = _run_subprocess(cmd, timeout=timeout)
    elapsed = round(time.monotonic() - t0, 3)

    if proc.timed_out:
        return RunnerResult(plugin=plugin, success=False,
                            elapsed=elapsed, command=" ".join(cmd),
                            error=f"timeout after {timeout}s",
                            timed_out=True)
    if proc.returncode != 0:
        return RunnerResult(plugin=plugin, success=False,
                            elapsed=elapsed, command=" ".join(cmd),
                            output=(proc.stdout or "")[-400:],
                            error=_short_error(proc.stderr, proc.stdout)
                                  or f"exit {proc.returncode}")

    if renderer == "csv":
        columns, rows = _parse_csv(proc.stdout)
    else:
        columns, rows = [], []

    return RunnerResult(
        plugin=plugin, success=True, elapsed=elapsed,
        rows=rows, columns=columns,
        output=(proc.stdout or "")[-400:],
        command=" ".join(cmd),
    )


# ---------------------------------------------------------------------------
# Plugin discovery
# ---------------------------------------------------------------------------

# Matches lines like:
#     linux.bash.Bash                          Recovers bash command history…
#     windows.netstat.NetStat                  Traverses ...
_DISCOVERY_RE = re.compile(
    r"^\s+([a-z][a-z0-9_]*(?:\.[A-Za-z_][A-Za-z0-9_]*)+)\b",
    re.MULTILINE,
)


def _normalize_plugin_name(name: str) -> str:
    """
    Drop the trailing PascalCase class component from a Vol3 plugin name.

    Vol3 ``--help`` reports plugins as ``namespace.module.ClassName`` (e.g.
    ``windows.pslist.PsList``) but accepts the short ``namespace.module``
    form on the command line (e.g. ``vol ... windows.pslist``). The
    plugin_plans.yaml and the runner both speak the short form, so the
    discovery set must use the short form too — otherwise the planner's
    availability filter rejects every plugin.

    Heuristic: if the last segment starts with an uppercase letter,
    treat it as the class suffix and strip it. Plugin namespaces and
    module names are always lowercase in Vol3, which makes this safe.
    """
    parts = name.split(".")
    if len(parts) > 2 and parts[-1] and parts[-1][0].isupper():
        return ".".join(parts[:-1])
    return name


def discover_available_plugins(vol_paths: dict | None = None,
                               timeout: int = 30) -> tuple[set[str], list[str]]:
    """
    Return ``(plugins, warnings)`` — the set of plugin names parsed from
    ``vol -h``, normalised to the short ``namespace.module`` form, plus
    any warning strings encountered along the way.

    On any failure we return ``(set(), [warning])`` rather than raising,
    so the planner can degrade to "plan with no availability filter".
    """
    warnings: list[str] = []
    vol3 = _vol3_binary(vol_paths)
    if not vol3:
        warnings.append("Volatility 3 binary not available — plugin discovery skipped")
        return set(), warnings

    proc = _run_subprocess([vol3, "-h"], timeout=timeout)
    if proc.timed_out:
        warnings.append("vol -h timed out — plugin discovery skipped")
        return set(), warnings
    # `vol -h` exits with non-zero in some Vol3 versions but still prints
    # the plugin list. Always try to parse whatever stdout we got.
    out = (proc.stdout or "") + "\n" + (proc.stderr or "")
    raw = set(_DISCOVERY_RE.findall(out))
    # Drop false positives that don't represent runnable plugins, then
    # normalise to the short ``namespace.module`` form.
    plugins = {
        _normalize_plugin_name(p)
        for p in raw
        if "." in p and not p.startswith("plugins.")
    }
    if not plugins:
        warnings.append("plugin discovery parsed zero entries from vol -h")
    return plugins, warnings


# ---------------------------------------------------------------------------
# Batch execution helper
# ---------------------------------------------------------------------------

def run_plugins(image_path: str | Path,
                plugins: Iterable[str],
                vol_paths: dict | None = None,
                timeout: int = 600,
                on_progress=None) -> list[RunnerResult]:
    """
    Run several plugins sequentially and return the results in order.
    A failure of one plugin never aborts the batch — every plugin yields
    a :class:`RunnerResult` regardless of success.

    *on_progress* is an optional callable receiving ``(index, total,
    result)`` after each plugin completes; the caller can use it to emit
    SSE events without this module knowing about SSE.
    """
    plugins = list(plugins)
    out: list[RunnerResult] = []
    for i, name in enumerate(plugins, start=1):
        try:
            res = run_plugin(image_path, name, vol_paths=vol_paths, timeout=timeout)
        except Exception as e:                                    # pragma: no cover
            log.exception("unexpected error running %s", name)
            res = RunnerResult(plugin=name, success=False,
                               error=f"unexpected error: {type(e).__name__}: {e}")
        out.append(res)
        if on_progress is not None:
            try:
                on_progress(i, len(plugins), res)
            except Exception:                                     # pragma: no cover
                log.exception("on_progress callback failed (ignored)")
    return out
