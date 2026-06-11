"""
Per-OS plugin → Artifact normalizers.

A normalizer is a function ``(columns, rows) → list[Artifact]`` that
converts one Volatility CSV result into one or more typed artifacts.
Each per-OS module exposes a ``<OS>_NORMALIZERS`` dispatch table; this
package aggregates them into :data:`NORMALIZERS` and provides
:func:`normalize` as the single public entry point.

Design rules (mirrored across every normalizer):

* Never raise on a malformed row — missing cells degrade to empty
  strings or ``None`` but the original cells are kept in ``raw``.
* Return an empty list rather than ``None`` for empty input.
* Set ``source_plugin`` to the full Volatility plugin name.

If a plugin has no registered normalizer :func:`normalize` returns an
empty list — the runner's raw CSV is still preserved separately so
nothing is lost.
"""
from __future__ import annotations

import logging
from typing import Sequence

from ..models import Artifact

from .windows import WINDOWS_NORMALIZERS
from .linux import LINUX_NORMALIZERS
from .mac import MAC_NORMALIZERS

log = logging.getLogger("m3mx.fa2.normalizers")


# ---------------------------------------------------------------------------
# Combined dispatch table
# ---------------------------------------------------------------------------

NORMALIZERS: dict[str, callable] = {
    **WINDOWS_NORMALIZERS,
    **LINUX_NORMALIZERS,
    **MAC_NORMALIZERS,
}


def supported_plugins() -> set[str]:
    """Return the set of plugin names with a registered normalizer."""
    return set(NORMALIZERS.keys())


def normalize(plugin: str,
              columns: Sequence[str] | None,
              rows: Sequence[Sequence[str]] | None) -> list[Artifact]:
    """
    Apply the normalizer registered for *plugin*. Returns an empty list
    when:

    * *plugin* has no normalizer (unsupported / extended plugin)
    * *rows* is empty/None
    * the normalizer raises (the exception is logged and swallowed —
      failure must never abort the pipeline)
    """
    if not rows:
        return []
    fn = NORMALIZERS.get(plugin)
    if fn is None:
        return []
    try:
        return fn(list(columns or []), list(rows or []))
    except Exception:                                              # pragma: no cover
        log.exception("normalizer for %s raised — returning empty list", plugin)
        return []


__all__ = ["NORMALIZERS", "normalize", "supported_plugins"]
