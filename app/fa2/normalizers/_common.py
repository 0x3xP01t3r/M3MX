"""
Shared helpers for the per-OS normalizers.

Kept private (leading underscore) so it stays an implementation detail
of the ``app.fa2.normalizers`` package. Anything reused across normalizers
lives here; everything else stays inside its per-OS module.
"""
from __future__ import annotations

import re
from typing import Any, Sequence


# ---------------------------------------------------------------------------
# Column-name resolution
# ---------------------------------------------------------------------------

def col_index(columns: Sequence[str]) -> dict[str, int]:
    """Case-insensitive column-name → index map. Empty/None columns are ignored."""
    return {c.strip().lower(): i for i, c in enumerate(columns or []) if c}


def get(idx: dict[str, int], row: Sequence[str], *names: str,
        default: str = "") -> str:
    """
    Look up *names* in *idx* (first match wins) and return the
    corresponding cell from *row*. Falls back to *default* if no name
    resolves to a valid index. Never raises on short rows.
    """
    for n in names:
        i = idx.get(n.lower())
        if i is not None and i < len(row):
            v = row[i]
            if v is None:
                return default
            return str(v).strip()
    return default


# ---------------------------------------------------------------------------
# Coercions
# ---------------------------------------------------------------------------

_INT_RE = re.compile(r"^-?\d+$")


def to_int(s: str | None) -> int | None:
    """Parse *s* as an int, returning None for empties or non-numerics."""
    if s is None:
        return None
    t = str(s).strip()
    if not t or not _INT_RE.match(t):
        return None
    try:
        return int(t)
    except (TypeError, ValueError):
        return None


def to_int_strict(s: str | None) -> int | None:
    """Same as to_int but accepts leading/trailing whitespace only."""
    return to_int(s)


def to_lower(s: str | None) -> str:
    return (s or "").strip().lower()


# Common placeholder strings Volatility emits for "no value" in IP /
# address columns. These must NOT propagate as real remote endpoints —
# otherwise the rule engine treats them as legitimate connections and
# the correlation engine groups them into spurious chains. See OD-003.
_IP_PLACEHOLDERS: frozenset[str] = frozenset((
    "", "-", "*",
    # Parsed artifact sentinel; this is not a listening socket.
    "0.0.0.0",  # nosec B104
    "::", "::0", "[::]",
    "::ffff:0.0.0.0",
))


def clean_ip(value: str | None) -> str | None:
    """
    Return ``None`` when *value* is empty, missing, or one of the well-known
    "no address" placeholders Volatility emits (``-``, ``*``, ``0.0.0.0``,
    ``::``). Otherwise return the stripped string.
    """
    if value is None:
        return None
    s = str(value).strip()
    if s in _IP_PLACEHOLDERS:
        return None
    # IPv6 forms wrapped in brackets ([::ffff:1.2.3.4]) should be unwrapped.
    if s.startswith("[") and s.endswith("]"):
        inner = s[1:-1].strip()
        return inner or None
    return s


def truthy(s: str | None) -> bool | None:
    """Map common volatility 'True/False' strings to bool. None if unknown."""
    t = (s or "").strip().lower()
    if t in ("true", "yes", "1"):
        return True
    if t in ("false", "no", "0"):
        return False
    return None


# ---------------------------------------------------------------------------
# Raw-row capture
# ---------------------------------------------------------------------------

def raw_dict(columns: Sequence[str], row: Sequence[str]) -> dict[str, Any]:
    """
    Return a stable column-name → cell-value dict from one row. Used as
    the ``raw`` field on every :class:`Artifact` so analysts can always
    inspect the original Volatility output for the artifact, regardless
    of which fields the normalizer chose to surface.
    """
    out: dict[str, Any] = {}
    cols = columns or []
    for i, col in enumerate(cols):
        if not col:
            continue
        if i < len(row):
            v = row[i]
            out[col] = "" if v is None else str(v)
        else:
            out[col] = ""
    return out
