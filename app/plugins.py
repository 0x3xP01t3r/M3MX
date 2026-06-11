"""
m3mx tool — Plugin registry loader.

Reads plugins.json (project root) and exposes it as flat/grouped views
to the UI. Later phases extend with runtime capability probing (which
plugins the installed Volatility actually provides).
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Iterable

ROOT = Path(__file__).resolve().parent.parent
REGISTRY_PATH = ROOT / "plugins.json"


def load_registry() -> dict:
    """Load plugins.json. Falls back to an empty registry on error."""
    if not REGISTRY_PATH.exists():
        return {"categories": []}
    try:
        return json.loads(REGISTRY_PATH.read_text())
    except json.JSONDecodeError:
        return {"categories": []}


def flat_plugins() -> list[dict]:
    """Return all plugins as a flat list with category attached."""
    reg = load_registry()
    out: list[dict] = []
    for cat in reg.get("categories", []):
        for p in cat.get("plugins", []):
            entry = dict(p)
            entry["category"] = cat.get("name", "Misc")
            entry["versions"] = [v for v in ("v2", "v3") if entry.get("vol2") and v == "v2" or entry.get("vol3") and v == "v3"]
            out.append(entry)
    return out


# ---------------------------------------------------------------------------
# Name resolution
# ---------------------------------------------------------------------------
# The UI historically sends plugin names in several shapes:
#   short:           "pslist"
#   os-prefixed:     "windows.pslist"
#   fully-qualified: "windows.pslist.PsList"
#   dotted path:     "windows.registry.hivelist"
# All should map to the same registry entry. Resolution is deterministic:
#   1. exact short-name match (what used to be the only path)
#   2. match against any entry whose `vol3` starts with the incoming name
#      (so "windows.pslist" matches entry with vol3="windows.pslist.PsList")
#   3. match against any entry whose `vol3` equals the incoming name
#   4. strip OS prefix + take last segment, retry short-name match
# ---------------------------------------------------------------------------

_OS_PREFIXES = ("windows.", "linux.", "mac.")


def _iter_candidates(name: str) -> Iterable[str]:
    n = (name or "").strip()
    if not n:
        return
    yield n
    lower = n.lower()
    # Strip OS prefix: "windows.pslist" -> "pslist"
    for pref in _OS_PREFIXES:
        if lower.startswith(pref):
            rest = n[len(pref):]
            yield rest
            # Last segment: "registry.hivelist" -> "hivelist"
            if "." in rest:
                yield rest.rsplit(".", 1)[-1]
            break
    else:
        # No OS prefix; still honour a dotted path by returning last segment
        if "." in n:
            yield n.rsplit(".", 1)[-1]


def find_plugin(name: str) -> dict | None:
    """Look up one plugin definition by (possibly-qualified) name."""
    if not name:
        return None
    entries = flat_plugins()
    n_lower = name.lower()

    # 1. exact short-name match
    for p in entries:
        if (p.get("name") or "").lower() == n_lower:
            return p

    # 2/3. match against full/partial vol3 identifier
    for p in entries:
        v3 = (p.get("vol3") or "").lower()
        if not v3:
            continue
        if v3 == n_lower or v3.startswith(n_lower + "."):
            return p

    # 4. OS-prefix stripped + last segment fallback
    for candidate in _iter_candidates(name):
        c_lower = candidate.lower()
        if c_lower == n_lower:
            continue
        for p in entries:
            if (p.get("name") or "").lower() == c_lower:
                return p

    return None
