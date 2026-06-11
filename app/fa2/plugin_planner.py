"""
m3mx tool — Full Analysis V2 plugin planner.

Reads ``rules/plugin_plans.yaml`` and picks the plugin list for a given
OS, filtered against the set of plugins actually available on this
machine. The planner is pure data — it does not invoke Volatility.

Contract (every code path returns this shape):

    {
        "os":       "windows" | "linux" | "mac" | "unknown",
        "plugins":  [<plugin_name>, …],     # in canonical order, de-duplicated
        "skipped":  [{"plugin": <name>, "reason": <str>}, …],
        "warnings": [<str>, …],
        "fallbacks_applied": [{"from": <name>, "to": <name>}, …],
        "include_extended": <bool>,
        "source":   "<absolute path to YAML>",
    }

Failure modes are explicit:

* Unknown OS  → empty plan + warning, never an exception.
* Missing/malformed YAML → empty plan + warning (handled by
  :func:`app.fa2.utils.load_yaml_safe`).
* Empty ``available`` set → every planned plugin lands in ``skipped``.

The planner *never* invents plugin names. If a fallback target is also
unavailable, the substitution is recorded but the result still lists
the target as skipped.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any, Iterable

from .utils import load_yaml_safe, project_root

log = logging.getLogger("m3mx.fa2.planner")

DEFAULT_PLANS_PATH = project_root() / "rules" / "plugin_plans.yaml"

_SUPPORTED_OS = ("windows", "linux", "mac")


def _load_plans(path: str | Path | None) -> dict[str, Any]:
    return load_yaml_safe(path or DEFAULT_PLANS_PATH)


def _dedupe_preserve(seq: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    out: list[str] = []
    for x in seq:
        if x in seen:
            continue
        seen.add(x)
        out.append(x)
    return out


def plan(os_name: str,
         available: Iterable[str] | None = None,
         *,
         include_extended: bool = False,
         plans_path: str | Path | None = None) -> dict[str, Any]:
    """
    Compute the planned plugin list for *os_name*.

    Args:
        os_name: one of ``"windows" | "linux" | "mac"`` (case-insensitive).
            Anything else returns an empty plan with a warning.
        available: iterable of plugin names available on this host. Pass
            ``None`` to skip availability filtering (use only when the
            caller has already verified availability — e.g. tests).
        include_extended: when True, append the ``extended`` plugin list
            after ``core``. Default False — Phase 2 runs core only by
            policy; extended plugins can be opted into later.
        plans_path: override path for ``plugin_plans.yaml``. Tests use
            this; production code should not.

    Never raises. See module docstring for return shape.
    """
    plans = _load_plans(plans_path)
    src = str(Path(plans_path) if plans_path else DEFAULT_PLANS_PATH)
    warnings: list[str] = []
    skipped: list[dict[str, str]] = []
    fallbacks_applied: list[dict[str, str]] = []

    osn = (os_name or "").lower().strip()
    if osn not in _SUPPORTED_OS:
        warnings.append(
            f"unknown OS {os_name!r} — returning empty plan; "
            f"supported values: {_SUPPORTED_OS}"
        )
        return {
            "os": "unknown", "plugins": [], "skipped": skipped,
            "warnings": warnings, "fallbacks_applied": fallbacks_applied,
            "include_extended": include_extended, "source": src,
        }

    block = plans.get(osn) or {}
    core = list(block.get("core") or [])
    extended = list(block.get("extended") or [])
    fallbacks: dict[str, str] = (plans.get("fallbacks") or {})

    if not core and not extended:
        warnings.append(
            f"no plugins listed for {osn!r} in {src}; "
            "check plugin_plans.yaml"
        )

    raw_order = core + (extended if include_extended else [])
    raw_order = _dedupe_preserve(raw_order)

    # Availability filter. ``None`` means "skip filtering entirely".
    avail_set: set[str] | None = (
        set(available) if available is not None else None
    )

    planned: list[str] = []
    for name in raw_order:
        if avail_set is not None and name not in avail_set:
            # Try the fallback table.
            replacement = fallbacks.get(name)
            if replacement and (avail_set is None or replacement in avail_set):
                fallbacks_applied.append({"from": name, "to": replacement})
                if replacement not in planned:
                    planned.append(replacement)
                continue
            reason = (
                f"plugin not available on this Volatility install"
                if replacement is None
                else (
                    f"plugin not available; fallback {replacement!r} also "
                    f"unavailable"
                )
            )
            skipped.append({"plugin": name, "reason": reason})
            continue
        if name not in planned:
            planned.append(name)

    return {
        "os": osn,
        "plugins": planned,
        "skipped": skipped,
        "warnings": warnings,
        "fallbacks_applied": fallbacks_applied,
        "include_extended": include_extended,
        "source": src,
    }


def supported_os() -> tuple[str, ...]:
    """Public accessor for the supported OS tuple."""
    return _SUPPORTED_OS
