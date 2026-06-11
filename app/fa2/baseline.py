"""
m3mx tool — Full Analysis V2 baseline / allowlist helpers.

Loads ``rules/baseline.yaml`` lazily and exposes safe predicate helpers:

* :func:`is_private_ip`
* :func:`is_known_browser`
* :func:`is_system_path`
* :func:`is_temp_path`
* :func:`is_allowlisted`

The intent is *not* to silently drop artifacts — V2 keeps every artifact
and merely reduces its score when one of these helpers fires. That keeps
the analyst's evidence trail intact while collapsing the noise floor.

If the YAML file is missing or malformed, every helper returns ``False``
(the conservative default) and a warning is logged once. Nothing here
ever raises.
"""
from __future__ import annotations

import fnmatch
import ipaddress
import logging
import threading
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any

from .utils import load_yaml_safe, project_root

log = logging.getLogger("m3mx.fa2.baseline")

# Default location; tests override via :func:`set_baseline_path`.
DEFAULT_BASELINE_PATH = project_root() / "rules" / "baseline.yaml"

_state_lock = threading.RLock()
_loaded: dict[str, Any] | None = None
_loaded_from: str | None = None


# ---------------------------------------------------------------------------
# Loader
# ---------------------------------------------------------------------------

def _reload() -> dict[str, Any]:
    """Force a re-read of the YAML file (used by tests + set_baseline_path)."""
    global _loaded
    _loaded = load_yaml_safe(_loaded_from or DEFAULT_BASELINE_PATH)
    return _loaded


def _get() -> dict[str, Any]:
    """Lazy accessor — loads on first call, returns cached dict afterwards."""
    global _loaded, _loaded_from
    with _state_lock:
        if _loaded is None:
            _loaded_from = str(DEFAULT_BASELINE_PATH)
            _loaded = load_yaml_safe(DEFAULT_BASELINE_PATH)
        return _loaded


def set_baseline_path(path: str | None) -> None:
    """
    Test helper: point the loader at a different YAML and force reload.
    Pass ``None`` to reset to the default project baseline.
    """
    global _loaded, _loaded_from
    with _state_lock:
        _loaded_from = str(path) if path else str(DEFAULT_BASELINE_PATH)
        _loaded = None  # next _get() will reload
        _reload()


# ---------------------------------------------------------------------------
# IP helpers
# ---------------------------------------------------------------------------

def _parse_networks(entries: list[str]) -> list[ipaddress._BaseNetwork]:
    nets: list[ipaddress._BaseNetwork] = []
    for entry in entries or ():
        try:
            nets.append(ipaddress.ip_network(entry, strict=False))
        except (ValueError, TypeError):
            log.warning("baseline: invalid network in private_networks: %r", entry)
    return nets


def is_private_ip(ip: str | None) -> bool:
    """
    True if *ip* is inside any range listed in
    ``private_networks`` (or, when YAML is unavailable, inside the
    standard RFC1918 + loopback + link-local set).

    Conservative on parse failure: returns False on non-IP input rather
    than ever claiming a public IP is private.
    """
    if not ip:
        return False
    try:
        addr = ipaddress.ip_address(ip.strip())
    except (ValueError, TypeError):
        return False
    nets = _parse_networks(_get().get("private_networks") or [])
    if not nets:
        # YAML missing — defer to Python's built-in classification.
        return addr.is_private or addr.is_loopback or addr.is_link_local
    return any(addr in n for n in nets)


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------

def _os_block(os_name: str | None) -> dict[str, Any]:
    """Return the per-OS sub-mapping (windows/linux/mac), or empty dict."""
    if not os_name:
        return {}
    return _get().get(os_name.lower(), {}) or {}


def _norm_path(p: str, os_name: str) -> str:
    """
    Normalise *p* for comparison: lowercase Windows paths and collapse
    backslashes; leave POSIX paths as-is but strip trailing slashes.
    """
    if not p:
        return ""
    if os_name == "windows":
        return PureWindowsPath(p).as_posix().lower().replace("\\", "/")
    return str(PurePosixPath(p)).rstrip("/")


def _path_matches(needle: str, candidates: list[str], os_name: str) -> bool:
    """
    True if *needle* lives under any of *candidates*. Supports glob
    wildcards in the baseline entries (e.g. ``C:\\Users\\*\\AppData…``).
    """
    if not needle:
        return False
    target = _norm_path(needle, os_name)
    for raw in candidates or ():
        pat = _norm_path(raw, os_name)
        if not pat:
            continue
        # Exact prefix match — keep behaviour predictable.
        if target == pat or target.startswith(pat.rstrip("/") + "/"):
            return True
        # Wildcard support for entries like /Users/*/AppData/Local/Temp.
        if "*" in pat or "?" in pat:
            if fnmatch.fnmatchcase(target, pat) or fnmatch.fnmatchcase(target, pat.rstrip("/") + "/*"):
                return True
    return False


def is_system_path(path: str | None, os_name: str) -> bool:
    """True if *path* is under a documented system-binary directory."""
    if not path:
        return False
    return _path_matches(path, _os_block(os_name).get("system_paths") or [], os_name.lower())


def is_temp_path(path: str | None, os_name: str) -> bool:
    """True if *path* is under a documented temp / drop-zone directory."""
    if not path:
        return False
    return _path_matches(path, _os_block(os_name).get("temp_paths") or [], os_name.lower())


# ---------------------------------------------------------------------------
# Process-name helpers
# ---------------------------------------------------------------------------

def _names_list(block: dict[str, Any], *keys: str) -> list[str]:
    out: list[str] = []
    for k in keys:
        out.extend(block.get(k) or [])
    return out


def _name_in(needle: str | None, names: list[str], *, case_insensitive: bool) -> bool:
    if not needle:
        return False
    n = needle.strip()
    if case_insensitive:
        n = n.lower()
        return any(n == (x or "").lower() for x in names)
    return any(n == x for x in names)


def is_known_browser(name: str | None, os_name: str) -> bool:
    """True if *name* matches one of the OS's known browser binaries."""
    block = _os_block(os_name)
    # macOS browsers are Bundle names (Safari, Google Chrome, …) so we
    # keep case-sensitive matching there; Windows binaries are
    # case-insensitive (chrome.exe / Chrome.EXE).
    case_insensitive = os_name.lower() != "mac"
    return _name_in(name, _names_list(block, "browsers"), case_insensitive=case_insensitive)


def is_allowlisted(name_or_path: str | None, os_name: str) -> bool:
    """
    True if *name_or_path* is either:

    * a known browser
    * a known installer / updater
    * a known system path / temp path holding a known interpreter

    This is the catch-all helper rules use to attach the
    ``allowlisted_path_or_process`` negative modifier.
    """
    if not name_or_path:
        return False
    if is_known_browser(name_or_path, os_name):
        return True
    block = _os_block(os_name)
    case_insensitive = os_name.lower() != "mac"
    installer_keys: tuple[str, ...]
    if os_name.lower() == "windows":
        installer_keys = ("known_installers",)
    elif os_name.lower() == "mac":
        installer_keys = ("script_interpreters",)
    else:
        installer_keys = ("shells", "web_processes")
    if _name_in(name_or_path, _names_list(block, *installer_keys),
                case_insensitive=case_insensitive):
        return True
    if is_system_path(name_or_path, os_name):
        return True
    return False
