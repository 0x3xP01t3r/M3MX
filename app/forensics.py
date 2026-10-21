"""
m3mx tool — Volatility wrapper.

Phase 3 provides a working runner; Phase 9 extends it with caching,
parallel execution, partial-result streaming, and v2 profile auto-pass.
"""
from __future__ import annotations

import concurrent.futures as _futures
import logging
import os
import re
import shutil
import subprocess
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from threading import RLock
from typing import Optional

from .plugins import find_plugin, flat_plugins
from .security import checked_path, PolicyError
from .evidence import image_identity
from .processes import run_command, child_environment


def _vol_env() -> dict:
    """
    Environment for every Vol invocation. Always sets
    VOL3_ALLOW_PARTIAL_DUMP=1 so our patched Vol3 layer-stacker accepts
    truncated/partial memory dumps (the standard 280 MB-class snapshots
    that fail validation on stock Vol3).
    """
    env = child_environment()
    env["VOL3_ALLOW_PARTIAL_DUMP"] = "1"
    return env

log = logging.getLogger("m3mx.forensics")

# In-process cache: { (image_abs_path, plugin, version, format) -> PluginResult }
_cache: dict[tuple, "PluginResult"] = {}
_cache_lock = RLock()

# Cache the detected OS profile per image
_profile_cache: dict[tuple, str] = {}


@dataclass
class PluginResult:
    success: bool
    output: str = ""
    error: str = ""
    elapsed: float = 0.0
    command: str = ""
    plugin: str = ""
    version: str = ""
    format: str = "text"
    rows: list | None = None
    columns: list | None = None

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Detection
# ---------------------------------------------------------------------------

def detect_volatility() -> dict:
    vol3 = next((shutil.which(x) for x in ("vol", "volatility3", "vol3") if shutil.which(x)), None)
    vol2 = next((shutil.which(x) for x in ("vol2", "vol.py", "volatility", "volatility2") if shutil.which(x)), None)
    bundled = Path(__file__).resolve().parent.parent / "bin" / "vol2"
    if not vol2 and shutil.which("python2") and bundled.is_file():
        vol2 = str(bundled)
    return {"vol2": vol2, "vol3": vol3}


# ---------------------------------------------------------------------------
# Command construction
# ---------------------------------------------------------------------------

def validate_extra_args(args: list[str]) -> list[str]:
    """Plugin options cannot select executables, input layers, or write paths."""
    allowed_numbers = {"--pid", "--offset", "--physaddr", "--virtaddr", "--address"}
    allowed_flags = {"--dump"}
    result = []
    i = 0
    while i < len(args):
        key, sep, value = args[i].partition("=")
        if key in allowed_flags and not sep:
            # Dump plugins need an application-controlled output directory.
            raise PolicyError("use File Extractor to create dumps in a controlled output directory")
        if key not in allowed_numbers | {"--yara-file"}:
            raise PolicyError(f"plugin option is not approved: {key}")
        if not sep:
            i += 1
            if i >= len(args):
                raise PolicyError(f"missing value for {key}")
            value = args[i]
        if key == "--yara-file":
            value = str(checked_path(value, ("rules",), file=True))
        elif not re.fullmatch(r"(?:0x[0-9a-fA-F]+|[0-9]+)(?:,(?:0x[0-9a-fA-F]+|[0-9]+))*", value):
            raise PolicyError(f"invalid numeric value for {key}")
        result.append(f"{key}={value}")
        i += 1
    return result

def _build_v3_cmd(vol_bin: str, image: str, plugin_v3: str, fmt: str,
                  extra_args: list[str] | None = None) -> list[str]:
    # Volatility 3 wants `-r <renderer>` BEFORE the plugin name
    renderer = "csv" if fmt == "csv" else "pretty"
    cmd = [vol_bin, "-q", "-f", image, "-r", renderer, plugin_v3]
    if extra_args:
        cmd.extend(extra_args)
    return cmd


def _detect_v2_profile(vol_bin: str, image: str, timeout: int = 600) -> str | None:
    """
    Run `vol.py -f IMAGE imageinfo` once and cache the first suggested
    profile so subsequent Vol2 plugin calls get a correct --profile=.
    Returns the profile string, or None if detection failed.
    """
    cached = _profile_cache.get(image_identity(image))
    if cached:
        return cached
    cmd = ["python2", vol_bin] if vol_bin.endswith(".py") else [vol_bin]
    cmd += ["-f", image, "imageinfo"]
    log.info("auto-detecting Vol2 profile: %s", " ".join(cmd))
    try:
        proc = run_command(cmd, timeout=timeout, env=_vol_env())
    except subprocess.TimeoutExpired:
        log.warning("imageinfo timed out after %ss", timeout)
        return None
    except Exception as e:                                      # pragma: no cover
        log.warning("imageinfo failed: %s", e)
        return None
    for line in (proc.stdout or "").splitlines():
        if "Suggested Profile(s)" in line:
            prof = line.split(":", 1)[-1].strip().split(",")[0].strip()
            if prof:
                _profile_cache[image_identity(image)] = prof
                log.info("auto-cached Vol2 profile %s for %s", prof, image)
                return prof
    log.warning("imageinfo produced no suggested profile (returncode=%s)",
                proc.returncode)
    return None


def _build_v2_cmd(vol_bin: str, image: str, plugin_v2: str, profile: str | None, fmt: str,
                  extra_args: list[str] | None = None) -> list[str]:
    # Volatility 2 only supports python2. If vol_bin is a .py script,
    # invoke it explicitly under python2 so a stray python3 in PATH can
    # never silently break the run. If vol_bin is a wrapper (.sh / shim
    # / compiled), trust it to dispatch python2 internally.
    cmd = ["python2", vol_bin] if vol_bin.endswith(".py") else [vol_bin]
    cmd += ["-f", image]
    # `imageinfo` and `kdbgscan` discover the profile themselves — passing
    # `--profile=` makes the command confusing in logs and CLI copy/paste.
    profile_agnostic = {"imageinfo", "kdbgscan"}
    if profile and plugin_v2 not in profile_agnostic:
        cmd += [f"--profile={profile}"]   # single-arg form, matches vol.py docs
    if fmt == "csv":
        cmd += ["--output=csv"]
    cmd += [plugin_v2]
    if extra_args:
        cmd.extend(extra_args)
    return cmd


# ---------------------------------------------------------------------------
# CSV parsing (lightweight — no pandas)
# ---------------------------------------------------------------------------

def _parse_csv(text: str) -> tuple[list[str], list[list[str]]]:
    import csv, io
    rdr = csv.reader(io.StringIO(text))
    rows = [r for r in rdr if r]
    if not rows:
        return [], []
    return rows[0], rows[1:]


# ---------------------------------------------------------------------------
# Main entry point
# ---------------------------------------------------------------------------

def run_plugin(image_path: str | Path,
               plugin: str,
               version: str = "auto",
               timeout: int = 600,
               vol_paths: dict | None = None,
               profile: str | None = None,
               use_cache: bool = True,
               extra_args: list[str] | None = None) -> PluginResult:
    """
    Execute a Volatility plugin.

    Args:
        image_path: path to memory dump
        plugin: short name (e.g. 'pslist') matching plugins.json
        version: 'v2', 'v3', or 'auto' (prefer v3)
        timeout: seconds before SIGKILL
        vol_paths: {'vol2': <path|None>, 'vol3': <path|None>}; if None, auto-detect
        profile: vol2 profile string (optional)
        use_cache: reuse previous identical run
    """
    try:
        image = str(checked_path(image_path, ("evidence",), file=True))
    except (PolicyError, OSError) as exc:
        return PluginResult(success=False, error=str(exc), plugin=plugin)
    meta = find_plugin(plugin)
    if not meta:
        return PluginResult(success=False, error=f"Unknown plugin '{plugin}'", plugin=plugin)

    fmt = meta.get("format", "text")
    paths = vol_paths or detect_volatility()
    vol2 = paths.get("vol2")
    vol3 = paths.get("vol3")

    # Decide version
    want_v3 = meta.get("vol3") is not None and vol3
    want_v2 = meta.get("vol2") is not None and vol2
    chosen: str
    if version == "v3" and want_v3: chosen = "v3"
    elif version == "v2" and want_v2: chosen = "v2"
    elif version == "auto" and want_v3: chosen = "v3"
    elif version == "auto" and want_v2: chosen = "v2"
    else:
        return PluginResult(
            success=False,
            error=("Volatility 3 not available for this plugin. "
                   "Install it or choose a different plugin.")
                  if version in ("v3", "auto") else
                  "Volatility 2 not available for this plugin.",
            plugin=plugin, format=fmt,
        )

    try:
        extra_args = validate_extra_args(extra_args or [])
    except (PolicyError, ValueError) as exc:
        return PluginResult(success=False, error=str(exc), plugin=plugin)
    cache_key = (image_identity(image), plugin, chosen, fmt, tuple(extra_args), profile, vol2, vol3)
    if use_cache:
        with _cache_lock:
            hit = _cache.get(cache_key)
            if hit:
                log.info("cache hit: %s (%s)", plugin, chosen)
                return hit

    def _build_cmd_for(version: str) -> list[str]:
        if version == "v3":
            return _build_v3_cmd(vol3, image, meta["vol3"], fmt, extra_args)
        prof = profile or _profile_cache.get(image_identity(image))
        if not prof and plugin != "imageinfo":
            prof = _detect_v2_profile(vol2, image, timeout)
        return _build_v2_cmd(vol2, image, meta["vol2"], prof, fmt, extra_args)

    cmd = _build_cmd_for(chosen)
    log.info("running: %s", " ".join(cmd))
    t0 = time.monotonic()
    try:
        proc = run_command(cmd, timeout=timeout, env=_vol_env())
        elapsed = time.monotonic() - t0
        ok = (proc.returncode == 0) and bool(proc.stdout.strip())

        # ── Vol3 → Vol2 fallback ─────────────────────────────────────
        # Vol3 is the modern engine but several real-world failure modes
        # leave older Windows images broken under v3 while v2 handles them
        # cleanly: missing PDB symbols (hashdump/lsadump/cachedump),
        # stricter layer stacking, plugins that don't exist in v3, etc.
        # If the user asked for "auto" and a v2 mapping + binary are both
        # available, transparently retry under Vol2.
        v3_stderr = proc.stderr or ""
        fallback_used = False
        if (not ok and chosen == "v3" and version == "auto"
                and vol2 and meta.get("vol2")):
            log.warning("vol3 failed for %s (rc=%s); falling back to vol2",
                        plugin, proc.returncode)
            chosen = "v2"
            cmd = _build_cmd_for("v2")
            log.info("running (v2 fallback): %s", " ".join(cmd))
            t1 = time.monotonic()
            proc = run_command(cmd, timeout=timeout, env=_vol_env())
            elapsed = time.monotonic() - t1
            ok = (proc.returncode == 0) and bool(proc.stdout.strip())
            fallback_used = True

        output = proc.stdout
        err = proc.stderr if (not ok or proc.returncode != 0) else ""
        if fallback_used and ok:
            v3_hint = (v3_stderr.strip().splitlines() or ["(no stderr)"])[-1][:200]
            err = (err or "") + (
                f"\n[note] Vol3 failed for this plugin/image — retried under Vol2 "
                f"successfully. Vol3 said: {v3_hint}"
            )
        # ── Friendly hints for common Vol2 failures ──────────────────
        # Vol2's error messages are terse and assume CLI familiarity.
        # Translate the most common ones into actionable guidance so
        # users know what to type in "Additional Parameters".
        if not ok and chosen == "v2" and err:
            err_low = err.lower()
            hint = None
            if "specify a dump directory" in err_low or "--dump-dir" in err_low:
                hint = ("This plugin needs an output directory. Add "
                        "`--dump-dir=outputs/extracted` (or `-D outputs/extracted`) "
                        "in Additional Parameters.")
            elif ("specify a regular expression" in err_low
                  or "specify a process" in err_low
                  or "-Q" in err and "-r" in err and "offset" in err_low):
                hint = ("This plugin needs `-Q <offset>` or `-r <regex>` AND "
                        "`-D <dir>` in Additional Parameters.")
            elif "must specify a pid" in err_low or "specify a process id" in err_low:
                hint = ("This plugin needs `-p <PID>` and usually `-D <dir>` "
                        "in Additional Parameters.")
            elif "specify a yara" in err_low or "specify a rule" in err_low:
                hint = ("yarascan needs `-Y <inline rule>` or `-y <rules.yar>` "
                        "in Additional Parameters.")
            elif "invalid plugin" in err_low or "no plugin named" in err_low or "cannot find plugin" in err_low:
                hint = ("Vol2 doesn't recognise this plugin. If it's a community "
                        "plugin (mimikatz, hollowfind, shimcache, shellbags, "
                        "usnjrnl, amcache), install the volatility-community repo "
                        "and pass `--plugins=/path/to/community` in Additional Parameters.")
            if hint:
                err = err.rstrip() + f"\n\n[hint] {hint}"

        result = PluginResult(
            success=ok, output=output, error=err,
            elapsed=round(elapsed, 2),
            command=" ".join(cmd), plugin=plugin, version=chosen, format=fmt,
        )
        if fmt == "csv" and ok:
            cols, rows = _parse_csv(output)
            result.columns = cols
            result.rows = rows

        # Auto-detect profile from v2 imageinfo output & cache it
        if plugin == "imageinfo" and chosen == "v2" and ok:
            for line in output.splitlines():
                if "Suggested Profile(s)" in line:
                    prof_str = line.split(":", 1)[-1].strip().split(",")[0].strip()
                    if prof_str:
                        _profile_cache[image_identity(image)] = prof_str
                        log.info("cached profile %s for %s", prof_str, image)
                    break

        if use_cache and ok and len(output) <= 4 * 1024**2:
            with _cache_lock:
                if len(_cache) >= 16:
                    _cache.pop(next(iter(_cache)))
                _cache[cache_key] = result
        return result

    except subprocess.TimeoutExpired as e:
        elapsed = time.monotonic() - t0
        return PluginResult(
            success=False,
            error=f"timed out after {timeout}s",
            output=(e.stdout or ""), command=" ".join(cmd),
            elapsed=round(elapsed, 2), plugin=plugin, version=chosen, format=fmt,
        )
    except FileNotFoundError as e:
        return PluginResult(
            success=False, error=f"binary not found: {e}",
            command=" ".join(cmd), plugin=plugin, version=chosen, format=fmt,
        )
    except Exception as e:  # pragma: no cover
        return PluginResult(
            success=False, error=f"{type(e).__name__}: {e}",
            command=" ".join(cmd), plugin=plugin, version=chosen, format=fmt,
        )


def stream_plugin(image_path: str | Path,
                  plugin: str,
                  version: str = "auto",
                  timeout: int = 600,
                  vol_paths: dict | None = None):
    """
    Generator variant: yields dicts for live streaming.

        {"type": "start", "command": str, "plugin": str, "version": str}
        {"type": "line",  "stream": "stdout"|"stderr", "line": str}
        {"type": "done",  "exit": int, "elapsed": float}
        {"type": "error", "message": str}
    """
    import threading, queue as _q
    image = str(Path(image_path).resolve())
    meta = find_plugin(plugin)
    if not meta:
        yield {"type": "error", "message": f"Unknown plugin '{plugin}'"}
        return

    fmt = meta.get("format", "text")
    paths = vol_paths or detect_volatility()
    vol3 = paths.get("vol3"); vol2 = paths.get("vol2")

    want_v3 = meta.get("vol3") is not None and vol3
    want_v2 = meta.get("vol2") is not None and vol2
    if version == "v3" and want_v3: chosen = "v3"
    elif version == "v2" and want_v2: chosen = "v2"
    elif want_v3: chosen = "v3"
    elif want_v2: chosen = "v2"
    else:
        yield {"type": "error", "message": "no compatible Volatility binary"}
        return

    if chosen == "v3":
        cmd = _build_v3_cmd(vol3, image, meta["vol3"], fmt)
    else:
        cmd = _build_v2_cmd(vol2, image, meta["vol2"],
                            _profile_cache.get(image_identity(image)), fmt)

    yield {"type": "start", "command": " ".join(cmd),
           "plugin": plugin, "version": chosen}

    from .processes import stream_command
    t0 = time.monotonic()
    try:
        for name, value in stream_command(cmd, timeout=timeout, env=_vol_env()):
            if name == "exit":
                yield {"type": "done", "exit": value,
                       "elapsed": round(time.monotonic() - t0, 2)}
            else:
                yield {"type": "line", "stream": name, "line": value}
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        yield {"type": "error", "message": str(exc)}


def cached_profile(image_path: str | Path) -> str | None:
    return _profile_cache.get(image_identity(image_path))


def set_profile(image_path: str | Path, profile: str) -> None:
    _profile_cache[image_identity(image_path)] = profile


def ensure_profile(image_path: str | Path,
                   vol2_path: str | None = None,
                   timeout: int = 600) -> str | None:
    """
    Public helper: return a Vol2 profile for the image, running
    imageinfo once if nothing is cached yet. Used by both run_plugin
    and the file extractor so anyone touching Vol2 gets a real profile
    instead of falling back to WinXPSP2x86.
    """
    image = str(Path(image_path).resolve())
    cached = _profile_cache.get(image_identity(image))
    if cached:
        return cached
    vol2 = vol2_path or detect_volatility().get("vol2")
    if not vol2:
        return None
    return _detect_v2_profile(vol2, image, timeout)


def clear_cache() -> None:
    with _cache_lock:
        _cache.clear()


# ---------------------------------------------------------------------------
# Friendly error diagnosis
# ---------------------------------------------------------------------------

_PROFILE_HINTS = [
    "no suitable address space",
    "could not find suitable",
    "requires_profile",
    "symbol table requirements",
    "unable to validate the plugin",
    "'profile' is required",
]

def diagnose(result: "PluginResult") -> PluginResult:
    """Annotate a result with a human-friendly hint if we recognize the error."""
    if result.success or not result.error:
        return result
    err = result.error.lower()
    hint = None
    if any(h in err for h in _PROFILE_HINTS):
        hint = ("No OS profile was detected or the plugin requires one. "
                "Run `imageinfo` (v2) or `windows.info` (v3) first to "
                "identify the image, then retry.")
    elif "no module named" in err or "not found" in err and ".py" in err:
        hint = "Volatility binary is missing a plugin module. Try the other version (v2/v3) if available."
    elif "command not found" in err or "No such file or directory" in (result.error or ""):
        hint = "Volatility binary is not on PATH. Install it or set the path in Settings."
    elif "timed out" in err:
        hint = "Plugin exceeded the timeout. Partial output is shown below — raise the timeout in Settings."
    elif "permission denied" in err:
        hint = "Can't read the memory image. Check filesystem permissions."

    if hint:
        # Append the hint to error without losing the original
        result.error = f"{result.error}\n\nhint: {hint}"
    return result


def _run_plugin_with_diagnosis(*a, **kw) -> PluginResult:
    return diagnose(run_plugin(*a, **kw))


# ---------------------------------------------------------------------------
# Parallel execution
# ---------------------------------------------------------------------------

def run_parallel(image_path: str | Path,
                 plugin_names: list[str],
                 version: str = "auto",
                 timeout: int = 600,
                 vol_paths: dict | None = None,
                 max_workers: int = 4) -> dict[str, PluginResult]:
    """Run several plugins concurrently. Returns {plugin_name: PluginResult}."""
    results: dict[str, PluginResult] = {}
    with _futures.ThreadPoolExecutor(max_workers=max_workers) as pool:
        future_map = {
            pool.submit(
                _run_plugin_with_diagnosis,
                image_path, name, version, timeout, vol_paths,
            ): name
            for name in plugin_names
        }
        for fut in _futures.as_completed(future_map):
            name = future_map[fut]
            try:
                results[name] = fut.result()
            except Exception as e:                              # pragma: no cover
                results[name] = PluginResult(
                    success=False, error=f"{type(e).__name__}: {e}",
                    plugin=name, version=version,
                )
    return results


# ---------------------------------------------------------------------------
# Quick Triage: essential plugins + parallel
# ---------------------------------------------------------------------------

ESSENTIAL_PLUGINS = [
    "imageinfo",   # profile + build info
    "pslist",      # running processes
    "pstree",      # process tree
    "psscan",      # hidden / terminated processes
    "cmdline",     # process command lines
    "netscan",     # network sockets
    "malfind",     # injected code
    "svcscan",     # services
    "filescan",    # cached files
    "hashdump",    # password hashes
]


def quick_triage(image_path: str | Path,
                 vol_paths: dict,
                 timeout: int = 600,
                 plugin_names: list[str] | None = None) -> dict:
    """
    Run the essential battery in parallel and return a summary dict
    suitable for the UI and for feeding to the AI report generator.
    """
    plugins = plugin_names or ESSENTIAL_PLUGINS
    # Skip plugins that aren't in the registry (defensive)
    valid = [p for p in plugins if find_plugin(p)]

    t0 = time.monotonic()
    raw = run_parallel(image_path, valid, timeout=timeout,
                       vol_paths=vol_paths, max_workers=4)
    elapsed = round(time.monotonic() - t0, 2)

    summary = []
    for name in valid:
        res = raw.get(name)
        if not res: continue
        summary.append({
            "plugin":  name,
            "success": res.success,
            "elapsed": res.elapsed,
            "version": res.version,
            "rows":    len(res.rows) if res.rows else None,
            "error":   (res.error.splitlines()[0] if res.error else None),
        })

    return {
        "elapsed":    elapsed,
        "plugins":    summary,
        "results":    {name: r.to_dict() for name, r in raw.items()},
        "successful": sum(1 for r in raw.values() if r.success),
        "total":      len(raw),
    }
