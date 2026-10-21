"""
m3mx tool — file discovery & extraction.

Uses Volatility's filescan + dumpfiles plugins. Results are normalized
into a structured list that the UI can filter, sort, and paginate.

AI-assisted flagging sends ONLY the metadata list to the LLM (never
file contents) and asks it to identify high-priority targets.
"""
from __future__ import annotations

import json
import logging
import re
import shutil
import subprocess
import uuid
from .security import checked_path, bounded_read
from .processes import run_command
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Optional

from . import forensics
from .config import OUTPUTS_DIR

log = logging.getLogger("m3mx.extractor")


# ---------------------------------------------------------------------------
# File classification
# ---------------------------------------------------------------------------

ICONS = {
    "exe": "⚙",  "dll": "⚙",  "sys": "⚙",  "scr": "⚙",  "bat": "⚙",  "cmd": "⚙",
    "pdf": "📄", "doc": "📄", "docx": "📄", "txt": "📄", "log": "📄",
    "xls": "📄", "xlsx": "📄", "csv": "📄", "rtf": "📄", "ini": "📄",
    "jpg": "🖼", "jpeg": "🖼","png": "🖼", "gif": "🖼", "bmp": "🖼",
    "zip": "📦", "rar": "📦", "7z": "📦",  "tar": "📦", "gz": "📦",
    "mp3": "🎵", "wav": "🎵", "mp4": "🎞", "avi": "🎞", "mkv": "🎞",
    "ps1": "⚡", "vbs": "⚡", "js":  "⚡", "py": "⚡", "sh": "⚡",
}

# Extensions that deserve priority by default
HIGH_VALUE_EXT = {"exe", "dll", "sys", "scr", "ps1", "vbs", "bat", "cmd",
                  "doc", "docx", "pdf", "xls", "xlsx", "zip", "rar", "7z", "lnk"}

SUSPICIOUS_PATH_RE = re.compile(
    r"\\(Temp|AppData\\Local\\Temp|Users\\Public|ProgramData)\\",
    re.IGNORECASE,
)


def _icon_for(ext: str) -> str:
    return ICONS.get(ext.lower(), "📁")


def _classify(entry: dict) -> dict:
    name = entry["name"]
    path = entry["path"]
    ext = entry["ext"]
    flags = []
    priority = 0

    if ext in HIGH_VALUE_EXT:
        priority += 2
        flags.append("executable" if ext in {"exe","dll","sys","scr"} else "document")
    if SUSPICIOUS_PATH_RE.search(path):
        priority += 3
        flags.append("temp-dir")
    if ext in {"exe", "dll"} and SUSPICIOUS_PATH_RE.search(path):
        priority += 2
        flags.append("suspicious-exe-location")
    if name.lower().startswith(tuple(["mimikatz", "pwdump", "proc", "nc.", "netcat", "beacon"])):
        priority += 5
        flags.append("known-malware-name")

    entry["flags"] = flags
    entry["priority"] = priority
    entry["high_value"] = ext in HIGH_VALUE_EXT or priority >= 3
    return entry


# ---------------------------------------------------------------------------
# Scan
# ---------------------------------------------------------------------------

@dataclass
class FileEntry:
    offset: str
    path: str
    name: str
    ext: str
    icon: str
    size: Optional[int]
    flags: list
    priority: int
    high_value: bool


def scan_for_files(image_path: str, vol_paths: dict, timeout: int = 600) -> dict:
    """Run filescan and return a normalized list."""
    if not Path(image_path).exists():
        return {"error": "memory image not found", "files": []}

    t0 = time.monotonic()
    result = forensics.run_plugin(image_path, "filescan",
                                  vol_paths=vol_paths, timeout=timeout)
    elapsed = round(time.monotonic() - t0, 2)

    if not result.success:
        return {"error": result.error or "filescan failed",
                "command": result.command, "files": [], "elapsed": elapsed}

    files = []
    # Prefer parsed CSV when available (vol3)
    if result.rows and result.columns:
        cols = [c.lower() for c in result.columns]
        off_idx  = next((i for i, c in enumerate(cols) if "offset" in c), 0)
        name_idx = next((i for i, c in enumerate(cols) if "name" in c), len(cols) - 1)
        size_idx = next((i for i, c in enumerate(cols) if "size" in c), None)
        for row in result.rows:
            path = row[name_idx] if name_idx < len(row) else ""
            if not path: continue
            leaf = path.replace("/", "\\").split("\\")[-1] or path
            ext = leaf.split(".")[-1].lower() if "." in leaf else ""
            files.append(_classify({
                "offset": row[off_idx] if off_idx < len(row) else "",
                "path":   path,
                "name":   leaf,
                "ext":    ext,
                "icon":   _icon_for(ext),
                "size":   int(row[size_idx]) if size_idx is not None and size_idx < len(row) and row[size_idx].isdigit() else None,
            }))
    else:
        # Fall back to parsing text output line by line
        for line in (result.output or "").splitlines():
            m = re.search(r"(0x[0-9a-fA-F]+)\s+.*?([A-Za-z]:\\\S+|\\\S+)", line)
            if m:
                path = m.group(2)
                leaf = path.replace("/", "\\").split("\\")[-1] or path
                ext = leaf.split(".")[-1].lower() if "." in leaf else ""
                files.append(_classify({
                    "offset": m.group(1), "path": path, "name": leaf,
                    "ext": ext, "icon": _icon_for(ext), "size": None,
                }))

    # Sort: high-priority first, then by path
    files.sort(key=lambda e: (-e["priority"], e["path"].lower()))

    return {
        "files": files,
        "count": len(files),
        "elapsed": elapsed,
        "command": result.command,
        "version": result.version,
    }


# ---------------------------------------------------------------------------
# Extract
# ---------------------------------------------------------------------------

def extract_files(image_path: str, offsets: list[str], output_dir: str | Path,
                  vol_paths: dict, timeout: int = 600) -> dict:
    """
    Dump files at the given offsets.

    Strategy:
        - Run vol with cwd set to the target dir so the dumpfiles plugin
          writes its output files there regardless of how it interprets `-o`.
        - Snapshot the directory contents before and after each call so we
          know exactly which files came from THIS extraction (vol3's exit
          code is 0 even when dumpfiles produces no output, e.g. when the
          offset points to a non-recoverable FILE_OBJECT).
        - Try --physaddr first, then fall back to --virtaddr if nothing
          was dumped (filescan offsets are physical, but some images need
          the virtual variant).
    """
    vol3 = vol_paths.get("vol3")
    vol2 = vol_paths.get("vol2")
    from .evidence import evidence_key
    image_path = str(checked_path(image_path, ("evidence",), file=True))
    out = checked_path(Path(output_dir) / "extracted" / evidence_key(image_path) / uuid.uuid4().hex,
                       ("output",), must_exist=False)
    out.mkdir(parents=True, exist_ok=True)

    results = []

    def _snapshot() -> set[str]:
        return {p.name for p in out.iterdir() if p.is_file()}

    if vol3:
        for off in offsets:
            off = str(off).strip()
            if not re.fullmatch(r"0x[0-9a-fA-F]+", off):
                results.append({"offset": off, "ok": False,
                                "error": "invalid offset format", "dumped": []})
                continue

            before = _snapshot()
            new_files = []
            attempts = []

            for variant in ("--physaddr", "--virtaddr"):
                cmd = [vol3, "-q", "-f", image_path,
                       "-o", str(out),
                       "windows.dumpfiles.DumpFiles", variant, off]
                res = _run(cmd, timeout, cwd=str(out))
                after = _snapshot()
                new_files = sorted(after - before)

                # Capture useful diagnostic output (stdout has the result table)
                tail = (res.get("out") or "")[-400:]
                err  = (res.get("error") or "").strip()[:400]
                attempts.append({
                    "variant": variant,
                    "exit_ok": res.get("ok"),
                    "stderr_tail": err,
                    "stdout_tail": tail,
                    "new_files": new_files,
                })

                if new_files:
                    break  # success — stop trying variants

            ok = bool(new_files)
            err_msg = None
            if not ok:
                # Build a friendly composite error from both attempts
                hints = []
                for a in attempts:
                    if a["stderr_tail"]:
                        hints.append(f"{a['variant']}: {a['stderr_tail']}")
                if not hints:
                    hints.append(
                        "Volatility ran but no file was produced — the offset "
                        "may not point to a recoverable FILE_OBJECT (no cached "
                        "data section / shared cache map). Try a different file."
                    )
                err_msg = " | ".join(hints)

            results.append({
                "offset":  off,
                "ok":      ok,
                "error":   err_msg,
                "dumped":  new_files,
                "attempts": attempts,
            })

    elif vol2:
        # Auto-run imageinfo once if no profile is cached, so dumpfiles
        # gets a real --profile= instead of vol2's WinXPSP2x86 fallback.
        profile = forensics.ensure_profile(image_path, vol2, timeout=timeout)
        for off in offsets:
            off = str(off).strip()
            if not re.fullmatch(r"0x[0-9a-fA-F]+", off):
                results.append({"offset": off, "ok": False,
                                "error": "invalid offset format", "dumped": []})
                continue

            before = _snapshot()
            # Volatility 2 only runs under python2. If vol2 is a .py
            # script, invoke it explicitly under python2; otherwise
            # trust the wrapper to dispatch the right interpreter.
            cmd = ["python2", vol2] if vol2.endswith(".py") else [vol2]
            cmd += ["-f", image_path]
            if profile:
                cmd += [f"--profile={profile}"]
            cmd += ["dumpfiles", "-Q", off, "-D", str(out)]
            res = _run(cmd, timeout, cwd=str(out))
            after = _snapshot()
            new_files = sorted(after - before)

            ok = bool(new_files)
            err = res.get("error") or ""
            if not ok and not err:
                err = "Volatility 2 ran but produced no file at this offset."
            results.append({
                "offset":  off, "ok": ok,
                "error":   err if not ok else None,
                "dumped":  new_files,
                "stdout_tail": (res.get("out") or "")[-400:],
            })
    else:
        return {"error": "No Volatility binary available for extraction. "
                         "Install vol3 (`pip install --user volatility3`).",
                "results": [], "dumped": [], "count": 0, "total": len(offsets)}

    # Final enumeration — every file that exists in the dir after the run
    dumped = []
    for p in sorted(out.iterdir()):
        if p.is_file():
            st = p.stat()
            dumped.append({
                "name": p.name, "size": st.st_size,
                "path": str(p.relative_to(Path(output_dir))),
            })

    return {
        "results":    results,
        "dumped":     dumped,
        "output_dir": str(out),
        "count":      sum(1 for r in results if r["ok"]),
        "total":      len(results),
    }


# ---------------------------------------------------------------------------
# Preview (hex + strings) — used by the new File Extractor UI tabs.
# Extracts a single offset and reads the first N bytes of the dumped file.
# ---------------------------------------------------------------------------

def preview_offset(image_path: str, offset: str, output_dir: str | Path,
                   vol_paths: dict, timeout: int = 600,
                   byte_limit: int = 1024, min_str_len: int = 4) -> dict:
    """Extract a single offset and return hex rows + ASCII strings."""
    extract = extract_files(image_path, [offset], output_dir, vol_paths, timeout=timeout)
    r0 = (extract.get("results") or [{}])[0]
    if not r0.get("ok") or not r0.get("dumped"):
        return {
            "offset": offset,
            "error": r0.get("error") or "no file recovered at this offset",
            "hex_rows": [],
            "strings": [],
            "size": 0,
            "dumped": r0.get("dumped", []),
        }

    out_dir = Path(extract["output_dir"])
    # Pick the largest dumped file (dumpfiles often emits data + shared-cache parts)
    candidates = sorted(
        (out_dir / n for n in r0["dumped"] if (out_dir / n).exists()),
        key=lambda p: p.stat().st_size, reverse=True,
    )
    if not candidates:
        return {"offset": offset, "error": "extracted file missing on disk",
                "hex_rows": [], "strings": [], "size": 0, "dumped": r0["dumped"]}

    target = candidates[0]
    size_total = target.stat().st_size
    from .security import bounded_read, checked_path
    target = checked_path(target, ("output",), file=True)
    data = bounded_read(target, byte_limit)

    # Build hex rows (16 bytes / row)
    hex_rows = []
    for row_off in range(0, len(data), 16):
        chunk = data[row_off:row_off + 16]
        hex_parts = [f"{b:02X}" for b in chunk]
        hex_str = " ".join(hex_parts[:8]) + "  " + " ".join(hex_parts[8:]) if len(hex_parts) > 8 else " ".join(hex_parts)
        ascii_str = "".join(chr(b) if 32 <= b <= 126 else "." for b in chunk)
        hex_rows.append({
            "offset": f"{row_off:08X}",
            "hex":    hex_str,
            "ascii":  ascii_str,
        })

    # Extract printable ASCII strings
    strings: list[dict] = []
    current = bytearray()
    start = 0
    for i, b in enumerate(data):
        if 32 <= b <= 126:
            if not current: start = i
            current.append(b)
        else:
            if len(current) >= min_str_len:
                strings.append({"offset": f"0x{start:04X}",
                                "value":  current.decode("ascii", errors="replace")})
            current = bytearray()
    if len(current) >= min_str_len:
        strings.append({"offset": f"0x{start:04X}",
                        "value":  current.decode("ascii", errors="replace")})

    # MIME sniff — magic bytes first, fall back to extension.
    mime = _sniff_mime(data, target.name)

    # exiftool — best-effort. Skips silently if exiftool isn't installed.
    exif = _exif_dump(target)

    return {
        "offset":         offset,
        "name":           target.name,
        "size":           size_total,
        "preview_bytes":  len(data),
        "hex_rows":       hex_rows,
        "strings":        strings,
        "dumped":         r0["dumped"],
        "output_dir":     extract["output_dir"],
        "extracted_path": str(target.resolve()),
        "mime":           mime,
        "is_image":       mime.startswith("image/"),
        "exif":           exif,
    }


# ---------------------------------------------------------------------------
# MIME sniffing + exiftool helpers
# ---------------------------------------------------------------------------

_MAGIC = [
    (b"\x89PNG\r\n\x1a\n",    "image/png"),
    (b"\xff\xd8\xff",         "image/jpeg"),
    (b"GIF87a",               "image/gif"),
    (b"GIF89a",               "image/gif"),
    (b"RIFF",                 "image/webp"),         # later confirmed by 'WEBP' marker
    (b"BM",                   "image/bmp"),
    (b"\x00\x00\x01\x00",     "image/x-icon"),
    (b"%PDF-",                "application/pdf"),
    (b"PK\x03\x04",           "application/zip"),
    (b"7z\xbc\xaf'\x1c",      "application/x-7z-compressed"),
    (b"MZ",                   "application/x-dosexec"),
    (b"\x7fELF",              "application/x-executable"),
]

def _sniff_mime(head: bytes, fname: str) -> str:
    for magic, mime in _MAGIC:
        if head.startswith(magic):
            # WebP needs the second marker
            if mime == "image/webp" and not head[8:12] == b"WEBP":
                continue
            return mime
    import mimetypes
    g, _ = mimetypes.guess_type(fname)
    return g or "application/octet-stream"


def _exif_dump(target: Path) -> list[dict]:
    """Run `exiftool -j -short -fast` against the file. Returns [] if
    exiftool isn't installed or the file has no metadata."""
    if not shutil.which("exiftool"):
        return []
    try:
        proc = run_command(
            ["exiftool", "-j", "-short", "-fast", "-m", "-q", str(target)],
            timeout=20, max_bytes=256 * 1024,
        )
    except Exception as e:
        log.warning("exiftool failed: %s", e)
        return []
    if proc.returncode != 0 or not proc.stdout.strip():
        return []
    import json as _json
    try:
        arr = _json.loads(proc.stdout)
    except _json.JSONDecodeError:
        return []
    if not arr or not isinstance(arr, list):
        return []
    obj = arr[0] or {}
    # Drop noisy fields, keep order from exiftool.
    drop = {"SourceFile", "ExifToolVersion", "FileAccessDate", "FileInodeChangeDate"}
    out = []
    for k, v in obj.items():
        if k in drop:
            continue
        out.append({"tag": k, "value": str(v)[:400]})
    # Cap to keep payload tight.
    return out[:60]


def _run(cmd: list[str], timeout: int, cwd: str | None = None) -> dict:
    import os as _os
    from .processes import child_environment
    env = child_environment()
    env["VOL3_ALLOW_PARTIAL_DUMP"] = "1"
    log.info("extract: %s  (cwd=%s)", " ".join(cmd), cwd or ".")
    try:
        proc = run_command(cmd, timeout=timeout, cwd=cwd, env=env)
        return {
            "ok":    proc.returncode == 0,
            "out":   proc.stdout,
            "error": None if proc.returncode == 0
                          else (proc.stderr.strip() or f"exit {proc.returncode}"),
        }
    except subprocess.TimeoutExpired:
        return {"ok": False, "error": f"timed out after {timeout}s"}
    except FileNotFoundError as e:
        return {"ok": False, "error": str(e)}
    except Exception as e:                                  # pragma: no cover
        return {"ok": False, "error": f"{type(e).__name__}: {e}"}
