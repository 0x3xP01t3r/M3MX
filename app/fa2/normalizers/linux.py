"""
Linux plugin normalizers.

See :mod:`app.fa2.normalizers.windows` for the design contract — same
rules apply: never raise on malformed rows, always preserve the raw row,
return an empty list rather than ``None``.
"""
from __future__ import annotations

from typing import Sequence

from ..models import Artifact
from ._common import clean_ip, col_index, get, raw_dict, to_int


# ---------------------------------------------------------------------------
# Process plugins
# ---------------------------------------------------------------------------

def _linux_process_row(plugin: str, columns: Sequence[str], row: Sequence[str]) -> Artifact:
    idx = col_index(columns)
    pid  = to_int(get(idx, row, "PID"))
    ppid = to_int(get(idx, row, "PPID"))
    name = get(idx, row, "COMM", "Process", "Name")
    euid = get(idx, row, "EUID")
    path = get(idx, row, "File output", "Path")
    return Artifact(
        type="process", os="linux", source_plugin=plugin,
        raw=raw_dict(columns, row),
        fields={
            "pid":  pid,
            "ppid": ppid,
            "name": name or None,
            "user": (euid or None),
            "path": path or None,
        },
    )


def _normalize_pslist(columns, rows) -> list[Artifact]:
    return [_linux_process_row("linux.pslist", columns, r) for r in (rows or [])]


def _normalize_psscan(columns, rows) -> list[Artifact]:
    return [_linux_process_row("linux.psscan", columns, r) for r in (rows or [])]


def _normalize_pstree(columns, rows) -> list[Artifact]:
    return [_linux_process_row("linux.pstree", columns, r) for r in (rows or [])]


# ---------------------------------------------------------------------------
# Network (sockstat)
# ---------------------------------------------------------------------------

def _normalize_sockstat(columns, rows) -> list[Artifact]:
    """
    linux.sockstat is bimodal: AF_UNIX rows carry a Path; AF_INET rows
    carry Source/Destination address+port. We split on whichever
    columns are populated.
    """
    idx = col_index(columns)
    out: list[Artifact] = []
    for row in rows or []:
        proto = get(idx, row, "Protocol", "Family").upper() or None
        path = get(idx, row, "Path")
        # clean_ip() collapses placeholder addresses (-, 0.0.0.0, ::) to None
        # so they don't propagate into rules / correlations (OD-003).
        src_ip = clean_ip(get(idx, row, "Source Address", "SrcIP", "Source"))
        src_port = to_int(get(idx, row, "Source Port", "SrcPort"))
        dst_ip = clean_ip(get(idx, row, "Destination Address", "DstIP", "Destination"))
        dst_port = to_int(get(idx, row, "Destination Port", "DstPort"))
        state = get(idx, row, "State")
        pid = to_int(get(idx, row, "PID"))
        proc = get(idx, row, "Process", "Task", "COMM")
        if path and not (src_ip or dst_ip):
            out.append(Artifact(
                type="file", os="linux", source_plugin="linux.sockstat",
                raw=raw_dict(columns, row),
                fields={
                    "file_path": path,
                    "pid": pid,
                    "process_name": proc or None,
                    "protocol": proto,
                },
            ))
        else:
            out.append(Artifact(
                type="network_connection", os="linux",
                source_plugin="linux.sockstat",
                raw=raw_dict(columns, row),
                fields={
                    "protocol":     proto,
                    "local_ip":     src_ip,
                    "local_port":   src_port,
                    "remote_ip":    dst_ip,
                    "remote_port":  dst_port,
                    "state":        state or None,
                    "pid":          pid,
                    "process_name": proc or None,
                },
            ))
    return out


# ---------------------------------------------------------------------------
# Open files (lsof)
# ---------------------------------------------------------------------------

def _normalize_lsof(columns, rows) -> list[Artifact]:
    idx = col_index(columns)
    out: list[Artifact] = []
    for row in rows or []:
        out.append(Artifact(
            type="file", os="linux", source_plugin="linux.lsof",
            raw=raw_dict(columns, row),
            fields={
                "pid":          to_int(get(idx, row, "PID")),
                "process_name": get(idx, row, "Process", "COMM") or None,
                "fd":           get(idx, row, "FD") or None,
                "file_path":    get(idx, row, "Path") or None,
            },
        ))
    return out


# ---------------------------------------------------------------------------
# Bash history
# ---------------------------------------------------------------------------

def _normalize_bash(columns, rows) -> list[Artifact]:
    idx = col_index(columns)
    out: list[Artifact] = []
    for row in rows or []:
        out.append(Artifact(
            type="bash_history", os="linux", source_plugin="linux.bash",
            raw=raw_dict(columns, row),
            fields={
                "pid":          to_int(get(idx, row, "PID")),
                "process_name": get(idx, row, "Process", "COMM") or None,
                "timestamp":    get(idx, row, "CommandTime", "Time") or None,
                "command":      get(idx, row, "Command", "CommandLine") or None,
            },
        ))
    return out


# ---------------------------------------------------------------------------
# Memory maps (proc.Maps)
# ---------------------------------------------------------------------------

def _normalize_proc_maps(columns, rows) -> list[Artifact]:
    idx = col_index(columns)
    out: list[Artifact] = []
    for row in rows or []:
        out.append(Artifact(
            type="memory_region", os="linux", source_plugin="linux.proc.Maps",
            raw=raw_dict(columns, row),
            fields={
                "pid":          to_int(get(idx, row, "PID")),
                "process_name": get(idx, row, "Process", "COMM") or None,
                "start":        get(idx, row, "Start", "Start Address") or None,
                "end":          get(idx, row, "End", "End Address") or None,
                "protection":   get(idx, row, "Protection", "Flags") or None,
                "module_path":  get(idx, row, "Path", "File Path") or None,
            },
        ))
    return out


# ---------------------------------------------------------------------------
# ELF binaries
# ---------------------------------------------------------------------------

def _normalize_elfs(columns, rows) -> list[Artifact]:
    idx = col_index(columns)
    out: list[Artifact] = []
    for row in rows or []:
        out.append(Artifact(
            type="file", os="linux", source_plugin="linux.elfs",
            raw=raw_dict(columns, row),
            fields={
                "pid":          to_int(get(idx, row, "PID")),
                "process_name": get(idx, row, "Process", "COMM") or None,
                "file_path":    get(idx, row, "File Path", "Path") or None,
                "elf_type":     get(idx, row, "ELF Type", "Type") or None,
                "start":        get(idx, row, "Start") or None,
                "end":          get(idx, row, "End") or None,
            },
        ))
    return out


# ---------------------------------------------------------------------------
# Kernel indicators (check_modules / check_syscall / check_idt / etc.)
# ---------------------------------------------------------------------------

def _kernel_indicator(plugin: str):
    """
    Generic kernel-indicator normalizer used for the linux.check_*
    family. Each plugin has different columns; we preserve the entire
    row in ``raw`` and copy a few common fields into ``fields``.
    """
    def _norm(columns, rows) -> list[Artifact]:
        idx = col_index(columns)
        out: list[Artifact] = []
        for row in rows or []:
            out.append(Artifact(
                type="kernel_indicator", os="linux", source_plugin=plugin,
                raw=raw_dict(columns, row),
                fields={
                    "name":   get(idx, row, "Name", "Module", "Symbol") or None,
                    "address": get(idx, row, "Address") or None,
                    "status": get(idx, row, "Status") or None,
                    "note":   get(idx, row, "Notes", "Note") or None,
                },
            ))
        return out
    return _norm


# ---------------------------------------------------------------------------
# Mount info
# ---------------------------------------------------------------------------

def _normalize_mountinfo(columns, rows) -> list[Artifact]:
    idx = col_index(columns)
    out: list[Artifact] = []
    for row in rows or []:
        out.append(Artifact(
            type="file", os="linux", source_plugin="linux.mountinfo",
            raw=raw_dict(columns, row),
            fields={
                "file_path": get(idx, row, "Mount Point", "Path", "Mountpoint") or None,
                "fstype":    get(idx, row, "FS Type", "Type") or None,
                "device":    get(idx, row, "Device", "Source") or None,
            },
        ))
    return out


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

LINUX_NORMALIZERS: dict[str, callable] = {
    "linux.pslist":     _normalize_pslist,
    "linux.psscan":     _normalize_psscan,
    "linux.pstree":     _normalize_pstree,
    "linux.sockstat":   _normalize_sockstat,
    "linux.lsof":       _normalize_lsof,
    "linux.bash":       _normalize_bash,
    "linux.proc.Maps":  _normalize_proc_maps,
    "linux.elfs":       _normalize_elfs,
    "linux.check_modules":      _kernel_indicator("linux.check_modules"),
    "linux.check_syscall":      _kernel_indicator("linux.check_syscall"),
    "linux.check_idt":          _kernel_indicator("linux.check_idt"),
    "linux.check_afinfo":       _kernel_indicator("linux.check_afinfo"),
    "linux.keyboard_notifiers": _kernel_indicator("linux.keyboard_notifiers"),
    "linux.tty_check":          _kernel_indicator("linux.tty_check"),
    "linux.mountinfo":  _normalize_mountinfo,
}
