"""
macOS plugin normalizers.

See :mod:`app.fa2.normalizers.windows` for the design contract.
"""
from __future__ import annotations

from typing import Sequence

from ..models import Artifact
from ._common import clean_ip, col_index, get, raw_dict, to_int


# ---------------------------------------------------------------------------
# Process plugins
# ---------------------------------------------------------------------------

def _mac_process_row(plugin: str, columns: Sequence[str], row: Sequence[str]) -> Artifact:
    idx = col_index(columns)
    return Artifact(
        type="process", os="mac", source_plugin=plugin,
        raw=raw_dict(columns, row),
        fields={
            "pid":  to_int(get(idx, row, "PID")),
            "ppid": to_int(get(idx, row, "PPID")),
            "name": get(idx, row, "COMM", "Process", "Name") or None,
            "user": get(idx, row, "User", "UID") or None,
            "path": get(idx, row, "Path", "File output") or None,
        },
    )


def _normalize_pslist(columns, rows) -> list[Artifact]:
    return [_mac_process_row("mac.pslist", columns, r) for r in (rows or [])]


def _normalize_pstree(columns, rows) -> list[Artifact]:
    return [_mac_process_row("mac.pstree", columns, r) for r in (rows or [])]


# ---------------------------------------------------------------------------
# Network (netstat)
# ---------------------------------------------------------------------------

def _normalize_netstat(columns, rows) -> list[Artifact]:
    idx = col_index(columns)
    out: list[Artifact] = []
    for row in rows or []:
        out.append(Artifact(
            type="network_connection", os="mac", source_plugin="mac.netstat",
            raw=raw_dict(columns, row),
            fields={
                "protocol":     (get(idx, row, "Proto", "Protocol").upper() or None),
                # clean_ip() removes placeholders (-, 0.0.0.0, ::) — OD-003.
                "local_ip":     clean_ip(get(idx, row, "Local Address", "LocalAddr", "Local")),
                "local_port":   to_int(get(idx, row, "Local Port", "LocalPort")),
                "remote_ip":    clean_ip(get(idx, row, "Foreign Address", "ForeignAddr", "Remote")),
                "remote_port":  to_int(get(idx, row, "Foreign Port", "ForeignPort", "Remote Port")),
                "state":        get(idx, row, "State") or None,
                "pid":          to_int(get(idx, row, "PID")),
                "process_name": get(idx, row, "Process", "Owner") or None,
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
            type="file", os="mac", source_plugin="mac.lsof",
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
# Code injection regions (malfind)
# ---------------------------------------------------------------------------

def _normalize_malfind(columns, rows) -> list[Artifact]:
    idx = col_index(columns)
    out: list[Artifact] = []
    for row in rows or []:
        out.append(Artifact(
            type="memory_region", os="mac", source_plugin="mac.malfind",
            raw=raw_dict(columns, row),
            fields={
                "pid":          to_int(get(idx, row, "PID")),
                "process_name": get(idx, row, "Process") or None,
                "start":        get(idx, row, "Start") or None,
                "end":          get(idx, row, "End") or None,
                "protection":   get(idx, row, "Protection") or None,
            },
        ))
    return out


# ---------------------------------------------------------------------------
# List of files on disk (list_files)
# ---------------------------------------------------------------------------

def _normalize_list_files(columns, rows) -> list[Artifact]:
    idx = col_index(columns)
    out: list[Artifact] = []
    for row in rows or []:
        out.append(Artifact(
            type="file", os="mac", source_plugin="mac.list_files",
            raw=raw_dict(columns, row),
            fields={
                "file_path": get(idx, row, "Path", "File") or None,
                "offset":    get(idx, row, "Offset") or None,
            },
        ))
    return out


# ---------------------------------------------------------------------------
# Kernel indicators (check_syscall / check_sysctl / check_trap_table)
# ---------------------------------------------------------------------------

def _kernel_indicator(plugin: str):
    def _norm(columns, rows) -> list[Artifact]:
        idx = col_index(columns)
        out: list[Artifact] = []
        for row in rows or []:
            out.append(Artifact(
                type="kernel_indicator", os="mac", source_plugin=plugin,
                raw=raw_dict(columns, row),
                fields={
                    "name":    get(idx, row, "Name", "Symbol") or None,
                    "address": get(idx, row, "Address") or None,
                    "status":  get(idx, row, "Status") or None,
                    "note":    get(idx, row, "Notes", "Note") or None,
                },
            ))
        return out
    return _norm


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

MAC_NORMALIZERS: dict[str, callable] = {
    "mac.pslist":          _normalize_pslist,
    "mac.pstree":          _normalize_pstree,
    "mac.netstat":         _normalize_netstat,
    "mac.lsof":            _normalize_lsof,
    "mac.malfind":         _normalize_malfind,
    "mac.list_files":      _normalize_list_files,
    "mac.check_syscall":   _kernel_indicator("mac.check_syscall"),
    "mac.check_sysctl":    _kernel_indicator("mac.check_sysctl"),
    "mac.check_trap_table":_kernel_indicator("mac.check_trap_table"),
}
