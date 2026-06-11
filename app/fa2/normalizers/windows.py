"""
Windows plugin normalizers.

Each ``_normalize_<plugin>`` function converts a Volatility 3 CSV
(``columns`` + ``rows``) into a list of :class:`Artifact`. Field names
follow the names already in use by ``app/full_analysis.py``'s rule
helpers (``ImageFileName`` / ``Name``, etc.) and stay permissive — many
Vol3 versions rename headers slightly.

Every normalizer:

* Never raises on a malformed row — missing cells degrade to empty
  strings or ``None``, but the original cell values are always preserved
  in the ``raw`` field.
* Returns an empty list for empty input rather than ``None``.
* Sets ``source_plugin`` to the full Volatility plugin name.
"""
from __future__ import annotations

from typing import Sequence

from ..models import Artifact
from ._common import clean_ip, col_index, get, raw_dict, to_int


# ---------------------------------------------------------------------------
# Process plugins
# ---------------------------------------------------------------------------

def _process_row(plugin: str, columns: Sequence[str], row: Sequence[str]) -> Artifact:
    """pslist / psscan / pstree share the same fields."""
    idx = col_index(columns)
    pid  = to_int(get(idx, row, "PID"))
    ppid = to_int(get(idx, row, "PPID"))
    name = get(idx, row, "ImageFileName", "Name")
    path = get(idx, row, "File output", "Path", "ImagePath")
    create_time = get(idx, row, "CreateTime")
    exit_time = get(idx, row, "ExitTime")
    fields: dict[str, object] = {
        "pid": pid,
        "ppid": ppid,
        "name": name,
        "path": path,
        "create_time": create_time or None,
        "exit_time": exit_time or None,
    }
    # Drop None/empty so artifact JSON stays clean.
    fields = {k: v for k, v in fields.items() if v not in (None, "", 0) or k in ("pid", "ppid")}
    return Artifact(
        type="process", os="windows", source_plugin=plugin,
        raw=raw_dict(columns, row), fields=fields,
    )


def _normalize_pslist(columns, rows) -> list[Artifact]:
    return [_process_row("windows.pslist", columns, r) for r in (rows or [])]


def _normalize_psscan(columns, rows) -> list[Artifact]:
    return [_process_row("windows.psscan", columns, r) for r in (rows or [])]


def _normalize_pstree(columns, rows) -> list[Artifact]:
    return [_process_row("windows.pstree", columns, r) for r in (rows or [])]


def _normalize_cmdline(columns, rows) -> list[Artifact]:
    """
    windows.cmdline columns: PID, Process, Args. We emit one process
    artifact per row carrying the cmdline; correlation with pslist is
    done later by the rule/correlation engines.
    """
    idx = col_index(columns)
    out: list[Artifact] = []
    for row in rows or []:
        pid = to_int(get(idx, row, "PID"))
        name = get(idx, row, "Process", "ImageFileName")
        cmd = get(idx, row, "Args", "CommandLine")
        out.append(Artifact(
            type="process", os="windows", source_plugin="windows.cmdline",
            raw=raw_dict(columns, row),
            fields={"pid": pid, "name": name, "cmdline": cmd or None},
        ))
    return out


# ---------------------------------------------------------------------------
# Memory regions (malfind)
# ---------------------------------------------------------------------------

def _normalize_malfind(columns, rows) -> list[Artifact]:
    idx = col_index(columns)
    out: list[Artifact] = []
    for row in rows or []:
        pid = to_int(get(idx, row, "PID"))
        name = get(idx, row, "Process", "ImageFileName")
        start = get(idx, row, "Start VPN", "Start")
        end   = get(idx, row, "End VPN", "End")
        prot  = get(idx, row, "Protection")
        tag   = get(idx, row, "Tag")
        out.append(Artifact(
            type="memory_region", os="windows", source_plugin="windows.malfind",
            raw=raw_dict(columns, row),
            fields={
                "pid": pid,
                "process_name": name,
                "start": start or None,
                "end":   end or None,
                "protection": prot or None,
                "tag":   tag or None,
            },
        ))
    return out


# ---------------------------------------------------------------------------
# Network (netscan / netstat)
# ---------------------------------------------------------------------------

def _network_row(plugin: str, columns: Sequence[str], row: Sequence[str]) -> Artifact:
    idx = col_index(columns)
    proto = get(idx, row, "Proto", "Protocol").upper() or None
    # clean_ip() collapses Vol3 placeholders ("-", "0.0.0.0", "::") to None
    # so the rule engine's field_nonempty filter doesn't fire on them, and
    # the correlation engine doesn't group them into spurious chains
    # (see OD-003).
    laddr = clean_ip(get(idx, row, "LocalAddr", "Local address"))
    lport = to_int(get(idx, row, "LocalPort", "Local port"))
    faddr = clean_ip(get(idx, row, "ForeignAddr", "Foreign address"))
    fport = to_int(get(idx, row, "ForeignPort", "Foreign port"))
    state = get(idx, row, "State")
    pid   = to_int(get(idx, row, "PID"))
    owner = get(idx, row, "Owner")
    return Artifact(
        type="network_connection", os="windows", source_plugin=plugin,
        raw=raw_dict(columns, row),
        fields={
            "protocol":     proto,
            "local_ip":     laddr,
            "local_port":   lport,
            "remote_ip":    faddr,
            "remote_port":  fport,
            "state":        state or None,
            "pid":          pid,
            "process_name": owner or None,
        },
    )


def _normalize_netscan(columns, rows) -> list[Artifact]:
    return [_network_row("windows.netscan", columns, r) for r in (rows or [])]


def _normalize_netstat(columns, rows) -> list[Artifact]:
    return [_network_row("windows.netstat", columns, r) for r in (rows or [])]


# ---------------------------------------------------------------------------
# Modules (ldrmodules)
# ---------------------------------------------------------------------------

def _normalize_ldrmodules(columns, rows) -> list[Artifact]:
    idx = col_index(columns)
    out: list[Artifact] = []
    for row in rows or []:
        out.append(Artifact(
            type="module", os="windows", source_plugin="windows.ldrmodules",
            raw=raw_dict(columns, row),
            fields={
                "pid":     to_int(get(idx, row, "Pid", "PID")),
                "process": get(idx, row, "Process") or None,
                "base":    get(idx, row, "Base") or None,
                "in_load": get(idx, row, "InLoad"),
                "in_init": get(idx, row, "InInit"),
                "in_mem":  get(idx, row, "InMem"),
                "module_path": get(idx, row, "MappedPath", "Path") or None,
            },
        ))
    return out


# ---------------------------------------------------------------------------
# Services (svcscan)
# ---------------------------------------------------------------------------

def _normalize_svcscan(columns, rows) -> list[Artifact]:
    idx = col_index(columns)
    out: list[Artifact] = []
    for row in rows or []:
        out.append(Artifact(
            type="service", os="windows", source_plugin="windows.svcscan",
            raw=raw_dict(columns, row),
            fields={
                "service_name":  get(idx, row, "Name", "ServiceName") or None,
                "display":       get(idx, row, "Display") or None,
                "binary":        get(idx, row, "Binary", "BinaryPath", "ImagePath") or None,
                "state":         get(idx, row, "State") or None,
                "start":         get(idx, row, "Start") or None,
                "type":          get(idx, row, "Type") or None,
                "pid":           to_int(get(idx, row, "Pid", "PID")),
            },
        ))
    return out


# ---------------------------------------------------------------------------
# Registry & forensic-only:
#
# These return ``user_activity`` / ``registry`` artifacts when the
# extended plugins are enabled. Phase 3 ships them so the dispatcher
# is OS-complete; the planner decides whether to actually run them.
# ---------------------------------------------------------------------------

def _normalize_userassist(columns, rows) -> list[Artifact]:
    idx = col_index(columns)
    out: list[Artifact] = []
    for row in rows or []:
        out.append(Artifact(
            type="user_activity", os="windows",
            source_plugin="windows.registry.userassist",
            raw=raw_dict(columns, row),
            fields={
                "user":     get(idx, row, "Name", "Hive Name") or None,
                "value":    get(idx, row, "Name", "Value", "Path") or None,
                "count":    to_int(get(idx, row, "Count")),
                "last_use": get(idx, row, "Last Updated", "Last accessed") or None,
            },
        ))
    return out


def _normalize_shimcachemem(columns, rows) -> list[Artifact]:
    idx = col_index(columns)
    out: list[Artifact] = []
    for row in rows or []:
        out.append(Artifact(
            type="file", os="windows",
            source_plugin="windows.registry.shimcachemem",
            raw=raw_dict(columns, row),
            fields={
                "file_path":   get(idx, row, "Path") or None,
                "last_modified": get(idx, row, "Last Modified") or None,
            },
        ))
    return out


def _normalize_amcache(columns, rows) -> list[Artifact]:
    idx = col_index(columns)
    out: list[Artifact] = []
    for row in rows or []:
        out.append(Artifact(
            type="file", os="windows",
            source_plugin="windows.amcache",
            raw=raw_dict(columns, row),
            fields={
                "file_path":  get(idx, row, "Path", "Full Path") or None,
                "sha1":       get(idx, row, "SHA1") or None,
                "size":       to_int(get(idx, row, "Size")),
                "last_modified": get(idx, row, "Last Modified", "Modified") or None,
            },
        ))
    return out


# ---------------------------------------------------------------------------
# Dispatch table
# ---------------------------------------------------------------------------

WINDOWS_NORMALIZERS: dict[str, callable] = {
    "windows.pslist":     _normalize_pslist,
    "windows.psscan":     _normalize_psscan,
    "windows.pstree":     _normalize_pstree,
    "windows.cmdline":    _normalize_cmdline,
    "windows.malfind":    _normalize_malfind,
    "windows.netscan":    _normalize_netscan,
    "windows.netstat":    _normalize_netstat,
    "windows.ldrmodules": _normalize_ldrmodules,
    "windows.svcscan":    _normalize_svcscan,
    "windows.registry.userassist":    _normalize_userassist,
    "windows.registry.shimcachemem":  _normalize_shimcachemem,
    "windows.amcache":    _normalize_amcache,
}
