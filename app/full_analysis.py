"""
m3mx tool — Full Analysis / One-Click Triage.

Runs a fixed battery of high-signal Volatility plugins, applies a small
rule engine to the parsed CSV output, and emits a structured findings
list. Rules are partly hardcoded (plugin-aware logic) and partly loaded
from `rules/full_analysis_rules.json` (regex-keyword rules) so an
analyst can extend detections without editing Python.

Public API:
    run_triage(image_path, vol_paths, ..., yield_progress=True)
        Generator. Yields {"type": "...", ...} events as plugins run and
        rules fire, then a final {"type": "done", "findings": [...]}.

    save_findings(findings, image_path) -> Path
        Writes outputs/full_analysis/<case_name>/findings.jsonl.

    load_findings(image_path) -> list[dict]
        Re-reads a previously-saved findings file for the given image.
"""
from __future__ import annotations

import json
import logging
import re
import time
from dataclasses import dataclass, field, asdict
from pathlib import Path
from typing import Callable, Generator

from . import forensics
from .config import OUTPUTS_DIR
from .plugins import find_plugin

log = logging.getLogger("m3mx.full_analysis")

# Project-root rules file (optional — built-ins always run).
RULES_FILE = Path(__file__).resolve().parent.parent / "rules" / "full_analysis_rules.json"

# Default plugin battery for triage. Short names, resolved via plugins.json.
TRIAGE_PLUGINS: list[str] = [
    "pslist",
    "psscan",
    "cmdline",
    "malfind",
    "netscan",
    "ldrmodules",
    "svcscan",
]

# Severity ordering (high → low) for sorting + UI badges.
SEVERITY_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# Common system-process names we expect to live ONLY in System32.
_SYSTEM_PROCS = {
    "svchost.exe", "lsass.exe", "csrss.exe", "winlogon.exe",
    "services.exe", "smss.exe", "wininit.exe", "spoolsv.exe",
}
_SYSTEM_PATH_OK = re.compile(r"\\Windows\\System32\\", re.IGNORECASE)
# True user-writable / drop-zone locations only. ProgramData is intentionally
# excluded: legitimate vendors (Defender, NVIDIA, Office, Adobe, Slack…) all
# install there and were the #1 source of false positives.
_SUSPECT_PATH_RE = re.compile(
    r"\\(Temp|AppData\\Local\\Temp|AppData\\Roaming\\Temp|Users\\Public|\$Recycle)\\",
    re.IGNORECASE,
)
# Filenames running under Temp/AppData that are almost always benign
# installers / updaters. Names checked case-insensitively, prefix match.
_INSTALLER_NAME_RE = re.compile(
    r"^(setup|installer|update|updater|msiexec|googleupdate|"
    r"squirrel|onedrive(setup|standalone)?|teams_?(setup|update)?|"
    r"slacksetup|zoominstaller|edgeupdate|chrome_installer|"
    r"firefoxinstaller|adobegc|nvidia|nvcontainer|nvtelemetry|"
    r"acrord32|reader_sl|officeclicktorun|msoia)",
    re.IGNORECASE,
)
# Extensions that actually warrant flagging when seen in user-writable dirs.
_FLAGGABLE_EXEC_EXT = re.compile(r"\.(exe|scr|bat|cmd|ps1|vbs|hta|js|wsf)$", re.IGNORECASE)
_RFC1918_RE = re.compile(
    r"^(10\.|192\.168\.|172\.(1[6-9]|2\d|3[01])\.|127\.|169\.254\.|::1|fe80:)"
)
# Browsers and other programs whose external connections aren't, by themselves,
# interesting — drowns out the real C2 traffic if every Chrome socket is "high".
_BROWSER_PROCS = {
    "chrome.exe", "msedge.exe", "firefox.exe", "iexplore.exe", "opera.exe",
    "brave.exe", "vivaldi.exe", "safari.exe", "operagx.exe",
}
# Ports common to legitimate user apps. External traffic on these ports from
# a known browser is demoted to "info"; from a non-browser still flagged.
_COMMON_USER_PORTS = {"80", "443", "8080", "8443"}


# ---------------------------------------------------------------------------
# Data classes
# ---------------------------------------------------------------------------

@dataclass
class Finding:
    id: str                   # e.g. "F-007"
    plugin: str               # plugin short name
    severity: str             # critical | high | medium | low | info
    title: str
    description: str
    evidence: dict            # raw row data (column → value)
    tags: list[str] = field(default_factory=list)   # MITRE ATT&CK ids etc.
    confidence: float = 0.7

    def to_dict(self) -> dict:
        return asdict(self)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _col_lookup(columns: list[str]) -> dict[str, int]:
    """Case-insensitive column-name → index map (handles Vol3 quirks)."""
    return {c.strip().lower(): i for i, c in enumerate(columns or [])}


def _row_dict(columns: list[str], row: list[str]) -> dict:
    return {c: (row[i] if i < len(row) else "") for i, c in enumerate(columns or [])}


def _get(idx: dict[str, int], row: list[str], *names: str, default: str = "") -> str:
    for n in names:
        i = idx.get(n.lower())
        if i is not None and i < len(row):
            return (row[i] or "").strip()
    return default


def _make_id(counter: list[int]) -> str:
    counter[0] += 1
    return f"F-{counter[0]:03d}"


# ---------------------------------------------------------------------------
# Built-in rules (one function per supported plugin)
# ---------------------------------------------------------------------------

def _rules_pslist(columns, rows, fid) -> list[Finding]:
    out: list[Finding] = []
    idx = _col_lookup(columns)
    for row in rows:
        name = _get(idx, row, "ImageFileName", "Name").lower()
        ppid = _get(idx, row, "PPID")
        pid  = _get(idx, row, "PID")
        path = _get(idx, row, "File output", "Path", "ImagePath")
        # Suspicious-process path: a system-named process living outside System32.
        if name in _SYSTEM_PROCS and path and not _SYSTEM_PATH_OK.search(path):
            out.append(Finding(
                id=_make_id(fid), plugin="pslist", severity="critical",
                title=f"System-named process '{name}' running from non-system path",
                description=f"PID {pid} ({name}) parent {ppid} loaded from {path!r}.",
                evidence=_row_dict(columns, row),
                tags=["T1036.005", "Masquerading"],
                confidence=0.92,
            ))
            continue
        # Generic suspect-path execution. Tightened: must be an executable script
        # extension AND not match a known installer/updater name pattern.
        if not (path and _SUSPECT_PATH_RE.search(path)):
            continue
        leaf = path.replace("/", "\\").rsplit("\\", 1)[-1]
        if not _FLAGGABLE_EXEC_EXT.search(leaf):
            continue
        bare = leaf.split(".", 1)[0]
        if _INSTALLER_NAME_RE.match(bare):
            continue
        # Drop severity → medium and confidence → 0.6: still report, but as
        # "review", not "fire-the-IR-team".
        out.append(Finding(
            id=_make_id(fid), plugin="pslist", severity="medium",
            title=f"Process '{name}' executing from temp/user directory",
            description=f"PID {pid} executing from {path!r}. "
                        "Verify against software-deployment expectations.",
            evidence=_row_dict(columns, row),
            tags=["T1059", "User Execution"],
            confidence=0.6,
        ))
    return out


def _rules_malfind(columns, rows, fid) -> list[Finding]:
    # Every malfind hit is a finding — process injection / shellcode region.
    out: list[Finding] = []
    idx = _col_lookup(columns)
    for row in rows:
        pid  = _get(idx, row, "PID")
        proc = _get(idx, row, "Process")
        out.append(Finding(
            id=_make_id(fid), plugin="malfind", severity="critical",
            title=f"Code-injection region in PID {pid} ({proc})",
            description="malfind detected a memory region with PAGE_EXECUTE_READWRITE "
                        "protection and no backing image — typical of injected shellcode.",
            evidence=_row_dict(columns, row),
            tags=["T1055", "Process Injection"],
            confidence=0.9,
        ))
    return out


def _rules_cmdline(columns, rows, fid) -> list[Finding]:
    out: list[Finding] = []
    idx = _col_lookup(columns)
    patterns = [
        (re.compile(r"\b-enc(odedcommand)?\b", re.I),       "PowerShell encoded command",   "T1059.001", "high"),
        (re.compile(r"\bIEX\b|Invoke-Expression",  re.I),    "PowerShell IEX execution",    "T1059.001", "high"),
        (re.compile(r"DownloadString|DownloadFile", re.I),   "PowerShell remote download",  "T1105",     "high"),
        (re.compile(r"\bcertutil\b.+(-urlcache|-decode)", re.I), "certutil LOLBin abuse",   "T1140",     "high"),
        (re.compile(r"\bbitsadmin\b.+/transfer",  re.I),     "bitsadmin transfer",          "T1197",     "high"),
        (re.compile(r"\bmshta\b.+http",            re.I),    "mshta remote payload",        "T1218.005", "high"),
        (re.compile(r"\brundll32\b.+\\AppData\\",  re.I),    "rundll32 from AppData",       "T1218.011", "critical"),
        (re.compile(r"\bvssadmin\b.+delete",       re.I),    "Shadow-copy deletion",        "T1490",     "critical"),
    ]
    for row in rows:
        cmd = _get(idx, row, "Args", "CommandLine")
        if not cmd: continue
        pid  = _get(idx, row, "PID")
        proc = _get(idx, row, "Process")
        for pat, title, mitre, sev in patterns:
            if pat.search(cmd):
                out.append(Finding(
                    id=_make_id(fid), plugin="cmdline", severity=sev,
                    title=f"{title} (PID {pid})",
                    description=f"{proc or 'process'} executed: {cmd[:240]}",
                    evidence=_row_dict(columns, row),
                    tags=[mitre],
                    confidence=0.88,
                ))
                break  # one finding per row
    return out


def _rules_netscan(columns, rows, fid) -> list[Finding]:
    out: list[Finding] = []
    idx = _col_lookup(columns)
    for row in rows:
        foreign = _get(idx, row, "ForeignAddr", "Foreign address")
        state   = _get(idx, row, "State")
        owner   = (_get(idx, row, "Owner") or "").strip()
        pid     = _get(idx, row, "PID")
        proto   = (_get(idx, row, "Proto", "Protocol") or "").upper()
        # Parsed artifact addresses, not socket bind configuration.
        if not foreign or foreign.startswith(("0.0.0.0", "*", "[::]", "::")):  # nosec B104
            continue
        # Only TCP connections — UDP "connections" without state are listening
        # endpoints, not exfil channels.
        if proto and proto not in ("TCPV4", "TCPV6", "TCP"):
            continue
        if state not in ("ESTABLISHED", "SYN_SENT"):
            continue
        # Strip port. Foreign may be ipv6 [::1]:443 — rsplit handles that.
        host_port = foreign.rsplit(":", 1)
        host = host_port[0].strip("[]")
        port = host_port[1] if len(host_port) > 1 else ""
        if _RFC1918_RE.match(host):
            continue
        owner_l = owner.lower()
        is_browser = owner_l in _BROWSER_PROCS
        is_common_port = port in _COMMON_USER_PORTS
        # Browser → 80/443 is web traffic; demote to info so it doesn't drown
        # the real signals. Don't emit at all to keep findings list usable.
        if is_browser and is_common_port:
            continue
        # Non-browser process talking out on a common web port → medium.
        # Anything else (unusual port OR known-bad-style process) → high.
        if is_common_port:
            sev, conf = "medium", 0.55
        else:
            sev, conf = "high", 0.7
        out.append(Finding(
            id=_make_id(fid), plugin="netscan", severity=sev,
            title=f"External network connection from {owner or 'unknown'} (PID {pid}) → {foreign}",
            description=f"State={state or 'n/a'} proto={proto or 'n/a'} — verify "
                        "against known C2 / threat-intel feeds.",
            evidence=_row_dict(columns, row),
            tags=["T1071", "Application Layer Protocol"],
            confidence=conf,
        ))
    return out


def _rules_ldrmodules(columns, rows, fid) -> list[Finding]:
    out: list[Finding] = []
    idx = _col_lookup(columns)
    for row in rows:
        in_load = _get(idx, row, "InLoad").lower()
        in_init = _get(idx, row, "InInit").lower()
        in_mem  = _get(idx, row, "InMem").lower()
        path = _get(idx, row, "MappedPath", "Path")
        pid  = _get(idx, row, "Pid", "PID")
        # Tightened: require InMem=true AND BOTH InLoad/InInit false. The old
        # "either false" condition fired on every benign DLL caught mid-unload.
        if not (in_mem == "true" and in_load == "false" and in_init == "false"):
            continue
        # An empty MappedPath is the strongest tell of reflective injection.
        # Any path under \Windows\System32\ is almost certainly a transient
        # legit DLL — skip those.
        if path and _SYSTEM_PATH_OK.search(path):
            continue
        # Empty path → high confidence; named path → medium (still worth review).
        if not path:
            sev, conf = "high", 0.85
            desc = (f"DLL with no MappedPath is mapped into PID {pid} but absent "
                    f"from both loader lists — consistent with reflective "
                    f"DLL injection.")
        else:
            sev, conf = "medium", 0.6
            desc = (f"DLL {path!r} is mapped into PID {pid} but unlinked from "
                    f"both loader lists — possible unhooking or reflective load.")
        out.append(Finding(
            id=_make_id(fid), plugin="ldrmodules", severity=sev,
            title=f"Unlinked DLL in PID {pid}",
            description=desc,
            evidence=_row_dict(columns, row),
            tags=["T1055.001", "DLL Injection"],
            confidence=conf,
        ))
    return out


def _rules_svcscan(columns, rows, fid) -> list[Finding]:
    out: list[Finding] = []
    idx = _col_lookup(columns)
    for row in rows:
        binpath = _get(idx, row, "Binary", "BinaryPath", "ImagePath")
        name    = _get(idx, row, "Name", "ServiceName")
        if not (binpath and _SUSPECT_PATH_RE.search(binpath)):
            continue
        # Skip benign installer/updater names (Squirrel, GoogleUpdate, …).
        leaf = binpath.replace("/", "\\").rsplit("\\", 1)[-1]
        bare = leaf.split(".", 1)[0]
        if _INSTALLER_NAME_RE.match(bare):
            continue
        out.append(Finding(
            id=_make_id(fid), plugin="svcscan", severity="high",
            title=f"Service '{name}' points into a user-writable directory",
            description=f"Binary path: {binpath!r} — likely persistence mechanism.",
            evidence=_row_dict(columns, row),
            tags=["T1543.003", "Service Persistence"],
            confidence=0.75,
        ))
    return out


def _rules_psscan(columns, rows, fid) -> list[Finding]:
    out: list[Finding] = []
    idx = _col_lookup(columns)
    # smss.exe legitimately has the kernel (PID 4) as parent which often appears
    # as PPID=0 once System has terminated — exclude from the orphan check.
    LEGIT_KERNEL_CHILDREN = {"smss.exe", "system"}
    for row in rows:
        name = _get(idx, row, "ImageFileName", "Name").lower()
        ppid = _get(idx, row, "PPID")
        pid  = _get(idx, row, "PID")
        if name not in _SYSTEM_PROCS or name in LEGIT_KERNEL_CHILDREN:
            continue
        if ppid != "0" or pid == "4":
            continue
        out.append(Finding(
            id=_make_id(fid), plugin="psscan", severity="medium",
            title=f"Orphan system-named process '{name}'",
            description=f"PID {pid} reported with PPID=0 — possible parent-PID "
                        "spoofing, or simply that the parent terminated. "
                        "Cross-check with pslist.",
            evidence=_row_dict(columns, row),
            tags=["T1134.004", "Parent PID Spoofing"],
            confidence=0.55,
        ))
    return out


_BUILTIN_RULES: dict[str, Callable] = {
    "pslist":     _rules_pslist,
    "psscan":     _rules_psscan,
    "malfind":    _rules_malfind,
    "cmdline":    _rules_cmdline,
    "netscan":    _rules_netscan,
    "ldrmodules": _rules_ldrmodules,
    "svcscan":    _rules_svcscan,
}


# ---------------------------------------------------------------------------
# User-extensible JSON rules
# ---------------------------------------------------------------------------
# rules/full_analysis_rules.json schema:
# {
#   "rules": [
#     {
#       "id": "user.suspicious_dropper",
#       "plugin": "cmdline",
#       "match": {"any_column_regex": "(?i)temp\\\\.+\\.exe"},
#       "severity": "high",
#       "title": "Dropper running from %temp%",
#       "tags": ["T1059", "User Execution"]
#     }
#   ]
# }

def _load_user_rules() -> list[dict]:
    if not RULES_FILE.exists():
        return []
    try:
        return (json.loads(RULES_FILE.read_text()) or {}).get("rules", [])
    except Exception as e:
        log.warning("could not parse %s: %s", RULES_FILE, e)
        return []


def _apply_user_rules(plugin: str, columns, rows, fid, user_rules) -> list[Finding]:
    out: list[Finding] = []
    for r in user_rules:
        if r.get("plugin") != plugin:
            continue
        pat = r.get("match", {}).get("any_column_regex")
        if not pat:
            continue
        try:
            regex = re.compile(pat)
        except re.error:
            continue
        for row in rows:
            joined = " | ".join(str(c) for c in row)
            if regex.search(joined):
                out.append(Finding(
                    id=_make_id(fid),
                    plugin=plugin,
                    severity=r.get("severity", "medium"),
                    title=r.get("title") or r.get("id") or "User rule match",
                    description=r.get("description")
                        or f"User rule {r.get('id', '')} matched a {plugin} row.",
                    evidence=_row_dict(columns, row),
                    tags=list(r.get("tags") or []),
                    confidence=float(r.get("confidence", 0.6)),
                ))
    return out


# ---------------------------------------------------------------------------
# Triage runner (generator → SSE-friendly)
# ---------------------------------------------------------------------------

def _case_dir(image_path: str | Path) -> Path:
    # Use the OPERATOR-CONFIGURED output directory so V2 case files land
    # in the same root that /api/outputs/download / Manual Analysis /
    # File Extractor already serve from. Falls back to OUTPUTS_DIR when
    # the configured dir is unwritable (safe_output_dir() handles that).
    from .evidence import case_directory
    return case_directory(image_path)


def save_findings(findings: list[Finding], image_path: str | Path) -> Path:
    case = _case_dir(image_path)
    case.mkdir(parents=True, exist_ok=True)
    target = case / "findings.jsonl"
    with open(target, "w", encoding="utf-8") as f:
        for fnd in findings:
            f.write(json.dumps(fnd.to_dict(), ensure_ascii=False) + "\n")
    return target


def run_triage(image_path: str | Path,
               vol_paths: dict | None = None,
               timeout: int = 600,
               plugin_names: list[str] | None = None) -> Generator[dict, None, None]:
    """
    Public Full Analysis entry point. **Dispatcher** that picks the
    pipeline based on the ``FULL_ANALYSIS_V2`` and
    ``FULL_ANALYSIS_LEGACY_V1`` feature flags.

    Phase A migration (Phase 13):

    * ``FULL_ANALYSIS_V2`` defaults to **True** — V2 is the primary
      pipeline. Starting Full Analysis from the existing button runs
      V2 by default.
    * ``FULL_ANALYSIS_LEGACY_V1`` defaults to **False**. The legacy V1
      pipeline only runs when this flag is *explicitly* enabled AND V2
      is *explicitly* disabled.
    * If V2 is disabled and the legacy flag is **not** set, the
      dispatcher emits an explicit ``error`` SSE event rather than
      silently falling back to V1.

    V2 emits every legacy SSE event type with compatible payloads (so
    the existing frontend keeps working), plus the V2 optional events:
    ``os_detected``, ``plugin_plan``, ``artifact_normalized``,
    ``mitre_done``, ``correlation``, ``correlations_done``,
    ``timeline_done``, ``report_ready``.
    """
    # Local import to avoid eagerly loading config + V2 modules at module
    # import time. V1 modules are imported only inside _run_triage_v1.
    from .config import fa2_enabled, fa2_legacy_v1_enabled
    from .evidence import begin_run
    if fa2_enabled() or fa2_legacy_v1_enabled():
        begin_run(image_path)
    if fa2_enabled():
        yield from _run_triage_v2(image_path, vol_paths, timeout, plugin_names)
        return
    if fa2_legacy_v1_enabled():
        yield from _run_triage_v1(image_path, vol_paths, timeout, plugin_names)
        return
    # Both pipelines explicitly disabled — make this visible to the
    # operator instead of silently doing nothing or picking V1.
    yield {
        "type":    "error",
        "message": ("Both V2 and V1 pipelines are disabled. "
                    "FULL_ANALYSIS_V2 defaults to true; if you set it "
                    "to false, also set FULL_ANALYSIS_LEGACY_V1=true to "
                    "run the legacy pipeline."),
    }


def _run_triage_v1(image_path: str | Path,
                   vol_paths: dict | None = None,
                   timeout: int = 600,
                   plugin_names: list[str] | None = None) -> Generator[dict, None, None]:
    """
    Legacy (V1) Full Analysis pipeline — preserved byte-identical from
    the pre-Phase-8 codebase. Used whenever ``FULL_ANALYSIS_V2`` is off.

    Yields events:

      {"type": "start",        "image": str, "plugins": [...]}
      {"type": "plugin_start", "plugin": str, "index": i, "total": n}
      {"type": "plugin_done",  "plugin": str, "success": bool,
                               "rows": int|None, "elapsed": float, "error": str|None}
      {"type": "finding",      "finding": {...}}
      {"type": "rules_done",   "total_findings": int}
      {"type": "saved",        "path": str}
      {"type": "done",         "findings": [...], "case_dir": str,
                               "findings_path": str, "elapsed": float}
      {"type": "error",        "message": str}
    """
    image = str(Path(image_path).resolve())
    if not Path(image).exists():
        yield {"type": "error", "message": f"image not found: {image}"}
        return

    plugins = [p for p in (plugin_names or TRIAGE_PLUGINS) if find_plugin(p)]
    yield {"type": "start", "image": image, "plugins": plugins}

    user_rules = _load_user_rules()
    findings: list[Finding] = []
    fid = [0]   # mutable counter for _make_id
    t0 = time.monotonic()

    for i, name in enumerate(plugins, start=1):
        yield {"type": "plugin_start", "plugin": name, "index": i, "total": len(plugins)}
        try:
            res = forensics.run_plugin(
                image, name, version="auto",
                timeout=timeout, vol_paths=vol_paths,
            )
        except Exception as e:
            yield {"type": "plugin_done", "plugin": name, "success": False,
                   "rows": None, "elapsed": 0.0, "error": str(e)}
            continue

        yield {
            "type":    "plugin_done",
            "plugin":  name,
            "success": bool(res.success),
            "rows":    (len(res.rows) if res.rows else 0),
            "elapsed": res.elapsed,
            "error":   (res.error.splitlines()[0] if res.error else None),
        }

        if not res.success or not res.rows:
            continue

        cols = res.columns or []
        rows = res.rows or []

        # Built-in plugin-aware rules.
        rule_fn = _BUILTIN_RULES.get(name)
        produced: list[Finding] = []
        if rule_fn:
            try:
                produced.extend(rule_fn(cols, rows, fid))
            except Exception as e:
                log.exception("built-in rule failed for %s: %s", name, e)

        # User regex rules.
        try:
            produced.extend(_apply_user_rules(name, cols, rows, fid, user_rules))
        except Exception as e:
            log.exception("user rule pass failed for %s: %s", name, e)

        for f in produced:
            findings.append(f)
            yield {"type": "finding", "finding": f.to_dict()}

    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))

    yield {"type": "rules_done", "total_findings": len(findings)}

    saved = save_findings(findings, image)
    yield {"type": "saved", "path": str(saved)}

    yield {
        "type":          "done",
        "findings":      [f.to_dict() for f in findings],
        "case_dir":      str(saved.parent),
        "findings_path": str(saved),
        "elapsed":       round(time.monotonic() - t0, 2),
    }


def _run_triage_v2(image_path: str | Path,
                   vol_paths: dict | None = None,
                   timeout: int = 600,
                   plugin_names: list[str] | None = None) -> Generator[dict, None, None]:
    """
    V2 Full Analysis pipeline. Activated only when ``FULL_ANALYSIS_V2``
    is enabled. Emits *every* legacy SSE event type with the same
    required payload keys (so the existing frontend keeps working), plus
    the optional V2 event types declared in :file:`app/fa2/CONTRACT.md`.

    Output files written under ``<outputs>/full_analysis/<image_stem>/``:

      * ``findings.jsonl``              (legacy name preserved)
      * ``artifacts/<plugin>.csv``      (raw plugin CSVs, additive)
      * ``normalized_artifacts.jsonl``  (V2 artifacts)
      * ``mitre_summary.json``          (V2 MITRE aggregation)
      * ``correlations.json``           (V2 attack chains)
      * ``timeline.json``               (V2 timeline)
      * ``failed_plugins.json``         (only if any plugin failed)
      * ``limitations.json``            (only if any pipeline stage produced warnings)

    Per-step failures are caught and recorded; one bad plugin never
    aborts the entire run.
    """
    # All V2 dependencies are imported inside this function so that
    # disabling the feature flag truly costs nothing — the V2 stack
    # never loads.
    import json as _json
    from .fa2.os_detect import detect_os
    from .fa2.plugin_planner import plan as _plan
    from .fa2.volatility_runner import (
        RunnerResult,
        run_plugin as v2_run_plugin,
        discover_available_plugins,
    )
    from .fa2.artifact_parser import normalize_and_persist
    from .fa2.rule_engine import apply_rules
    from .fa2.mitre import (
        summarize_and_persist as mitre_persist,
        mitre_done_event,
    )
    from .fa2.correlation import (
        correlate_and_persist,
        correlation_event,
        correlations_done_event,
    )
    from .fa2.timeline import (
        build_and_persist as timeline_persist,
        timeline_done_event,
    )
    from .fa2.report import (
        build_and_persist as report_persist,
        report_ready_event,
    )

    image = str(Path(image_path).resolve())
    if not Path(image).exists():
        yield {"type": "error", "message": f"image not found: {image}"}
        return

    t0 = time.monotonic()
    case = _case_dir(image)
    pipeline_warnings: list[dict] = []

    # ── Step 1: OS detection ──────────────────────────────────────────
    detection = detect_os(image, vol_paths=vol_paths,
                          timeout=min(timeout, 120))
    yield {
        "type":          "os_detected",
        "os":            detection.os,
        "confidence":    detection.confidence,
        "detected_by":   detection.detected_by,
        "kernel":        detection.kernel,
        "arch":          detection.arch,
        "symbol_status": detection.symbol_status,
        "warnings":      list(detection.warnings),
    }
    if detection.warnings:
        pipeline_warnings.append({"phase": "os_detection",
                                  "warnings": list(detection.warnings)})

    # ── Step 2: plugin discovery + planning ──────────────────────────
    available, disc_warnings = discover_available_plugins(
        vol_paths, timeout=min(timeout, 30),
    )
    if disc_warnings:
        pipeline_warnings.append({"phase": "plugin_discovery",
                                  "warnings": list(disc_warnings)})

    if plugin_names:
        # User-provided plugin list — trust it, but still let the planner
        # produce the warnings/fallback metadata if it can.
        plan_result = {
            "os":                detection.os,
            "plugins":           list(plugin_names),
            "skipped":           [],
            "warnings":          [],
            "fallbacks_applied": [],
            "include_extended":  False,
            "source":            "user-supplied",
        }
    else:
        plan_result = _plan(detection.os,
                            available=(available or None))

    yield {
        "type":              "plugin_plan",
        "os":                plan_result["os"],
        "plugins":           list(plan_result["plugins"]),
        "skipped":           list(plan_result["skipped"]),
        "fallbacks_applied": list(plan_result["fallbacks_applied"]),
        "warnings":          list(plan_result["warnings"]),
    }
    if plan_result.get("warnings") or plan_result.get("skipped"):
        pipeline_warnings.append({
            "phase":    "plugin_planning",
            "warnings": list(plan_result.get("warnings") or []),
            "skipped":  list(plan_result.get("skipped") or []),
        })

    plugins_to_run: list[str] = list(plan_result["plugins"])

    # ── Step 3: Volatility execution ─────────────────────────────────
    # Legacy `start` event — keeps the V1 frontend contract.
    yield {"type": "start", "image": image,
           "plugins": list(plugins_to_run)}

    runner_results: list[RunnerResult] = []
    failed_plugins: list[dict] = []

    for i, plugin in enumerate(plugins_to_run, start=1):
        yield {"type": "plugin_start", "plugin": plugin,
               "index": i, "total": len(plugins_to_run)}
        try:
            result = v2_run_plugin(image, plugin,
                                   vol_paths=vol_paths, timeout=timeout)
        except Exception as e:                                    # pragma: no cover
            log.exception("V2 runner crashed on %s", plugin)
            result = RunnerResult(
                plugin=plugin, success=False,
                error=f"{type(e).__name__}: {e}",
            )
        runner_results.append(result)
        if not result.success:
            failed_plugins.append({
                "plugin":  plugin,
                "error":   result.error or "unknown error",
                "elapsed": result.elapsed,
                "timed_out": bool(result.timed_out),
            })
        yield {
            "type":    "plugin_done",
            "plugin":  plugin,
            "success": bool(result.success),
            "rows":    int(result.row_count or 0),
            "elapsed": float(result.elapsed or 0.0),
            "error":   (result.error or None) if not result.success else None,
        }

    # ── Step 4: artifact normalisation + persistence ────────────────
    try:
        norm_result = normalize_and_persist(runner_results, case)
    except Exception as e:                                        # pragma: no cover
        log.exception("artifact normalisation failed")
        norm_result = None
        pipeline_warnings.append({"phase": "normalization",
                                  "warnings": [str(e)]})

    if norm_result is not None:
        yield {
            "type":              "artifact_normalized",
            "total":             norm_result.total,
            "per_plugin":        dict(norm_result.per_plugin),
            "skipped":           list(norm_result.skipped),
            "normalized_path":   norm_result.normalized_path,
            "raw_artifacts_dir": norm_result.raw_artifacts_dir,
        }
        if norm_result.warnings:
            pipeline_warnings.append({"phase": "normalization",
                                      "warnings": list(norm_result.warnings)})

    artifacts = (norm_result.artifacts if norm_result is not None else [])

    # ── Step 5: rule engine ──────────────────────────────────────────
    try:
        findings = apply_rules(artifacts)
    except Exception as e:                                        # pragma: no cover
        log.exception("rule engine failed")
        findings = []
        pipeline_warnings.append({"phase": "rule_engine",
                                  "warnings": [str(e)]})

    # Emit individual finding events for backward compat.
    for f in findings:
        yield {"type": "finding", "finding": f.to_dict()}

    # Sort critical → low, mirroring V1.
    findings.sort(key=lambda f: SEVERITY_ORDER.get(f.severity, 99))
    yield {"type": "rules_done", "total_findings": len(findings)}

    # ── Step 6: save findings.jsonl (preserve legacy filename) ───────
    findings_path = case / "findings.jsonl"
    try:
        with findings_path.open("w", encoding="utf-8") as fh:
            for f in findings:
                fh.write(_json.dumps(f.to_dict(), ensure_ascii=False) + "\n")
        yield {"type": "saved", "path": str(findings_path)}
    except OSError as e:
        log.warning("could not write findings.jsonl: %s", e)
        pipeline_warnings.append({"phase": "save_findings",
                                  "warnings": [str(e)]})

    # ── Step 7: MITRE summary ────────────────────────────────────────
    try:
        mitre_summary, _mitre_path = mitre_persist(findings, case)
        yield mitre_done_event(mitre_summary)
    except Exception as e:                                        # pragma: no cover
        log.warning("MITRE summary failed: %s", e)
        pipeline_warnings.append({"phase": "mitre", "warnings": [str(e)]})

    # ── Step 8: correlation ──────────────────────────────────────────
    try:
        corr_result, _corr_path = correlate_and_persist(
            findings, case, artifacts=artifacts,
        )
        for chain in corr_result.chains:
            yield correlation_event(chain)
        yield correlations_done_event(corr_result)
    except Exception as e:                                        # pragma: no cover
        log.warning("correlation failed: %s", e)
        pipeline_warnings.append({"phase": "correlation",
                                  "warnings": [str(e)]})

    # ── Step 9: timeline ─────────────────────────────────────────────
    try:
        timeline_result, _timeline_path = timeline_persist(
            findings, case, artifacts=artifacts,
        )
        yield timeline_done_event(timeline_result)
    except Exception as e:                                        # pragma: no cover
        log.warning("timeline failed: %s", e)
        pipeline_warnings.append({"phase": "timeline",
                                  "warnings": [str(e)]})

    # ── Step 10: persist failed_plugins.json + limitations.json ─────
    if failed_plugins:
        try:
            (case / "failed_plugins.json").write_text(
                _json.dumps(failed_plugins, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError as e:
            log.warning("could not write failed_plugins.json: %s", e)

    if pipeline_warnings:
        try:
            (case / "limitations.json").write_text(
                _json.dumps(pipeline_warnings, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
        except OSError as e:
            log.warning("could not write limitations.json: %s", e)

    # ── Step 9b: deterministic Markdown/HTML report ──────────────────
    # Uses ONLY the already-written outputs — no LLM, no Volatility.
    # Produced after timeline so the report can include timeline totals.
    try:
        report_result = report_persist(case, image_path=image)
        yield report_ready_event(report_result)
    except Exception as e:                                        # pragma: no cover
        log.warning("deterministic report failed: %s", e)
        pipeline_warnings.append({"phase": "report",
                                  "warnings": [str(e)]})
        from .storage import write_json
        write_json(case / "limitations.json", pipeline_warnings)

    # ── Step 11: terminal `done` event (legacy contract) ────────────
    yield {
        "type":          "done",
        "findings":      [f.to_dict() for f in findings],
        "case_dir":      str(case),
        "findings_path": str(findings_path),
        "elapsed":       round(time.monotonic() - t0, 2),
    }


def load_findings(image_path: str | Path) -> list[dict]:
    """Helper for the API and the report generator to re-read what was saved."""
    target = _case_dir(image_path) / "findings.jsonl"
    if not target.exists():
        return []
    out: list[dict] = []
    for line in target.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line: continue
        try:
            out.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return out
