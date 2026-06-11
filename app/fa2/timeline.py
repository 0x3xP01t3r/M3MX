"""
m3mx tool — Full Analysis V2 timeline engine.

Reconstructs an evidence-based timeline from existing V2 Findings and
normalised Artifacts. The engine **never invents timestamps** and never
imposes a chronological order on entries it could not date — those land
in a separate ``untimed_events`` bucket so the consumer can distinguish
"happened at T" from "we observed this but don't know when".

Time-bearing fields the engine recognises:

* ``timestamp``, ``create_time``, ``start_time`` — process / generic
* ``exit_time``                                  — process exit
* ``last_use``, ``last_modified``                — registry / file
* ``trigger_time``                               — scheduled task
* ``created``                                    — network endpoint

A finding / artifact may emit multiple events (e.g. a Windows process
artifact with both ``create_time`` and ``exit_time``) — that's fine, each
event documents one observation.

Parsing rules:

* The engine accepts ISO-8601 plus several common Volatility variants
  (``2025-01-02 10:00:00`` / ``Wed Jan 2 10:00:00 2025`` / etc.).
* On a malformed timestamp the event is preserved but moved to
  ``untimed_events`` and tagged ``type = "untimed:<kind>"``.
* No ordering is faked. Untimed events appear in input order.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path
from typing import Any, Iterable, Optional

from .models import Artifact, Finding, TimelineEvent

log = logging.getLogger("m3mx.fa2.timeline")


# ---------------------------------------------------------------------------
# Time-field tables
# ---------------------------------------------------------------------------

# (field_name, event_type). The same artifact / finding may emit one
# event per field that's populated.
_FINDING_TIME_FIELDS: tuple[tuple[str, str], ...] = (
    ("timestamp",     "event"),
    ("create_time",   "process_start"),
    ("start_time",    "process_start"),
    ("exit_time",     "process_exit"),
    ("last_use",      "user_activity"),
    ("last_modified", "file_event"),
    ("trigger_time",  "scheduled_task_run"),
    ("created",       "connection_open"),
)

# Artifact type → list of (field_name, event_type).
_ARTIFACT_TIME_FIELDS: dict[str, tuple[tuple[str, str], ...]] = {
    "process":            (("create_time", "process_start"),
                           ("exit_time",   "process_exit")),
    "bash_history":       (("timestamp",   "bash_command"),),
    "user_activity":      (("last_use",    "user_activity"),
                           ("last_modified", "user_activity")),
    "file":               (("last_modified", "file_event"),
                           ("timestamp",     "file_event")),
    "registry":           (("last_modified", "registry_event"),
                           ("timestamp",     "registry_event")),
    "scheduled_task":     (("trigger_time", "scheduled_task_run"),),
    "network_connection": (("created",      "connection_open"),),
    "service":            (("last_modified", "service_observation"),),
    "module":             (("last_modified", "module_event"),),
    "kernel_indicator":   (("timestamp",     "kernel_event"),),
    "memory_region":      (("timestamp",     "memory_event"),),
}

# Untimed event labels (used when a finding/artifact carries no parseable
# timestamp but is still worth recording on the timeline). All
# untimed types are prefixed ``untimed:`` so the consumer can filter
# them at a glance.
_UNTIMED_TYPES: dict[str, str] = {
    "process":            "untimed:process_observed",
    "network_connection": "untimed:connection_observed",
    "service":            "untimed:service_observed",
    "scheduled_task":     "untimed:scheduled_task_observed",
    "memory_region":      "untimed:memory_region_observed",
    "module":             "untimed:module_observed",
    "kernel_indicator":   "untimed:kernel_indicator_observed",
    "bash_history":       "untimed:bash_command",
    "file":               "untimed:file_observed",
    "registry":           "untimed:registry_observed",
    "user_activity":      "untimed:user_activity",
}

# Confidence assigned to timeline events depending on timestamp clarity.
_CONFIDENCE_TIMED   = 0.85
_CONFIDENCE_UNTIMED = 0.45


# ---------------------------------------------------------------------------
# Result wrapper
# ---------------------------------------------------------------------------

@dataclass
class TimelineResult:
    events: list[TimelineEvent] = field(default_factory=list)         # timed
    untimed_events: list[TimelineEvent] = field(default_factory=list)
    totals: dict[str, Any] = field(default_factory=dict)
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "events":         [e.to_dict() for e in self.events],
            "untimed_events": [e.to_dict() for e in self.untimed_events],
            "totals":         dict(self.totals),
            "warnings":       list(self.warnings),
        }


# ---------------------------------------------------------------------------
# Timestamp parsing
# ---------------------------------------------------------------------------

# Accepted strptime formats in descending specificity. The first match wins.
# The "UTC" / microsecond pairs cover Vol3's actual output format:
#   2024-07-15 07:00:06.000000 UTC
_TS_FORMATS: tuple[str, ...] = (
    "%Y-%m-%dT%H:%M:%S.%f",
    "%Y-%m-%dT%H:%M:%S",
    "%Y-%m-%d %H:%M:%S.%f UTC",          # ← Vol3 Windows pslist/psscan format
    "%Y-%m-%d %H:%M:%S.%f",
    "%Y-%m-%d %H:%M:%S UTC",
    "%Y-%m-%d %H:%M:%S",
    "%a %b %d %H:%M:%S %Y",
    "%a %b %d %H:%M:%S UTC %Y",
)


def parse_timestamp(raw: Any) -> Optional[str]:
    """
    Attempt to parse *raw* into a normalised ISO-8601 string.

    Returns ``None`` on any failure — the engine never invents values.
    Always preserves the calling code's right to put the original
    string in the untimed bucket.
    """
    if raw is None:
        return None
    s = str(raw).strip()
    if not s:
        return None
    # Vol3 sometimes emits literal "N/A" for missing process exit times.
    if s.upper() in ("N/A", "NONE", "NULL", "-"):
        return None
    # Allow trailing Z (UTC marker) — strip and try as naive.
    if s.endswith("Z"):
        s = s[:-1]
    # Try fromisoformat first (cheapest in 3.11+ and tolerant of T/space).
    candidate = s.replace(" ", "T", 1)
    try:
        return datetime.fromisoformat(candidate).isoformat()
    except (ValueError, TypeError):
        pass
    # Fall back to a small set of explicit formats.
    for fmt in _TS_FORMATS:
        try:
            return datetime.strptime(s, fmt).isoformat()
        except ValueError:
            continue
    return None


# ---------------------------------------------------------------------------
# Finding / Artifact accessors
# ---------------------------------------------------------------------------

def _is_finding(o: Any) -> bool:
    return isinstance(o, Finding) or (isinstance(o, dict) and "tags" in o)


def _fid(f: Any) -> str:
    return f.id if isinstance(f, Finding) else str((f or {}).get("id") or "")


def _fentities(f: Any) -> dict[str, Any]:
    if isinstance(f, Finding):
        return dict(f.entities or {})
    if isinstance(f, dict):
        return dict(f.get("entities") or {})
    return {}


def _fos(f: Any) -> str:
    if isinstance(f, Finding):
        return f.os or "unknown"
    if isinstance(f, dict):
        return str(f.get("os") or "unknown")
    return "unknown"


def _fcategory(f: Any) -> str:
    if isinstance(f, Finding):
        return f.category or ""
    if isinstance(f, dict):
        return str(f.get("category") or "")
    return ""


def _fsource_plugin(f: Any) -> str:
    if isinstance(f, Finding):
        return f.source_plugin or f.plugin or ""
    if isinstance(f, dict):
        return str(f.get("source_plugin") or f.get("plugin") or "")
    return ""


def _ftitle(f: Any) -> str:
    if isinstance(f, Finding):
        return f.title or ""
    if isinstance(f, dict):
        return str(f.get("title") or "")
    return ""


def _fdescription(f: Any) -> str:
    if isinstance(f, Finding):
        return f.description or ""
    if isinstance(f, dict):
        return str(f.get("description") or "")
    return ""


def _afields(a: Any) -> dict[str, Any]:
    if isinstance(a, Artifact):
        return dict(a.fields or {})
    if isinstance(a, dict):
        return dict(a.get("fields") or {})
    return {}


def _atype(a: Any) -> str:
    if isinstance(a, Artifact):
        return a.type
    if isinstance(a, dict):
        return str(a.get("type", ""))
    return ""


def _aos(a: Any) -> str:
    if isinstance(a, Artifact):
        return a.os or "unknown"
    if isinstance(a, dict):
        return str(a.get("os") or "unknown")
    return "unknown"


def _asource_plugin(a: Any) -> str:
    if isinstance(a, Artifact):
        return a.source_plugin or ""
    if isinstance(a, dict):
        return str(a.get("source_plugin") or "")
    return ""


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _norm_pid(v: Any) -> Optional[int]:
    if v in (None, "", 0):
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _collect_pids(*sources: dict[str, Any]) -> list[int]:
    """Collect distinct PIDs / PPIDs from one or more dicts."""
    out: list[int] = []
    for src in sources:
        for k in ("pid", "ppid"):
            p = _norm_pid(src.get(k))
            if p is not None and p not in out:
                out.append(p)
    return out


def _short(s: str, n: int = 240) -> str:
    s = (s or "").strip()
    return s if len(s) <= n else s[: n - 1] + "…"


# ---------------------------------------------------------------------------
# Event builders
# ---------------------------------------------------------------------------

def _make_event_from_finding(f: Any, field_name: str, ts: Optional[str],
                             event_type: str) -> TimelineEvent:
    ent = _fentities(f)
    pids = _collect_pids(ent)
    title = _ftitle(f) or event_type
    desc = _short(_fdescription(f))
    if not desc and ent.get("name"):
        desc = f"{ent.get('name')}"
    return TimelineEvent(
        ts=ts,
        type=event_type,
        os=_fos(f),
        title=title,
        description=desc,
        related_finding_ids=[_fid(f)] if _fid(f) else [],
        related_pids=pids,
        source_plugin=_fsource_plugin(f),
        confidence=_CONFIDENCE_TIMED if ts else _CONFIDENCE_UNTIMED,
    )


def _make_event_from_artifact(a: Any, field_name: str, ts: Optional[str],
                              event_type: str) -> TimelineEvent:
    fields = _afields(a)
    pids = _collect_pids(fields)
    title_bits: list[str] = []
    for k in ("name", "process_name", "service_name", "file_path",
              "module_path", "command"):
        v = fields.get(k)
        if v:
            title_bits.append(str(v))
            break
    title = title_bits[0] if title_bits else event_type
    desc_parts: list[str] = []
    if event_type.startswith("process_"):
        if fields.get("pid") is not None:
            desc_parts.append(f"PID {fields['pid']}")
        if fields.get("name"):
            desc_parts.append(str(fields["name"]))
    elif event_type == "bash_command":
        desc_parts.append(_short(str(fields.get("command", "")), 240))
    elif event_type.startswith("file") or event_type.startswith("registry"):
        if fields.get("file_path"):
            desc_parts.append(str(fields["file_path"]))
    desc = " · ".join(p for p in desc_parts if p)
    return TimelineEvent(
        ts=ts,
        type=event_type,
        os=_aos(a),
        title=title,
        description=desc,
        related_finding_ids=[],
        related_pids=pids,
        source_plugin=_asource_plugin(a),
        confidence=_CONFIDENCE_TIMED if ts else _CONFIDENCE_UNTIMED,
    )


def _untimed_event_for_finding(f: Any) -> Optional[TimelineEvent]:
    cat = _fcategory(f)
    kind_map = {
        "process":     "untimed:process_observed",
        "network":     "untimed:connection_observed",
        "persistence": "untimed:persistence_observed",
        "memory":      "untimed:memory_region_observed",
        "kernel":      "untimed:kernel_indicator_observed",
        "credential":  "untimed:credential_observed",
        "registry":    "untimed:registry_observed",
        "user_activity": "untimed:user_activity",
        "file":        "untimed:file_observed",
    }
    label = kind_map.get(cat)
    if not label:
        return None
    return _make_event_from_finding(f, "", None, label)


def _untimed_event_for_artifact(a: Any) -> Optional[TimelineEvent]:
    label = _UNTIMED_TYPES.get(_atype(a))
    if not label:
        return None
    return _make_event_from_artifact(a, "", None, label)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def build_timeline(findings: Iterable[Any],
                   artifacts: Iterable[Any] | None = None) -> TimelineResult:
    """
    Construct a timeline from *findings* (and optional *artifacts*).

    Never raises. Returns a :class:`TimelineResult` with two lists:

    * ``events``         — entries that carry a parseable ISO timestamp,
      sorted ascending (oldest first).
    * ``untimed_events`` — entries without a parseable timestamp,
      preserved in input order and clearly labelled
      ``type = "untimed:<kind>"``.
    """
    findings = list(findings or [])
    artifacts = list(artifacts or [])
    warnings: list[str] = []
    timed: list[TimelineEvent] = []
    untimed: list[TimelineEvent] = []

    # ---- Findings ----
    for f in findings:
        ent = _fentities(f)
        emitted_any = False
        for field_name, event_type in _FINDING_TIME_FIELDS:
            raw = ent.get(field_name)
            if raw in (None, ""):
                continue
            # If the data source explicitly says "no value" (Vol3 emits
            # ``N/A`` for live processes' ExitTime), skip silently — do
            # not pollute the untimed bucket with placeholders.
            if str(raw).strip().upper() in ("N/A", "NONE", "NULL", "-"):
                continue
            ts = parse_timestamp(raw)
            if ts:
                timed.append(_make_event_from_finding(f, field_name, ts, event_type))
                emitted_any = True
            else:
                warnings.append(
                    f"finding {_fid(f)}: unparseable timestamp {raw!r} in {field_name}"
                )
                # Tag with untimed:<event_type> so the consumer keeps the link.
                untimed.append(
                    _make_event_from_finding(
                        f, field_name, None, f"untimed:{event_type}",
                    )
                )
                emitted_any = True
        if not emitted_any:
            # Still worth putting the finding on the timeline as an untimed
            # event when the category is meaningfully temporal.
            ev = _untimed_event_for_finding(f)
            if ev:
                untimed.append(ev)

    # ---- Artifacts ----
    for a in artifacts:
        atype = _atype(a)
        fields = _afields(a)
        time_fields = _ARTIFACT_TIME_FIELDS.get(atype, ())
        emitted_any = False
        for field_name, event_type in time_fields:
            raw = fields.get(field_name)
            if raw in (None, ""):
                continue
            # Skip "no value" placeholders silently — see Findings loop above.
            if str(raw).strip().upper() in ("N/A", "NONE", "NULL", "-"):
                continue
            ts = parse_timestamp(raw)
            if ts:
                timed.append(_make_event_from_artifact(a, field_name, ts, event_type))
                emitted_any = True
            else:
                warnings.append(
                    f"artifact {atype}/{_asource_plugin(a)}: unparseable "
                    f"timestamp {raw!r} in {field_name}"
                )
                untimed.append(
                    _make_event_from_artifact(
                        a, field_name, None, f"untimed:{event_type}",
                    )
                )
                emitted_any = True
        if not emitted_any:
            ev = _untimed_event_for_artifact(a)
            if ev:
                untimed.append(ev)

    # Stable ordering of timed events: timestamp asc, then source_plugin.
    timed.sort(key=lambda e: (e.ts or "", e.source_plugin, e.title))

    totals: dict[str, Any] = {
        "timed":   len(timed),
        "untimed": len(untimed),
    }
    if timed:
        totals["earliest"] = timed[0].ts
        totals["latest"]   = timed[-1].ts

    return TimelineResult(events=timed,
                          untimed_events=untimed,
                          totals=totals,
                          warnings=warnings)


def write_timeline(result: TimelineResult, case_dir: str | Path) -> str:
    """Write the result to ``<case_dir>/timeline.json`` and return the path."""
    case = Path(case_dir)
    case.mkdir(parents=True, exist_ok=True)
    target = case / "timeline.json"
    target.write_text(
        json.dumps(result.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return str(target.resolve())


def build_and_persist(findings: Iterable[Any],
                      case_dir: str | Path,
                      artifacts: Iterable[Any] | None = None
                      ) -> tuple[TimelineResult, str]:
    """Convenience helper: build the timeline and persist it."""
    result = build_timeline(findings, artifacts=artifacts)
    path = write_timeline(result, case_dir)
    return result, path


def timeline_done_event(result: TimelineResult) -> dict[str, Any]:
    """Optional ``timeline_done`` SSE event payload."""
    return {
        "type":     "timeline_done",
        "timed":    int(result.totals.get("timed", 0)),
        "untimed":  int(result.totals.get("untimed", 0)),
        "earliest": result.totals.get("earliest"),
        "latest":   result.totals.get("latest"),
    }
