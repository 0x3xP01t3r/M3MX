"""
m3mx tool — Full Analysis V2 MITRE ATT&CK summary generation.

Aggregates the MITRE mappings already attached to V2 findings (or the
legacy ``tags`` list inherited from the V1 schema) into one
deterministic summary document and persists it as
``mitre_summary.json``.

Strict rules:

* **No invention.** A technique appears in the summary only if it
  appears in at least one finding. Tactic, name, and reason are copied
  verbatim from the source finding; nothing is inferred from a static
  catalog. Legacy ``tags``-only techniques carry an explicit
  ``reason = "legacy tag — no detail recorded"`` marker.
* Duplicate techniques across findings are aggregated; the
  per-technique ``count`` reflects how many findings cited the
  technique, and ``finding_ids`` carries those finding IDs.
* Confidence is summarised as ``{min, max, mean}`` over the
  ``MitreMapping.confidence`` values that *had* a non-zero confidence.
  Legacy-tags-only techniques receive ``{None, None, None}``.
* This module reads :class:`Finding` objects or finding-shaped dicts
  (e.g. lines from ``findings.jsonl``) interchangeably.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Iterator

from .models import Finding

log = logging.getLogger("m3mx.fa2.mitre")

# Token used as the ``reason`` for techniques sourced only from the
# legacy ``tags`` list. Surface it verbatim — the UI / report should
# show that the detail is unavailable, not fabricate one.
LEGACY_REASON = "legacy tag — no detail recorded"

# Constant used in by_tactic for techniques that have no tactic field.
UNKNOWN_TACTIC = "Unknown"


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass
class TechniqueEntry:
    """A single MITRE technique aggregated across all findings that cited it."""

    technique: str
    name: str = ""
    tactic: str = ""
    count: int = 0
    finding_ids: list[str] = field(default_factory=list)
    confidence: dict[str, float | None] = field(
        default_factory=lambda: {"min": None, "max": None, "mean": None}
    )
    reasons: list[str] = field(default_factory=list)
    source: str = "detailed"     # detailed | legacy_tags | mixed

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique":   self.technique,
            "name":        self.name,
            "tactic":      self.tactic,
            "count":       int(self.count),
            "finding_ids": list(self.finding_ids),
            "confidence":  dict(self.confidence),
            "reasons":     list(self.reasons),
            "source":      self.source,
        }


@dataclass
class MitreSummary:
    """Top-level summary written as ``mitre_summary.json``."""

    techniques: list[TechniqueEntry] = field(default_factory=list)
    by_tactic: dict[str, list[str]] = field(default_factory=dict)
    totals: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "techniques": [t.to_dict() for t in self.techniques],
            "by_tactic":  {k: list(v) for k, v in self.by_tactic.items()},
            "totals":     dict(self.totals),
        }


# ---------------------------------------------------------------------------
# Finding accessors (dict-or-dataclass duck-typing)
# ---------------------------------------------------------------------------

def _fid(f: Any) -> str:
    if isinstance(f, Finding):
        return f.id
    if isinstance(f, dict):
        return str(f.get("id") or "")
    return str(getattr(f, "id", "") or "")


def _tags(f: Any) -> list[str]:
    if isinstance(f, Finding):
        return list(f.tags or [])
    if isinstance(f, dict):
        return list(f.get("tags") or [])
    return list(getattr(f, "tags", []) or [])


def _iter_mitre(f: Any) -> Iterator[tuple[str, str, str, str, float]]:
    """
    Yield ``(technique, name, tactic, reason, confidence)`` for each
    MITRE mapping on *f*. Works on :class:`Finding` and on plain dicts
    (e.g. one JSON line from ``findings.jsonl``).
    """
    if isinstance(f, Finding):
        for m in (f.mitre or []):
            yield (m.technique or "", m.name or "", m.tactic or "",
                   m.reason or "", float(m.confidence or 0.0))
        return
    if isinstance(f, dict):
        for m in (f.get("mitre") or []):
            if not isinstance(m, dict):
                continue
            yield (
                str(m.get("technique") or ""),
                str(m.get("name") or ""),
                str(m.get("tactic") or ""),
                str(m.get("reason") or ""),
                float(m.get("confidence") or 0.0),
            )
        return
    # Generic object — best effort.
    for m in (getattr(f, "mitre", None) or []):
        yield (
            getattr(m, "technique", "") or "",
            getattr(m, "name", "") or "",
            getattr(m, "tactic", "") or "",
            getattr(m, "reason", "") or "",
            float(getattr(m, "confidence", 0.0) or 0.0),
        )


# ---------------------------------------------------------------------------
# Per-technique accumulator (internal)
# ---------------------------------------------------------------------------

def _empty_accumulator(technique: str) -> dict[str, Any]:
    return {
        "technique":   technique,
        "name":        "",
        "tactic":      "",
        "count":       0,
        "finding_ids": [],
        "confidences": [],
        "reasons":     [],
        "sources":     set(),
    }


def _append_finding_id(acc: dict, fid: str) -> None:
    if fid and fid not in acc["finding_ids"]:
        acc["finding_ids"].append(fid)


def _append_reason(acc: dict, reason: str) -> None:
    if reason and reason not in acc["reasons"]:
        acc["reasons"].append(reason)


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def summarize_findings(findings: Iterable[Any]) -> MitreSummary:
    """
    Build a :class:`MitreSummary` from a sequence of findings (Finding
    objects or dicts). Never raises.

    Behaviour:

    * Aggregates duplicate techniques across findings.
    * For each finding, techniques present in both ``mitre`` and
      ``tags`` are counted once (the ``mitre`` detail wins).
    * Techniques present only in ``tags`` are recorded with
      ``source = "legacy_tags"`` and a stable ``reasons`` marker.
    * ``confidence`` is omitted (None) when no detailed mapping
      contributed a non-zero confidence value.
    """
    accumulators: dict[str, dict[str, Any]] = {}
    findings_with_mitre: set[str] = set()

    for f in findings:
        fid = _fid(f)
        detailed_seen: set[str] = set()

        # Detailed mitre mappings.
        for tech, name, tactic, reason, conf in _iter_mitre(f):
            tech = tech.strip()
            if not tech:
                continue
            detailed_seen.add(tech)
            findings_with_mitre.add(fid)

            acc = accumulators.setdefault(tech, _empty_accumulator(tech))
            acc["count"] += 1
            _append_finding_id(acc, fid)
            if name and not acc["name"]:
                acc["name"] = name
            if tactic and not acc["tactic"]:
                acc["tactic"] = tactic
            if conf > 0:
                acc["confidences"].append(float(conf))
            _append_reason(acc, reason)
            acc["sources"].add("detailed")

        # Legacy tags — only those NOT already seen as detailed mappings.
        for raw_tag in _tags(f):
            tag = str(raw_tag or "").strip()
            if not tag or tag in detailed_seen:
                continue
            findings_with_mitre.add(fid)
            acc = accumulators.setdefault(tag, _empty_accumulator(tag))
            acc["count"] += 1
            _append_finding_id(acc, fid)
            acc["sources"].add("legacy_tags")
            _append_reason(acc, LEGACY_REASON)

    # Materialise TechniqueEntry objects.
    entries: list[TechniqueEntry] = []
    for tech, acc in accumulators.items():
        confs = acc["confidences"]
        if confs:
            conf_summary = {
                "min":  round(min(confs), 4),
                "max":  round(max(confs), 4),
                "mean": round(sum(confs) / len(confs), 4),
            }
        else:
            conf_summary = {"min": None, "max": None, "mean": None}

        sources = acc["sources"]
        if sources == {"detailed"}:
            source = "detailed"
        elif sources == {"legacy_tags"}:
            source = "legacy_tags"
        else:
            source = "mixed"

        entries.append(TechniqueEntry(
            technique=tech,
            name=acc["name"],
            tactic=acc["tactic"],
            count=acc["count"],
            finding_ids=list(acc["finding_ids"]),
            confidence=conf_summary,
            reasons=list(acc["reasons"]),
            source=source,
        ))

    # Stable ordering: tactic (empty last), then technique id.
    entries.sort(key=lambda e: ((e.tactic or "~"), e.technique))

    by_tactic: dict[str, list[str]] = {}
    for e in entries:
        key = e.tactic or UNKNOWN_TACTIC
        by_tactic.setdefault(key, []).append(e.technique)
    for v in by_tactic.values():
        v.sort()

    totals = {
        "techniques":             len(entries),
        "findings_with_mitre":    len(findings_with_mitre),
        "legacy_only_techniques": sum(1 for e in entries if e.source == "legacy_tags"),
    }

    return MitreSummary(techniques=entries, by_tactic=by_tactic, totals=totals)


def write_mitre_summary(summary: MitreSummary,
                        case_dir: str | Path) -> str:
    """
    Write *summary* to ``<case_dir>/mitre_summary.json``. Returns the
    absolute path as a string. The file is overwritten if it already
    exists — V2 is the sole owner of this filename.
    """
    case = Path(case_dir)
    case.mkdir(parents=True, exist_ok=True)
    target = case / "mitre_summary.json"
    target.write_text(
        json.dumps(summary.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return str(target.resolve())


def summarize_and_persist(findings: Iterable[Any],
                          case_dir: str | Path) -> tuple[MitreSummary, str]:
    """
    Convenience helper: build the summary and persist it.
    Returns ``(summary, path)``.
    """
    summary = summarize_findings(findings)
    path = write_mitre_summary(summary, case_dir)
    return summary, path


def mitre_done_event(summary: MitreSummary) -> dict[str, Any]:
    """
    Build the optional ``mitre_done`` SSE event payload. Kept small —
    the consumer (frontend) can fetch the full ``mitre_summary.json``
    when it needs detail.

    This event is **not** part of the legacy SSE contract; the route
    must keep firing the existing 11 events and may add this one
    *additionally*. Frontends that don't know it must safely ignore
    it (Phase 0 / CONTRACT.md §4).
    """
    return {
        "type":                   "mitre_done",
        "technique_count":        int(summary.totals.get("techniques", 0)),
        "findings_with_mitre":    int(summary.totals.get("findings_with_mitre", 0)),
        "legacy_only_techniques": int(summary.totals.get("legacy_only_techniques", 0)),
        "tactics":                sorted(summary.by_tactic.keys()),
    }
