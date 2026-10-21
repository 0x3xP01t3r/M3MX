"""
m3mx tool — Full Analysis V2 AI Report context builder.

Loads the saved outputs of a completed Full Analysis run from the case
directory and packages them into a strict evidence-bound context the
optional AI Report generator can hand to an LLM.

The builder is **read-only**: it never invokes Volatility, never
re-runs rules, never invents data. If a file is missing the absence is
recorded in ``files_missing`` so the LLM prompt can mention it as a
limitation.

Required files:

* ``findings.jsonl`` — the canonical V1/V2 finding list.

Optional files (added context if present):

* ``normalized_artifacts.jsonl``
* ``correlations.json``
* ``timeline.json``
* ``mitre_summary.json``
* ``failed_plugins.json``
* ``limitations.json``
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

log = logging.getLogger("m3mx.fa2.ai_report_context")


# ---------------------------------------------------------------------------
# Result wrapper
# ---------------------------------------------------------------------------

@dataclass
class CaseOutputs:
    """Everything the AI Report builder loaded from disk."""
    findings: list[dict] = field(default_factory=list)
    normalized_artifacts: list[dict] = field(default_factory=list)
    correlations: dict[str, Any] | None = None
    timeline: dict[str, Any] | None = None
    mitre_summary: dict[str, Any] | None = None
    failed_plugins: list[dict] = field(default_factory=list)
    limitations: list[dict] = field(default_factory=list)
    files_present: list[str] = field(default_factory=list)
    files_missing: list[str] = field(default_factory=list)
    case_dir: str = ""

    @property
    def has_findings(self) -> bool:
        return bool(self.findings)

    @property
    def has_findings_file(self) -> bool:
        """A valid completed run may contain zero findings."""
        return "findings.jsonl" in self.files_present


# ---------------------------------------------------------------------------
# Loaders
# ---------------------------------------------------------------------------

def _load_json_lines(path: Path) -> list[dict]:
    out: list[dict] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            obj = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(obj, dict):
            out.append(obj)
    return out


def _load_json_file(path: Path) -> Any:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as e:
        log.warning("could not parse %s: %s", path, e)
        return None


def load_case_outputs(case_dir: str | Path) -> CaseOutputs:
    """
    Read every available output file from *case_dir*. Never raises.

    ``has_findings_file`` distinguishes completed zero-finding runs from
    missing input. ``has_findings`` indicates actual positive findings.
    """
    case = Path(case_dir)
    out = CaseOutputs(case_dir=str(case.resolve() if case.exists() else case))

    # findings.jsonl (required input)
    findings_path = case / "findings.jsonl"
    if findings_path.exists():
        out.findings = _load_json_lines(findings_path)
        out.files_present.append("findings.jsonl")
    else:
        out.files_missing.append("findings.jsonl")

    # normalized_artifacts.jsonl (optional)
    nap = case / "normalized_artifacts.jsonl"
    if nap.exists():
        out.normalized_artifacts = _load_json_lines(nap)
        out.files_present.append("normalized_artifacts.jsonl")
    else:
        out.files_missing.append("normalized_artifacts.jsonl")

    # Single-document JSONs.
    for fname, attr in (
        ("correlations.json",   "correlations"),
        ("timeline.json",       "timeline"),
        ("mitre_summary.json",  "mitre_summary"),
    ):
        p = case / fname
        if p.exists():
            data = _load_json_file(p)
            if isinstance(data, dict):
                setattr(out, attr, data)
                out.files_present.append(fname)
            else:
                out.files_missing.append(fname)
        else:
            out.files_missing.append(fname)

    # List-document JSONs (we tolerate both list and dict-with-list).
    for fname, attr in (
        ("failed_plugins.json", "failed_plugins"),
        ("limitations.json",    "limitations"),
    ):
        p = case / fname
        if p.exists():
            data = _load_json_file(p)
            if isinstance(data, list):
                setattr(out, attr, data)
                out.files_present.append(fname)
            elif isinstance(data, dict):
                # Some writers wrap a list in a dict; pick the obvious key.
                lst = data.get("items") or data.get("entries") or []
                if isinstance(lst, list):
                    setattr(out, attr, lst)
                    out.files_present.append(fname)
                else:
                    out.files_missing.append(fname)
            else:
                out.files_missing.append(fname)
        else:
            out.files_missing.append(fname)

    return out


# ---------------------------------------------------------------------------
# Compaction helpers (keep the LLM context tight)
# ---------------------------------------------------------------------------

_MAX_FINDINGS_FOR_PROMPT = 60
_MAX_CHAINS_FOR_PROMPT = 30
_MAX_TIMELINE_FOR_PROMPT = 80


def _compact_finding(f: dict) -> dict:
    """Strip giant ``evidence`` blobs from the prompt while keeping IDs."""
    out: dict[str, Any] = {
        "id":         f.get("id", ""),
        "plugin":     f.get("plugin", ""),
        "severity":   f.get("severity", ""),
        "title":      f.get("title", ""),
        "description": (f.get("description") or "")[:400],
        "tags":       list(f.get("tags") or []),
        "confidence": f.get("confidence", 0.0),
    }
    for k in ("os", "category", "score", "entities",
              "source_plugin", "false_positive_notes",
              "recommended_validation"):
        v = f.get(k)
        if v not in (None, "", [], {}):
            out[k] = v
    # MITRE list: keep technique + reason; drop nothing else.
    mitre = f.get("mitre") or []
    if mitre:
        out["mitre"] = [
            {"technique": m.get("technique", ""),
             "name":      m.get("name", ""),
             "tactic":    m.get("tactic", ""),
             "reason":    m.get("reason", ""),
             "confidence": m.get("confidence", 0.0)}
            for m in mitre
        ]
    return out


def _compact_chain(c: dict) -> dict:
    return {
        "chain_id":   c.get("chain_id", ""),
        "title":      c.get("title", ""),
        "severity":   c.get("severity", ""),
        "confidence": c.get("confidence", 0.0),
        "findings":   list(c.get("findings") or []),
        "summary":    (c.get("summary") or "")[:400],
        "evidence_summary": (c.get("evidence_summary") or "")[:300],
        "mitre":      list(c.get("mitre") or []),
    }


def _compact_timeline_event(e: dict) -> dict:
    return {
        "ts":    e.get("ts"),
        "type":  e.get("type", ""),
        "title": (e.get("title") or "")[:160],
        "related_finding_ids": list(e.get("related_finding_ids") or []),
        "related_pids":        list(e.get("related_pids") or []),
        "source_plugin":       e.get("source_plugin", ""),
    }


def build_prompt_context(outputs: CaseOutputs) -> dict[str, Any]:
    """
    Pack *outputs* into a deterministic structure suitable for an LLM
    user-message. Caps the size of long lists so the prompt stays
    bounded; the original files on disk remain authoritative.
    """
    findings = outputs.findings or []

    severity_counts: dict[str, int] = {}
    category_counts: dict[str, int] = {}
    for f in findings:
        sev = f.get("severity") or "info"
        cat = f.get("category") or "unknown"
        severity_counts[sev] = severity_counts.get(sev, 0) + 1
        category_counts[cat] = category_counts.get(cat, 0) + 1

    timeline = outputs.timeline or {}
    chains = (outputs.correlations or {}).get("chains") or []

    return {
        "case_dir":         outputs.case_dir,
        "files_present":    list(outputs.files_present),
        "files_missing":    list(outputs.files_missing),
        "findings_total":   len(findings),
        "severity_counts":  severity_counts,
        "category_counts":  category_counts,
        "findings":         [_compact_finding(f)
                             for f in findings[:_MAX_FINDINGS_FOR_PROMPT]],
        "findings_truncated": max(0, len(findings) - _MAX_FINDINGS_FOR_PROMPT),
        "mitre_summary":    outputs.mitre_summary or {},
        "correlations": {
            "total":   len((outputs.correlations or {}).get("chains") or []),
            "chains":  [_compact_chain(c)
                        for c in chains[:_MAX_CHAINS_FOR_PROMPT]],
        },
        "timeline": {
            "totals":         timeline.get("totals", {}),
            "timed_events":   [_compact_timeline_event(e)
                               for e in (timeline.get("events") or [])
                                        [:_MAX_TIMELINE_FOR_PROMPT]],
            "untimed_events": [_compact_timeline_event(e)
                               for e in (timeline.get("untimed_events") or [])
                                        [:_MAX_TIMELINE_FOR_PROMPT]],
        },
        "failed_plugins":   list(outputs.failed_plugins),
        "limitations":      list(outputs.limitations),
    }
