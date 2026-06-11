"""
m3mx tool — Full Analysis V2 data models.

These dataclasses are intentionally additive: :class:`Finding` is a
**superset** of the legacy ``app.full_analysis.Finding`` schema. The
eight original fields are required and serialise into the same JSON
shape the existing frontend already consumes; every new field is
optional and is **omitted from the serialised payload when empty** so
old readers never see unexpected keys.

Compatibility guarantees (see :file:`CONTRACT.md`):

* The required fields and their value domains are unchanged.
* ``severity`` is always one of ``SEVERITIES``.
* ``confidence`` is always a float in ``[0.0, 1.0]``.
* ``tags`` is always a list of MITRE technique-id strings, present even
  when empty (preserves the old wire format).
* New optional fields default to ``None`` / empty containers and are
  dropped from :meth:`Finding.to_dict` when they carry no information.
"""
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Any, Optional

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SEVERITIES: tuple[str, ...] = ("info", "low", "medium", "high", "critical")
"""Allowed severity strings, low→high. Matches the existing V1 contract."""

OS_VALUES: tuple[str, ...] = ("windows", "linux", "mac", "unknown")
"""Allowed values for the optional ``os`` field on a Finding/Artifact."""

CATEGORIES: tuple[str, ...] = (
    "process", "memory", "network", "persistence", "credential",
    "kernel", "file", "registry", "user_activity", "unknown",
)
"""Allowed values for the optional ``category`` field on a Finding."""


# ---------------------------------------------------------------------------
# MITRE mapping (optional, with required reason)
# ---------------------------------------------------------------------------

@dataclass
class MitreMapping:
    """A single MITRE ATT&CK technique reference with mandatory reason."""

    technique: str               # e.g. "T1059.001"
    name: str = ""               # e.g. "PowerShell"
    tactic: str = ""             # e.g. "Execution"
    reason: str = ""             # why this technique applies — required content
    confidence: float = 0.0      # 0.0–1.0

    def to_dict(self) -> dict[str, Any]:
        return {
            "technique":  self.technique,
            "name":       self.name,
            "tactic":     self.tactic,
            "reason":     self.reason,
            "confidence": float(self.confidence),
        }


# ---------------------------------------------------------------------------
# Finding — superset of V1 schema
# ---------------------------------------------------------------------------

# Optional-field names; these are omitted from to_dict() when empty/None.
_FINDING_OPTIONAL_FIELDS: tuple[str, ...] = (
    "os", "category", "score", "entities", "mitre",
    "false_positive_notes", "recommended_validation",
    "source_plugin", "raw_artifact_ref", "correlation_refs", "limitations",
)


@dataclass
class Finding:
    # ── Legacy required fields (must not change) ──────────────────────────
    id: str                      # "F-NNN"
    plugin: str                  # short name, e.g. "pslist"
    severity: str                # one of SEVERITIES
    title: str
    description: str
    evidence: dict[str, Any] = field(default_factory=dict)
    tags: list[str] = field(default_factory=list)        # MITRE ids as strings
    confidence: float = 0.7

    # ── New V2 optional fields ────────────────────────────────────────────
    os: Optional[str] = None                              # one of OS_VALUES
    category: Optional[str] = None                        # one of CATEGORIES
    score: Optional[int] = None                           # final integer score
    entities: dict[str, Any] = field(default_factory=dict)
    mitre: list[MitreMapping] = field(default_factory=list)
    false_positive_notes: Optional[str] = None
    recommended_validation: Optional[str] = None
    source_plugin: Optional[str] = None
    raw_artifact_ref: Optional[str] = None
    correlation_refs: list[str] = field(default_factory=list)
    limitations: list[str] = field(default_factory=list)

    # ── Validation ────────────────────────────────────────────────────────
    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(
                f"severity must be one of {SEVERITIES}, got {self.severity!r}"
            )
        if not isinstance(self.confidence, (int, float)):
            raise TypeError("confidence must be a float")
        self.confidence = max(0.0, min(1.0, float(self.confidence)))
        if self.os is not None and self.os not in OS_VALUES:
            raise ValueError(f"os must be one of {OS_VALUES}, got {self.os!r}")
        if self.category is not None and self.category not in CATEGORIES:
            raise ValueError(
                f"category must be one of {CATEGORIES}, got {self.category!r}"
            )

    # ── Serialisation ─────────────────────────────────────────────────────
    def to_dict(self) -> dict[str, Any]:
        """
        Wire-format JSON. Always emits the eight legacy required keys so
        the existing frontend keeps working unchanged. Optional V2 keys
        are emitted only when they carry content.
        """
        out: dict[str, Any] = {
            "id":          self.id,
            "plugin":      self.plugin,
            "severity":    self.severity,
            "title":       self.title,
            "description": self.description,
            "evidence":    dict(self.evidence),
            "tags":        list(self.tags),
            "confidence":  float(self.confidence),
        }
        # Scalars: include if non-None and non-empty-string.
        for k in ("os", "category", "score", "false_positive_notes",
                  "recommended_validation", "source_plugin", "raw_artifact_ref"):
            v = getattr(self, k)
            if v is None or v == "":
                continue
            out[k] = v
        # Containers: include only when non-empty.
        if self.entities:
            out["entities"] = dict(self.entities)
        if self.mitre:
            out["mitre"] = [m.to_dict() for m in self.mitre]
        if self.correlation_refs:
            out["correlation_refs"] = list(self.correlation_refs)
        if self.limitations:
            out["limitations"] = list(self.limitations)
        return out


# ---------------------------------------------------------------------------
# Artifact (normalized view of plugin rows)
# ---------------------------------------------------------------------------

@dataclass
class Artifact:
    """Unified artifact: a normalised view of one plugin row."""

    type: str                                             # e.g. "process"
    os: str = "unknown"                                   # one of OS_VALUES
    source_plugin: str = ""
    raw: dict[str, Any] = field(default_factory=dict)
    # Free-form fields populated by normalizers (pid, ppid, name, path, etc.)
    fields: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {
            "type":          self.type,
            "os":            self.os,
            "source_plugin": self.source_plugin,
            "raw":           dict(self.raw),
        }
        if self.fields:
            out.update(self.fields)
        return out


# ---------------------------------------------------------------------------
# AttackChain (correlated multi-finding narrative)
# ---------------------------------------------------------------------------

@dataclass
class AttackChain:
    chain_id: str
    os: str = "unknown"
    title: str = ""
    severity: str = "info"
    confidence: float = 0.0
    summary: str = ""
    nodes: list[dict[str, Any]] = field(default_factory=list)
    edges: list[dict[str, Any]] = field(default_factory=list)
    findings: list[str] = field(default_factory=list)     # Finding.id references
    mitre: list[MitreMapping] = field(default_factory=list)
    evidence_summary: str = ""
    recommended_validation: str = ""

    def __post_init__(self) -> None:
        if self.severity not in SEVERITIES:
            raise ValueError(
                f"severity must be one of {SEVERITIES}, got {self.severity!r}"
            )
        self.confidence = max(0.0, min(1.0, float(self.confidence)))

    def to_dict(self) -> dict[str, Any]:
        return {
            "chain_id":               self.chain_id,
            "os":                     self.os,
            "title":                  self.title,
            "severity":               self.severity,
            "confidence":             float(self.confidence),
            "summary":                self.summary,
            "nodes":                  list(self.nodes),
            "edges":                  list(self.edges),
            "findings":               list(self.findings),
            "mitre":                  [m.to_dict() for m in self.mitre],
            "evidence_summary":       self.evidence_summary,
            "recommended_validation": self.recommended_validation,
        }


# ---------------------------------------------------------------------------
# TimelineEvent
# ---------------------------------------------------------------------------

@dataclass
class TimelineEvent:
    ts: Optional[str] = None             # ISO-8601 or None when unknown
    type: str = "event"
    os: str = "unknown"
    title: str = ""
    description: str = ""
    related_finding_ids: list[str] = field(default_factory=list)
    related_pids: list[int] = field(default_factory=list)
    source_plugin: str = ""
    confidence: float = 0.0

    def __post_init__(self) -> None:
        self.confidence = max(0.0, min(1.0, float(self.confidence)))

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)
