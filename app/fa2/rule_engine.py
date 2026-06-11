"""
m3mx tool — Full Analysis V2 rule engine.

The engine is intentionally simple and conservative:

* Rules live in YAML (one rule per object in ``rules:``). Python is the
  *engine*, YAML is the *content*.
* Rules operate on normalised :class:`Artifact` objects from
  :mod:`app.fa2.normalizers`.
* No rule fires "critical" unless its YAML declares a high ``base_score``
  in a strong-evidence category (memory / kernel / credential /
  persistence). Quality gates are enforced at load time as warnings.
* Per-rule modifiers consult :mod:`app.fa2.baseline` to *demote* matches
  that hit known-benign patterns (browser HTTPS, private IPs,
  allowlisted paths). They do not raise severity — that's the job of
  the correlation engine in Phase 6.

The engine emits :class:`Finding` (the Phase-1 superset) so the legacy
JSON shape is preserved while new V2 fields are populated.
"""
from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from . import baseline as bl
from .models import (
    Artifact, Finding, MitreMapping,
    CATEGORIES, OS_VALUES,
)
from .scoring import Score, score_to_severity, NEGATIVE_MODIFIERS
from .utils import load_yaml_safe, project_root

log = logging.getLogger("m3mx.fa2.rule_engine")


# ---------------------------------------------------------------------------
# Defaults
# ---------------------------------------------------------------------------

DEFAULT_RULE_FILES: list[Path] = [
    project_root() / "rules" / "common_rules.yaml",
    project_root() / "rules" / "windows_rules.yaml",
    project_root() / "rules" / "linux_rules.yaml",
    project_root() / "rules" / "mac_rules.yaml",
]

# Strong-evidence categories — only these may carry base_score ≥ 15
# (i.e. produce critical findings from a single artifact). Anything else
# at that score gets a quality-gate warning at load time.
_STRONG_EVIDENCE_CATEGORIES: set[str] = {
    "memory", "kernel", "credential", "persistence",
}

# Fields that may appear on a Finding's ``entities`` block. We surface
# them whenever the artifact carries them.
_ENTITY_FIELDS: tuple[str, ...] = (
    "pid", "ppid", "process_name", "name", "cmdline", "path", "user",
    "remote_ip", "remote_port", "local_ip", "local_port", "protocol",
    "state", "file_path", "module_path", "service_name", "command",
    "timestamp",
)


# ---------------------------------------------------------------------------
# Rule dataclass
# ---------------------------------------------------------------------------

@dataclass
class Rule:
    id: str
    title: str
    description: str
    applies_to: list[str]          # ["windows"], ["linux", "mac"], ["all"]
    artifact_type: str
    match: dict[str, Any]
    base_score: int
    confidence: float
    category: str
    mitre: list[MitreMapping] = field(default_factory=list)
    false_positive_notes: str = ""
    recommended_validation: str = ""
    enabled: bool = True
    modifiers: list[dict[str, Any]] = field(default_factory=list)
    source_file: str = ""


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------

REQUIRED_FIELDS: tuple[str, ...] = (
    "id", "title", "description", "applies_to",
    "artifact_type", "match", "base_score", "confidence",
    "category",
)


def validate_rule(rd: Any) -> tuple[bool, list[str]]:
    """
    Validate a single YAML-loaded rule dict. Returns ``(ok, errors)``.
    Never raises; returns a non-empty error list on any structural issue.
    """
    errors: list[str] = []
    if not isinstance(rd, dict):
        return False, ["rule must be a mapping"]

    for fld in REQUIRED_FIELDS:
        if fld not in rd:
            errors.append(f"missing required field: {fld}")

    # base_score: non-negative number
    bs = rd.get("base_score")
    if not isinstance(bs, (int, float)) or isinstance(bs, bool) or bs < 0:
        errors.append(f"base_score must be a non-negative number, got {bs!r}")

    # confidence: [0.0, 1.0]
    conf = rd.get("confidence")
    if not isinstance(conf, (int, float)) or isinstance(conf, bool) or \
            conf < 0 or conf > 1:
        errors.append(f"confidence must be in [0.0, 1.0], got {conf!r}")

    # applies_to: list of strings
    a2 = rd.get("applies_to")
    if not isinstance(a2, list) or not all(isinstance(x, str) for x in a2 or []):
        errors.append("applies_to must be a list of OS strings")

    # match: dict
    if not isinstance(rd.get("match"), dict):
        errors.append("match must be a mapping of conditions")

    # category: must be one of the known categories
    cat = rd.get("category")
    if isinstance(cat, str) and cat not in CATEGORIES:
        errors.append(f"category {cat!r} not in {sorted(CATEGORIES)}")

    # mitre: optional, but each entry needs technique + reason
    mitre = rd.get("mitre", [])
    if mitre is not None and not isinstance(mitre, list):
        errors.append("mitre must be a list when present")
    elif isinstance(mitre, list):
        for i, m in enumerate(mitre):
            if not isinstance(m, dict):
                errors.append(f"mitre[{i}] must be a mapping")
                continue
            if not m.get("technique"):
                errors.append(f"mitre[{i}]: technique is required")
            if not (m.get("reason") or "").strip():
                errors.append(f"mitre[{i}]: reason is required (no MITRE-as-decoration)")

    return (not errors), errors


def _quality_gate_warnings(rd: dict) -> list[str]:
    """
    Non-fatal warnings: rules that *could* technically be valid but
    violate the detection quality gates from CONTRACT.md §12.

    * Rules with ``base_score >= 15`` must be in a strong-evidence
      category (memory / kernel / credential / persistence). Otherwise
      a single-artifact match would land in ``critical``, which the
      spec forbids for weak signals.
    """
    out: list[str] = []
    bs = rd.get("base_score") or 0
    cat = rd.get("category") or ""
    if bs >= 15 and cat not in _STRONG_EVIDENCE_CATEGORIES:
        out.append(
            f"rule {rd.get('id')!r}: base_score {bs} reaches 'critical' but "
            f"category {cat!r} is not strong-evidence "
            f"({sorted(_STRONG_EVIDENCE_CATEGORIES)})"
        )
    return out


def _rule_from_dict(rd: dict, source_file: str) -> Rule:
    """Build a Rule from a validated YAML dict. Caller must pre-validate."""
    mitre = []
    for m in (rd.get("mitre") or []):
        mitre.append(MitreMapping(
            technique=str(m.get("technique", "")),
            name=str(m.get("name", "")),
            tactic=str(m.get("tactic", "")),
            reason=str(m.get("reason", "")),
            confidence=float(m.get("confidence", 0.5)),
        ))
    return Rule(
        id=str(rd["id"]),
        title=str(rd["title"]),
        description=str(rd["description"]),
        applies_to=list(rd.get("applies_to") or []),
        artifact_type=str(rd["artifact_type"]),
        match=dict(rd.get("match") or {}),
        base_score=int(rd["base_score"]),
        confidence=float(rd["confidence"]),
        category=str(rd.get("category") or "unknown"),
        mitre=mitre,
        false_positive_notes=str(rd.get("false_positive_notes") or ""),
        recommended_validation=str(rd.get("recommended_validation") or ""),
        enabled=bool(rd.get("enabled", True)),
        modifiers=list(rd.get("modifiers") or []),
        source_file=source_file,
    )


# ---------------------------------------------------------------------------
# Loading
# ---------------------------------------------------------------------------

def load_rules(paths: Iterable[str | Path] | None = None
               ) -> tuple[list[Rule], list[str]]:
    """
    Load rules from one or more YAML files. Returns ``(rules, warnings)``.

    Missing files are not errors — they produce a warning and contribute
    no rules. Malformed YAML is also caught by :func:`load_yaml_safe`
    and surfaces as a single warning per bad file.

    Duplicate rule ids are skipped (first wins) and warned.
    """
    warnings: list[str] = []
    rules: list[Rule] = []
    seen: set[str] = set()
    targets = list(paths) if paths is not None else list(DEFAULT_RULE_FILES)

    for p in targets:
        path = Path(p)
        data = load_yaml_safe(path)
        if not data:
            # load_yaml_safe already logs; surface here too for callers.
            if not path.exists():
                warnings.append(f"rule file not found: {path}")
            continue
        items = data.get("rules")
        if items is None:
            warnings.append(f"{path}: missing top-level 'rules' list — skipped")
            continue
        if not isinstance(items, list):
            warnings.append(f"{path}: 'rules' must be a list — skipped")
            continue
        for i, rd in enumerate(items):
            ok, errs = validate_rule(rd)
            if not ok:
                rid = (rd.get("id") if isinstance(rd, dict) else f"#{i}") or f"#{i}"
                warnings.append(f"{path}: rule {rid!r} rejected: {'; '.join(errs)}")
                continue
            rid = rd["id"]
            if rid in seen:
                warnings.append(f"{path}: duplicate rule id {rid!r} — first wins")
                continue
            seen.add(rid)
            warnings.extend(_quality_gate_warnings(rd))
            rules.append(_rule_from_dict(rd, source_file=str(path)))
    return rules, warnings


# ---------------------------------------------------------------------------
# Field lookup
# ---------------------------------------------------------------------------

def _str_field(art: Artifact, name: str) -> str | None:
    """
    Look up *name* in ``art.fields`` first, then ``art.raw``. Returns
    ``None`` if neither exists or the value is None/empty. Case-sensitive.
    """
    if name in art.fields and art.fields[name] not in (None, ""):
        return str(art.fields[name])
    if name in art.raw and art.raw[name] not in (None, ""):
        return str(art.raw[name])
    return None


def _rule_applies_to_os(rule: Rule, os_name: str) -> bool:
    if not rule.applies_to or "all" in rule.applies_to:
        return True
    return os_name in rule.applies_to


# ---------------------------------------------------------------------------
# Match conditions
# ---------------------------------------------------------------------------

def _check_match(match: dict, art: Artifact) -> bool:
    """
    Evaluate the match block against *art*. Supported keys (all optional
    except ``artifact_type``):

    * ``artifact_type``: required — string equal to ``art.type``.
    * ``os``: optional — string equal to ``art.os``.
    * ``field_regex``: ``{field: pattern}`` — every regex must match its
      field. ``re.search`` semantics.
    * ``field_equals``: ``{field: value}`` — every field must equal value.
    * ``field_not_equals``: ``{field: value}`` — every field must differ.
    * ``field_in``: ``{field: [values]}`` — value must be in list.
    * ``field_nonempty``: list of field names that must be present + non-empty.
    * ``any_field_regex``: list of patterns — at least one must match
      any value (fields + raw concatenated, separated by `` | ``).

    Returns False on the first failing predicate. Regex errors are
    caught by :func:`apply_rules` (rule is skipped with a log line).
    """
    at = match.get("artifact_type")
    if at and art.type != at:
        return False
    if match.get("os") and art.os != match["os"]:
        return False

    for fn, pat in (match.get("field_regex") or {}).items():
        v = _str_field(art, fn)
        if v is None or not re.search(pat, v):
            return False

    for fn, expected in (match.get("field_equals") or {}).items():
        v = _str_field(art, fn)
        if v is None or v != str(expected):
            return False

    for fn, unwanted in (match.get("field_not_equals") or {}).items():
        v = _str_field(art, fn)
        if v is not None and v == str(unwanted):
            return False

    for fn, allowed in (match.get("field_in") or {}).items():
        v = _str_field(art, fn)
        if v is None or v not in [str(x) for x in (allowed or [])]:
            return False

    for fn in (match.get("field_nonempty") or []):
        if _str_field(art, fn) is None:
            return False

    pats = match.get("any_field_regex") or []
    if pats:
        parts: list[str] = []
        for v in art.fields.values():
            if v not in (None, ""):
                parts.append(str(v))
        for v in art.raw.values():
            if v not in (None, ""):
                parts.append(str(v))
        haystack = " | ".join(parts)
        if not any(re.search(p, haystack) for p in pats):
            return False

    return True


# ---------------------------------------------------------------------------
# Modifier triggers (baseline-driven negatives)
# ---------------------------------------------------------------------------

_COMMON_WEB_PORTS: set[str] = {"80", "443", "8080", "8443"}


def _trigger_browser_https(art: Artifact) -> bool:
    if art.type != "network_connection":
        return False
    name = art.fields.get("process_name") or art.fields.get("name") or ""
    rp = str(art.fields.get("remote_port") or "")
    return bl.is_known_browser(name, art.os or "") and rp in _COMMON_WEB_PORTS


def _trigger_private_ip(art: Artifact) -> bool:
    if art.type != "network_connection":
        return False
    return bl.is_private_ip(str(art.fields.get("remote_ip") or ""))


def _trigger_allowlisted_path(art: Artifact) -> bool:
    path = art.fields.get("path") or art.fields.get("file_path") \
           or art.fields.get("module_path") or art.fields.get("binary") \
           or art.fields.get("name")
    return bl.is_allowlisted(str(path or ""), art.os or "")


_NEGATIVE_TRIGGERS: dict[str, Any] = {
    "known_benign_browser_https":  _trigger_browser_https,
    "private_ip_only":             _trigger_private_ip,
    "allowlisted_path_or_process": _trigger_allowlisted_path,
}


def _apply_modifiers(rule: Rule, art: Artifact) -> Score:
    """Build a Score honouring the rule's opt-in modifier list."""
    score = Score(base_score=rule.base_score, confidence=rule.confidence)
    for mod in rule.modifiers or []:
        name = mod.get("apply") if isinstance(mod, dict) else None
        if not name:
            continue
        trigger = _NEGATIVE_TRIGGERS.get(name)
        if trigger and trigger(art):
            pts = NEGATIVE_MODIFIERS.get(name, 0)
            if pts > 0:
                score.add_negative(name, pts)
    return score


# ---------------------------------------------------------------------------
# Apply
# ---------------------------------------------------------------------------

def _build_finding(rule: Rule, art: Artifact, score: Score,
                   counter: list[int]) -> Finding:
    counter[0] += 1
    fid = f"F-{counter[0]:03d}"

    entities: dict[str, Any] = {}
    for k in _ENTITY_FIELDS:
        v = art.fields.get(k)
        if v not in (None, "", 0) or k in ("pid", "ppid"):
            if v not in (None, ""):
                entities[k] = v

    evidence = dict(art.raw or {})
    tags = [m.technique for m in rule.mitre if m.technique]
    fos = art.os if art.os in OS_VALUES else None
    cat = rule.category if rule.category in CATEGORIES else "unknown"

    return Finding(
        id=fid,
        plugin=art.source_plugin or rule.id,
        severity=score.severity,
        title=rule.title,
        description=rule.description,
        evidence=evidence,
        tags=tags,
        confidence=score.confidence,
        os=fos,
        category=cat,
        score=score.final,
        entities=entities,
        mitre=list(rule.mitre),
        false_positive_notes=(rule.false_positive_notes or None),
        recommended_validation=(rule.recommended_validation or None),
        source_plugin=art.source_plugin or None,
    )


def apply_rules(artifacts: Iterable[Artifact],
                rules: Iterable[Rule] | None = None,
                os_filter: str | None = None) -> list[Finding]:
    """
    Apply *rules* to *artifacts* and return :class:`Finding` objects.

    If *rules* is None, the default rule pack is loaded fresh.
    If *os_filter* is set, only artifacts whose ``os`` equals the filter
    (or is "unknown") are considered.

    Never raises. Per-rule regex errors are logged and the rule is
    skipped for that artifact.
    """
    if rules is None:
        loaded, warnings = load_rules()
        for w in warnings:
            log.warning(w)
        rules = loaded
    rules = [r for r in rules if r.enabled]

    findings: list[Finding] = []
    counter: list[int] = [0]

    for art in artifacts:
        if os_filter and art.os != os_filter and art.os != "unknown":
            continue
        for rule in rules:
            if not _rule_applies_to_os(rule, art.os):
                continue
            try:
                if not _check_match(rule.match, art):
                    continue
            except re.error as e:
                log.warning("regex error in rule %s: %s — skipping", rule.id, e)
                continue
            score = _apply_modifiers(rule, art)
            findings.append(_build_finding(rule, art, score, counter))

    return findings
