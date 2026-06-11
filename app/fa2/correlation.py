"""
m3mx tool — Full Analysis V2 correlation engine.

Builds :class:`AttackChain` objects from existing :class:`Finding` and
:class:`Artifact` records. The engine adds *no new raw detections* and
invents *no evidence* — it only relates existing facts.

Two flavours of chain are emitted:

1. **Composite chains** — multi-category narratives that match a
   specific attack pattern:

   * ``injection + network``        (category=memory + category=network on same PID)
   * ``persistence + process + network``
   * ``kernel anomaly + process``   (kernel_indicator + a process on the same host)

2. **Axis chains** — N≥2 findings that share one attribute:

   * same PID
   * parent-child (one finding's PID equals another's PPID)
   * same remote IP
   * same suspicious file path

Severity rules (CONTRACT §10 / §12):

* Severity defaults to ``max(severity_of(f) for f in chain)`` — never
  inflated from below.
* Composite chains may be lifted **one** notch when every required
  category is present (e.g. injection + network on the same PID can
  push high → critical), and the constituent confidences justify it.
* C2 / exfiltration / initial-access are not synthesised here. The
  chain's MITRE list is the union of constituent findings' MITRE
  mappings — nothing more.
* Public IP alone is still not C2. Temp execution alone is still not
  critical. The engine inherits these guardrails from its inputs.
"""
from __future__ import annotations

import json
import logging
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from .models import AttackChain, Artifact, Finding, MitreMapping, SEVERITIES

log = logging.getLogger("m3mx.fa2.correlation")


# ---------------------------------------------------------------------------
# Tuning constants
# ---------------------------------------------------------------------------

_SEVERITY_ORDER: dict[str, int] = {s: i for i, s in enumerate(SEVERITIES)}
_NEXT_SEVERITY: dict[str, str] = {
    "info": "low", "low": "medium", "medium": "high",
    "high": "critical", "critical": "critical",
}

# Minimum number of findings required to form a chain.
MIN_CHAIN_SIZE = 2

# Maximum number of chains we'll emit per axis to bound output.
_AXIS_CAP = 50


# ---------------------------------------------------------------------------
# Result wrapper
# ---------------------------------------------------------------------------

@dataclass
class CorrelationResult:
    chains: list[AttackChain] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    totals: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "chains":   [c.to_dict() for c in self.chains],
            "warnings": list(self.warnings),
            "totals":   dict(self.totals),
        }


# ---------------------------------------------------------------------------
# Finding/Artifact accessors (dict-or-dataclass duck typing)
# ---------------------------------------------------------------------------

def _is_finding(o: Any) -> bool:
    return isinstance(o, Finding) or (isinstance(o, dict) and "tags" in o)


def _fid(f: Any) -> str:
    return f.id if isinstance(f, Finding) else str((f or {}).get("id") or "")


def _fseverity(f: Any) -> str:
    return f.severity if isinstance(f, Finding) else str((f or {}).get("severity") or "info")


def _fconfidence(f: Any) -> float:
    if isinstance(f, Finding):
        return float(f.confidence or 0.0)
    return float((f or {}).get("confidence") or 0.0)


def _fcategory(f: Any) -> str:
    if isinstance(f, Finding):
        return f.category or "unknown"
    return str((f or {}).get("category") or "unknown")


def _fos(f: Any) -> str:
    if isinstance(f, Finding):
        return f.os or "unknown"
    return str((f or {}).get("os") or "unknown")


def _ftitle(f: Any) -> str:
    if isinstance(f, Finding):
        return f.title or ""
    return str((f or {}).get("title") or "")


def _fmitre(f: Any) -> list[MitreMapping]:
    if isinstance(f, Finding):
        return list(f.mitre or [])
    out: list[MitreMapping] = []
    for m in (f or {}).get("mitre") or []:
        if isinstance(m, dict):
            out.append(MitreMapping(
                technique=str(m.get("technique", "")),
                name=str(m.get("name", "")),
                tactic=str(m.get("tactic", "")),
                reason=str(m.get("reason", "")),
                confidence=float(m.get("confidence", 0.0)),
            ))
    return out


def _fentities(f: Any) -> dict[str, Any]:
    if isinstance(f, Finding):
        return dict(f.entities or {})
    return dict((f or {}).get("entities") or {})


def _fvalidation(f: Any) -> str:
    if isinstance(f, Finding):
        return f.recommended_validation or ""
    return str((f or {}).get("recommended_validation") or "")


def _afields(a: Any) -> dict[str, Any]:
    if isinstance(a, Artifact):
        return dict(a.fields or {})
    if isinstance(a, dict):
        # Artifact-shaped dict (with 'fields') or normalized JSONL line
        return dict(a.get("fields") or {k: v for k, v in a.items()
                                       if k not in ("type", "os", "source_plugin", "raw")})
    return {}


def _atype(a: Any) -> str:
    if isinstance(a, Artifact):
        return a.type
    if isinstance(a, dict):
        return str(a.get("type", ""))
    return ""


# ---------------------------------------------------------------------------
# Indices
# ---------------------------------------------------------------------------

def _norm_pid(v: Any) -> int | None:
    if v in (None, "", 0):
        return None
    try:
        return int(v)
    except (TypeError, ValueError):
        return None


def _norm_str(v: Any) -> str | None:
    if v in (None, ""):
        return None
    s = str(v).strip()
    return s or None


def _index_findings_by(findings: list[Any], entity_key: str,
                       norm=_norm_str) -> dict[Any, list[Any]]:
    out: dict[Any, list[Any]] = defaultdict(list)
    for f in findings:
        v = norm(_fentities(f).get(entity_key))
        if v is None:
            continue
        out[v].append(f)
    return out


def _index_findings_by_category(findings: list[Any]) -> dict[str, list[Any]]:
    out: dict[str, list[Any]] = defaultdict(list)
    for f in findings:
        out[_fcategory(f)].append(f)
    return out


def _index_artifacts_by(artifacts: list[Any], field_key: str,
                       norm=_norm_str) -> dict[Any, list[Any]]:
    out: dict[Any, list[Any]] = defaultdict(list)
    for a in artifacts:
        v = norm(_afields(a).get(field_key))
        if v is None:
            continue
        out[v].append(a)
    return out


# ---------------------------------------------------------------------------
# Severity / confidence helpers
# ---------------------------------------------------------------------------

def _max_severity(severities: Iterable[str]) -> str:
    best = -1
    out = "info"
    for s in severities:
        i = _SEVERITY_ORDER.get(s, 0)
        if i > best:
            best, out = i, s
    return out


def _upgrade_severity(sev: str) -> str:
    return _NEXT_SEVERITY.get(sev, sev)


def _avg_conf(findings: list[Any], bonus: float = 0.0) -> float:
    if not findings:
        return 0.0
    confs = [_fconfidence(f) for f in findings if _fconfidence(f) > 0]
    if not confs:
        base = 0.5
    else:
        base = sum(confs) / len(confs)
    return max(0.0, min(1.0, base + bonus))


def _merge_mitre(findings: list[Any]) -> list[MitreMapping]:
    """Union of constituent MITRE mappings; first occurrence wins on ties."""
    seen: dict[str, MitreMapping] = {}
    for f in findings:
        for m in _fmitre(f):
            if not m.technique:
                continue
            if m.technique in seen:
                continue
            seen[m.technique] = m
    return list(seen.values())


def _merge_validation(findings: list[Any]) -> str:
    parts: list[str] = []
    for f in findings:
        v = (_fvalidation(f) or "").strip()
        if v and v not in parts:
            parts.append(v)
    return "\n\n".join(parts)


def _chain_os(findings: list[Any]) -> str:
    for f in findings:
        o = _fos(f)
        if o and o != "unknown":
            return o
    return "unknown"


# ---------------------------------------------------------------------------
# Chain construction
# ---------------------------------------------------------------------------

@dataclass
class _ChainCtx:
    """Mutable per-run state passed between detectors."""
    counter: list[int] = field(default_factory=lambda: [0])
    seen_keys: set[tuple] = field(default_factory=set)


def _new_chain_id(ctx: _ChainCtx) -> str:
    ctx.counter[0] += 1
    return f"C-{ctx.counter[0]:03d}"


def _dedupe_key(findings: list[Any], kind: str) -> tuple:
    """Stable key so we don't emit two chains for the same finding set + kind."""
    return (kind, tuple(sorted(_fid(f) for f in findings if _fid(f))))


def _build_chain(*, ctx: _ChainCtx,
                 findings: list[Any],
                 kind: str,
                 title: str,
                 summary: str,
                 evidence_summary: str,
                 severity_upgrade: bool = False,
                 confidence_bonus: float = 0.0,
                 edges: list[dict] | None = None) -> AttackChain | None:
    """
    Build an :class:`AttackChain` from *findings*. Returns None when the
    chain doesn't satisfy minimum size or has been emitted already.
    """
    findings = [f for f in findings if f is not None]
    if len(findings) < MIN_CHAIN_SIZE:
        return None
    key = _dedupe_key(findings, kind)
    if key in ctx.seen_keys:
        return None
    ctx.seen_keys.add(key)

    severities = [_fseverity(f) for f in findings]
    base_severity = _max_severity(severities)
    severity = _upgrade_severity(base_severity) if severity_upgrade else base_severity

    confidence = _avg_conf(findings, bonus=confidence_bonus)

    nodes: list[dict[str, Any]] = []
    for f in findings:
        ent = _fentities(f)
        nodes.append({
            "finding_id": _fid(f),
            "category":   _fcategory(f),
            "severity":   _fseverity(f),
            "title":      _ftitle(f),
            "entities":   ent,
        })

    return AttackChain(
        chain_id=_new_chain_id(ctx),
        os=_chain_os(findings),
        title=title,
        severity=severity,
        confidence=confidence,
        summary=summary,
        nodes=nodes,
        edges=list(edges or []),
        findings=[_fid(f) for f in findings if _fid(f)],
        mitre=_merge_mitre(findings),
        evidence_summary=evidence_summary,
        recommended_validation=_merge_validation(findings),
    )


# ---------------------------------------------------------------------------
# Detectors — composite chains
# ---------------------------------------------------------------------------

def _detect_injection_network(ctx: _ChainCtx,
                              f_by_pid: dict[Any, list[Any]],
                              f_by_cat: dict[str, list[Any]]) -> list[AttackChain]:
    """
    Strong composite: a memory-category finding (e.g. malfind) and a
    network-category finding cite the same PID. Severity may be lifted
    one notch from its constituents.
    """
    chains: list[AttackChain] = []
    for mf in f_by_cat.get("memory", []):
        pid = _norm_pid(_fentities(mf).get("pid"))
        if pid is None:
            continue
        same_pid = f_by_pid.get(pid, []) or []
        net_findings = [f for f in same_pid
                        if _fcategory(f) == "network" and _fid(f) != _fid(mf)]
        if not net_findings:
            continue
        proc_findings = [f for f in same_pid
                         if _fcategory(f) == "process" and _fid(f) != _fid(mf)]
        findings = [mf] + net_findings + proc_findings
        edges: list[dict] = []
        for nf in net_findings:
            edges.append({
                "from": _fid(mf), "to": _fid(nf),
                "type": "same_pid",
                "reason": f"injected code region and outbound network share PID {pid}",
            })
        for pf in proc_findings:
            edges.append({
                "from": _fid(mf), "to": _fid(pf),
                "type": "same_pid",
                "reason": f"injected code region inside the same PID {pid}",
            })
        chain = _build_chain(
            ctx=ctx,
            findings=findings,
            kind="injection_network",
            title=f"Code injection + outbound network in PID {pid}",
            summary=(f"PID {pid} exhibits both an injected memory region "
                     f"and an outbound network connection — strong indicator "
                     f"of an implant beaconing or staging payload."),
            evidence_summary=(f"memory-region finding + network-connection "
                              f"finding (+ process context) bound to PID {pid}"),
            severity_upgrade=True,
            confidence_bonus=0.05,
            edges=edges,
        )
        if chain:
            chains.append(chain)
        if len(chains) >= _AXIS_CAP:
            break
    return chains


def _detect_persistence_process_network(ctx: _ChainCtx,
                                        f_by_pid: dict[Any, list[Any]],
                                        f_by_cat: dict[str, list[Any]]) -> list[AttackChain]:
    """
    Composite: persistence artefact (service / scheduled task) + a process
    finding + a network finding observed on the same PID.
    """
    chains: list[AttackChain] = []
    for sf in f_by_cat.get("persistence", []):
        pid = _norm_pid(_fentities(sf).get("pid"))
        # Persistence findings often lack a PID (it's a config), so only
        # tie them to a chain when at least the service_name / binary
        # matches a process artifact (handled in path-axis below). For
        # PID-tied cases, do the full composite.
        if pid is None:
            continue
        same_pid = f_by_pid.get(pid, []) or []
        proc_findings = [f for f in same_pid if _fcategory(f) == "process"]
        net_findings = [f for f in same_pid if _fcategory(f) == "network"]
        if not proc_findings or not net_findings:
            continue
        findings = [sf] + proc_findings + net_findings
        edges = []
        for f in proc_findings + net_findings:
            edges.append({
                "from": _fid(sf), "to": _fid(f),
                "type": "same_pid",
                "reason": f"persistence + behaviour bound to PID {pid}",
            })
        chain = _build_chain(
            ctx=ctx,
            findings=findings,
            kind="persistence_process_network",
            title=f"Persistence + active process + outbound network (PID {pid})",
            summary=(f"PID {pid} runs a persistence-installed binary "
                     "with active outbound network — consistent with "
                     "implant tasking."),
            evidence_summary="persistence-finding + process-finding + network-finding",
            severity_upgrade=True,
            confidence_bonus=0.05,
            edges=edges,
        )
        if chain:
            chains.append(chain)
    return chains


def _detect_kernel_anomaly_process(ctx: _ChainCtx,
                                   f_by_cat: dict[str, list[Any]],
                                   findings: list[Any]) -> list[AttackChain]:
    """
    Composite: a kernel-indicator finding (rootkit / hook) plus any
    suspicious process finding on the same OS — both are independently
    strong, but together they reinforce each other.
    """
    chains: list[AttackChain] = []
    kerns = f_by_cat.get("kernel", [])
    procs = [f for f in findings if _fcategory(f) == "process"]
    if not kerns or not procs:
        return chains
    for kf in kerns:
        os_name = _fos(kf)
        proc_findings = [f for f in procs if _fos(f) == os_name][:5]
        if not proc_findings:
            continue
        findings_in_chain = [kf] + proc_findings
        edges = []
        for pf in proc_findings:
            edges.append({
                "from": _fid(kf), "to": _fid(pf),
                "type": "kernel_anomaly_plus_process",
                "reason": "kernel anomaly co-occurs with suspicious process activity",
            })
        chain = _build_chain(
            ctx=ctx,
            findings=findings_in_chain,
            kind="kernel_anomaly_process",
            title=f"Kernel anomaly co-occurring with suspicious processes ({os_name})",
            summary=("A kernel-level hook / hidden structure was reported "
                     "alongside suspicious process behaviour on the same "
                     "host — strongly consistent with a rootkit."),
            evidence_summary="kernel-indicator finding + ≥1 suspicious process finding",
            severity_upgrade=False,  # kernel anomaly is already critical
            confidence_bonus=0.05,
            edges=edges,
        )
        if chain:
            chains.append(chain)
    return chains


# ---------------------------------------------------------------------------
# Detectors — axis chains
# ---------------------------------------------------------------------------

def _detect_same_pid(ctx: _ChainCtx,
                     f_by_pid: dict[Any, list[Any]]) -> list[AttackChain]:
    chains: list[AttackChain] = []
    for pid, fs in f_by_pid.items():
        if len(fs) < MIN_CHAIN_SIZE:
            continue
        edges = [{
            "from": _fid(fs[0]), "to": _fid(f),
            "type": "same_pid",
            "reason": f"findings share PID {pid}",
        } for f in fs[1:]]
        chain = _build_chain(
            ctx=ctx,
            findings=list(fs),
            kind="same_pid",
            title=f"Multiple suspicious behaviours in PID {pid}",
            summary=(f"{len(fs)} findings cite PID {pid}. Correlation "
                     "alone does not increase severity unless one of the "
                     "composite chains is also satisfied."),
            evidence_summary=f"shared PID {pid}",
            severity_upgrade=False,
            edges=edges,
        )
        if chain:
            chains.append(chain)
        if len(chains) >= _AXIS_CAP:
            break
    return chains


def _detect_parent_child(ctx: _ChainCtx,
                         findings: list[Any]) -> list[AttackChain]:
    """
    Match findings whose PID equals another finding's PPID. Each match
    becomes a tiny 2-node chain — no severity upgrade by itself.
    """
    pid_to_findings: dict[int, list[Any]] = defaultdict(list)
    for f in findings:
        pid = _norm_pid(_fentities(f).get("pid"))
        if pid is not None:
            pid_to_findings[pid].append(f)

    chains: list[AttackChain] = []
    for child in findings:
        ppid = _norm_pid(_fentities(child).get("ppid"))
        if ppid is None or ppid not in pid_to_findings:
            continue
        parents = pid_to_findings[ppid]
        for parent in parents:
            if _fid(parent) == _fid(child):
                continue
            chain = _build_chain(
                ctx=ctx,
                findings=[parent, child],
                kind="parent_child",
                title=f"Parent–child process chain: PID {ppid} → PID {_fentities(child).get('pid')}",
                summary="A parent process and one of its child processes "
                        "both produced findings.",
                evidence_summary=f"PID {ppid} (parent) → PID {_fentities(child).get('pid')} (child)",
                severity_upgrade=False,
                edges=[{
                    "from": _fid(parent), "to": _fid(child),
                    "type": "parent_child",
                    "reason": f"PID {ppid} is parent of PID {_fentities(child).get('pid')}",
                }],
            )
            if chain:
                chains.append(chain)
            if len(chains) >= _AXIS_CAP:
                return chains
    return chains


def _detect_same_remote_ip(ctx: _ChainCtx,
                           f_by_ip: dict[Any, list[Any]]) -> list[AttackChain]:
    chains: list[AttackChain] = []
    for ip, fs in f_by_ip.items():
        if len(fs) < MIN_CHAIN_SIZE:
            continue
        edges = [{
            "from": _fid(fs[0]), "to": _fid(f),
            "type": "same_remote_ip",
            "reason": f"findings share remote IP {ip}",
        } for f in fs[1:]]
        chain = _build_chain(
            ctx=ctx,
            findings=list(fs),
            kind="same_remote_ip",
            title=f"Multiple findings communicate with {ip}",
            summary=(f"{len(fs)} findings cite remote IP {ip}. A shared "
                     "remote IP is not on its own evidence of C2; verify "
                     "against reputation feeds and look for matching "
                     "process / persistence findings."),
            evidence_summary=f"shared remote IP {ip}",
            severity_upgrade=False,
            edges=edges,
        )
        if chain:
            chains.append(chain)
        if len(chains) >= _AXIS_CAP:
            break
    return chains


def _path_key(f: Any) -> str | None:
    ent = _fentities(f)
    return _norm_str(ent.get("path") or ent.get("file_path")
                     or ent.get("module_path") or ent.get("binary"))


def _detect_same_file_path(ctx: _ChainCtx,
                           findings: list[Any]) -> list[AttackChain]:
    by_path: dict[str, list[Any]] = defaultdict(list)
    for f in findings:
        p = _path_key(f)
        if p:
            by_path[p].append(f)

    chains: list[AttackChain] = []
    for path, fs in by_path.items():
        if len(fs) < MIN_CHAIN_SIZE:
            continue
        edges = [{
            "from": _fid(fs[0]), "to": _fid(f),
            "type": "same_file_path",
            "reason": f"findings share file path {path}",
        } for f in fs[1:]]
        chain = _build_chain(
            ctx=ctx,
            findings=list(fs),
            kind="same_file_path",
            title=f"Multiple findings reference {path}",
            summary=(f"{len(fs)} findings reference the same path "
                     f"{path}. Useful to track persistence + execution "
                     "of the same binary across artefacts."),
            evidence_summary=f"shared path {path}",
            severity_upgrade=False,
            edges=edges,
        )
        if chain:
            chains.append(chain)
        if len(chains) >= _AXIS_CAP:
            break
    return chains


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def correlate(findings: Iterable[Any],
              artifacts: Iterable[Any] | None = None) -> CorrelationResult:
    """
    Run the correlation engine over *findings* (and optional
    *artifacts*). Returns a :class:`CorrelationResult` with the list of
    detected chains.
    """
    findings = list(findings or [])
    artifacts = list(artifacts or [])
    warnings: list[str] = []

    if not findings:
        return CorrelationResult(
            chains=[], warnings=warnings,
            totals={"chains": 0, "findings_in_chains": 0},
        )

    f_by_pid = _index_findings_by(findings, "pid", norm=_norm_pid)
    f_by_remote_ip = _index_findings_by(findings, "remote_ip", norm=_norm_str)
    f_by_cat = _index_findings_by_category(findings)

    ctx = _ChainCtx()

    chains: list[AttackChain] = []
    # Composite first — they earn higher severity, axis chains add context.
    chains.extend(_detect_injection_network(ctx, f_by_pid, f_by_cat))
    chains.extend(_detect_persistence_process_network(ctx, f_by_pid, f_by_cat))
    chains.extend(_detect_kernel_anomaly_process(ctx, f_by_cat, findings))
    # Axis chains.
    chains.extend(_detect_same_pid(ctx, f_by_pid))
    chains.extend(_detect_parent_child(ctx, findings))
    chains.extend(_detect_same_remote_ip(ctx, f_by_remote_ip))
    chains.extend(_detect_same_file_path(ctx, findings))

    findings_in_chains: set[str] = set()
    for c in chains:
        for fid in c.findings:
            findings_in_chains.add(fid)

    return CorrelationResult(
        chains=chains,
        warnings=warnings,
        totals={
            "chains":              len(chains),
            "findings_in_chains":  len(findings_in_chains),
        },
    )


def write_correlations(result: CorrelationResult,
                       case_dir: str | Path) -> str:
    """
    Persist *result* to ``<case_dir>/correlations.json``. Returns the
    absolute path.
    """
    case = Path(case_dir)
    case.mkdir(parents=True, exist_ok=True)
    target = case / "correlations.json"
    target.write_text(
        json.dumps(result.to_dict(), indent=2, ensure_ascii=False),
        encoding="utf-8",
    )
    return str(target.resolve())


def correlate_and_persist(findings: Iterable[Any],
                          case_dir: str | Path,
                          artifacts: Iterable[Any] | None = None
                          ) -> tuple[CorrelationResult, str]:
    """Convenience helper: correlate and persist in one call."""
    result = correlate(findings, artifacts=artifacts)
    path = write_correlations(result, case_dir)
    return result, path


# ---------------------------------------------------------------------------
# Optional SSE event payloads
# ---------------------------------------------------------------------------

def correlation_event(chain: AttackChain) -> dict[str, Any]:
    """Per-chain ``correlation`` SSE event payload (one per chain)."""
    return {
        "type":       "correlation",
        "chain_id":   chain.chain_id,
        "title":      chain.title,
        "severity":   chain.severity,
        "confidence": float(chain.confidence),
        "findings":   list(chain.findings),
    }


def correlations_done_event(result: CorrelationResult) -> dict[str, Any]:
    """Terminal ``correlations_done`` SSE event payload (emit once)."""
    return {
        "type":              "correlations_done",
        "chain_count":       int(result.totals.get("chains", 0)),
        "findings_in_chains": int(result.totals.get("findings_in_chains", 0)),
    }
