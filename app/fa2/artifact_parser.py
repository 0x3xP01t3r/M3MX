"""
m3mx tool — Full Analysis V2 artifact parser.

The entry point a V2 orchestrator will call to:

1. Convert a list of :class:`RunnerResult` into a list of normalized
   :class:`Artifact` via the per-OS dispatch tables in
   :mod:`app.fa2.normalizers`.
2. Persist the artifacts as ``normalized_artifacts.jsonl`` in the case
   directory.
3. Save the raw plugin CSV output to ``artifacts/<plugin>.csv`` for
   evidence preservation.

This module does **not** invoke Volatility. It does **not** know about
SSE, Flask, or the V1 pipeline. It is safe to import and call from
tests with hand-built :class:`RunnerResult` objects.
"""
from __future__ import annotations

import csv
import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

from .models import Artifact
from .volatility_runner import RunnerResult
from . import normalizers

log = logging.getLogger("m3mx.fa2.artifact_parser")


# ---------------------------------------------------------------------------
# Result wrapper
# ---------------------------------------------------------------------------

@dataclass
class NormalizationResult:
    """
    Outcome of a batch normalize-and-persist call.

    Carries both summary counts and the artifact list itself so callers
    can chain into rule/correlation engines without re-reading the file.
    """
    artifacts: list[Artifact] = field(default_factory=list)
    normalized_path: str | None = None
    raw_artifacts_dir: str | None = None
    per_plugin: dict[str, int] = field(default_factory=dict)
    skipped: list[dict[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.artifacts)

    def to_dict(self) -> dict:
        return {
            "total":             self.total,
            "normalized_path":   self.normalized_path,
            "raw_artifacts_dir": self.raw_artifacts_dir,
            "per_plugin":        dict(self.per_plugin),
            "skipped":           list(self.skipped),
            "warnings":          list(self.warnings),
        }


# ---------------------------------------------------------------------------
# Normalization
# ---------------------------------------------------------------------------

def normalize_runner_results(results: Iterable[RunnerResult]) -> NormalizationResult:
    """
    Apply per-plugin normalizers to *results*. Successful plugins with
    a registered normalizer contribute artifacts; everything else is
    listed in :attr:`NormalizationResult.skipped` with a reason.

    Never raises. Per-plugin normalizer failures are caught and
    recorded as warnings.
    """
    out = NormalizationResult()
    supported = normalizers.supported_plugins()
    for res in results:
        plugin = res.plugin
        if not res.success:
            out.skipped.append({
                "plugin": plugin,
                "reason": res.error or "plugin did not succeed",
            })
            continue
        if not res.rows:
            out.skipped.append({
                "plugin": plugin,
                "reason": "plugin produced no rows",
            })
            continue
        if plugin not in supported:
            out.skipped.append({
                "plugin": plugin,
                "reason": "no normalizer registered for this plugin",
            })
            continue

        try:
            artifacts = normalizers.normalize(plugin, res.columns, res.rows)
        except Exception as e:                                    # pragma: no cover
            out.warnings.append(f"{plugin}: normalizer raised {type(e).__name__}: {e}")
            continue

        if not artifacts:
            out.skipped.append({
                "plugin": plugin,
                "reason": "normalizer returned no artifacts",
            })
            continue

        out.artifacts.extend(artifacts)
        out.per_plugin[plugin] = out.per_plugin.get(plugin, 0) + len(artifacts)

    return out


# ---------------------------------------------------------------------------
# Raw CSV preservation
# ---------------------------------------------------------------------------

def write_raw_artifacts(results: Iterable[RunnerResult],
                        case_dir: str | Path) -> tuple[str, list[str]]:
    """
    Persist each runner result's CSV in ``<case_dir>/artifacts/<plugin>.csv``.
    Returns ``(artifacts_dir, warnings)``. Best-effort: an unwritable
    file is logged but never aborts the batch.
    """
    artifacts_dir = Path(case_dir) / "artifacts"
    warnings: list[str] = []
    try:
        artifacts_dir.mkdir(parents=True, exist_ok=True)
    except OSError as e:
        warnings.append(f"could not create {artifacts_dir}: {e}")
        return str(artifacts_dir), warnings

    for res in results:
        if not res.success or not res.columns:
            continue
        target = artifacts_dir / f"{res.plugin}.csv"
        try:
            with target.open("w", encoding="utf-8", newline="") as fh:
                w = csv.writer(fh)
                w.writerow(res.columns)
                for row in (res.rows or []):
                    w.writerow(row)
        except OSError as e:
            warnings.append(f"{res.plugin}: could not write {target}: {e}")

    return str(artifacts_dir), warnings


# ---------------------------------------------------------------------------
# Normalized JSONL writer
# ---------------------------------------------------------------------------

def write_normalized_artifacts(artifacts: Iterable[Artifact],
                               case_dir: str | Path) -> str:
    """
    Write *artifacts* to ``<case_dir>/normalized_artifacts.jsonl``.
    Returns the absolute path as a string. The file is overwritten if
    it already exists — V2 is the sole owner of this filename.
    """
    case = Path(case_dir)
    case.mkdir(parents=True, exist_ok=True)
    target = case / "normalized_artifacts.jsonl"
    with target.open("w", encoding="utf-8") as fh:
        for a in artifacts:
            fh.write(json.dumps(a.to_dict(), ensure_ascii=False) + "\n")
    return str(target.resolve())


# ---------------------------------------------------------------------------
# One-shot helper
# ---------------------------------------------------------------------------

def normalize_and_persist(results: Iterable[RunnerResult],
                          case_dir: str | Path) -> NormalizationResult:
    """
    Convenience wrapper: normalize *results*, write the raw CSVs and
    the JSONL, and return the :class:`NormalizationResult` with the
    output paths filled in.
    """
    results = list(results)
    norm = normalize_runner_results(results)

    raw_dir, raw_warnings = write_raw_artifacts(results, case_dir)
    norm.raw_artifacts_dir = raw_dir
    norm.warnings.extend(raw_warnings)

    try:
        path = write_normalized_artifacts(norm.artifacts, case_dir)
        norm.normalized_path = path
    except OSError as e:
        norm.warnings.append(f"could not write normalized_artifacts.jsonl: {e}")

    return norm
