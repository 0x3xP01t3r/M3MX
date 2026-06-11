"""
m3mx tool — Full Analysis V2 scoring engine.

Severity is derived deterministically from a numeric score. Confidence
is **independent** of severity — a finding can be high-severity but
medium-confidence (the behaviour is dangerous if real but the evidence
is partial), or medium-severity but high-confidence (the evidence is
solid but the behaviour itself isn't catastrophic).

Bands (CONTRACT.md §11):

    score ≥ 15   → critical
    score ≥ 10   → high
    score ≥ 6    → medium
    score ≥ 3    → low
    score <  3   → info

This module is pure: no IO, no globals other than the band table. It is
safe to import from anywhere (rule engine, tests, ad-hoc tooling).
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Iterable

from .models import SEVERITIES

# ---------------------------------------------------------------------------
# Severity bands
# ---------------------------------------------------------------------------

# (min_score_inclusive, severity). Ordered high→low so the first match wins.
_BANDS: tuple[tuple[int, str], ...] = (
    (15, "critical"),
    (10, "high"),
    (6,  "medium"),
    (3,  "low"),
)


def score_to_severity(score: int | float) -> str:
    """
    Map a numeric score to one of :data:`SEVERITIES`. Anything below 3
    falls into ``info``. Negative scores still resolve to ``info``.

    Boundaries are inclusive on the lower edge so the bands compose
    cleanly (10 is high, 9 is medium, 15 is critical, 14 is high).
    """
    s = int(score)
    for threshold, label in _BANDS:
        if s >= threshold:
            return label
    return "info"


# ---------------------------------------------------------------------------
# Score builder
# ---------------------------------------------------------------------------

@dataclass
class Score:
    """
    Composed score for a single detection.

    Use :meth:`compute` for a fresh score, or instantiate directly with
    a baseline and call :meth:`add_positive` / :meth:`add_negative`.

    ``confidence`` is carried alongside but is **not** derived from the
    score. Severity-vs-confidence independence is enforced by tests.
    """

    base_score: int = 0
    positive: list[tuple[str, int]] = field(default_factory=list)
    negative: list[tuple[str, int]] = field(default_factory=list)
    confidence: float = 0.5

    # ── builders ──────────────────────────────────────────────────────────
    def add_positive(self, reason: str, points: int) -> "Score":
        if points < 0:
            raise ValueError("positive modifier points must be non-negative")
        if points > 0:
            self.positive.append((reason, int(points)))
        return self

    def add_negative(self, reason: str, points: int) -> "Score":
        if points < 0:
            raise ValueError("negative modifier points must be non-negative")
        if points > 0:
            self.negative.append((reason, int(points)))
        return self

    def set_confidence(self, value: float) -> "Score":
        self.confidence = max(0.0, min(1.0, float(value)))
        return self

    # ── derivations ───────────────────────────────────────────────────────
    @property
    def final(self) -> int:
        pos = sum(p for _, p in self.positive)
        neg = sum(p for _, p in self.negative)
        # Final score is clamped to 0 — a deeply allowlisted artifact
        # should land in ``info``, not in negative territory.
        return max(0, int(self.base_score) + pos - neg)

    @property
    def severity(self) -> str:
        return score_to_severity(self.final)

    # ── one-shot constructor ──────────────────────────────────────────────
    @classmethod
    def compute(
        cls,
        base: int = 0,
        positives: Iterable[tuple[str, int]] | None = None,
        negatives: Iterable[tuple[str, int]] | None = None,
        confidence: float = 0.5,
    ) -> "Score":
        s = cls(base_score=int(base), confidence=confidence)
        for reason, pts in (positives or ()):
            s.add_positive(reason, pts)
        for reason, pts in (negatives or ()):
            s.add_negative(reason, pts)
        return s

    # ── serialisation ─────────────────────────────────────────────────────
    def to_dict(self) -> dict:
        return {
            "base_score": int(self.base_score),
            "positive":   [{"reason": r, "points": p} for r, p in self.positive],
            "negative":   [{"reason": r, "points": p} for r, p in self.negative],
            "final":      int(self.final),
            "severity":   self.severity,
            "confidence": float(self.confidence),
        }


# ---------------------------------------------------------------------------
# Conventional modifier libraries
# ---------------------------------------------------------------------------
#
# These are *suggested* point values matching the V2 scoring spec.
# They are not applied automatically — rules opt into them by reason
# string so confidence + correlation can be reasoned about per-rule.
# Kept here as a single source of truth.

POSITIVE_MODIFIERS: dict[str, int] = {
    "same_pid_public_network":          3,
    "suspicious_parent_child":          4,
    "temp_or_dropzone_execution":       3,
    "deleted_binary_still_running":     4,
    "code_injection_malfind":           5,
    "kernel_hook_or_rootkit":           6,
    "persistence_artifact":             4,
    "credential_access_evidence":       5,
    "obfuscated_cmdline":               3,
    "web_server_spawning_shell":        5,
    "browser_or_office_spawning_script":5,
}

NEGATIVE_MODIFIERS: dict[str, int] = {
    "known_benign_browser_https":       4,
    "allowlisted_path_or_process":      5,
    "private_ip_only":                  2,
    "known_updater_or_installer":       3,
    "missing_key_evidence":             2,
    "plugin_output_partial":            2,
}
