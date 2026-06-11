"""
m3mx tool — Full Analysis V2 scaffolding.

This package contains the next-generation Full Analysis pipeline. It is
strictly opt-in via the ``FULL_ANALYSIS_V2`` feature flag and is **not**
wired into the existing :func:`app.full_analysis.run_triage` path while
the flag is off.

Phase 1 ships foundation primitives only:

* :mod:`app.fa2.models`    — dataclasses for Finding / Artifact / AttackChain / TimelineEvent
* :mod:`app.fa2.baseline`  — allowlist / baseline helpers (loads ``rules/baseline.yaml``)
* :mod:`app.fa2.scoring`   — score → severity bands, with confidence kept independent
* :mod:`app.fa2.utils`     — shared YAML / path helpers

See :file:`app/fa2/CONTRACT.md` for the compatibility contract every
phase must respect.
"""

__all__ = ["models", "baseline", "scoring", "utils"]
