"""
m3mx tool — Full Analysis V2 shared utilities.

Phase 1 keeps this intentionally tiny:

* :func:`load_yaml_safe` — load a YAML file, returning an empty dict and
  logging a warning if the file is missing or malformed, instead of
  crashing the pipeline.
* :func:`project_root` — returns the repository root path (one level up
  from the ``app/`` package).

No business logic lives here. Anything that grows beyond a single helper
should move to its own module.
"""
from __future__ import annotations

import logging
from pathlib import Path
from typing import Any

import yaml

log = logging.getLogger("m3mx.fa2.utils")

# Repository root: <repo>/app/fa2/utils.py  →  parents[2] is <repo>
PROJECT_ROOT: Path = Path(__file__).resolve().parents[2]


def project_root() -> Path:
    """Return the repository root, regardless of cwd."""
    return PROJECT_ROOT


def load_yaml_safe(path: str | Path) -> dict[str, Any]:
    """
    Load a YAML file and return its top-level mapping. On any failure
    (missing file, parse error, non-mapping root) log a warning and
    return ``{}`` — callers must never crash on a bad config file.

    Returning an empty dict is intentional so downstream code can treat
    "no baseline" identically to "baseline with no entries".
    """
    p = Path(path)
    if not p.exists():
        log.warning("YAML file not found: %s — using empty defaults", p)
        return {}
    try:
        with p.open("r", encoding="utf-8") as fh:
            data = yaml.safe_load(fh)
    except yaml.YAMLError as e:
        log.warning("YAML parse error in %s: %s — using empty defaults", p, e)
        return {}
    except OSError as e:
        log.warning("could not read %s: %s — using empty defaults", p, e)
        return {}
    if data is None:
        return {}
    if not isinstance(data, dict):
        log.warning("YAML root in %s is not a mapping (got %s) — using empty defaults",
                    p, type(data).__name__)
        return {}
    return data
