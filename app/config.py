"""
m3mx tool — configuration manager.

Persists settings to config.json in the project root. Settings cover AI
providers, Volatility paths, and output preferences. API keys are stored
locally (never hardcoded) and masked when returned to the UI.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = ROOT / "config.json"
OUTPUTS_DIR = ROOT / "outputs"
UPLOADS_DIR = ROOT / "uploads"

_lock = threading.RLock()

DEFAULT_CONFIG: dict[str, Any] = {
    "ai": {
        "provider": "ollama",          # openai | anthropic | google | ollama | glm | agentrouter
        "model": "",                    # specific model name, e.g. gpt-4o
        "api_keys": {
            "openai": "",
            "anthropic": "",
            "google": "",
            "glm": "",
            "agentrouter": "",          # multi-model proxy (Claude/DeepSeek/GLM)
            "abuseipdb": "",            # threat_intel tool — IP reputation
            "virustotal": "",           # threat_intel tool — file/domain reputation
        },
        "glm_base_url": "https://open.bigmodel.cn/api/paas/v4/",
        "agentrouter_base_url": "https://agentrouter.org/v1",
        "ollama_url": "http://localhost:11434",
        "max_tokens": 1000,
        "temperature": 0.2,
        # Let the agent run shell tools (strings, yara, sleuthkit, …).
        # A denylist in agent.py still rejects clearly destructive ops.
        "allow_shell_commands": True,
        "shell_command_timeout": 300,   # hard cap per invocation (seconds)
        "shell_workdir": "",             # blank → uploads/ directory
    },
    "volatility": {
        "vol2_path": "",                # auto-detected if empty
        "vol3_path": "",
        "preference": "auto",           # v2 | v3 | auto
        "timeout_seconds": 600,
    },
    "output": {
        "directory": str(OUTPUTS_DIR),
        "auto_save": True,
        "formats": ["txt", "json", "csv"],
    },
    "appearance": {
        "theme": "dark",
        "language": "en",               # en | ar
        "font_size": 14,
    },
}


def _deep_merge(base: dict, override: dict) -> dict:
    """Merge override into base, preserving nested keys that are missing."""
    result = dict(base)
    for k, v in override.items():
        if k in result and isinstance(result[k], dict) and isinstance(v, dict):
            result[k] = _deep_merge(result[k], v)
        else:
            result[k] = v
    return result


def load_config() -> dict:
    """Load config.json, filling in defaults for any missing keys."""
    with _lock:
        if not CONFIG_PATH.exists():
            CONFIG_PATH.write_text(json.dumps(DEFAULT_CONFIG, indent=2))
            return json.loads(json.dumps(DEFAULT_CONFIG))
        try:
            data = json.loads(CONFIG_PATH.read_text() or "{}")
        except json.JSONDecodeError:
            data = {}
        return _deep_merge(DEFAULT_CONFIG, data)


def save_config(new_config: dict) -> dict:
    """Merge new_config into the existing file and persist."""
    with _lock:
        current = load_config()
        merged = _deep_merge(current, new_config)
        CONFIG_PATH.write_text(json.dumps(merged, indent=2))
        return merged


def masked_config() -> dict:
    """Return config with API keys masked for safe UI transmission."""
    cfg = load_config()
    keys = cfg.get("ai", {}).get("api_keys", {})
    cfg["ai"]["api_keys"] = {
        name: (f"{v[:4]}…{v[-4:]}" if v and len(v) > 8 else ("***" if v else ""))
        for name, v in keys.items()
    }
    return cfg


def get_api_key(provider: str) -> str:
    cfg = load_config()
    return cfg.get("ai", {}).get("api_keys", {}).get(provider, "") or os.environ.get(
        f"{provider.upper()}_API_KEY", ""
    )


# ---------------------------------------------------------------------------
# Full Analysis feature flags.
#
# Resolution order for each flag:
#   1. Environment variable (truthy = "1" / "true" / "yes" / "on", any case).
#   2. config.json   →   features.<FLAG_NAME>   (boolean).
#   3. Per-flag default (see helpers below).
#
# Phase A migration (Phase 13):
#   * FULL_ANALYSIS_V2 now defaults to **True** — V2 is the primary pipeline.
#   * FULL_ANALYSIS_LEGACY_V1 (new) defaults to False — legacy V1 is opt-in.
#   * FULL_ANALYSIS_OPTIONAL_AI_REPORT stays default False — opt-in.
#
# The dispatcher in app/full_analysis.run_triage runs V2 unless V2 is
# *explicitly* disabled, in which case V1 runs only if the legacy flag
# is explicitly enabled. There is no silent fallback to V1.
# ---------------------------------------------------------------------------

_TRUTHY = {"1", "true", "yes", "on"}
_FALSY  = {"0", "false", "no", "off"}


def feature_flag_enabled(name: str, cfg: dict | None = None,
                         *, default: bool = False) -> bool:
    """
    Return whether feature flag *name* is enabled.

    Env var beats config.json; config.json beats the per-flag *default*.
    """
    env_val = (os.environ.get(name) or "").strip().lower()
    if env_val in _TRUTHY:
        return True
    if env_val in _FALSY:
        return False
    cfg = cfg if cfg is not None else load_config()
    features = (cfg.get("features") or {})
    return bool(features.get(name, default))


def fa2_enabled(cfg: dict | None = None) -> bool:
    """``FULL_ANALYSIS_V2`` — V2 pipeline. **ON by default** (Phase A)."""
    return feature_flag_enabled("FULL_ANALYSIS_V2", cfg, default=True)


def fa2_legacy_v1_enabled(cfg: dict | None = None) -> bool:
    """
    ``FULL_ANALYSIS_LEGACY_V1`` — opt-in to the legacy V1 pipeline.

    Has no effect unless ``FULL_ANALYSIS_V2`` is *explicitly* disabled
    (e.g. ``FULL_ANALYSIS_V2=false``). There is no silent fallback.
    """
    return feature_flag_enabled("FULL_ANALYSIS_LEGACY_V1", cfg, default=False)


def fa2_ai_report_enabled(cfg: dict | None = None) -> bool:
    """``FULL_ANALYSIS_OPTIONAL_AI_REPORT`` — opt-in. OFF by default."""
    return feature_flag_enabled("FULL_ANALYSIS_OPTIONAL_AI_REPORT", cfg,
                                default=False)


_safe_dir_cache: dict[str, str] = {}

def safe_output_dir(cfg: dict | None = None) -> str:
    """
    Return a writable output directory. Tries the value configured in
    config.json; if that path can't be created or written to (permission
    error, missing parent on a read-only mount, typo like /shr/...), falls
    back to the project's bundled `outputs/` dir which is always writable.
    Caches the result so we don't probe the filesystem on every request.
    """
    cfg = cfg or load_config()
    requested = (cfg.get("output", {}) or {}).get("directory") or str(OUTPUTS_DIR)
    cached = _safe_dir_cache.get(requested)
    if cached:
        return cached
    p = Path(requested)
    try:
        p.mkdir(parents=True, exist_ok=True)
        # Probe writability with a short-lived sentinel.
        probe = p / ".m3mx_write_probe"
        probe.write_bytes(b"")
        probe.unlink(missing_ok=True)
        _safe_dir_cache[requested] = str(p)
        return str(p)
    except (PermissionError, FileNotFoundError, OSError):
        OUTPUTS_DIR.mkdir(parents=True, exist_ok=True)
        fallback = str(OUTPUTS_DIR)
        _safe_dir_cache[requested] = fallback
        import logging
        logging.getLogger("m3mx.config").warning(
            "configured output dir %r is not writable — falling back to %s",
            requested, fallback,
        )
        return fallback


def reset_safe_output_cache() -> None:
    """Call after save_config() so re-configured paths take effect."""
    _safe_dir_cache.clear()


# Ensure output directories exist on import
OUTPUTS_DIR.mkdir(exist_ok=True)
UPLOADS_DIR.mkdir(exist_ok=True)
