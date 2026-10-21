"""
m3mx tool — configuration manager.

Persists public settings and mode-0600 secrets separately in the private
state directory. Environment credentials take priority over stored keys.
"""
from __future__ import annotations

import json
import os
import threading
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
STATE_DIR = Path(os.environ.get("M3MX_STATE_DIR", str(ROOT / ".m3mx"))).expanduser().resolve()
CONFIG_PATH = STATE_DIR / "config.json"
SECRETS_PATH = STATE_DIR / "secrets.json"
OUTPUTS_DIR = Path(os.environ.get("M3MX_OUTPUTS_DIR", str(ROOT / "outputs"))).resolve()
UPLOADS_DIR = Path(os.environ.get("M3MX_UPLOADS_DIR", str(ROOT / "uploads"))).resolve()

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
        "ollama_url": os.environ.get("M3MX_OLLAMA_URL", "http://localhost:11434"),
        "max_tokens": 1000,
        "temperature": 0.2,
        # Only validated, read-only commands with explicit one-use approval.
        "allow_shell_commands": False,
        "allow_network_tools": False,
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
    """Read public settings. Legacy shell access is disabled until re-enabled."""
    with _lock:
        path = CONFIG_PATH if CONFIG_PATH.exists() else ROOT / "config.json"
        try:
            data = json.loads(path.read_text() or "{}") if path.exists() else {}
        except (json.JSONDecodeError, OSError):
            data = {}
        if not isinstance(data, dict):
            data = {}
        cfg = _deep_merge(json.loads(json.dumps(DEFAULT_CONFIG)), data)
        if data.get("security_policy_version") != 1:
            cfg["ai"]["allow_shell_commands"] = False
        cfg["ai"]["api_keys"] = {k: "" for k in DEFAULT_CONFIG["ai"]["api_keys"]}
        if os.environ.get("M3MX_OLLAMA_URL"):
            cfg["ai"]["ollama_url"] = os.environ["M3MX_OLLAMA_URL"]
        return cfg


def save_config(new_config: dict) -> dict:
    """Persist public settings separately from mode-0600 secrets."""
    from .storage import write_json
    with _lock:
        current = load_config()
        merged = _deep_merge(current, new_config)
        keys = dict(_stored_keys())
        for name, value in new_config.get("ai", {}).get("api_keys", {}).items():
            if value and "…" not in value and "*" not in value:
                keys[name] = value
        if keys:
            write_json(SECRETS_PATH, keys)
        merged["ai"]["api_keys"] = {k: "" for k in DEFAULT_CONFIG["ai"]["api_keys"]}
        merged["security_policy_version"] = 1
        write_json(CONFIG_PATH, merged)
        return merged


def _stored_keys() -> dict:
    try:
        if SECRETS_PATH.exists():
            return json.loads(SECRETS_PATH.read_text())
        legacy = ROOT / "config.json"
        if legacy.exists():
            return json.loads(legacy.read_text()).get("ai", {}).get("api_keys", {})
    except (OSError, ValueError, AttributeError):
        pass
    return {}


def migrate_config() -> None:
    """Move legacy settings/keys out of the source tree without deleting data."""
    from .storage import write_json
    with _lock:
        if not CONFIG_PATH.exists():
            save_config({})
        legacy = ROOT / "config.json"
        if legacy.exists():
            data = json.loads(legacy.read_text())
            old = data.get("ai", {}).get("api_keys", {})
            if any(old.values()):
                keys = dict(_stored_keys())
                for k, v in old.items():
                    if v:
                        keys.setdefault(k, v)
                write_json(SECRETS_PATH, keys)
                data["ai"]["api_keys"] = {k: "" for k in old}
                write_json(legacy, data)


def masked_config() -> dict:
    """Return config with API keys masked for safe UI transmission."""
    cfg = load_config()
    keys = cfg.get("ai", {}).get("api_keys", {})
    cfg["ai"]["api_keys"] = {
        name: ("***" if get_api_key(name) else "") for name in keys
    }
    return cfg


def get_api_key(provider: str) -> str:
    aliases = {"abuseipdb": "ABUSEIPDB_KEY", "virustotal": "VT_API_KEY"}
    return (os.environ.get(f"{provider.upper()}_API_KEY", "") or
            os.environ.get(aliases.get(provider, "M3MX_UNUSED_KEY"), "") or
            _stored_keys().get(provider, ""))


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
    from .security import checked_path, PolicyError
    try:
        p = checked_path(requested, ("output",), must_exist=False)
    except PolicyError:
        p = OUTPUTS_DIR
    try:
        p.mkdir(parents=True, exist_ok=True)
        # Probe writability with a short-lived sentinel.
        import tempfile
        with tempfile.TemporaryFile(dir=p):
            pass
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
OUTPUTS_DIR.mkdir(exist_ok=True, parents=True)
UPLOADS_DIR.mkdir(exist_ok=True, parents=True)
