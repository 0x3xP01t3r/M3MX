"""Application-enforced boundaries for the single-analyst workbench.

Trust roots and network destinations come from the launch environment, never
from model arguments or browser settings. All paths are resolved before use.
"""
from __future__ import annotations

import hmac
import ipaddress
import json
import math
import os
from pathlib import Path
import re
import secrets
import socket
import threading
from urllib.parse import urlsplit

from flask import jsonify, request

ROOT = Path(__file__).resolve().parent.parent


class PolicyError(ValueError):
    """An operation exceeded the operator's configured trust boundary."""


def roots(kind: str) -> tuple[Path, ...]:
    from .config import OUTPUTS_DIR, UPLOADS_DIR
    defaults = {"evidence": UPLOADS_DIR, "output": OUTPUTS_DIR,
                "rules": ROOT / "rules"}
    extra = os.environ.get(f"M3MX_{kind.upper()}_ROOTS", "")
    return (defaults[kind].resolve(), *(Path(p).expanduser().resolve()
             for p in extra.split(os.pathsep) if p))


def checked_path(value: str | Path, kinds=("evidence", "output", "rules"),
                 *, must_exist: bool = True, file: bool = False) -> Path:
    if not isinstance(value, (str, Path)) or not str(value).strip():
        raise PolicyError("a nonempty path is required")
    target = Path(value).expanduser().resolve()
    if not any(target == base or base in target.parents
               for kind in kinds for base in roots(kind)):
        raise PolicyError("path is outside approved directories")
    # Secrets and internal state are never evidence, even under an approved root.
    if any(p.startswith(".") or p.lower() in {"config.json", "secrets.json"}
           or p.lower().endswith((".key", ".pem"))
           for p in target.relative_to(next(base for kind in kinds for base in roots(kind)
                                           if target == base or base in target.parents)).parts):
        raise PolicyError("private files cannot be accessed through forensic tools")
    if must_exist and not target.exists():
        raise PolicyError("path does not exist")
    if file and not target.is_file():
        raise PolicyError("a regular file is required")
    return target


def bounded_read(path: Path, limit: int = 500_000, offset: int = 0) -> bytes:
    limit = max(1, min(int(limit), 512 * 1024))
    # Do not follow a last-component symlink swapped in after validation.
    fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        stream.seek(max(0, int(offset)))
        return stream.read(limit)


def _endpoint(value: str) -> tuple[str, str, int, str]:
    try:
        u = urlsplit(value)
        if (u.scheme not in {"http", "https"} or not u.hostname or
                u.username or u.password or u.query or u.fragment or
                any(c in value for c in ("\\", "\r", "\n", "\t"))):
            raise ValueError
        port = u.port or (443 if u.scheme == "https" else 80)
        path = u.path.rstrip("/")
        if any(p in {".", ".."} for p in path.split("/")) or "%" in path:
            raise ValueError
        return u.scheme, u.hostname.lower(), port, path
    except (ValueError, TypeError):
        raise PolicyError("invalid AI service URL") from None


def checked_endpoint(value: str, provider: str) -> str:
    defaults = {
        "ollama": ["http://localhost:11434", "http://127.0.0.1:11434", "http://[::1]:11434"],
        "glm": ["https://open.bigmodel.cn/api/paas/v4"],
        "agentrouter": ["https://agentrouter.org/v1"],
    }
    approved = defaults.get(provider, []) + [p.strip() for p in
        os.environ.get(f"M3MX_{provider.upper()}_ENDPOINTS", "").split(",") if p.strip()]
    endpoint = _endpoint(value)
    if endpoint not in {_endpoint(p) for p in approved}:
        raise PolicyError("AI endpoint is not approved in the launch environment")
    # Loopback aliases may not resolve to another host. Other destinations are
    # explicitly operator-trusted; never permit link-local/cloud metadata IPs.
    host = endpoint[1]
    try:
        addresses = {ipaddress.ip_address(a[4][0]) for a in
                     socket.getaddrinfo(host, endpoint[2], type=socket.SOCK_STREAM)}
    except OSError:
        raise PolicyError("AI endpoint cannot be resolved") from None
    if not addresses or any(a.is_link_local or a.is_unspecified or a.is_multicast
                            for a in addresses):
        raise PolicyError("AI endpoint resolves to a prohibited address")
    if host in {"localhost", "127.0.0.1", "::1"} and not all(a.is_loopback for a in addresses):
        raise PolicyError("loopback endpoint resolved outside loopback")
    if host in {"open.bigmodel.cn", "agentrouter.org"} and not all(a.is_global for a in addresses):
        raise PolicyError("public AI provider resolved to a private address")
    return value.rstrip("/")


def validate_settings(body: dict) -> None:
    if not isinstance(body, dict):
        raise PolicyError("settings must be an object")
    allowed = {"ai", "volatility", "output", "appearance", "features"}
    if set(body) - allowed or any(not isinstance(v, dict) for v in body.values()):
        raise PolicyError("unknown settings section or invalid settings object")
    ai = body.get("ai", {})
    from .config import DEFAULT_CONFIG
    for section, values in body.items():
        known = set(DEFAULT_CONFIG.get(section, {})) if section != "features" else {
            "FULL_ANALYSIS_V2", "FULL_ANALYSIS_LEGACY_V1", "FULL_ANALYSIS_OPTIONAL_AI_REPORT"}
        if set(values) - known:
            raise PolicyError(f"unknown option in {section}")
    if "provider" in ai and (not isinstance(ai["provider"], str) or ai["provider"] not in {
            "ollama", "openai", "anthropic", "google", "glm", "agentrouter"}):
        raise PolicyError("unknown AI provider")
    for key in ("model", "shell_workdir"):
        if key in ai and (not isinstance(ai[key], str) or len(ai[key]) > 4096):
            raise PolicyError(f"{key} must be a bounded string")
    if "temperature" in ai and (type(ai["temperature"]) not in {int, float} or
            not math.isfinite(ai["temperature"]) or not 0 <= ai["temperature"] <= 2):
        raise PolicyError("temperature must be between 0 and 2")
    for key, provider in (("ollama_url", "ollama"), ("glm_base_url", "glm"),
                          ("agentrouter_base_url", "agentrouter")):
        if key in ai:
            checked_endpoint(ai[key], provider)
    for key in ("allow_shell_commands", "allow_network_tools"):
        if key in ai and type(ai[key]) is not bool:
            raise PolicyError(f"{key} must be a boolean")
    for section, key, low, high in (("ai", "max_tokens", 1, 32768),
            ("ai", "shell_command_timeout", 1, 300),
            ("volatility", "timeout_seconds", 1, 3600)):
        if key in body.get(section, {}):
            v = body[section][key]
            if type(v) is not int or not low <= v <= high:
                raise PolicyError(f"{key} must be an integer between {low} and {high}")
    if "api_keys" in ai and (not isinstance(ai["api_keys"], dict) or
            any(not isinstance(k, str) or not isinstance(v, str) or len(v) > 4096
                for k, v in ai["api_keys"].items())):
        raise PolicyError("API keys must be bounded strings")
    if ai.get("shell_workdir"):
        checked_path(ai["shell_workdir"], ("evidence", "output"))
    if "directory" in body.get("output", {}):
        checked_path(body["output"]["directory"], ("output",), must_exist=False)
    output = body.get("output", {})
    if "auto_save" in output and type(output["auto_save"]) is not bool:
        raise PolicyError("auto_save must be a boolean")
    if "formats" in output and (not isinstance(output["formats"], list) or
            any(not isinstance(v, str) or v not in {"txt", "json", "csv"} for v in output["formats"])):
        raise PolicyError("unknown output format")
    # Executable selection is a launch-time operation, not a browser capability.
    from .config import load_config
    current = load_config()
    for key in ("vol2_path", "vol3_path"):
        if key in body.get("volatility", {}) and body["volatility"][key] != current["volatility"].get(key, ""):
            raise PolicyError("set Volatility executable paths in the launch environment")
    for v in body.get("features", {}).values():
        if type(v) is not bool:
            raise PolicyError("feature flags must be booleans")


def install_request_security(app) -> None:
    """Protect browser requests and bound concurrent forensic workloads."""
    token = secrets.token_urlsafe(32)
    app.config["M3MX_REQUEST_TOKEN"] = token
    app.config["MAX_CONTENT_LENGTH"] = int(os.environ.get("M3MX_MAX_UPLOAD_BYTES", 64 * 1024**3))
    app.config["MAX_FORM_MEMORY_SIZE"] = 512 * 1024
    app.config["MAX_FORM_PARTS"] = 8
    hosts = {"localhost", "127.0.0.1", "::1"} | {
        h.strip().lower() for h in os.environ.get("M3MX_TRUSTED_HOSTS", "").split(",") if h.strip()}
    workload = threading.Lock()
    heavy = {"/api/upload", "/api/run-plugin", "/api/run-plugin/stream",
             "/api/full-analysis", "/api/triage", "/api/agent/chat",
             "/api/files/scan", "/api/files/extract", "/api/files/preview",
             "/api/reports/generate", "/api/full-analysis/ai-report",
             "/api/full-analysis/export-pdf", "/api/agent/approve", "/api/agent/reset",
             "/api/outputs/delete"}

    @app.before_request
    def enforce_request_policy():
        try:
            host = urlsplit(request.host_url).hostname
            if host not in hosts:
                raise PolicyError("untrusted Host header")
            origin = request.headers.get("Origin")
            if origin and origin != request.host_url.rstrip("/"):
                raise PolicyError("cross-origin requests are not allowed")
            if request.path.startswith("/api/") and request.headers.get("Sec-Fetch-Site") == "cross-site":
                raise PolicyError("cross-site requests are not allowed")
            if request.method not in {"GET", "HEAD", "OPTIONS"}:
                supplied = request.headers.get("X-M3MX-Token", "")
                if not hmac.compare_digest(supplied.encode("utf-8"), token.encode("utf-8")):
                    raise PolicyError("missing or invalid request token; reload the page")
            if request.is_json:
                if request.content_length is None or request.content_length > 1024 * 1024:
                    return jsonify(error="JSON request exceeds 1 MiB"), 413
                body = request.get_json(silent=True)
                if not isinstance(body, dict):
                    return jsonify(error="JSON body must be an object"), 400
            else:
                body = {}
            image = body.get("image") or request.args.get("image")
            if image:
                checked_path(image, ("evidence",), file=True)
            if "plugins" in body:
                plugins = body["plugins"]
                if not isinstance(plugins, list) or not 1 <= len(plugins) <= 200 or any(
                        not isinstance(p, str) or not re.fullmatch(r"[A-Za-z_][\w.]{0,150}", p) for p in plugins):
                    raise PolicyError("invalid plugin list")
            if "plugin" in body and (not isinstance(body["plugin"], str) or
                    not re.fullmatch(r"[A-Za-z_][\w.]{0,150}", body["plugin"])):
                raise PolicyError("invalid plugin name")
            for key in ("message", "offset", "extra_params", "version", "provider", "model", "api_key", "ollama_url", "name", "mode"):
                if key in body and (not isinstance(body[key], str) or len(body[key]) > 65536):
                    raise PolicyError(f"{key} must be a bounded string")
            if "offsets" in body and (not isinstance(body["offsets"], list) or len(body["offsets"]) > 100 or any(
                    not isinstance(v, str) or not re.fullmatch(r"0x[0-9a-fA-F]{1,16}", v) for v in body["offsets"])):
                raise PolicyError("invalid extraction offsets")
            if request.path in heavy or (request.path == "/api/settings" and request.method == "POST"):
                if not workload.acquire(blocking=False):
                    return jsonify(error="another forensic task is running; wait for it to finish"), 409
                request.environ["m3mx.workload_acquired"] = True
        except (PolicyError, OSError, ValueError) as exc:
            return jsonify(error=str(exc)), 403

    @app.after_request
    def secure_response(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Content-Security-Policy"] = (
            "default-src 'none'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
            "font-src 'self'; img-src 'self' data: blob:; connect-src 'self'; "
            "base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'")
        if request.path == "/" or request.path.startswith("/api/"):
            response.headers["Cache-Control"] = "no-store"
        if request.environ.get("m3mx.workload_acquired", False):
            released = False
            def release():
                nonlocal released
                if not released:
                    released = True
                    workload.release()
            if response.is_streamed:
                original = response.response
                def stream():
                    try:
                        yield from original
                    finally:
                        if hasattr(original, "close"):
                            original.close()
                        release()
                response.response = stream()
                response.call_on_close(release)
            else:
                release()
        return response

    @app.errorhandler(PolicyError)
    def policy_error(exc):
        return jsonify(error=str(exc)), 403

    @app.errorhandler(413)
    def upload_too_large(exc):
        return jsonify(error="request exceeds the configured size limit"), 413

    from subprocess import TimeoutExpired

    @app.errorhandler(TimeoutExpired)
    def process_timed_out(exc):
        return jsonify(error="operation exceeded its configured time limit"), 504
