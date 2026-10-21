"""
m3mx tool — Flask application factory.

Phase 1 provides the bootstrap server: health check, config endpoints,
and the root UI route. Later phases register blueprints for:
  - /api/run-plugin, /api/plugins        (Phase 3 / 9)
  - /api/agent/chat                       (Phase 4)
  - /api/extract-files                    (Phase 5)
  - /api/outputs/*                        (Phase 6)
  - /api/settings                         (Phase 7)
"""
from __future__ import annotations

import logging
import shlex
from pathlib import Path

import json as _json
import os
import tempfile
import hashlib
import uuid
from logging.handlers import RotatingFileHandler

import requests
from flask import Flask, Response, jsonify, render_template, request, send_from_directory, stream_with_context
from werkzeug.utils import secure_filename

from . import __appname__, __version__
from .config import (
    load_config, masked_config, save_config,
    safe_output_dir, reset_safe_output_cache,
    OUTPUTS_DIR, UPLOADS_DIR, migrate_config,
)
from .security import (install_request_security, validate_settings, checked_path,
                       checked_endpoint, bounded_read, PolicyError)
from .storage import write_json
from . import forensics, plugins as plugin_registry, agent as agent_mod, file_extractor, reports
from . import full_analysis, attack_story

ROOT = Path(__file__).resolve().parent.parent

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
)
log = logging.getLogger("m3mx")

# Bounded application log with three rotated backups.
_log_path = OUTPUTS_DIR / "m3mx.log"
_log_path.parent.mkdir(exist_ok=True, parents=True)
try:
    _fh = RotatingFileHandler(_log_path, maxBytes=5 * 1024**2, backupCount=3, encoding="utf-8")
except OSError:
    # Old bind mounts may contain a log owned by another UID. Keep startup
    # usable and report diagnostics to stderr without changing its ownership.
    _fh = logging.StreamHandler()
_fh.setFormatter(logging.Formatter(
    "%(asctime)s [%(levelname)s] %(name)s: %(message)s"))
# Attach to the m3mx.* hierarchy only (not to root, to keep console clean)
logging.getLogger("m3mx").addHandler(_fh)


def create_app(volatility_paths: dict | None = None) -> Flask:
    app = Flask(
        __name__,
        static_folder=str(ROOT / "static"),
        template_folder=str(ROOT / "templates"),
    )
    # Don't let the browser cache static JS/CSS — hot-reload on every refresh.
    app.config["SEND_FILE_MAX_AGE_DEFAULT"] = 0
    migrate_config()

    # Store runtime state on the app
    app.config["VOLATILITY_PATHS"] = volatility_paths or {"vol2": None, "vol3": None}
    app.config["APP_NAME"] = __appname__
    app.config["APP_VERSION"] = __version__
    app.config["UPLOADS_DIR"] = str(UPLOADS_DIR)
    app.config["OUTPUTS_DIR"] = str(OUTPUTS_DIR)
    install_request_security(app)
    from .routes.filesystem import filesystem
    app.register_blueprint(filesystem)

    # Werkzeug's multipart parser spills to tempfile when the part exceeds 500 KB.
    # The default tempdir on many systems is /tmp (often a small tmpfs). Redirect
    # to uploads/ which lives on the real filesystem so multi-GB uploads succeed.
    UPLOADS_DIR.mkdir(parents=True, exist_ok=True)
    tempfile.tempdir = str(UPLOADS_DIR)
    os.environ["TMPDIR"] = str(UPLOADS_DIR)

    # ------------------------------------------------------------------
    # Core routes
    # ------------------------------------------------------------------

    @app.route("/")
    def index():
        return render_template(
            "index.html",
            app_name=__appname__,
            version=__version__,
            request_token=app.config["M3MX_REQUEST_TOKEN"],
        )

    @app.route("/api/health")
    def health():
        return jsonify({
            "status": "ok",
            "app": __appname__,
            "version": __version__,
            "volatility": app.config["VOLATILITY_PATHS"],
        })

    @app.route("/api/settings", methods=["GET"])
    def get_settings():
        return jsonify(masked_config())

    @app.route("/api/settings", methods=["POST"])
    def update_settings():
        body = request.get_json(silent=True) or {}
        validate_settings(body)
        # Filter out masked/placeholder API keys so "••••" doesn't overwrite real values
        keys = body.get("ai", {}).get("api_keys", {})
        body.setdefault("ai", {})["api_keys"] = {
            k: v for k, v in keys.items() if v and "…" not in v and "*" not in v
        }
        merged = save_config(body)
        # Output dir might have changed — invalidate the writability cache so
        # the next request re-probes (and silently falls back if needed).
        reset_safe_output_cache()
        return jsonify(masked_config())

    @app.route("/favicon.ico")
    def favicon():
        return send_from_directory(app.static_folder, "assets/favicon.svg")

    # ------------------------------------------------------------------
    # File upload
    # ------------------------------------------------------------------

    ALLOWED_EXT = {".mem", ".raw", ".dmp", ".vmem", ".bin", ".lime", ".img"}

    def _human_size(n: int) -> str:
        for unit in ("B", "KB", "MB", "GB", "TB"):
            if n < 1024: return f"{n:.1f}{unit}"
            n /= 1024
        return f"{n:.1f}PB"

    @app.route("/api/upload", methods=["POST"])
    def upload_image():
        # Pre-flight disk-space check. Werkzeug's multipart parser spills
        # to a tempfile whose path is `tempfile.tempdir` (we redirect to
        # UPLOADS_DIR above). If the disk is near-full, fail fast with a
        # readable message instead of a generic 500.
        try:
            import shutil as _shutil
            free = _shutil.disk_usage(str(UPLOADS_DIR)).free
        except Exception:
            free = None
        # Want ≥ 1 GB free as a baseline + a hint about user-declared size.
        declared = int(request.headers.get("Content-Length") or 0)
        need = max(declared * 2, 1024 * 1024 * 1024)   # roughly 2× content + 1 GB floor
        if free is not None and free < need:
            return jsonify({
                "error": (f"insufficient disk space at {UPLOADS_DIR}: "
                          f"{free // (1024*1024)} MB free, ~{need // (1024*1024)} MB required"),
                "free_bytes":     free,
                "required_bytes": need,
            }), 507  # 507 Insufficient Storage

        f = request.files.get("image")
        if not f or not f.filename:
            return jsonify({"error": "no file"}), 400
        fname = secure_filename(f.filename)
        ext = Path(fname).suffix.lower()
        if ext not in ALLOWED_EXT:
            return jsonify({"error": f"unsupported extension {ext}"}), 400
        evidence_id = uuid.uuid4().hex
        evidence_dir = checked_path(UPLOADS_DIR / evidence_id, ("evidence",), must_exist=False)
        evidence_dir.mkdir(mode=0o700)
        dest = evidence_dir / fname
        digest = hashlib.sha256()

        # Stream to disk in 16 MB chunks so 10 GB+ images don't buffer in RAM.
        CHUNK = 16 * 1024 * 1024
        size = 0
        try:
            with open(dest, "xb") as out:
                while True:
                    buf = f.stream.read(CHUNK)
                    if not buf:
                        break
                    out.write(buf)
                    digest.update(buf)
                    size += len(buf)
            if not size:
                dest.unlink()
                evidence_dir.rmdir()
                return jsonify(error="empty memory image"), 400
            dest.chmod(0o400)
            write_json(evidence_dir / "manifest.json", {
                "evidence_id": evidence_id, "filename": fname,
                "size": size, "sha256": digest.hexdigest(),
            })
        except OSError as e:
            # Best-effort cleanup of the partial file so we don't leak space.
            try:
                if dest.exists(): dest.unlink()
            except Exception:
                pass
            errno_no = getattr(e, "errno", None)
            if errno_no == 28:    # ENOSPC
                return jsonify({"error": "disk full while writing — free space and retry"}), 507
            return jsonify({"error": f"disk write failed: {e}"}), 500

        app.config["LOADED_IMAGE"] = str(dest)
        log.info("Image uploaded: %s (%.2f GB)", dest, size / 1024 / 1024 / 1024)
        return jsonify({"filename": fname, "path": str(dest), "size": size,
                        "size_human": _human_size(size), "evidence_id": evidence_id,
                        "sha256": digest.hexdigest()})

    # ------------------------------------------------------------------
    # Ollama model discovery
    # ------------------------------------------------------------------

    @app.route("/api/ollama/models")
    def ollama_models():
        cfg = load_config()
        try:
            url = checked_endpoint(cfg.get("ai", {}).get("ollama_url", "http://localhost:11434"), "ollama")
            r = requests.get(f"{url}/api/tags", timeout=1.5, allow_redirects=False)
            if 300 <= r.status_code < 400:
                raise PolicyError("AI service redirects are not allowed")
            r.raise_for_status()
            data = r.json()
            names = [m.get("name") for m in data.get("models", []) if m.get("name")]
            return jsonify({"models": names, "url": url})
        except Exception as e:
            return jsonify({"models": [], "error": str(e)}), 200

    # ------------------------------------------------------------------
    # Plugin registry & execution
    # ------------------------------------------------------------------

    @app.route("/api/plugins")
    def list_plugins():
        reg = plugin_registry.load_registry()
        vol_paths = app.config.get("VOLATILITY_PATHS", {})
        # Annotate availability per plugin
        for cat in reg.get("categories", []):
            for p in cat.get("plugins", []):
                p["available"] = bool(
                    (p.get("vol3") and vol_paths.get("vol3")) or
                    (p.get("vol2") and vol_paths.get("vol2"))
                )
                p["versions"] = [v for v in ("v2", "v3")
                                 if (v == "v2" and p.get("vol2")) or (v == "v3" and p.get("vol3"))]
        return jsonify(reg)

    @app.route("/api/run-plugin", methods=["POST"])
    def run_plugin_route():
        body = request.get_json(silent=True) or {}
        plugin = body.get("plugin")
        version = body.get("version", "auto")
        if not plugin:
            return jsonify({"error": "plugin required"}), 400

        image = body.get("image") or app.config.get("LOADED_IMAGE")
        if not image:
            return jsonify({"error": "no memory image loaded"}), 400
        if not Path(image).exists():
            return jsonify({"error": f"image not found: {image}"}), 400

        cfg = load_config()
        timeout = int(cfg.get("volatility", {}).get("timeout_seconds", 600))
        vol_paths = app.config.get("VOLATILITY_PATHS", {})

        raw_extra = (body.get("extra_params") or "").strip()
        try:
            extra_args = shlex.split(raw_extra) if raw_extra else None
        except ValueError:
            return jsonify({"error": f"invalid extra_params: {raw_extra!r}"}), 400

        result = forensics.run_plugin(
            image, plugin, version=version,
            timeout=timeout, vol_paths=vol_paths,
            extra_args=extra_args,
        )

        # Persist output if auto-save enabled
        if result.success and cfg.get("output", {}).get("auto_save", True):
            out_dir = Path(safe_output_dir(cfg))
            out_dir.mkdir(parents=True, exist_ok=True)
            fmts = cfg.get("output", {}).get("formats", ["txt"])
            from .evidence import evidence_key
            run_id = uuid.uuid4().hex
            stem = f"{evidence_key(image)}_{run_id}_{plugin}_{result.version}"
            if "txt" in fmts:
                (out_dir / f"{stem}.txt").write_text(result.output)
            if "csv" in fmts and result.format == "csv":
                (out_dir / f"{stem}.csv").write_text(result.output)
            if "json" in fmts:
                import json as _json
                write_json(out_dir / f"{stem}.json", {**result.to_dict(), "image_path": image,
                    "evidence_key": evidence_key(image), "run_id": run_id})

        return jsonify(result.to_dict())

    # ------------------------------------------------------------------
    # AI agent chat
    # ------------------------------------------------------------------

    @app.route("/api/agent/chat", methods=["POST"])
    def agent_chat():
        body = request.get_json(silent=True) or {}
        message = (body.get("message") or "").strip()
        if not message:
            return jsonify({"error": "message required"}), 400

        ctx = agent_mod.current_context(app.config)
        synthesis = body.get("mode") == "synthesis"
        history = [] if synthesis else agent_mod.load_history()

        def sse():
            try:
                for evt in agent_mod.stream_chat(message, ctx, history,
                        allow_tools=not synthesis, persist_history=not synthesis):
                    yield f"data: {_json.dumps(evt)}\n\n"
            except Exception as e:
                log.exception("agent stream crashed")
                yield f"data: {_json.dumps({'type': 'error', 'message': str(e)})}\n\n"

        return Response(stream_with_context(sse()),
                        mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache",
                                 "X-Accel-Buffering": "no"})

    @app.route("/api/agent/history", methods=["GET"])
    def agent_history():
        return jsonify({"history": agent_mod.load_history()})

    @app.route("/api/agent/test", methods=["POST"])
    def agent_test():
        body = request.get_json(silent=True) or {}
        cfg = load_config()
        provider   = body.get("provider") or cfg.get("ai", {}).get("provider")
        model      = body.get("model")    or cfg.get("ai", {}).get("model", "")
        api_key    = body.get("api_key", "")  # if empty, falls back to stored key
        ollama_url = body.get("ollama_url") or cfg.get("ai", {}).get("ollama_url",
                                                                     "http://localhost:11434")
        return jsonify(agent_mod.test_connection(provider, model, api_key, ollama_url))

    @app.route("/api/agent/reset", methods=["POST"])
    def agent_reset():
        agent_mod.reset_history()
        return jsonify({"ok": True})

    @app.route("/api/agent/approve", methods=["POST"])
    def approve_agent_command():
        from .command_policy import approve_command
        body = request.get_json(silent=True) or {}
        if body.get("approve") is not True:
            return jsonify(error="explicit approval is required"), 400
        approval_id = body.get("approval_id")
        if not isinstance(approval_id, str) or len(approval_id) > 100:
            return jsonify(error="invalid approval identifier"), 400
        result = approve_command(approval_id, app.config.get("LOADED_IMAGE"))
        agent_mod._security_event("APPROVE", result["command"], "one-use browser approval")
        return jsonify(result)

    # ------------------------------------------------------------------
    # File extractor
    # ------------------------------------------------------------------

    @app.route("/api/files/scan", methods=["POST"])
    def files_scan():
        image = app.config.get("LOADED_IMAGE")
        if not image:
            return jsonify({"error": "no memory image loaded"}), 400
        cfg = load_config()
        timeout = int(cfg.get("volatility", {}).get("timeout_seconds", 600))
        data = file_extractor.scan_for_files(
            image, app.config.get("VOLATILITY_PATHS", {}), timeout=timeout,
        )
        return jsonify(data)

    @app.route("/api/files/preview", methods=["POST"])
    def files_preview():
        image = app.config.get("LOADED_IMAGE")
        if not image:
            return jsonify({"error": "no memory image loaded"}), 400
        body = request.get_json(silent=True) or {}
        offset = (body.get("offset") or "").strip()
        if not offset:
            return jsonify({"error": "offset required"}), 400
        cfg = load_config()
        out_dir = safe_output_dir(cfg)
        timeout = int(cfg.get("volatility", {}).get("timeout_seconds", 600))
        data = file_extractor.preview_offset(
            image, offset, out_dir,
            app.config.get("VOLATILITY_PATHS", {}), timeout=timeout,
        )
        return jsonify(data)

    @app.route("/api/files/extract", methods=["POST"])
    def files_extract():
        image = app.config.get("LOADED_IMAGE")
        if not image:
            return jsonify({"error": "no memory image loaded"}), 400
        body = request.get_json(silent=True) or {}
        offsets = body.get("offsets") or []
        if not isinstance(offsets, list) or not offsets:
            return jsonify({"error": "offsets list required"}), 400
        if len(offsets) > 100:
            return jsonify({"error": "max 100 offsets per batch"}), 400

        cfg = load_config()
        out_dir = safe_output_dir(cfg)
        timeout = int(cfg.get("volatility", {}).get("timeout_seconds", 600))
        data = file_extractor.extract_files(
            image, offsets, out_dir,
            app.config.get("VOLATILITY_PATHS", {}), timeout=timeout,
        )
        return jsonify(data)

    @app.route("/api/files/raw")
    def files_raw():
        """Stream a previously-extracted file by its absolute path. The path
        MUST live inside the configured output directory — no traversal."""
        from flask import abort, send_file
        import mimetypes as _mt
        raw = (request.args.get("path") or "").strip()
        if not raw:
            return jsonify({"error": "path required"}), 400
        try:
            target = checked_path(raw, ("output",), file=True)
        except Exception as e:
            return jsonify({"error": f"bad path: {e}"}), 400
        cfg = load_config()
        out_root = Path(safe_output_dir(cfg)).resolve()
        try:
            target.relative_to(out_root)
        except ValueError:
            abort(403)
        if not target.exists() or not target.is_file():
            return jsonify({"error": "not found"}), 404
        mt = file_extractor._sniff_mime(bounded_read(target, 64), "")
        safe_image = mt in {"image/png", "image/jpeg", "image/gif", "image/webp", "image/bmp", "image/x-icon"}
        return send_file(str(target), mimetype=mt if safe_image else "application/octet-stream",
                         as_attachment=not safe_image, conditional=True)

    # ------------------------------------------------------------------
    # Results viewer & report generator
    # ------------------------------------------------------------------

    @app.route("/api/outputs")
    def outputs_list():
        cfg = load_config()
        out_dir = safe_output_dir(cfg)
        return jsonify({"categories": reports.list_outputs(out_dir),
                        "output_dir": out_dir})

    @app.route("/api/outputs/view")
    def outputs_view():
        name = request.args.get("name", "")
        cfg = load_config()
        out_dir = safe_output_dir(cfg)
        p = reports.resolve_output_path(name, out_dir)
        if not p:
            return jsonify({"error": "not found or path not allowed"}), 404
        return jsonify({"name": p.name, **reports.read_text(p)})

    @app.route("/api/outputs/download")
    def outputs_download():
        name = request.args.get("name", "")
        cfg = load_config()
        out_dir = safe_output_dir(cfg)
        p = reports.resolve_output_path(name, out_dir)
        if not p:
            return jsonify({"error": "not found"}), 404
        return send_from_directory(p.parent, p.name, as_attachment=True)

    @app.route("/api/outputs/delete", methods=["POST"])
    def outputs_delete():
        body = request.get_json(silent=True) or {}
        name = body.get("name", "")
        cfg = load_config()
        out_dir = safe_output_dir(cfg)
        p = reports.resolve_output_path(name, out_dir)
        if not p:
            return jsonify({"error": "not found or path not allowed"}), 404
        try:
            p.unlink()
            return jsonify({"ok": True})
        except Exception as e:
            return jsonify({"error": str(e)}), 500

    @app.route("/api/reports/generate", methods=["POST"])
    def reports_generate():
        image = app.config.get("LOADED_IMAGE")
        result = reports.generate_report(image_path=image)
        return jsonify(result)

    # ------------------------------------------------------------------
    # Global status + streaming plugin execution
    # ------------------------------------------------------------------

    import threading as _t
    app.config["_STATUS"] = {"state": "idle", "message": "", "updated": None}
    app.config["_STATUS_LOCK"] = _t.Lock()

    def _set_status(state_: str, message: str = "") -> None:
        import datetime as _dt
        with app.config["_STATUS_LOCK"]:
            app.config["_STATUS"] = {
                "state": state_, "message": message,
                "updated": _dt.datetime.now(_dt.timezone.utc).isoformat(),
            }

    @app.route("/api/status")
    def status():
        # Surface feature-flag state to the frontend so the V2 UI can
        # gate the AI Report button and pick the right placeholder
        # copy. Resolution honours env vars + config.json.
        from .config import (
            fa2_enabled, fa2_ai_report_enabled, fa2_legacy_v1_enabled,
        )
        return jsonify({
            **app.config["_STATUS"],
            "loaded_image": app.config.get("LOADED_IMAGE"),
            "volatility":   app.config.get("VOLATILITY_PATHS"),
            "features": {
                "full_analysis_v2":                  fa2_enabled(),
                "full_analysis_legacy_v1":           fa2_legacy_v1_enabled(),
                "full_analysis_optional_ai_report":  fa2_ai_report_enabled(),
            },
        })

    @app.route("/api/run-plugin/stream", methods=["POST"])
    def run_plugin_stream():
        body = request.get_json(silent=True) or {}
        plugin = body.get("plugin")
        version = body.get("version", "auto")
        image = app.config.get("LOADED_IMAGE")
        if not plugin:
            return jsonify({"error": "plugin required"}), 400
        if not image or not Path(image).exists():
            return jsonify({"error": "no memory image loaded"}), 400

        cfg = load_config()
        timeout = int(cfg.get("volatility", {}).get("timeout_seconds", 600))
        vol_paths = app.config.get("VOLATILITY_PATHS", {})

        def sse():
            _set_status("running", f"plugin: {plugin}")
            try:
                for evt in forensics.stream_plugin(
                    image, plugin, version=version,
                    timeout=timeout, vol_paths=vol_paths,
                ):
                    yield f"data: {_json.dumps(evt)}\n\n"
                    if evt.get("type") == "done":
                        _set_status("idle", f"{plugin} done in {evt.get('elapsed')}s")
                    elif evt.get("type") == "error":
                        _set_status("err", f"{plugin}: {evt.get('message')}")
            except Exception as e:                              # pragma: no cover
                log.exception("stream_plugin crashed")
                yield f"data: {_json.dumps({'type':'error','message':str(e)})}\n\n"
                _set_status("err", str(e))

        return Response(stream_with_context(sse()),
                        mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache",
                                 "X-Accel-Buffering": "no"})

    # ------------------------------------------------------------------
    # Quick Triage
    # ------------------------------------------------------------------

    @app.route("/api/triage", methods=["POST"])
    def quick_triage():
        image = app.config.get("LOADED_IMAGE")
        if not image or not Path(image).exists():
            return jsonify({"error": "no memory image loaded"}), 400
        cfg = load_config()
        timeout = int(cfg.get("volatility", {}).get("timeout_seconds", 600))

        body = request.get_json(silent=True) or {}
        plugin_list = body.get("plugins")  # optional override

        _set_status("running", "quick triage")
        try:
            result = forensics.quick_triage(
                image, app.config.get("VOLATILITY_PATHS", {}),
                timeout=timeout, plugin_names=plugin_list,
            )
        finally:
            _set_status("idle", f"triage {result.get('successful',0)}/{result.get('total',0)}"
                                if 'result' in dir() else "triage done")

        # Auto-save individual outputs
        out_dir = Path(safe_output_dir(cfg))
        out_dir.mkdir(parents=True, exist_ok=True)
        for name, r in result.get("results", {}).items():
            if r.get("success"):
                from .evidence import evidence_key
                run_id = uuid.uuid4().hex
                stem = f"{evidence_key(image)}_{run_id}_{name}_{r.get('version','auto')}"
                write_json(out_dir / f"{stem}.json", {**r, "image_path": image,
                    "evidence_key": evidence_key(image), "run_id": run_id})
                if r.get("output"):
                    (out_dir / f"{stem}.txt").write_text(r["output"])

        # Don't ship the full results back to the client (can be large);
        # the summary + per-plugin status is enough for the UI.
        return jsonify({k: v for k, v in result.items() if k != "results"})

    @app.route("/api/loaded-image")
    def loaded_image():
        img = app.config.get("LOADED_IMAGE")
        return jsonify({
            "path": img,
            "profile": forensics.cached_profile(img) if img else None,
        })

    # ------------------------------------------------------------------
    # Full Analysis — rule-engine triage + AI attack story (SSE)
    # ------------------------------------------------------------------
    @app.route("/api/full-analysis", methods=["POST"])
    def full_analysis_route():
        body = request.get_json(silent=True) or {}
        image = body.get("image") or app.config.get("LOADED_IMAGE")
        if not image:
            return jsonify({"error": "no memory image loaded"}), 400
        if not Path(image).exists():
            return jsonify({"error": f"image not found: {image}"}), 400

        cfg = load_config()
        timeout = int(cfg.get("volatility", {}).get("timeout_seconds", 600))
        vol_paths = app.config.get("VOLATILITY_PATHS", {})
        plugin_override = body.get("plugins")
        skip_story = bool(body.get("skip_story"))

        def sse():
            findings_buf: list[dict] = []
            _set_status("running", "full analysis: triage")
            try:
                for evt in full_analysis.run_triage(
                    image, vol_paths=vol_paths, timeout=timeout,
                    plugin_names=plugin_override,
                ):
                    et = evt.get("type")
                    if et == "finding":
                        findings_buf.append(evt["finding"])
                    elif et == "done":
                        findings_buf = evt.get("findings", findings_buf)
                    yield f"data: {_json.dumps(evt)}\n\n"
                    if et == "error":
                        _set_status("err", evt.get("message", "triage error"))
                        return
            except Exception as e:
                log.exception("full_analysis triage crashed")
                yield f"data: {_json.dumps({'type':'error','message':str(e)})}\n\n"
                _set_status("err", str(e))
                return

            if skip_story:
                yield f"data: {_json.dumps({'type':'all_done','phase':'triage'})}\n\n"
                _set_status("idle", "full analysis (triage only) done")
                return

            # Attack Story phase
            _set_status("running", "full analysis: attack story")
            yield f"data: {_json.dumps({'type':'story_start','findings_count':len(findings_buf)})}\n\n"
            story_buf: list[str] = []
            try:
                for evt in attack_story.yield_attack_story(findings_buf, image):
                    if evt.get("type") == "story_token":
                        story_buf.append(evt["content"])
                    yield f"data: {_json.dumps(evt)}\n\n"
                    if evt.get("type") == "error":
                        _set_status("err", evt.get("message", "story error"))
                        return
            except Exception as e:
                log.exception("attack story stream crashed")
                yield f"data: {_json.dumps({'type':'error','message':str(e)})}\n\n"
                _set_status("err", str(e))
                return

            # Persist the markdown alongside findings.jsonl.
            try:
                case = full_analysis._case_dir(image)
                md = case / "attack_story.md"
                text = "".join(story_buf).strip()
                md.write_text(
                    f"# Attack Story\n\n_Generated by m3mx Full Analysis · "
                    f"{len(findings_buf)} findings_\n\n{text}\n",
                    encoding="utf-8",
                )
                yield f"data: {_json.dumps({'type':'story_saved','path':str(md)})}\n\n"
            except Exception as e:
                log.warning("failed to save attack_story.md: %s", e)

            yield f"data: {_json.dumps({'type':'all_done','phase':'story'})}\n\n"
            _set_status("idle", "full analysis done")

        return Response(stream_with_context(sse()),
                        mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache",
                                 "X-Accel-Buffering": "no"})

    @app.route("/api/full-analysis/case")
    def full_analysis_case():
        image = request.args.get("image") or app.config.get("LOADED_IMAGE")
        if not image:
            return jsonify({"error": "no image loaded"}), 400
        findings = full_analysis.load_findings(image)
        case = full_analysis._case_dir(image)
        md_path = case / "attack_story.md"
        return jsonify({
            "findings":      findings,
            "story_md":      md_path.read_text(encoding="utf-8") if md_path.exists() else "",
            "case_dir":      str(case),
            "findings_path": str(case / "findings.jsonl"),
        })

    # ------------------------------------------------------------------
    # Optional AI Report (Phase 9 — gated by FULL_ANALYSIS_OPTIONAL_AI_REPORT)
    # ------------------------------------------------------------------
    # This endpoint is the SOLE entry point for the optional AI Report.
    # It NEVER runs automatically — it must be explicitly invoked. It
    # reads only the existing case outputs (findings.jsonl + optional
    # mitre/correlations/timeline/limitations) and never re-runs
    # Volatility. The output filename is ``ai_report.md``, distinct from
    # the lightweight ``attack_story.md`` produced by the Full Analysis
    # SSE route.
    @app.route("/api/full-analysis/ai-report", methods=["POST"])
    def full_analysis_ai_report():
        # Gate everything on the feature flag — local import keeps the
        # V2 stack cold when the flag is off.
        from .config import fa2_ai_report_enabled
        if not fa2_ai_report_enabled():
            return jsonify({
                "error":    "AI Report is disabled.",
                "reason":   "FULL_ANALYSIS_OPTIONAL_AI_REPORT is OFF",
                "hint":     ("Set FULL_ANALYSIS_OPTIONAL_AI_REPORT=true in env "
                             "or features.FULL_ANALYSIS_OPTIONAL_AI_REPORT=true "
                             "in config.json to enable."),
                "enabled":  False,
            }), 403

        body = request.get_json(silent=True) or {}
        image = body.get("image") or app.config.get("LOADED_IMAGE")
        if not image:
            return jsonify({"error": "no memory image loaded"}), 400
        if not Path(image).exists():
            return jsonify({"error": f"image not found: {image}"}), 400

        # Pre-flight: findings.jsonl must exist (Full Analysis must have run).
        case = full_analysis._case_dir(image)
        findings_path = case / "findings.jsonl"
        if not findings_path.exists():
            return jsonify({
                "error":         "Run Full Analysis first before generating an AI Report.",
                "case_dir":      str(case),
                "findings_path": str(findings_path),
                "missing":       "findings.jsonl",
            }), 412   # Precondition Failed

        def sse():
            # Lazy V2 import — keeps the route module-level surface
            # clean and ensures we never load the V2 stack unless the
            # operator explicitly invoked the endpoint.
            from .fa2.ai_report import yield_ai_report
            _set_status("running", "ai report")
            try:
                for evt in yield_ai_report(image, case):
                    yield f"data: {_json.dumps(evt)}\n\n"
                    if evt.get("type") == "ai_report_error":
                        _set_status("err", evt.get("message", "ai report error"))
                        return
                _set_status("idle", "ai report done")
            except Exception as e:
                log.exception("ai-report stream crashed")
                err = {"type": "ai_report_error", "message": str(e)}
                yield f"data: {_json.dumps(err)}\n\n"
                _set_status("err", str(e))

        return Response(stream_with_context(sse()),
                        mimetype="text/event-stream",
                        headers={"Cache-Control": "no-cache",
                                 "X-Accel-Buffering": "no"})

    # ------------------------------------------------------------------
    # Deterministic PDF export (report.md → report.html → report.pdf)
    # ------------------------------------------------------------------
    # Purely file-on-disk: reads the already-written report.md, re-renders
    # the HTML and PDF. Never re-runs Volatility. Never invokes the LLM /
    # AI Report stack. Returns the absolute paths plus output-relative
    # names suitable for /api/outputs/download?name=…
    @app.route("/api/full-analysis/export-pdf", methods=["POST"])
    def full_analysis_export_pdf():
        body = request.get_json(silent=True) or {}
        image = body.get("image") or app.config.get("LOADED_IMAGE")
        if not image:
            return jsonify({"error": "no memory image loaded"}), 400
        if not Path(image).exists():
            return jsonify({"error": f"image not found: {image}"}), 400

        case = full_analysis._case_dir(image)
        md_path = case / "report.md"
        if not md_path.exists():
            return jsonify({
                "error":    "Run Full Analysis first before exporting a PDF.",
                "case_dir": str(case),
                "missing":  "report.md",
            }), 412

        try:
            from .fa2.report import export_pdf_from_case
            result = export_pdf_from_case(case)
        except Exception as e:                                    # pragma: no cover
            log.exception("export-pdf failed")
            return jsonify({"error": str(e)}), 500

        # Output-relative names so the frontend can route them through
        # the existing safe /api/outputs/download endpoint.
        def _rel(abs_path: str) -> str | None:
            if not abs_path:
                return None
            try:
                from .config import safe_output_dir
                root = Path(safe_output_dir()).resolve()
                return str(Path(abs_path).resolve().relative_to(root))
            except (ValueError, OSError):
                return None

        payload = {
            "md_path":    result.md_path,
            "html_path":  result.html_path,
            "pdf_path":   result.pdf_path,
            "pdf_error":  result.pdf_error,
            "md_rel":     _rel(result.md_path),
            "html_rel":   _rel(result.html_path),
            "pdf_rel":    _rel(result.pdf_path),
            "case_dir":   str(case),
        }
        if not result.pdf_path:
            # PDF backend unavailable — return the partial payload with a
            # 503 so the frontend can surface a clean error.
            return jsonify(payload), 503
        return jsonify(payload)

    # ------------------------------------------------------------------
    log.info("%s v%s ready. Volatility: %s", __appname__, __version__, app.config["VOLATILITY_PATHS"])
    return app
