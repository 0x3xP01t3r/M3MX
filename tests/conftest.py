"""Tests use temporary evidence, outputs and secrets, never analyst data."""
import os
from pathlib import Path
import tempfile

import pytest

_session = tempfile.TemporaryDirectory(prefix="m3mx-tests-")
for name, suffix in (("M3MX_STATE_DIR", "state"), ("M3MX_UPLOADS_DIR", "uploads"),
                     ("M3MX_OUTPUTS_DIR", "outputs")):
    os.environ[name] = str(Path(_session.name) / suffix)


@pytest.fixture
def workspace(tmp_path, monkeypatch):
    from app import config, agent, main, command_policy
    uploads, outputs, state = (tmp_path / name for name in ("uploads", "outputs", "state"))
    for path in (uploads, outputs, state):
        path.mkdir()
    for module in (config, main):
        monkeypatch.setattr(module, "UPLOADS_DIR", uploads)
        monkeypatch.setattr(module, "OUTPUTS_DIR", outputs)
    monkeypatch.setattr(config, "STATE_DIR", state)
    monkeypatch.setattr(config, "CONFIG_PATH", state / "config.json")
    monkeypatch.setattr(config, "SECRETS_PATH", state / "secrets.json")
    monkeypatch.setitem(config.DEFAULT_CONFIG["output"], "directory", str(outputs))
    monkeypatch.setattr(agent, "HISTORY_FILE", state / "chat_history.json")
    monkeypatch.setattr(agent, "SECURITY_LOG", outputs / "agent_security.log")
    monkeypatch.setattr(command_policy, "UPLOADS_DIR", uploads)
    for key in ("M3MX_OUTPUT_ROOTS", "M3MX_EVIDENCE_ROOTS", "M3MX_RULES_ROOTS",
                "M3MX_OLLAMA_ENDPOINTS", "M3MX_OLLAMA_URL", "FULL_ANALYSIS_V2",
                "FULL_ANALYSIS_LEGACY_V1", "FULL_ANALYSIS_OPTIONAL_AI_REPORT",
                "OPENAI_API_KEY", "ANTHROPIC_API_KEY", "GOOGLE_API_KEY", "GLM_API_KEY",
                "AGENTROUTER_API_KEY", "ABUSEIPDB_API_KEY", "VIRUSTOTAL_API_KEY",
                "ABUSEIPDB_KEY", "VT_API_KEY"):
        monkeypatch.delenv(key, raising=False)
    config.reset_safe_output_cache()
    command_policy._pending.clear()
    return uploads, outputs, state


@pytest.fixture
def app(workspace):
    from app.main import create_app
    application = create_app({"vol2": None, "vol3": None})
    application.config["TESTING"] = True
    return application


@pytest.fixture
def client(app):
    return app.test_client()


@pytest.fixture
def headers(app):
    return {"X-M3MX-Token": app.config["M3MX_REQUEST_TOKEN"]}


@pytest.fixture
def image(workspace):
    path = workspace[0] / "memory.raw"
    path.write_bytes(b"benign synthetic memory fixture\x00" * 8)
    return path
