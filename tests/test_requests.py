import hashlib
from io import BytesIO
import json
from pathlib import Path
from unittest.mock import Mock

import pytest


@pytest.mark.parametrize("host", ["untrusted.example", "localhost.evil", "127.0.0.1.evil", "evil:5000"])
def test_untrusted_hosts(client, host):
    assert client.get("/api/health", headers={"Host": host}).status_code == 403


@pytest.mark.parametrize("origin", ["https://evil.example", "null", "http://localhost.evil", "https://localhost", "http://localhost:9999"])
def test_untrusted_origins(client, headers, origin):
    assert client.post("/api/agent/reset", headers={**headers, "Origin": origin}).status_code == 403


def test_cross_site_fetch(client):
    assert client.get("/api/settings", headers={"Sec-Fetch-Site": "cross-site"}).status_code == 403


def test_token_protects_mutations(client, headers, monkeypatch):
    from app import agent
    reset = Mock()
    monkeypatch.setattr(agent, "reset_history", reset)
    assert client.post("/api/agent/reset").status_code == 403
    assert client.post("/api/agent/reset", headers={"X-M3MX-Token": "wrong"}).status_code == 403
    reset.assert_not_called()
    assert client.post("/api/agent/reset", headers={**headers, "Origin": "http://localhost"}).status_code == 200
    reset.assert_called_once()


def test_page_and_headers(client, app):
    result = client.get("/")
    assert result.status_code == 200
    assert app.config["M3MX_REQUEST_TOKEN"].encode() in result.data
    assert result.headers["Cache-Control"] == "no-store"
    assert "script-src 'self'" in result.headers["Content-Security-Policy"]
    assert "script-src 'self' 'unsafe-inline'" not in result.headers["Content-Security-Policy"]
    assert "Access-Control-Allow-Origin" not in result.headers
    assert b"onclick=" not in result.data
    assert b"fonts.googleapis.com" not in result.data


@pytest.mark.parametrize("body", [[], [1], None, "settings", 123])
def test_invalid_json_shapes(client, headers, body):
    result = client.post("/api/settings", headers=headers, data=json.dumps(body), content_type="application/json")
    assert result.status_code == 400


def test_json_limit(client, headers):
    result = client.post("/api/settings", headers=headers, json={"oversized": "x" * (1024 * 1024)})
    assert result.status_code == 413


def test_settings_root_cannot_be_expanded(client, headers):
    assert client.post("/api/settings", headers=headers, json={"output": {"directory": "/"}}).status_code == 403
    assert client.post("/api/settings", headers=headers, json={"volatility": {"vol3_path": "/bin/sh"}}).status_code == 403


@pytest.mark.parametrize("settings", [{"ai": {"allow_shell_commands": "false"}},
    {"volatility": {"timeout_seconds": -5}}, {"ai": {"api_keys": []}}, {"features": {"FULL_ANALYSIS_V2": "false"}},
    {"ai": {"provider": []}}, {"output": {"formats": [{}]}}])
def test_settings_types(client, headers, settings):
    assert client.post("/api/settings", headers=headers, json=settings).status_code == 403


def test_upload_unique_hash_and_no_analysis(client, headers, app, workspace, monkeypatch):
    from app import full_analysis, attack_story
    triage, story = Mock(), Mock()
    monkeypatch.setattr(full_analysis, "run_triage", triage)
    monkeypatch.setattr(attack_story, "yield_attack_story", story)
    payload = b"synthetic memory image"
    results = [client.post("/api/upload", headers=headers,
                data={"image": (BytesIO(payload), "memory.raw")}).get_json() for _ in range(2)]
    assert results[0]["path"] != results[1]["path"]
    assert results[0]["sha256"] == hashlib.sha256(payload).hexdigest()
    for result in results:
        path = Path(result["path"])
        assert path.read_bytes() == payload
        assert path.stat().st_mode & 0o222 == 0
        assert json.loads((path.parent / "manifest.json").read_text())["sha256"] == result["sha256"]
    assert app.config["LOADED_IMAGE"] == results[1]["path"]
    triage.assert_not_called()
    story.assert_not_called()


def test_upload_rejects_empty_or_invalid(client, headers):
    for content, filename in ((b"", "memory.raw"), (b"x", "script.py")):
        assert client.post("/api/upload", headers=headers, data={"image": (BytesIO(content), filename)}).status_code == 400


def test_image_path_is_confined(client, headers):
    assert client.post("/api/run-plugin", headers=headers, json={"plugin": "pslist", "image": "/etc/passwd"}).status_code == 403


def test_full_analysis_sse_contract(client, headers, app, image, monkeypatch):
    from app import full_analysis, attack_story
    app.config["LOADED_IMAGE"] = str(image)
    expected = [{"type": "start", "image": str(image), "plugins": ["pslist"]},
                {"type": "plugin_done", "plugin": "pslist", "success": True},
                {"type": "done", "findings": []}]
    monkeypatch.setattr(full_analysis, "run_triage", lambda *a, **kw: iter(expected))
    story = Mock()
    monkeypatch.setattr(attack_story, "yield_attack_story", story)
    result = client.post("/api/full-analysis", headers=headers, json={"skip_story": True}, buffered=True)
    events = [json.loads(line[6:]) for line in result.get_data(as_text=True).splitlines() if line.startswith("data: ")]
    assert events[:-1] == expected
    assert events[-1] == {"type": "all_done", "phase": "triage"}
    story.assert_not_called()
    # A completed stream releases the workload lock.
    assert client.post("/api/triage", headers=headers).status_code != 409


def test_busy_stream_releases_on_disconnect(client, headers, app, image, monkeypatch):
    from app import forensics
    app.config["LOADED_IMAGE"] = str(image)
    monkeypatch.setattr(forensics, "stream_plugin", lambda *a, **kw: iter([
        {"type": "start"}, {"type": "line", "line": "fixture"}]))
    result = client.post("/api/run-plugin/stream", headers=headers, json={"plugin": "pslist"}, buffered=False)
    assert client.post("/api/upload", headers=headers).status_code == 409
    result.close()
    assert client.post("/api/upload", headers=headers).status_code == 400
