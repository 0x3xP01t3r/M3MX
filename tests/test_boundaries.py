import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest


def test_file_boundaries_and_symlinks(workspace, tmp_path):
    from app.security import checked_path, PolicyError
    outside = tmp_path / "outside.txt"
    outside.write_text("private")
    link = workspace[0] / "link.txt"
    link.symlink_to(outside)
    for target in (outside, link, workspace[0] / ".." / "outside.txt"):
        with pytest.raises(PolicyError):
            checked_path(target, file=True)
    for name in ("config.json", "secret.key", ".env"):
        target = workspace[1] / name
        target.write_text("private")
        with pytest.raises(PolicyError):
            checked_path(target, file=True)


def test_filesystem_routes(client, headers, workspace):
    assert client.get("/api/fs/browse?path=/").status_code == 403
    assert client.post("/api/fs/mkdir", headers=headers, json={"path": "/outside"}).status_code == 403
    folder = workspace[1] / "case"
    assert client.post("/api/fs/mkdir", headers=headers, json={"path": str(folder)}).status_code == 200
    assert folder.is_dir()
    assert client.get("/api/fs/browse", query_string={"path": str(workspace[1])}).get_json()["parent"] is None


def test_agent_read_and_caps(workspace, image):
    from app import agent
    result = agent.dispatch_tool("read_file", {"path": str(image), "max_bytes": 6}, {})
    assert result["bytes_read"] == 6
    assert result["truncated"]
    assert "error" in agent.dispatch_tool("read_file", {"path": "/etc/passwd"}, {})
    assert "error" in agent.dispatch_tool("unknown", {}, {})


def test_output_viewer_is_bounded(workspace, monkeypatch):
    from app import reports
    path = workspace[1] / "large.txt"
    path.write_bytes(b"x" * 600_000)
    monkeypatch.setattr(Path, "read_bytes", lambda self: (_ for _ in ()).throw(AssertionError("unbounded read")))
    result = reports.read_text(path, 32)
    assert result["text"] == "x" * 32
    assert result["truncated"]


@pytest.mark.parametrize("url", ["http://169.254.169.254", "file:///etc/passwd", "http://localhost:80",
    "http://localhost.evil:11434", "http://user:pass@localhost:11434", "http://localhost:11434/extra",
    "http://localhost:11434?query=x", "http://localhost:11434/#fragment", "http://127.0.0.1:11434/../other"])
def test_ssrf_invalid_urls(workspace, url):
    from app.security import checked_endpoint, PolicyError
    with pytest.raises(PolicyError):
        checked_endpoint(url, "ollama")


def test_ollama_validation_all_entry_points(client, headers, monkeypatch):
    from app import agent
    get = Mock()
    monkeypatch.setattr(agent.requests, "get", get)
    result = client.post("/api/agent/test", headers=headers, json={"provider": "ollama", "ollama_url": "http://169.254.169.254"})
    assert not result.get_json()["ok"]
    assert client.post("/api/settings", headers=headers, json={"ai": {"ollama_url": "http://169.254.169.254"}}).status_code == 403
    get.assert_not_called()


def test_ollama_does_not_follow_redirects(workspace, monkeypatch):
    from app import agent
    response = Mock(status_code=302)
    response.raise_for_status.return_value = None
    get = Mock(return_value=response)
    monkeypatch.setattr(agent.requests, "get", get)
    result = agent.test_connection("ollama", ollama_url="http://127.0.0.1:11434")
    assert not result["ok"]
    assert get.call_args.kwargs["allow_redirects"] is False


def test_dns_loopback_rebinding(workspace, monkeypatch):
    import socket
    from app.security import checked_endpoint, PolicyError
    monkeypatch.setattr(socket, "getaddrinfo", lambda *a, **kw: [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.1", 11434))])
    with pytest.raises(PolicyError):
        checked_endpoint("http://localhost:11434", "ollama")


def test_secrets_separated_and_environment_wins(client, headers, workspace, monkeypatch):
    from app import config
    assert client.post("/api/settings", headers=headers, json={"ai": {"api_keys": {"openai": "fixture-secret-value"}}}).status_code == 200
    assert "fixture-secret-value" not in config.CONFIG_PATH.read_text()
    assert json.loads(config.SECRETS_PATH.read_text())["openai"] == "fixture-secret-value"
    assert config.SECRETS_PATH.stat().st_mode & 0o777 == 0o600
    monkeypatch.setenv("OPENAI_API_KEY", "fixture-env-value")
    assert config.get_api_key("openai") == "fixture-env-value"
    masked = client.get("/api/settings").get_json()
    assert masked["ai"]["api_keys"]["openai"] == "***"
    assert "fixture-env-value" not in str(masked)


def test_legacy_shell_true_is_disabled(workspace):
    from app import config
    config.CONFIG_PATH.write_text(json.dumps({"ai": {"allow_shell_commands": True}}))
    assert config.load_config()["ai"]["allow_shell_commands"] is False


def test_legacy_secret_migration(workspace, monkeypatch, tmp_path):
    from app import config
    legacy = tmp_path / "legacy"
    legacy.mkdir()
    path = legacy / "config.json"
    path.write_text(json.dumps({"ai": {"allow_shell_commands": True,
                                       "api_keys": {"openai": "fixture-legacy-key"}}}))
    monkeypatch.setattr(config, "ROOT", legacy)
    config.migrate_config()
    assert config.get_api_key("openai") == "fixture-legacy-key"
    assert "fixture-legacy-key" not in path.read_text()
    assert "fixture-legacy-key" not in config.CONFIG_PATH.read_text()
    assert config.load_config()["ai"]["allow_shell_commands"] is False


def test_raw_active_content_downloads(client, workspace):
    path = workspace[1] / "payload.html"
    path.write_text('<script>alert("fixture")</script>')
    result = client.get("/api/files/raw", query_string={"path": str(path)})
    assert result.status_code == 200
    assert result.mimetype == "application/octet-stream"
    assert result.headers["Content-Disposition"].startswith("attachment")
