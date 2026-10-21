import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest


def test_cases_have_unique_runs_and_manifests(workspace, image):
    from app.evidence import begin_run, case_directory
    first = begin_run(image)
    (first / "findings.jsonl").write_text("fixture")
    second = begin_run(image)
    assert first != second
    assert case_directory(image) == second
    assert (first / "findings.jsonl").read_text() == "fixture"
    assert json.loads((second / "manifest.json").read_text())["image"] == str(image)


def test_same_basename_does_not_mix_cases(workspace, image):
    from app.evidence import begin_run
    other = workspace[0] / "other" / image.name
    other.parent.mkdir()
    other.write_bytes(b"other")
    assert begin_run(image).parent != begin_run(other).parent


def test_cache_invalidated_when_image_changes(workspace, image, monkeypatch):
    from app import forensics
    calls = []
    def run(*args, **kwargs):
        calls.append(args)
        return SimpleNamespace(returncode=0, stdout="PID,Name\n1,fixture\n", stderr="")
    monkeypatch.setattr(forensics, "run_command", run)
    forensics._cache.clear()
    paths = {"vol3": "/fixture/vol", "vol2": None}
    assert forensics.run_plugin(image, "pslist", vol_paths=paths).success
    assert forensics.run_plugin(image, "pslist", vol_paths=paths).success
    assert len(calls) == 1
    image.write_bytes(b"replacement content")
    assert forensics.run_plugin(image, "pslist", vol_paths=paths).success
    assert len(calls) == 2


@pytest.mark.parametrize("args", [["--output-dir=/etc"], ["--plugin-dirs=/tmp"], ["--pid=1;id"],
    ["--yara-file=/etc/passwd"], ["--dump"], ["--pid"]])
def test_plugin_options_are_confined(workspace, args):
    from app.forensics import validate_extra_args
    from app.security import PolicyError
    with pytest.raises(PolicyError):
        validate_extra_args(args)


def test_subprocess_bounds_and_timeout(workspace):
    from app.processes import run_command
    result = run_command([sys.executable, "-c", "print('x'*200000)"], max_bytes=1000)
    assert result.returncode != 0
    assert len(result.stdout) <= 1000
    with pytest.raises(subprocess.TimeoutExpired):
        run_command([sys.executable, "-c", "import time; time.sleep(5)"], timeout=0.1)


def test_child_environment_excludes_credentials(workspace, monkeypatch):
    from app.processes import child_environment
    monkeypatch.setenv("OPENAI_API_KEY", "fixture")
    monkeypatch.setenv("VT_API_KEY", "fixture")
    monkeypatch.setenv("APP_SECRET", "fixture")
    assert not {"OPENAI_API_KEY", "VT_API_KEY", "APP_SECRET"} & child_environment().keys()


@pytest.mark.parametrize("score,severity", [(0,"info"),(2,"info"),(3,"low"),(5,"low"),
    (6,"medium"),(9,"medium"),(10,"high"),(14,"high"),(15,"critical")])
def test_severity_boundaries(score, severity):
    from app.fa2.scoring import score_to_severity
    assert score_to_severity(score) == severity


@pytest.mark.parametrize("plugin,columns,row,os", [
    ("windows.pslist", ["PID","PPID","ImageFileName"], ["42","1","fixture.exe"], "windows"),
    ("linux.pslist", ["PID","PPID","COMM"], ["42","1","fixture"], "linux"),
    ("mac.pslist", ["PID","PPID","Name"], ["42","1","fixture"], "mac")])
def test_normalizers(plugin, columns, row, os):
    from app.fa2.normalizers import normalize
    artifacts = normalize(plugin, columns, [row])
    assert artifacts[0].os == os
    assert artifacts[0].fields["pid"] == 42
    assert artifacts[0].raw
    assert normalize(plugin, columns, []) == []
    assert normalize(plugin, columns, [["bad"]])  # malformed rows degrade safely


def test_rules_positive_negative_and_schema():
    from app.fa2.rule_engine import load_rules, apply_rules
    from app.fa2.models import Artifact
    rules, warnings = load_rules()
    assert rules
    assert not any("rejected" in warning for warning in warnings)
    rule = next(r for r in rules if r.id == "win.powershell_encoded")
    positive = Artifact(type="process", os="windows", source_plugin="windows.cmdline",
        fields={"pid": 42, "cmdline": "powershell.exe -EncodedCommand ZQBjAGgAbwA="})
    negative = Artifact(type="process", os="windows", fields={"cmdline": "notepad.exe"})
    findings = apply_rules([positive], [rule])
    assert len(findings) == 1
    assert not apply_rules([negative], [rule])
    assert {"id","plugin","severity","title","description","evidence","tags","confidence"} <= findings[0].to_dict().keys()
    assert findings[0].severity != "critical"


def test_pdf_html_and_resource_sanitization():
    from app.fa2.report import markdown_to_html
    from app.pdf_renderer import deny_resource_fetch
    html = markdown_to_html('<script>alert(1)</script>\n\n<img src="file:///etc/passwd">\n\n[x](javascript:alert(1))')
    assert "<script>" not in html
    assert "<img" not in html
    assert "javascript:" not in html
    for url in ("file:///etc/passwd", "https://example.com", "data:text/html,fixture"):
        with pytest.raises(ValueError):
            deny_resource_fetch(url)


def test_pdf_export_real_renderer(workspace):
    from app.pdf_renderer import render_pdf
    path = workspace[1] / "fixture.pdf"
    render_pdf("<html><body><h1>Synthetic forensic report</h1></body></html>", path)
    with path.open("rb") as stream:
        assert stream.read(5) == b"%PDF-"


def test_feature_defaults(workspace):
    from app.config import fa2_enabled, fa2_legacy_v1_enabled, fa2_ai_report_enabled
    assert fa2_enabled()
    assert not fa2_legacy_v1_enabled()
    assert not fa2_ai_report_enabled()


def test_reports_do_not_mix_evidence(workspace, image):
    from app.reports import _gather_summary
    from app.evidence import evidence_key
    root = workspace[1]
    current = {"plugin": "pslist", "success": True, "evidence_key": evidence_key(image), "output": "correct"}
    foreign = {**current, "evidence_key": "different", "output": "wrong"}
    (root / "current_pslist_v3.json").write_text(json.dumps(current))
    (root / "foreign_pslist_v3.json").write_text(json.dumps(foreign))
    plugins, summary = _gather_summary(root, image_path=str(image))
    assert plugins == ["pslist"]
    assert summary["pslist"]["preview"] == "correct"


def test_full_pipeline_synthetic_outputs_and_repeat_runs(workspace, image, monkeypatch):
    from app import full_analysis
    from app.fa2 import volatility_runner as runner
    def fake_run(cmd, timeout):
        if "-h" in cmd:
            return runner._CompletedProcess(stdout="    windows.pslist.PsList     Process list\n")
        if cmd[-1] == "windows.info":
            return runner._CompletedProcess(stdout="Variable,Value\nKernel,NT Kernel 10.0 x64\n")
        return runner._CompletedProcess(stdout="PID,PPID,ImageFileName,CreateTime\n42,1,fixture.exe,2026-01-01 00:00:00+00:00\n")
    monkeypatch.setattr(runner, "_run_subprocess", fake_run)
    paths = {"vol3": "/fixture/vol", "vol2": None}
    first = list(full_analysis.run_triage(image, vol_paths=paths, plugin_names=["windows.pslist"]))
    done = next(event for event in first if event["type"] == "done")
    case = Path(done["case_dir"])
    assert not [event for event in first if event["type"] == "error"]
    for filename in ("manifest.json", "findings.jsonl", "normalized_artifacts.jsonl", "timeline.json",
                     "mitre_summary.json", "correlations.json", "report.md", "report.html"):
        assert (case / filename).exists(), filename
    second = list(full_analysis.run_triage(image, vol_paths=paths, plugin_names=["windows.pslist"]))
    assert next(event for event in second if event["type"] == "done")["case_dir"] != str(case)
    assert (case / "report.md").exists()
