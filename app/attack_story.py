"""
m3mx tool — Attack Story generator.

Reads findings.jsonl produced by full_analysis.run_triage(), pipes a
compact summary into the configured LLM, and returns a step-by-step
narrative organised along ATT&CK tactics.

Streaming is supported (yield_attack_story) so the SSE route can stream
tokens straight to the browser.
"""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any, Generator

from . import agent as _agent
from . import full_analysis
from .config import load_config

log = logging.getLogger("m3mx.attack_story")

SYSTEM_PROMPT = """\
You are a senior digital forensics and incident response (DFIR) analyst.

You will receive a JSON list of FINDINGS produced by automated memory
triage (Volatility 3 + a small rule engine). Each finding includes:
  id, plugin, severity, title, description, evidence (raw row), tags
  (MITRE ATT&CK ids), confidence.

Your task: construct a cohesive ATTACK STORY explaining the most
likely chain of events on this host. Use this exact structure with
Markdown headers:

### 1. Initial Access
### 2. Execution
### 3. Persistence
### 4. Defense Evasion
### 5. Discovery / Lateral Movement / Exfiltration
### 6. Indicators of Compromise

Rules:
- Cite finding ids inline like "(F-007)".
- Map each step to an ATT&CK technique id when supported by evidence.
- If evidence is thin or missing for a tactic, write "No evidence in
  the current findings" rather than inventing details.
- Keep it tight: 2–6 sentences per section is plenty.
- The IOC section should be a flat bullet list of concrete artifacts
  (PIDs, file paths, hashes, IPs, domains).
"""

_MAX_FINDING_CHARS = 18000   # cap the prompt so we don't blow the token budget


def _trim_findings_for_prompt(findings: list[dict]) -> str:
    """Compact JSON of findings, truncated if it exceeds the budget."""
    full = json.dumps(findings, ensure_ascii=False, indent=2)
    if len(full) <= _MAX_FINDING_CHARS:
        return full
    slim = []
    for f in findings:
        slim.append({
            "id":       f.get("id"),
            "plugin":   f.get("plugin"),
            "severity": f.get("severity"),
            "title":    f.get("title"),
            "tags":     f.get("tags", []),
            "evidence_summary": ", ".join(
                f"{k}={str(v)[:80]}" for k, v in (f.get("evidence") or {}).items()
            )[:300],
        })
    compact = json.dumps(slim, ensure_ascii=False, indent=2)
    if len(compact) > _MAX_FINDING_CHARS:
        compact = compact[:_MAX_FINDING_CHARS] + "\n…[findings truncated]"
    return compact


def _build_messages(findings: list[dict], image_path: str | None) -> list[dict]:
    body = _trim_findings_for_prompt(findings)
    intro = (
        f"Memory image: {image_path or '(unknown)'}\n"
        f"Total findings: {len(findings)}\n\n"
        f"FINDINGS:\n```json\n{body}\n```\n"
    )
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user",   "content": intro},
    ]


def yield_attack_story(findings: list[dict],
                       image_path: str | None = None) -> Generator[dict, None, None]:
    """
    Streams the LLM response. Yields:
        {"type": "story_token", "content": str}
        {"type": "story_done",  "model": str, "usage": {...}, "text": str}
        {"type": "error",       "message": str}
    """
    if not findings:
        yield {"type": "story_done", "model": "(none)", "usage": {}, "text":
               "_No findings were produced — nothing to narrate._"}
        return

    cfg = load_config()
    provider = cfg.get("ai", {}).get("provider", "ollama").lower()
    model    = cfg.get("ai", {}).get("model") or ""
    fn = _agent.PROVIDER_STREAM.get(provider)
    if not fn:
        yield {"type": "error", "message": f"Unknown LLM provider: {provider}"}
        return

    messages = _build_messages(findings, image_path)
    collected: list[str] = []
    last_model = model
    last_usage: dict[str, Any] = {"input": 0, "output": 0}

    try:
        for evt in fn(messages, model, cfg):
            t = evt.get("type")
            if t == "token":
                collected.append(evt["content"])
                yield {"type": "story_token", "content": evt["content"]}
            elif t == "done":
                last_model = evt.get("model", last_model)
                last_usage = evt.get("usage", last_usage)
            elif t == "error":
                yield {"type": "error", "message": evt.get("message", "LLM error")}
                return
    except Exception as e:                                # pragma: no cover
        log.exception("attack story stream crashed")
        yield {"type": "error", "message": f"{type(e).__name__}: {e}"}
        return

    text = "".join(collected).strip()
    yield {"type": "story_done", "model": last_model, "usage": last_usage, "text": text}


def generate_attack_story(image_path: str | Path | None = None,
                          findings: list[dict] | None = None) -> dict:
    """
    Synchronous variant — runs the LLM end-to-end and returns the story
    plus the path it was saved to.
    """
    if findings is None:
        if not image_path:
            return {"ok": False, "error": "image_path or findings required"}
        findings = full_analysis.load_findings(image_path)

    text_parts: list[str] = []
    model = ""
    err: str | None = None
    for evt in yield_attack_story(findings, str(image_path) if image_path else None):
        if evt["type"] == "story_token":
            text_parts.append(evt["content"])
        elif evt["type"] == "story_done":
            model = evt.get("model", "")
        elif evt["type"] == "error":
            err = evt.get("message")

    text = "".join(text_parts).strip()
    if err and not text:
        return {"ok": False, "error": err}

    saved = None
    if image_path:
        case = full_analysis._case_dir(image_path)
        saved = case / "attack_story.md"
        saved.write_text(
            f"# Attack Story\n\n"
            f"_Generated by_ `{model or 'unknown model'}` · "
            f"{len(findings)} findings\n\n{text}\n",
            encoding="utf-8",
        )

    return {"ok": True, "text": text, "model": model,
            "saved_to": str(saved) if saved else None,
            "warning": err}
