"""
m3mx tool — results viewer + AI report generator.

Categorization
==============
Outputs under the configured output directory are grouped into 4 buckets:

    plugins  → <image>_<plugin>_v[23].(txt|csv|json)
    files    → anything inside outputs/extracted/
    reports  → report_*.md / report_*.pdf / report_*.docx

Report generator
================
summarize_findings() collects recent plugin JSON outputs, feeds a
compact summary to the configured LLM (via the regular agent pipeline,
with streaming disabled here), and writes:

    outputs/report_<timestamp>.md
    outputs/report_<timestamp>.pdf    (reportlab)
    outputs/report_<timestamp>.docx   (python-docx)
"""
from __future__ import annotations

import datetime
import json
import logging
import re
from pathlib import Path
from typing import Iterable

from . import agent as agent_mod
from .config import OUTPUTS_DIR, load_config, safe_output_dir
from .security import checked_path, bounded_read, PolicyError

log = logging.getLogger("m3mx.reports")

CATEGORIES = ("plugins", "files", "chats", "reports")


# ---------------------------------------------------------------------------
# Output listing
# ---------------------------------------------------------------------------

def _plugin_match(name: str) -> bool:
    # name like: imageName_pslist_v3.json
    return bool(re.search(r"_(v2|v3)\.(txt|csv|json)$", name))

def _report_match(name: str) -> bool:
    return name.startswith("report_") and name.endswith((".md", ".pdf", ".docx"))

def _chat_match(name: str) -> bool:
    return name in ("chat_history.json", "agent_security.log")


def list_outputs(out_dir: Path | str | None = None) -> dict:
    root = checked_path(out_dir or OUTPUTS_DIR, ("output",))
    if not root.exists():
        return {c: [] for c in CATEGORIES}

    buckets: dict[str, list] = {c: [] for c in CATEGORIES}

    for p in root.iterdir():
        if p.is_file() and not p.is_symlink() and not p.name.startswith("."):
            meta = _meta(p)
            if _report_match(p.name):
                buckets["reports"].append(meta)
            elif _chat_match(p.name):
                buckets["chats"].append(meta)
            elif _plugin_match(p.name):
                buckets["plugins"].append(meta)
            else:
                buckets["plugins"].append(meta)  # any other file defaults to plugins

    # Extracted files
    extracted = root / "extracted"
    if extracted.exists() and not extracted.is_symlink():
        for p in sorted(extracted.rglob("*")):
            if p.is_file() and not p.is_symlink() and not any(part.startswith(".") for part in p.relative_to(root).parts):
                try:
                    checked_path(p, ("output",), file=True)
                except PolicyError:
                    continue
                meta = _meta(p)
                meta["relpath"] = str(p.relative_to(root))
                buckets["files"].append(meta)

    for c in buckets:
        buckets[c].sort(key=lambda m: m.get("mtime", 0), reverse=True)
    return buckets


def _meta(p: Path) -> dict:
    st = p.stat()
    return {
        "name":  p.name,
        "size":  st.st_size,
        "mtime": st.st_mtime,
        "modified": datetime.datetime.fromtimestamp(st.st_mtime).isoformat(timespec="seconds"),
        "ext":   p.suffix.lstrip(".").lower(),
    }


# ---------------------------------------------------------------------------
# Viewer-safe file read
# ---------------------------------------------------------------------------

def resolve_output_path(name: str, out_dir: Path | str | None = None) -> Path | None:
    """Resolve a name (possibly 'extracted/foo') safely inside out_dir."""
    try:
        root = checked_path(out_dir or OUTPUTS_DIR, ("output",))
        cand = checked_path(root / name, ("output",), file=True)
        cand.relative_to(root)
    except (ValueError, OSError):
        return None
    return cand if cand.exists() and cand.is_file() else None


def read_text(p: Path, max_bytes: int = 500_000) -> dict:
    max_bytes = max(1, min(int(max_bytes), 512 * 1024))
    data = bounded_read(p, max_bytes)
    binary = _looks_binary(data)
    if binary:
        return {"binary": True, "hex": _hex_preview(data, 4096),
                "truncated": p.stat().st_size > max_bytes}
    return {"binary": False, "text": data.decode("utf-8", errors="replace"),
            "truncated": p.stat().st_size > max_bytes}


def _looks_binary(data: bytes) -> bool:
    sample = data[:4096]
    if not sample: return False
    # non-text byte ratio
    textchars = bytes({7, 8, 9, 10, 12, 13, 27} | set(range(0x20, 0x100)) - {0x7f})
    nontext = sample.translate(None, textchars)
    return len(nontext) / len(sample) > 0.3


def _hex_preview(data: bytes, limit: int = 4096) -> str:
    buf = data[:limit]
    lines = []
    for i in range(0, len(buf), 16):
        chunk = buf[i:i+16]
        hexpart = " ".join(f"{b:02x}" for b in chunk).ljust(48)
        asciipart = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
        lines.append(f"{i:08x}  {hexpart}  {asciipart}")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# AI report generator
# ---------------------------------------------------------------------------

REPORT_PROMPT = """\
You are writing a memory forensics report. Below is a compact summary of
plugin outputs from a Volatility investigation. Produce a thorough
investigator-ready report in Markdown. The report MUST have these sections
in this order, using ## headings:

## Executive Summary
## Timeline
## Processes
## Network
## Files & Persistence
## Suspicious Artifacts
## Recommendations

Rules:
- Cite specific processes, PIDs, IPs, file paths when you have them.
- If data is missing for a section, say so — do not fabricate.
- Be concise but complete; use bullet lists for findings.
- Conclude with clear next-step recommendations for the investigator.
- Do NOT include backticks around the whole report.

Context:
- Image: {image_path}
- OS profile: {os_profile}
- Plugins run: {plugins_run}

Summary (top rows per plugin):
{summary_json}
"""


def _gather_summary(out_dir: Path, max_plugins: int = 15, rows_per_plugin: int = 10,
                    image_path: str | None = None) -> tuple[list[str], dict]:
    """Collect plugin JSON outputs and condense them."""
    plugins_run = []
    summary = {}

    jsons = sorted(out_dir.glob("*_v[23].json"), key=lambda p: p.stat().st_mtime, reverse=True)
    for p in jsons:
        if len(plugins_run) >= max_plugins:
            break
        try:
            d = json.loads(p.read_text())
        except Exception:
            continue
        if image_path:
            from .evidence import evidence_key
            if d.get("evidence_key") != evidence_key(image_path):
                continue
        plugin = d.get("plugin") or p.stem
        if plugin in summary:
            continue
        plugins_run.append(plugin)

        entry = {
            "success": d.get("success"),
            "elapsed": d.get("elapsed"),
            "version": d.get("version"),
        }
        if d.get("columns") and d.get("rows"):
            entry["columns"] = d["columns"]
            entry["rows"] = d["rows"][:rows_per_plugin]
            entry["total_rows"] = len(d["rows"])
        else:
            out = d.get("output") or d.get("error") or ""
            entry["preview"] = out[:1500]
        summary[plugin] = entry

    return plugins_run, summary


def generate_report(image_path: str | None = None, provider: str | None = None) -> dict:
    """
    Create a markdown report (plus PDF + DOCX copies) based on current outputs.

    Returns:
        {"markdown": "...", "files": {"md": path, "pdf": path, "docx": path}}
    """
    cfg = load_config()
    out_dir = Path(safe_output_dir(cfg))
    out_dir.mkdir(parents=True, exist_ok=True)

    plugins_run, summary = _gather_summary(out_dir, image_path=image_path)
    if not plugins_run:
        return {"error": "No plugin JSON outputs found. Run some plugins first."}

    # Trim to a reasonable token budget
    summary_json = json.dumps(summary, indent=2, default=str)
    if len(summary_json) > 40_000:
        summary_json = summary_json[:40_000] + "\n…[truncated]"

    prompt = REPORT_PROMPT.format(
        image_path = image_path or "(unknown)",
        os_profile = "(auto-detected)",
        plugins_run = ", ".join(plugins_run),
        summary_json = summary_json,
    )

    ctx = {
        "image_path": image_path,
        "os_profile": None,
        "output_dir": str(out_dir),
        "vol_paths":  {},
    }

    collected = ""
    last_error = None
    last_model = None
    for evt in agent_mod.stream_chat(prompt, ctx, history=None, allow_tools=False, persist_history=False):
        if evt["type"] == "token":
            collected += evt["content"]
        elif evt["type"] == "done":
            last_model = evt.get("model")
        elif evt["type"] == "error":
            last_error = evt["message"]

    if last_error and not collected:
        return {"error": f"Report generation failed: {last_error}"}

    ts = datetime.datetime.now().strftime("%Y%m%d_%H%M%S")
    stem = f"report_{ts}"
    md_path = out_dir / f"{stem}.md"
    md_path.write_text(collected or "# Empty report\n")

    pdf_path = out_dir / f"{stem}.pdf"
    docx_path = out_dir / f"{stem}.docx"

    paths = {"md": str(md_path)}
    try:
        _write_pdf(collected, pdf_path, image_path, plugins_run, last_model)
        paths["pdf"] = str(pdf_path)
    except Exception as e:
        log.warning("PDF generation failed: %s", e)

    try:
        _write_docx(collected, docx_path, image_path, plugins_run, last_model)
        paths["docx"] = str(docx_path)
    except Exception as e:
        log.warning("DOCX generation failed: %s", e)

    return {"markdown": collected, "files": paths, "model": last_model,
            "plugins_run": plugins_run}


# ---------------------------------------------------------------------------
# PDF / DOCX writers
# ---------------------------------------------------------------------------

def _write_pdf(markdown_text: str, path: Path,
               image_path: str | None, plugins: list[str], model: str | None) -> None:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.lib import colors
    from reportlab.platypus import (
        SimpleDocTemplate, Paragraph, Spacer, PageBreak,
    )

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("H1", parent=styles["Heading1"], textColor=colors.HexColor("#7c3aed"))
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], textColor=colors.HexColor("#4f46e5"))
    body = ParagraphStyle("Body", parent=styles["BodyText"], fontSize=10, leading=14)
    meta = ParagraphStyle("Meta", parent=styles["BodyText"], fontSize=9,
                          textColor=colors.HexColor("#64748b"))

    story = []
    story.append(Paragraph("m3mx tool — Memory Forensics Report", h1))
    story.append(Paragraph(
        f"Image: {_escape_rl(image_path or '(unknown)')}<br/>"
        f"Generated: {datetime.datetime.now().isoformat(timespec='seconds')}<br/>"
        f"Model: {_escape_rl(model or '(unknown)')}<br/>"
        f"Plugins: {_escape_rl(', '.join(plugins))}",
        meta,
    ))
    story.append(Spacer(1, 0.25 * inch))

    for block in _markdown_blocks(markdown_text):
        kind, text = block
        if kind == "h2":
            story.append(Paragraph(_escape_rl(text), h2))
        elif kind == "p":
            story.append(Paragraph(_escape_rl(text), body))
            story.append(Spacer(1, 0.08 * inch))
        elif kind == "li":
            story.append(Paragraph("• " + _escape_rl(text), body))

    doc = SimpleDocTemplate(str(path), pagesize=letter,
                            topMargin=0.6*inch, bottomMargin=0.6*inch,
                            leftMargin=0.7*inch, rightMargin=0.7*inch)
    doc.build(story)


def _write_docx(markdown_text: str, path: Path,
                image_path: str | None, plugins: list[str], model: str | None) -> None:
    from docx import Document

    doc = Document()
    doc.add_heading("m3mx tool — Memory Forensics Report", 0)
    meta = doc.add_paragraph()
    meta.add_run("Image: ").bold = True
    meta.add_run(f"{image_path or '(unknown)'}\n")
    meta.add_run("Generated: ").bold = True
    meta.add_run(f"{datetime.datetime.now().isoformat(timespec='seconds')}\n")
    meta.add_run("Model: ").bold = True
    meta.add_run(f"{model or '(unknown)'}\n")
    meta.add_run("Plugins: ").bold = True
    meta.add_run(", ".join(plugins))

    for kind, text in _markdown_blocks(markdown_text):
        if kind == "h2":
            doc.add_heading(text, level=1)
        elif kind == "p":
            doc.add_paragraph(text)
        elif kind == "li":
            doc.add_paragraph(text, style="List Bullet")

    doc.save(str(path))


def _markdown_blocks(md: str) -> Iterable[tuple[str, str]]:
    """Yield (kind, text) for a small markdown subset: h2, p, li."""
    paragraph: list[str] = []
    for line in md.splitlines():
        s = line.rstrip()
        if not s:
            if paragraph:
                yield ("p", " ".join(paragraph)); paragraph = []
            continue
        m = re.match(r"^#{1,6}\s+(.*)$", s)
        if m:
            if paragraph:
                yield ("p", " ".join(paragraph)); paragraph = []
            yield ("h2", m.group(1))
            continue
        m = re.match(r"^[-*]\s+(.*)$", s)
        if m:
            if paragraph:
                yield ("p", " ".join(paragraph)); paragraph = []
            yield ("li", m.group(1))
            continue
        paragraph.append(s)
    if paragraph:
        yield ("p", " ".join(paragraph))


def _escape_rl(t: str) -> str:
    """Escape ReportLab HTML-ish paragraph text + convert **bold**."""
    t = t.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
    t = re.sub(r"\*\*([^*]+)\*\*", r"<b>\1</b>", t)
    t = re.sub(r"`([^`]+)`", r'<font face="Courier" color="#7c3aed">\1</font>', t)
    return t
