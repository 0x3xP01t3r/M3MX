"""
m3mx tool — Full Analysis V2 deterministic report generator.

Builds a 12-section Markdown report (``report.md``) from the *existing*
case outputs and renders it to HTML (``report.html``). **Never** invokes
an LLM, **never** re-runs Volatility, **never** invents data. Anything
not derivable from the inputs is omitted, and missing optional files
are listed in the Limitations section.

Pipeline:

    findings.jsonl + optional context  →  report.md  →  report.html

Source of truth is the Markdown — the HTML is produced from the same
text via :mod:`markdown` so the two stay in lock-step.

Distinct from the optional AI Report:

* ``report.md`` / ``report.html``     — *this* module, deterministic.
* ``ai_report.md`` / ``ai_report.html`` — :mod:`app.fa2.ai_report`,
  LLM-backed, gated by a separate feature flag.
* ``attack_story.md``                 — :mod:`app.attack_story`,
  the legacy lightweight AI narrative attached to Full Analysis.

The three are intentionally separate files and code paths.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from datetime import datetime
from html import escape as _h
from pathlib import Path
from typing import Any, Iterable

import markdown as _markdown

from .ai_report_context import CaseOutputs, load_case_outputs

log = logging.getLogger("m3mx.fa2.report")


# ---------------------------------------------------------------------------
# Result wrapper
# ---------------------------------------------------------------------------

@dataclass
class ReportResult:
    md_path: str = ""
    html_path: str = ""
    pdf_path: str = ""              # may be empty if weasyprint unavailable
    pdf_error: str = ""             # explanation when pdf_path is empty
    findings_count: int = 0
    chains_count: int = 0
    techniques_count: int = 0
    failed_plugins_count: int = 0
    warnings: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "md_path":              self.md_path,
            "html_path":            self.html_path,
            "pdf_path":             self.pdf_path,
            "pdf_error":            self.pdf_error,
            "findings_count":       int(self.findings_count),
            "chains_count":         int(self.chains_count),
            "techniques_count":     int(self.techniques_count),
            "failed_plugins_count": int(self.failed_plugins_count),
            "warnings":             list(self.warnings),
        }


# ---------------------------------------------------------------------------
# Markdown section builders
# ---------------------------------------------------------------------------

_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def _table(rows: list[list[str]], header: list[str]) -> str:
    if not rows:
        return ""
    sep = "|" + "|".join(["---"] * len(header)) + "|"
    head = "|" + "|".join(header) + "|"
    body = "\n".join("|" + "|".join(r) + "|" for r in rows)
    return "\n".join([head, sep, body])


def _bullet_list(items: Iterable[str]) -> str:
    items = [str(i).strip() for i in items if str(i).strip()]
    return "\n".join(f"- {x}" for x in items)


def _section_executive_summary(out: CaseOutputs) -> str:
    fs = out.findings
    severity_counts: dict[str, int] = {}
    for f in fs:
        s = (f.get("severity") or "info").lower()
        severity_counts[s] = severity_counts.get(s, 0) + 1

    chains = ((out.correlations or {}).get("chains") or [])
    techniques = ((out.mitre_summary or {}).get("techniques") or [])
    failed = out.failed_plugins or []

    parts = [
        f"- **Findings**: {len(fs)} total"
        + (" (" +
           ", ".join(f"{severity_counts.get(s, 0)} {s}"
                     for s in ("critical","high","medium","low","info")
                     if severity_counts.get(s, 0)) +
           ")" if severity_counts else ""),
        f"- **Attack chains**: {len(chains)}",
        f"- **MITRE techniques observed**: {len(techniques)}",
        f"- **Failed plugins**: {len(failed)}",
    ]
    if not fs:
        parts.append("")
        parts.append(
            "No findings were produced by the rule engine. The detector "
            "may simply not have observed anything noteworthy; absence "
            "of findings is **not** evidence of absence of compromise."
        )
    return "\n".join(parts)


def _section_scope_and_inputs(out: CaseOutputs, image_path: str | None) -> str:
    lines: list[str] = []
    if image_path:
        lines.append(f"- **Memory image**: `{image_path}`")
    if out.case_dir:
        lines.append(f"- **Case directory**: `{out.case_dir}`")
    lines.append(f"- **Generated**: {datetime.now().isoformat(timespec='seconds')}")
    lines.append("")
    if out.files_present:
        lines.append("**Loaded inputs:**")
        lines.append(_bullet_list(out.files_present))
    if out.files_missing:
        lines.append("")
        lines.append("**Inputs not available (treated as limitations):**")
        lines.append(_bullet_list(out.files_missing))
    return "\n".join(lines)


def _section_plugin_summary(out: CaseOutputs) -> str:
    failed = out.failed_plugins or []
    if not failed:
        return ("No plugin failures were recorded for this run "
                "(no `failed_plugins.json` produced).")
    rows = []
    for fp in failed:
        rows.append([
            f"`{fp.get('plugin', '')}`",
            ("⏱ timeout" if fp.get("timed_out") else "✗ failed"),
            str((fp.get("error") or "")).splitlines()[0][:160],
            f"{float(fp.get('elapsed') or 0):.2f}s",
        ])
    head = ["Plugin", "Result", "Error (first line)", "Elapsed"]
    return _table(rows, head)


def _section_severity_summary(out: CaseOutputs) -> str:
    counts: dict[str, int] = {}
    for f in out.findings:
        s = (f.get("severity") or "info").lower()
        counts[s] = counts.get(s, 0) + 1
    if not counts:
        return "_No findings; severity distribution unavailable._"
    rows = []
    for sev in ("critical", "high", "medium", "low", "info"):
        n = counts.get(sev, 0)
        rows.append([f"**{sev.upper()}**", str(n)])
    return _table(rows, ["Severity", "Count"])


def _format_finding_inline(f: dict) -> str:
    fid = f.get("id", "")
    title = f.get("title") or ""
    plugin = f.get("plugin") or f.get("source_plugin") or ""
    sev = (f.get("severity") or "info").lower()
    tags = list(f.get("tags") or [])
    bits = [f"**{fid}** · {sev.upper()} · `{plugin}`"]
    if tags:
        bits.append("MITRE: " + ", ".join(f"`{t}`" for t in tags))
    bits.append("")
    bits.append(f"  _{title}_")
    desc = (f.get("description") or "").strip()
    if desc:
        bits.append("")
        bits.append("  " + desc.replace("\n", " "))
    return "\n".join(bits)


def _section_critical_and_high(out: CaseOutputs) -> str:
    sel = [f for f in out.findings
           if (f.get("severity") or "").lower() in ("critical", "high")]
    if not sel:
        return ("_No critical or high findings._\n\n"
                "Lower-severity findings still appear in `findings.jsonl`.")
    sel.sort(key=lambda f: (_SEVERITY_RANK.get((f.get("severity") or "info").lower(), 9),
                             f.get("id", "")))
    return "\n\n".join(_format_finding_inline(f) for f in sel)


def _section_attack_chains(out: CaseOutputs) -> str:
    chains = (out.correlations or {}).get("chains") or []
    if not chains:
        return "_No attack chains were produced._"
    out_lines: list[str] = []
    for c in chains:
        cid = c.get("chain_id", "")
        title = c.get("title", "")
        sev = (c.get("severity") or "info").lower()
        confidence = c.get("confidence", 0.0)
        findings = list(c.get("findings") or [])
        summary = (c.get("summary") or "").strip()
        out_lines.append(
            f"### {cid} — {title}\n\n"
            f"- **Severity**: {sev.upper()}\n"
            f"- **Confidence**: {float(confidence):.2f}\n"
            f"- **Findings**: " + (", ".join(f"`{x}`" for x in findings) or "—") + "\n"
        )
        if summary:
            out_lines.append(summary)
        out_lines.append("")
    return "\n".join(out_lines).rstrip()


def _section_timeline(out: CaseOutputs) -> str:
    t = out.timeline or {}
    totals = t.get("totals") or {}
    if not totals:
        return "_No timeline available (timeline.json is missing)._"
    timed = totals.get("timed", 0)
    untimed = totals.get("untimed", 0)
    earliest = totals.get("earliest")
    latest = totals.get("latest")
    parts = [
        f"- **Timed events**: {timed}",
        f"- **Untimed events**: {untimed}",
    ]
    if earliest:
        parts.append(f"- **Earliest**: `{earliest}`")
    if latest:
        parts.append(f"- **Latest**: `{latest}`")
    events = (t.get("events") or [])[:10]
    if events:
        parts.append("")
        parts.append("**First 10 timed events:**")
        rows = []
        for e in events:
            rows.append([
                f"`{e.get('ts') or ''}`",
                f"`{e.get('type') or ''}`",
                (e.get("title") or "")[:80],
                ", ".join(str(p) for p in (e.get("related_pids") or [])),
            ])
        parts.append(_table(rows, ["Timestamp", "Type", "Title", "PIDs"]))
    return "\n".join(parts)


def _section_mitre(out: CaseOutputs) -> str:
    summary = out.mitre_summary or {}
    techs = summary.get("techniques") or []
    if not techs:
        return "_No MITRE techniques surfaced from findings._"
    rows = []
    for t in techs:
        rows.append([
            f"`{t.get('technique', '')}`",
            t.get("name") or "",
            t.get("tactic") or "—",
            str(t.get("count", 0)),
            t.get("source") or "",
        ])
    head = ["Technique", "Name", "Tactic", "Count", "Source"]
    parts = [_table(rows, head)]
    by_tactic = summary.get("by_tactic") or {}
    if by_tactic:
        parts.append("")
        parts.append("**By tactic:**")
        for tactic, ids in sorted(by_tactic.items()):
            parts.append(f"- **{tactic}**: " + ", ".join(f"`{i}`" for i in ids))
    return "\n".join(parts)


def _section_false_positive(out: CaseOutputs) -> str:
    notes = []
    for f in out.findings:
        n = (f.get("false_positive_notes") or "").strip()
        if not n:
            continue
        notes.append(f"- **{f.get('id', '')}** ({(f.get('severity') or '').upper()}): {n}")
    if not notes:
        return ("_No false-positive notes were attached to the findings. "
                "Review each finding against expected baseline activity before "
                "treating it as confirmed._")
    return "\n".join(notes)


def _section_limitations(out: CaseOutputs) -> str:
    lines: list[str] = []
    if out.files_missing:
        lines.append("**Missing optional inputs:**")
        lines.append(_bullet_list(out.files_missing))
    if out.failed_plugins:
        lines.append("")
        lines.append("**Plugins that failed during Full Analysis:**")
        for fp in out.failed_plugins:
            lines.append(f"- `{fp.get('plugin', '')}`: "
                         f"{(fp.get('error') or '').splitlines()[0][:200]}")
    if out.limitations:
        lines.append("")
        lines.append("**Pipeline warnings recorded:**")
        for lim in out.limitations:
            phase = lim.get("phase", "unknown")
            for w in (lim.get("warnings") or []):
                lines.append(f"- `{phase}`: {w}")
            for s in (lim.get("skipped") or []):
                lines.append(f"- `{phase}` skipped: "
                             f"`{s.get('plugin') if isinstance(s, dict) else s}`")
    if not lines:
        return "_No limitations recorded for this run._"
    return "\n".join(lines)


def _section_validation_steps(out: CaseOutputs) -> str:
    parts = []
    for f in out.findings:
        v = (f.get("recommended_validation") or "").strip()
        if not v:
            continue
        parts.append(f"### {f.get('id', '')} — {f.get('title', '')}\n\n{v}")
    if not parts:
        return ("_No per-finding validation steps were attached. The "
                "engine still recommends: review the parent process, "
                "decode any obfuscated arguments, and corroborate with "
                "network / persistence artefacts on the same PID._")
    return "\n\n".join(parts)


def _section_evidence_appendix(out: CaseOutputs) -> str:
    if not out.findings:
        return "_No findings recorded._"
    rows = []
    for f in out.findings:
        rows.append([
            f"`{f.get('id', '')}`",
            (f.get("severity") or "info").upper(),
            f"`{f.get('plugin') or f.get('source_plugin') or ''}`",
            (f.get("title") or "")[:80],
            ", ".join(f"`{t}`" for t in (f.get("tags") or [])),
        ])
    return _table(rows, ["ID", "Severity", "Plugin", "Title", "MITRE"])


# ---------------------------------------------------------------------------
# Top-level builder
# ---------------------------------------------------------------------------

_REPORT_TITLE = "m3mx Full Analysis — Forensic Report"

_SECTIONS: tuple[tuple[str, Any], ...] = (
    ("Executive Summary",                   _section_executive_summary),
    ("Scope and Inputs",                    _section_scope_and_inputs),
    ("Plugin Execution / Failure Summary",  _section_plugin_summary),
    ("Severity Summary",                    _section_severity_summary),
    ("Critical and High Findings",          _section_critical_and_high),
    ("Attack Chains",                       _section_attack_chains),
    ("Timeline Summary",                    _section_timeline),
    ("MITRE ATT&CK Summary",                _section_mitre),
    ("False Positive Considerations",       _section_false_positive),
    ("Limitations",                         _section_limitations),
    ("Recommended Analyst Validation Steps", _section_validation_steps),
    ("Appendix / Evidence References",      _section_evidence_appendix),
)


def build_report_md(outputs: CaseOutputs,
                    image_path: str | None = None) -> str:
    """
    Render the full Markdown report from *outputs*. Pure function — no
    I/O, no LLM, no Volatility. Returns a single Markdown string.
    """
    sections: list[str] = []
    # H1 title + meta line.
    sections.append(f"# {_REPORT_TITLE}\n")
    sections.append(
        f"_Generated by m3mx Full Analysis V2 · "
        f"{datetime.now().isoformat(timespec='seconds')}_\n"
    )
    sections.append("---\n")

    for title, fn in _SECTIONS:
        sections.append(f"## {title}\n")
        try:
            if title == "Scope and Inputs":
                body = fn(outputs, image_path)
            else:
                body = fn(outputs)
        except Exception as e:                                    # pragma: no cover
            log.exception("section %s failed: %s", title, e)
            body = f"_Section failed to render: {e!s}_"
        sections.append((body or "").strip())
        sections.append("")  # blank line between sections

    return "\n".join(sections).rstrip() + "\n"


# ---------------------------------------------------------------------------
# Markdown → HTML
# ---------------------------------------------------------------------------

_HTML_TEMPLATE = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8"/>
<meta name="viewport" content="width=device-width, initial-scale=1"/>
<title>{title}</title>
<style>
  :root {{
    --bg: #0f1115; --fg: #e6e8ec; --muted: #9aa3b2; --accent: #5eead4;
    --line: #2a2f3a; --code-bg: #1a1d24;
  }}
  body {{
    margin: 0; padding: 40px 56px; max-width: 980px;
    background: var(--bg); color: var(--fg);
    font: 15px/1.55 -apple-system, BlinkMacSystemFont, "Segoe UI",
          Roboto, Helvetica, Arial, sans-serif;
  }}
  h1, h2, h3 {{ color: #fff; letter-spacing: 0.01em; }}
  h1 {{ font-size: 1.8rem; margin-bottom: 0.4em; }}
  h2 {{ font-size: 1.25rem; margin-top: 2em;
       border-bottom: 1px solid var(--line); padding-bottom: 0.3em; }}
  h3 {{ font-size: 1.05rem; margin-top: 1.4em; color: var(--accent); }}
  a {{ color: var(--accent); }}
  code, pre {{
    font-family: ui-monospace, "SF Mono", Menlo, Consolas, monospace;
    background: var(--code-bg); padding: 1px 5px; border-radius: 3px;
    font-size: 0.9em;
  }}
  pre {{ padding: 12px 14px; overflow-x: auto; }}
  table {{
    border-collapse: collapse; margin: 1em 0; width: 100%;
    font-size: 0.92em;
  }}
  th, td {{
    border: 1px solid var(--line); padding: 6px 10px; text-align: left;
    vertical-align: top;
  }}
  th {{ background: var(--code-bg); color: #fff; }}
  ul, ol {{ padding-left: 1.4em; }}
  hr {{ border: 0; border-top: 1px solid var(--line); margin: 1.6em 0; }}
  em {{ color: var(--muted); }}
  blockquote {{
    border-left: 3px solid var(--accent); margin: 1em 0;
    padding: 0.4em 0.9em; color: var(--muted);
  }}
</style>
</head>
<body>
{content}
</body>
</html>
"""


def markdown_to_html(md_text: str,
                     title: str = _REPORT_TITLE) -> str:
    """
    Convert *md_text* to a self-contained HTML document. Uses the
    ``markdown`` library already in requirements.txt with the
    ``extra``, ``tables``, and ``toc`` extensions enabled so GFM-style
    tables render correctly.
    """
    inner = _markdown.markdown(
        md_text or "",
        extensions=["extra", "tables", "toc", "sane_lists"],
        output_format="html5",
    )
    return _HTML_TEMPLATE.format(title=_h(title or _REPORT_TITLE),
                                 content=inner)


# ---------------------------------------------------------------------------
# Writers
# ---------------------------------------------------------------------------

def write_report_md(md_text: str, case_dir: str | Path) -> str:
    case = Path(case_dir)
    case.mkdir(parents=True, exist_ok=True)
    target = case / "report.md"
    target.write_text(md_text, encoding="utf-8")
    return str(target.resolve())


def write_report_html(html_text: str, case_dir: str | Path) -> str:
    case = Path(case_dir)
    case.mkdir(parents=True, exist_ok=True)
    target = case / "report.html"
    target.write_text(html_text, encoding="utf-8")
    return str(target.resolve())


# ---------------------------------------------------------------------------
# HTML → PDF (best-effort, weasyprint-only)
# ---------------------------------------------------------------------------

def html_to_pdf(html_text: str, target: str | Path) -> tuple[bool, str | None]:
    """
    Render *html_text* to a PDF at *target*. Returns ``(ok, error)``.

    Uses :mod:`weasyprint` when available. Never raises — if the
    library is missing or rendering fails, returns ``(False, reason)``
    and the caller proceeds without a PDF. The accompanying Markdown
    and HTML files are produced regardless.
    """
    try:
        import weasyprint  # type: ignore[import]
    except Exception as e:                                        # pragma: no cover
        return False, (f"weasyprint not available ({e!r}); install with "
                       "`pip install weasyprint`")
    try:
        out_path = Path(target)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        weasyprint.HTML(string=html_text).write_pdf(str(out_path))
        return True, None
    except Exception as e:                                        # pragma: no cover
        log.warning("PDF rendering failed: %s", e)
        return False, f"weasyprint render failed: {e!s}"


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def build_and_persist(case_dir: str | Path,
                      image_path: str | None = None) -> ReportResult:
    """
    Load the case outputs, render ``report.md`` then ``report.html``,
    and return a :class:`ReportResult` summarising what was written.

    Raises :class:`FileNotFoundError` if ``findings.jsonl`` is missing —
    a deterministic report requires *at least* the canonical finding
    list to be present.
    """
    outputs = load_case_outputs(case_dir)
    if not outputs.has_findings:
        raise FileNotFoundError(
            f"findings.jsonl is missing in {outputs.case_dir or case_dir!s} "
            "— run Full Analysis first"
        )

    md_text = build_report_md(outputs, image_path=image_path)
    md_path = write_report_md(md_text, case_dir)

    html_text = markdown_to_html(md_text)
    html_path = write_report_html(html_text, case_dir)

    return ReportResult(
        md_path=md_path,
        html_path=html_path,
        findings_count=len(outputs.findings),
        chains_count=len((outputs.correlations or {}).get("chains") or []),
        techniques_count=len((outputs.mitre_summary or {}).get("techniques") or []),
        failed_plugins_count=len(outputs.failed_plugins or []),
    )


def report_ready_event(result: ReportResult) -> dict[str, Any]:
    """Optional ``report_ready`` SSE event payload (CONTRACT §4 reserves the name)."""
    def _rel(abs_path: str | None) -> str | None:
        if not abs_path:
            return None
        try:
            from ..config import safe_output_dir
            root = Path(safe_output_dir()).resolve()
            return str(Path(abs_path).resolve().relative_to(root))
        except (ValueError, OSError):
            return None
    payload = {"type": "report_ready", **result.to_dict()}
    payload["md_rel"]   = _rel(result.md_path)
    payload["html_rel"] = _rel(result.html_path)
    return payload


# ---------------------------------------------------------------------------
# Deterministic PDF export
# ---------------------------------------------------------------------------

def export_pdf_from_case(case_dir: str | Path) -> ReportResult:
    """
    Render ``report.pdf`` from the existing ``report.md`` / ``report.html``
    in *case_dir*. Pure file-on-disk transform — never runs Volatility and
    never invokes the LLM. Pipeline:

        report.md  →  report.html  →  report.pdf

    The HTML is re-rendered from the canonical Markdown so the PDF cannot
    drift from the source. If ``weasyprint`` is unavailable the returned
    :class:`ReportResult` has ``pdf_path=""`` and ``pdf_error`` populated.
    """
    case = Path(case_dir)
    md_target = case / "report.md"
    if not md_target.exists():
        raise FileNotFoundError(
            f"report.md missing in {case} — run Full Analysis first"
        )

    md_text   = md_target.read_text(encoding="utf-8")
    html_text = markdown_to_html(md_text)
    html_path = write_report_html(html_text, case)

    pdf_target = case / "report.pdf"
    ok, err = html_to_pdf(html_text, pdf_target)
    pdf_path = str(pdf_target.resolve()) if ok else ""
    pdf_error = "" if ok else (err or "PDF render failed")

    return ReportResult(
        md_path=str(md_target.resolve()),
        html_path=html_path,
        pdf_path=pdf_path,
        pdf_error=pdf_error,
    )
