"""Sanitized report content and isolated, bounded PDF rendering."""
from __future__ import annotations

import os
from pathlib import Path
import sys
import tempfile


def clean_report_html(html: str) -> str:
    import nh3
    return nh3.clean(html, tags={"p", "br", "hr", "h1", "h2", "h3", "h4", "h5", "h6",
        "strong", "em", "b", "i", "code", "pre", "blockquote", "ul", "ol", "li",
        "table", "thead", "tbody", "tr", "th", "td", "a", "span", "div"},
        attributes={"*": {"class", "id"}, "a": {"href", "title"}},
        url_schemes={"https", "http"}, link_rel="noopener noreferrer")


def deny_resource_fetch(url, *args, **kwargs):
    raise ValueError("External and local resources are disabled in reports")


def render_pdf(html: str, target: Path) -> None:
    from .security import checked_path
    from .processes import run_command
    target = checked_path(target, ("output",), must_exist=False)
    encoded = html.encode("utf-8")
    if len(encoded) > 4 * 1024**2:
        raise ValueError("report exceeds the 4 MiB rendering limit")
    target.parent.mkdir(parents=True, exist_ok=True)
    fd, filename = tempfile.mkstemp(prefix=".pdf-", suffix=".html", dir=target.parent)
    source = Path(filename)
    try:
        with os.fdopen(fd, "wb") as stream:
            stream.write(encoded)
        result = run_command([sys.executable, "-m", "app.pdf_renderer", str(source), str(target)],
                             timeout=90, max_bytes=64 * 1024)
        if result.returncode:
            raise RuntimeError("PDF rendering failed: " + result.stderr[-2000:])
    finally:
        source.unlink(missing_ok=True)


def _worker(source: str, target: str) -> None:
    import resource
    resource.setrlimit(resource.RLIMIT_CPU, (60, 60))
    resource.setrlimit(resource.RLIMIT_AS, (1536 * 1024**2, 1536 * 1024**2))
    resource.setrlimit(resource.RLIMIT_FSIZE, (64 * 1024**2, 64 * 1024**2))
    from weasyprint import HTML
    HTML(string=Path(source).read_text(), url_fetcher=deny_resource_fetch).write_pdf(target)


if __name__ == "__main__":
    _worker(*sys.argv[1:])
