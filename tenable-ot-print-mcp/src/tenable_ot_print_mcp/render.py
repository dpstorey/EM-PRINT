"""Markdown -> themed HTML rendering pipeline. PDF (WeasyPrint) is Phase 1 —
see pyproject.toml's `pdf` extra, not wired in here yet.

Theming is visual/layout only (confirmed with Dom, 2026-08-25 — see
design-notes.md §4.4): header/footer text + branding, no AI-authored
narrative content, so this whole pipeline stays deterministic.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

import markdown as md
from jinja2 import Environment, FileSystemLoader, select_autoescape

_THEMES_DIR = Path(__file__).parent / "themes"

_HTML_SHELL = """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>{title}</title>
<style>
  body {{ font-family: -apple-system, Helvetica, Arial, sans-serif; margin: 2rem auto; max-width: 900px; color: #1a1a1a; }}
  table {{ border-collapse: collapse; width: 100%; margin: 1rem 0; }}
  th, td {{ border: 1px solid #ccc; padding: 0.4rem 0.6rem; text-align: left; font-size: 0.9rem; }}
  th {{ background: #f2f2f2; }}
  .report-header {{ border-bottom: 2px solid #333; margin-bottom: 1.5rem; padding-bottom: 0.5rem; }}
  .report-header-title {{ font-size: 1.6rem; font-weight: 600; }}
  .report-header-meta, .report-footer-meta {{ color: #666; font-size: 0.85rem; }}
  .report-footer {{ border-top: 1px solid #ccc; margin-top: 2rem; padding-top: 0.5rem; }}
</style>
</head>
<body>
{header}
{body}
{footer}
</body>
</html>
"""


@dataclass(frozen=True)
class RenderResult:
    markdown_path: Path
    html_path: Path
    markdown_bytes: int
    html_bytes: int


def _slugify(text: str) -> str:
    return re.sub(r"[^a-z0-9-]+", "-", text.lower()).strip("-") or "report"


def render_report(
    *,
    module_name: str,
    module_template_dir: Path,
    template_name: str,
    context: dict[str, Any],
    theme_name: str,
    theme_overrides: dict[str, Any] | None,
    output_dir: Path,
    formats: list[str],
) -> RenderResult:
    """Render one module's context through its template + the chosen theme.

    Writes <output_dir>/<module_name>/<timestamp>-<slug>.md (and .html)
    and returns the paths. Never returns the rendered content itself —
    callers (the MCP tool) should hand back paths/sizes, not bytes, to
    keep the token-cost guarantee intact (design-notes.md §3.2).
    """
    theme_dir = _THEMES_DIR / theme_name
    if not theme_dir.is_dir():
        raise ValueError(f"Unknown theme {theme_name!r}; expected a directory under {_THEMES_DIR}")

    module_env = Environment(
        loader=FileSystemLoader(str(module_template_dir)),
        autoescape=select_autoescape(disabled_extensions=(".j2",)),
    )
    body_markdown = module_env.get_template(template_name).render(**context)

    theme_context = {**context, **(theme_overrides or {})}
    theme_env = Environment(
        loader=FileSystemLoader(str(theme_dir)),
        autoescape=select_autoescape(["html"]),
    )
    header_html = theme_env.get_template("header.html.j2").render(**theme_context)
    footer_html = theme_env.get_template("footer.html.j2").render(**theme_context)

    body_html = md.markdown(body_markdown, extensions=["tables"])
    full_html = _HTML_SHELL.format(
        title=context.get("report_title", module_name),
        header=header_html,
        body=body_html,
        footer=footer_html,
    )

    ts = datetime.now(UTC).strftime("%Y%m%dT%H%M%SZ")
    slug = _slugify(context.get("report_title", module_name))
    job_dir = output_dir / module_name
    job_dir.mkdir(parents=True, exist_ok=True)
    base = job_dir / f"{ts}-{slug}"

    md_path = base.with_suffix(".md")
    html_path = base.with_suffix(".html")

    md_bytes = body_markdown.encode("utf-8")
    html_bytes = full_html.encode("utf-8")
    if "markdown" in formats:
        md_path.write_bytes(md_bytes)
    if "html" in formats:
        html_path.write_bytes(html_bytes)

    return RenderResult(
        markdown_path=md_path,
        html_path=html_path,
        markdown_bytes=len(md_bytes),
        html_bytes=len(html_bytes),
    )
