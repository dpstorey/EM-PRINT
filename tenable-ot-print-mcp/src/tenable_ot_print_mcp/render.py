"""Markdown -> themed HTML rendering pipeline. PDF (WeasyPrint) is Phase 1 —
see pyproject.toml's `pdf` extra, not wired in here yet.

Theming is visual/layout only (confirmed with Dom, 2026-08-25 — see
design-notes.md §4.4): header/footer text + branding, no AI-authored
narrative content, so this whole pipeline stays deterministic.

Logo support (2026-08-26, planning session for "header page with a
customer logo"): a theme directory may bundle a default logo at
<theme_dir>/assets/logo.<ext> -- if present, it's base64-encoded into
a `data:` URI and exposed to header.html.j2/footer.html.j2 as
`logo_data_uri`, so the rendered report stays a single self-contained
HTML file with no external image reference to keep track of or lose
when the file is copied/emailed elsewhere. A caller can override it
per-report with their own logo via `theme_overrides={"logo_data_uri":
"data:image/png;base64,..."}`  -- `theme_overrides` already wins over
everything else in `theme_context` below, so no new plumbing was
needed for that half of the ask; only the *default* branded logo is
new.
"""

from __future__ import annotations

import base64
import mimetypes
import re
from dataclasses import dataclass
from datetime import UTC, datetime
from functools import lru_cache
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
  .report-header {{ display: flex; align-items: center; gap: 1rem; border-bottom: 2px solid #333; margin-bottom: 1.5rem; padding-bottom: 0.5rem; }}
  .report-header-logo {{ height: 48px; width: auto; flex-shrink: 0; }}
  .report-header-title {{ font-size: 1.6rem; font-weight: 600; }}
  .report-header-meta, .report-footer-meta {{ color: #666; font-size: 0.85rem; }}
  .report-footer {{ display: flex; align-items: center; gap: 0.5rem; border-top: 1px solid #ccc; margin-top: 2rem; padding-top: 0.5rem; }}
  .report-footer-mini-logo {{ height: 16px; width: auto; flex-shrink: 0; }}
</style>
</head>
<body>
{header}
{body}
{footer}
</body>
</html>
"""


@lru_cache(maxsize=None)
def _theme_asset_data_uri(theme_dir: Path, stem: str) -> str | None:
    """`<theme_dir>/assets/<stem>.*` -> a `data:` URI, or None if that
    theme has no such bundled asset. Cached per (theme_dir, stem) --
    these files never change at runtime, and re-reading/re-encoding on
    every report would be pure waste.

    Two logo slots (2026-08-26, per Dom): `logo` is the main lockup --
    the full wordmark, used in the report header, big enough to read
    on its own -- and `logo-mini` is the bare icon mark, used wherever
    a small dressing element is wanted (currently: the footer) rather
    than the full wordmark at a size too small to read. Same override
    mechanism for both: `theme_overrides={"logo_data_uri": ...}` /
    `{"mini_logo_data_uri": ...}` each win over the bundled default
    independently.
    """
    assets_dir = theme_dir / "assets"
    if not assets_dir.is_dir():
        return None
    for candidate in sorted(assets_dir.glob(f"{stem}.*")):
        mime, _ = mimetypes.guess_type(candidate.name)
        if mime is None:
            continue
        encoded = base64.b64encode(candidate.read_bytes()).decode("ascii")
        return f"data:{mime};base64,{encoded}"
    return None


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

    # Default logos (this theme's own bundled branding) first, then the
    # module's own context, then `theme_overrides` -- which already
    # wins over everything, so a caller passing
    # `theme_overrides={"logo_data_uri": "...", "mini_logo_data_uri":
    # "..."}` for their own customer branding overrides the bundled
    # defaults for free, no extra plumbing needed for that case.
    theme_context = {
        "logo_data_uri": _theme_asset_data_uri(theme_dir, "logo"),
        "mini_logo_data_uri": _theme_asset_data_uri(theme_dir, "logo-mini"),
        **context,
        **(theme_overrides or {}),
    }
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
