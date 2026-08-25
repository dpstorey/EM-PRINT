"""Builds the FastMCP server and exposes it as a Streamable HTTP ASGI app.

Phase 0: `submit_report_job` runs synchronously and returns file paths
immediately — no job queue yet. Phase 2 replaces the body of this tool
with "write a job row, return job_id" and adds get_job_status/list_jobs;
the tool's external signature is written now to already look like the
async version so callers don't need to change later.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

from mcp.server.fastmcp import FastMCP
from mcp.server.transport_security import TransportSecuritySettings

from .audit import AuditLog
from .config import Config, get_ca_bundle_path, get_output_dir
from .modules import discover_manifests, load_module
from .tenable_client import TenableClient

SERVER_INSTRUCTIONS = """\
You are connected to a Tenable OT print-report generator. Use
`list_report_types` to see available report modules and their
parameters, then `submit_report_job` to generate one.

Operating principles:

1. This server writes rendered reports (Markdown/HTML, PDF in a later
   phase) to a filestore mounted on the host — it does NOT return the
   report content to you. Tool results are file paths and small
   summaries by design, so large reports don't burn your context
   window. Tell the user where the file landed; don't try to
   reconstruct or re-quote its contents from the tool result.

2. `theme` controls visual layout/branding only (header/footer text,
   images, density) — it never changes what data is queried or how
   it's worded. There is no AI-authored narrative content in these
   reports.

3. Phase 0: jobs run synchronously. A very large `limit` on a
   data-heavy module can take a while and there is no cancel/poll yet
   — prefer modest limits until the async job queue (a later phase)
   lands.
"""

_THEMES_DIR = Path(__file__).parent / "themes"


def _list_themes() -> list[str]:
    if not _THEMES_DIR.is_dir():
        return []
    return sorted(p.name for p in _THEMES_DIR.iterdir() if p.is_dir())


def build_mcp_app(cfg: Config, audit: AuditLog, data_dir: Path) -> Any:
    """Construct the FastMCP server and return its Streamable HTTP app."""
    ca_bundle = get_ca_bundle_path(data_dir)
    client = TenableClient(
        cfg.tenable_url,
        cfg.tenable_api_key,
        tls_verify=cfg.tls_verify,
        ca_bundle=str(ca_bundle) if ca_bundle else None,
    )
    output_dir = get_output_dir()

    mcp = FastMCP(
        name="tenable-ot-print-mcp",
        instructions=SERVER_INSTRUCTIONS,
        transport_security=TransportSecuritySettings(enable_dns_rebinding_protection=False),
    )

    @mcp.tool(
        title="List available report types",
        description="Lists report modules this server can generate, with their parameters and supported output formats.",
    )
    async def list_report_types() -> dict[str, Any]:
        manifests = discover_manifests()
        return {
            "modules": [
                {
                    "name": m.name,
                    "title": m.title,
                    "description": m.description,
                    "params": m.params,
                    "output_formats": m.output_formats,
                }
                for m in manifests.values()
            ]
        }

    @mcp.tool(title="List available themes", description="Lists the visual/layout themes available for report output.")
    async def list_themes() -> dict[str, Any]:
        return {"themes": _list_themes()}

    @mcp.tool(
        title="Generate a print report",
        description=(
            "Runs a report module and writes Markdown + HTML output to the server's "
            "filestore. Returns file paths and sizes only — never the report content "
            "itself. Phase 0: runs synchronously; keep `limit`-style params modest."
        ),
    )
    async def submit_report_job(
        module: str,
        params: dict[str, Any] | None = None,
        theme: str = "default",
        theme_overrides: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        params = params or {}
        try:
            instance = load_module(module)
            normalized_params = instance.validate_params(params)
            data = await instance.fetch_data(client, normalized_params)
            context = instance.to_markdown_context(data, normalized_params)
        except Exception as e:  # noqa: BLE001 — surfaced to the caller, then re-raised context
            audit.record(event="report_job_submitted", module=module, params=params, outcome="error", error=str(e))
            raise

        from .modules import _MODULES_DIR
        from .render import render_report

        result = render_report(
            module_name=module,
            module_template_dir=_MODULES_DIR / module,
            template_name=instance.template_name,
            context=context,
            theme_name=theme,
            theme_overrides=theme_overrides,
            output_dir=output_dir,
            formats=["markdown", "html"],
        )

        output_paths = [str(result.markdown_path), str(result.html_path)]
        audit.record(
            event="report_job_completed",
            module=module,
            params=params,
            outcome="ok",
            output_paths=output_paths,
        )
        return {
            "module": module,
            "output_paths": output_paths,
            "markdown_bytes": result.markdown_bytes,
            "html_bytes": result.html_bytes,
            "returned_count": context.get("returned_count"),
            "total_count": context.get("total_count"),
        }

    return mcp.streamable_http_app()
