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

4. If a job's outcome seems to be missing -- e.g. the connection
   dropped, or a client-side error appeared, before you saw a result
   -- use `list_recent_report_jobs` to check whether it actually
   completed on the server before assuming it failed and resubmitting.
   Note this reports *past* jobs (ok/error, from the audit log); since
   Phase 0 runs synchronously there is no separate "still running"
   state to report for a job in progress right now.

5. Some modules accept a `columns` param to pick which fields appear
   in the report and in what order. Call `list_available_columns` for
   a module before guessing column names -- a wrong name is rejected
   outright rather than silently ignored, so it's cheaper to check
   first than to retry after an error. A module that doesn't support
   column selection returns `columns: null` from that call.

6. For asset_inventory specifically, custom fields are selectable
   either by their stable key (`custom_field_1`..`custom_field_10`)
   or by their live operator-configured name (e.g. "Owner", "Geotag")
   -- exactly as that name appears in Tenable OT's own UI, since the
   stable key is never shown there. Pass `site_uuid`/`site_name` to
   `list_available_columns` to see the live names for a specific ICP
   before picking one.
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

    @mcp.tool(
        title="List available report columns",
        description=(
            "Lists the columns a report module can include via its `columns` param "
            "(key + display label), and which columns are used when `columns` is "
            "omitted. Not every module supports column selection -- if it doesn't, "
            "`columns` and `default_columns` come back null.\n\n"
            "Pass `site_uuid` or `site_name` for a module whose columns depend on "
            "live per-ICP configuration (e.g. asset_inventory's custom-field slots, "
            "which show their operator-configured label like 'Plant ID' once the "
            "ICP is known) -- otherwise those columns fall back to a generic label "
            "like 'Custom Field 3'. Omit both on a single-ICP EM; it auto-resolves.\n\n"
            "For asset_inventory, a custom-field slot's live label (the `label` "
            "shown here) works directly in `columns` too, not just its `key` -- "
            "use whichever one Tenable OT's own UI actually shows you, since the "
            "stable key is never displayed there."
        ),
    )
    async def list_available_columns(
        module: str,
        site_uuid: str | None = None,
        site_name: str | None = None,
    ) -> dict[str, Any]:
        instance = load_module(module)
        list_columns = getattr(instance, "list_columns", None)
        default_columns = getattr(instance, "default_columns", None)
        if list_columns is None:
            return {
                "module": module,
                "columns": None,
                "default_columns": None,
                "note": "This module does not support column selection.",
            }
        columns = await list_columns(client, site_uuid=site_uuid, site_name=site_name)
        return {
            "module": module,
            "columns": columns,
            "default_columns": default_columns() if default_columns else None,
        }

    @mcp.tool(
        title="List recent report jobs",
        description=(
            "Lists the most recent report jobs from the audit log, newest first: "
            "outcome (ok/error), module, params, and output file paths. Answers "
            "'did my last job actually finish' -- useful if a connection dropped or "
            "the client-side result looked wrong -- rather than polling a job that's "
            "still running: Phase 0's submit_report_job is synchronous (it only "
            "returns once done), so there is no in-progress state to report yet."
        ),
    )
    async def list_recent_report_jobs(limit: int = 10) -> dict[str, Any]:
        return {"jobs": audit.recent(limit=limit)}

    return mcp.streamable_http_app()
