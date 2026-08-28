# SPDX-License-Identifier: Apache-2.0
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
from .retention import RetentionStore, apply_purge, list_report_jobs, plan_purge, validate_policy
from .tenable_client import TenableClient

SERVER_INSTRUCTIONS = """\
You are connected to a Tenable One OT Exposure print-report generator. Use
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
   -- exactly as that name appears in Tenable One OT Exposure's own UI,
   since the stable key is never shown there. Pass `site_uuid`/`site_name` to
   `list_available_columns` to see the live names for a specific ICP
   before picking one.

7. asset_inventory also accepts a `sort` param: a list of column
   selectors (same name language as `columns`), each optionally
   prefixed with "-" for descending, evaluated in priority order --
   e.g. `["-total_risk", "name"]`. Not every column is sortable (some
   are computed from a nested field with no single sortable GraphQL
   field); `list_available_columns` reports a `sortable` flag per
   column, check it before guessing.

8. Two additional report modules: `vulnerability_findings` (Tenable's
   per-asset x plugin `findings` surface -- port/service/status/plugin/
   severity/VPR/CVEs) and `policy_findings` (Tenable's per-policy x
   asset `policyFindings` surface -- this is also what the product's
   GUI "Compliance"/"Policy Violations" pages show, just under a
   different label). Both support `columns` and `sort` the same way
   asset_inventory does, now confirmed against a real GraphQL schema
   introspection query rather than inferred from captures:
   `vulnerability_findings` sorts on every column except `cves`;
   `policy_findings` sorts on every column except `resolved_hits`,
   `active_policy_hits`, `policy_level`, `policy_enabled`, and the
   `event_type_*` columns (no matching field on that surface's
   sort/filter enum). Check `list_available_columns`' `sortable` flag
   per column before guessing. Both fall back to most-recently-hit-
   first when `sort` is omitted.

9. `risk_profile` generates a single-asset risk dossier (identity,
   vulnerabilities, recent events, a 1-hop communication/attack-pathway
   neighborhood) plus a risk-grade table. Grades are never computed by
   this server -- pass `risk_grades` for this report, or
   `risk_grade_fields` to read a grade already assigned on the asset
   via Tenable's own custom fields (mapped by their live label or slot
   name). The rubric is entirely caller-defined: dimension codes,
   display labels (`risk_dimension_labels`), and value scale (letters,
   numbers, words) are whatever your organization's model uses --
   nothing here assumes a specific one. Each dimension's grade table
   "Detail" text can come from `risk_grade_scale` -- a full
   {dimension: {grade: description}} reference table (e.g. a RAISE
   matrix), looked up automatically per dimension using that report's
   own `risk_grades` -- or from `risk_grade_descriptions` for a
   one-off per-dimension override. Don't retype the whole reference
   table into every call: save it once with `save_risk_grade_scale`
   and pass `risk_grade_scale_name` on every later report instead;
   call `list_risk_grade_scales` to see what's already saved before
   guessing a name or saving a duplicate.

10. Themes control visual layout/branding (see point 2), and as of the
   `risk_profile` module, that now includes color/typography too, not
   just header/footer content -- a theme directory may bundle
   `styles.css` on top of `header.html.j2`/`footer.html.j2`. The
   `dark-banner` theme (dark background, high-contrast accent, a large
   banner-style header logo) exists for reports that want a distinct
   look from `default`; call `list_themes` to see what's available in
   a given deployment.

11. Rendered reports accumulate on this server's filestore with no
   automatic cleanup. `set_report_retention_policy` saves a rule once
   (mode='count'/'days'/'weeks'/'months', plus a value) -- one global
   rule, not per module. `purge_reports` applies that saved rule;
   it defaults to `dry_run=true`, which only reports what WOULD be
   deleted, so treat that preview as a real answer on its own and
   only pass `dry_run=false` after the user has actually confirmed
   they want the deletion to happen -- same "require explicit
   confirmation immediately before any write" rule as everywhere
   else, since deleting reports is a write. `get_report_retention_policy`
   checks whether a rule is already saved before guessing one.
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
    retention_store = RetentionStore(data_dir)

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
            # Optional module-specific hook (getattr, same pattern as
            # list_columns/default_columns below) -- resolves any
            # server-stored data (e.g. risk_profile's
            # risk_grade_scale_name) that validate_params' synchronous/
            # I/O-free contract has no room for. Not every module
            # defines this; most don't and this is a no-op for them.
            resolve_stored_params = getattr(instance, "resolve_stored_params", None)
            if resolve_stored_params is not None:
                normalized_params = resolve_stored_params(normalized_params, data_dir)
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
            "use whichever one Tenable One OT Exposure's own UI actually shows you, since "
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

    @mcp.tool(
        title="Save a named risk-grade scale table",
        description=(
            "Saves a risk_grade_scale reference table (e.g. a full RAISE matrix) to "
            "this server's own data directory under a short name, so future "
            "risk_profile reports can pass risk_grade_scale_name instead of "
            "resupplying the whole table every call -- saves it once, reuse forever. "
            "Overwrites an existing table of the same name. Not every module "
            "supports this; if the named module doesn't, this returns an error "
            "saying so rather than silently doing nothing."
        ),
    )
    async def save_risk_grade_scale(module: str, name: str, scale: dict[str, Any]) -> dict[str, Any]:
        instance = load_module(module)
        saver = getattr(instance, "save_stored_scale", None)
        if saver is None:
            raise ValueError(f"Module {module!r} does not support stored risk-grade scales.")
        saver(data_dir, name, scale)
        return {"module": module, "saved_as": name}

    @mcp.tool(
        title="List saved risk-grade scale tables",
        description=(
            "Lists the names already saved via save_risk_grade_scale for a given "
            "module -- check this before guessing a risk_grade_scale_name, or "
            "before saving a new one if you're not sure whether it already exists."
        ),
    )
    async def list_risk_grade_scales(module: str) -> dict[str, Any]:
        instance = load_module(module)
        lister = getattr(instance, "list_stored_scales", None)
        if lister is None:
            return {"module": module, "names": None, "note": "This module does not support stored risk-grade scales."}
        return {"module": module, "names": lister(data_dir)}

    @mcp.tool(
        title="Set report retention policy",
        description=(
            "Saves a rule for how many rendered reports to keep on this server, so "
            "a later purge_reports call can just apply it without respecifying it "
            "every time -- e.g. mode='count', value=10 ('keep the last 10 reports') "
            "or mode='days'/'weeks'/'months', value=N ('keep reports from the last "
            "N days/weeks/months'). One global rule across every report module, "
            "not per-module. Overwrites any previously saved rule. 'months' is "
            "approximated as 30-day blocks, not calendar months. A 'report' is "
            "one submit_report_job call's .md+.html pair, always kept or deleted "
            "together as one unit."
        ),
    )
    async def set_report_retention_policy(mode: str, value: int) -> dict[str, Any]:
        policy = validate_policy(mode, value)
        retention_store.save(policy)
        return {"saved": policy.to_dict()}

    @mcp.tool(
        title="Get report retention policy",
        description="Returns the currently saved report-retention rule, or null if none has been set yet.",
    )
    async def get_report_retention_policy() -> dict[str, Any]:
        policy = retention_store.load()
        return {"policy": policy.to_dict() if policy else None}

    @mcp.tool(
        title="Purge old reports",
        description=(
            "Applies the saved report-retention policy (set via "
            "set_report_retention_policy) to this server's report filestore, "
            "deleting jobs beyond the configured count or older than the "
            "configured time window, oldest first. dry_run=true (the default) "
            "only reports what WOULD be deleted -- pass dry_run=false to actually "
            "delete. Errors, naming set_report_retention_policy, if no policy has "
            "been set yet. Only ever touches files matching this server's own "
            "report-filename convention; anything else in the filestore is left "
            "alone untouched."
        ),
    )
    async def purge_reports(dry_run: bool = True) -> dict[str, Any]:
        policy = retention_store.load()
        if policy is None:
            raise ValueError(
                "No report-retention policy has been set yet. Call "
                "set_report_retention_policy(mode, value) first -- e.g. "
                "mode='count', value=10, or mode='days', value=30."
            )
        jobs = list_report_jobs(output_dir)
        to_keep, to_delete = plan_purge(jobs, policy)
        result: dict[str, Any] = {
            "policy": policy.to_dict(),
            "total_jobs": len(jobs),
            "kept_count": len(to_keep),
            "dry_run": dry_run,
        }
        if dry_run:
            result["would_delete_count"] = len(to_delete)
            result["would_delete"] = [
                {"module": j.module, "base": j.base, "timestamp": j.timestamp.isoformat()} for j in to_delete
            ]
            audit.record(event="report_purge_preview", outcome="ok", params={"policy": policy.to_dict()})
            return result
        deleted_paths = apply_purge(to_delete)
        result["deleted_count"] = len(deleted_paths)
        result["deleted"] = deleted_paths
        audit.record(
            event="report_purge",
            outcome="ok",
            params={"policy": policy.to_dict()},
            output_paths=deleted_paths,
        )
        return result

    return mcp.streamable_http_app()
