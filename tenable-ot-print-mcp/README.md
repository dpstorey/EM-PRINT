# tenable-ot-print-mcp

MCP server that generates print-style reports (Markdown / HTML today,
PDF planned for Phase 1) from Tenable One OT Exposure Enterprise
Manager data via GraphQL, writing output directly to a mounted
filestore rather than through the calling model's context window.

Sibling repo: `../EM-MCP` (the `tenable-ot-mcp` project). This repo
currently **duplicates** a few files from there (`tenable_client.py`,
`tls.py`, `config.py`, `auth.py`) rather than importing a shared
package — that's a deliberate placeholder, not the final design. See
"Open items" below.

## Status: Phase 0 — read + print pipeline built, async/PDF still to come

Nine MCP tools are live:

**Discovery**
- `list_report_types` — introspects `modules/*/manifest.yaml` for every report module's params and output formats.
- `list_available_columns` — full column list, defaults, and sortability for a tabular module.
- `list_themes` — visual/layout themes available for report output.
- `list_recent_report_jobs` — most recent jobs from the audit log.

**Report generation**
- `submit_report_job` — the only report-generation tool, but it now covers four modules: `asset_inventory`, `vulnerability_findings`, `policy_findings`, `risk_profile`. Runs **synchronously** (no job queue yet — that's Phase 2), writes a themed Markdown + HTML report to `MCP_OUTPUT_DIR` (default `./output`), and returns only the file paths and a small summary — never the rendered content — back to the caller.

**Risk-grade scales** (for `risk_profile` reports)
- `save_risk_grade_scale` / `list_risk_grade_scales` — save and reuse a named risk-grading table instead of resending it on every call.

**Retention**
- `set_report_retention_policy` / `get_report_retention_policy` — one global rule (by count, days, weeks, or months) across every module.
- `purge_reports` — applies the saved rule; defaults to `dry_run=true`, same "confirm before any write" pattern as EM-MCP's write tools.

Two themes ship today: `default` and `dark-banner`.

Full tool-by-tool and module-by-module reference: [`docs/tenable-ot-print-mcp-user-guide.md`](docs/tenable-ot-print-mcp-user-guide.md).

### What's intentionally not here yet

- **Async job store/worker** (Phase 2) — `submit_report_job` blocks until the report is done. Fine for a handful of assets or even an unfiltered ~3,500-asset fetch (confirmed a few seconds, live), not guaranteed for a 10k-asset / all-ICP job with no cancel/poll.
- **Multi-ICP fan-out** (`_sites.py`-style bounded-concurrency read, as EM-MCP has) — every module queries a single ICP/EM connection only.
- **PDF output** (Phase 1) — WeasyPrint is in `pyproject.toml` as an optional extra, not wired into `render.py` yet.
- **Syslog audit shipping / tamper-evident destination changes** (Phase 4) — `audit.py` currently just appends local JSONL, same as EM-MCP's does today.
- **The job summary web page** (Phase 3).

## Running it

```bash
cd tenable-ot-print-mcp
python -m venv .venv && source .venv/bin/activate
pip install -e .
MCP_TLS_DISABLE=1 tenable-ot-print-mcp serve
# then open http://127.0.0.1:40444/setup
```

If your EM/ICP's TLS cert is signed by an internal/private CA, drop it (PEM format) at `./data/tenable-ca.pem` (matches `MCP_DATA_DIR`'s default) before hitting `/setup`, or point `MCP_TENABLE_CA_BUNDLE` at it. See `config.get_ca_bundle_path()`.

## Open items

- Decide how `tenable_client.py` / `tls.py` / `config.py` / `auth.py`
  become an actual shared package both this repo and EM-MCP import,
  instead of parallel copies that can drift.
- Confirm real GraphQL pagination behavior against a live EM for
  `asset_inventory` at scale (10k+ assets).
