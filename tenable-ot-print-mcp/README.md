# tenable-ot-print-mcp (Phase 0 skeleton)

MCP server that generates print-style reports (Markdown / HTML, PDF in
Phase 1) from Tenable OT Enterprise Manager data via GraphQL, writing
output directly to a mounted filestore rather than through the calling
model's context window.

Sibling repo: `../EM-MCP` (the `tenable-ot-mcp` project). This repo
currently **duplicates** a few files from there (`tenable_client.py`,
`tls.py`, `config.py`, `auth.py`) rather than importing a shared
package — that's a deliberate placeholder, not the final design. See
"Open items" below.

## Status: Phase 0

What works end-to-end right now:
- `/setup` wizard (same pattern as EM-MCP): enter the EM/ICP GraphQL
  URL + API key, verifies connectivity, issues a bearer token.
- One MCP tool, `submit_report_job`, runs **synchronously** (no job
  queue yet — that's Phase 2) against the `asset_inventory` sample
  module, and writes a themed Markdown + HTML report to
  `MCP_OUTPUT_DIR` (default `./output`), returning only the file
  paths — never the raw asset data — back to the caller.
- `list_report_types` introspects `modules/*/manifest.yaml`.

What's intentionally NOT here yet (see the project's design-notes.md
for the phased plan):
- Async job store/worker (Phase 2) — right now `submit_report_job`
  blocks until the report is done, fine for a handful of assets, not
  for a 10k-asset / all-ICP job.
- Multi-ICP fan-out (`_sites.py`-style bounded-concurrency read) —
  Phase 0's sample module queries a single ICP/EM connection only.
- PDF output (Phase 1) — WeasyPrint is in `pyproject.toml` as an
  optional extra, not wired into `render.py` yet.
- Syslog audit shipping / tamper-evident destination changes (Phase
  4) — `audit.py` currently just appends local JSONL, same as
  EM-MCP's does today.
- The job summary web page (Phase 3).

## Running it

```bash
cd tenable-ot-print-mcp
python -m venv .venv && source .venv/bin/activate
pip install -e .
MCP_TLS_DISABLE=1 tenable-ot-print-mcp serve
# then open http://127.0.0.1:40444/setup
```

If your EM/ICP's TLS cert is signed by an internal/private CA, drop it (PEM format) at `./data/tenable-ca.pem` (matches `MCP_DATA_DIR`'s default) before hitting `/setup`, or point `MCP_TENABLE_CA_BUNDLE` at it. See `config.get_ca_bundle_path()`.

## Open items (tracked in the project's design-notes.md)

- Decide how `tenable_client.py` / `tls.py` / `config.py` / `auth.py`
  become an actual shared package both this repo and EM-MCP import,
  instead of parallel copies that can drift.
- Confirm real GraphQL pagination behavior against a live EM for
  `asset_inventory` at scale (10k+ assets).
- Licensing for this repo (EM-MCP is Apache-2.0; this one is
  unlicensed/internal for now — decide before any external listing).
