# EM-PRINT

Print-report MCP server for Tenable One OT Exposure — generates Markdown/HTML (PDF planned) reports from live Enterprise Manager GraphQL data and writes them to a mounted filestore, so a large report never has to pass through a calling LLM's context window.

**License**: Apache-2.0. See `LICENSE` and `NOTICE`.
**Author**: Dominic Storey <dstorey@barossafarm.com>

Sibling project to [EM-MCP](../EM-MCP) (`tenable-ot-mcp`) — same conversational-tool ecosystem, but this repo prints reports rather than answering chat queries. It currently duplicates a few of EM-MCP's core files (`tenable_client.py`, `tls.py`, `config.py`, `auth.py`) rather than importing a shared package; see `tenable-ot-print-mcp/README.md`'s "Open items" for the plan there.

### Quick start

```bash
docker compose up -d --build --force-recreate tenable-ot-print
```

Then open `http://127.0.0.1:3309/setup` (see `docker-compose.yaml` for the port mapping) to run the setup wizard.

### More detail

- `tenable-ot-print-mcp/README.md` — build/run instructions, phase status, open items.
- `tenable-ot-print-mcp/docs/tenable-ot-print-mcp-user-guide.md` — full tool and report-module reference.
