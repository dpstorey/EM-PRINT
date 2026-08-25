"""Sample Phase 0 report module: asset_inventory.

GraphQL field selection mirrors EM-MCP's tools/assets.py `_ASSET_BASE`
fragment (trimmed to what a print report needs) so this module stays
consistent with the real, working schema rather than inventing field
names. See ../../../../EM-MCP/tenable-ot-mcp/src/tenable_ot_mcp/tools/assets.py.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from ...tenable_client import TenableClient
from .. import _base

_QUERY_ASSETS = """
query Q($pageSize: Int!) {
  assets(first: $pageSize) {
    totalCount
    nodes {
      id
      name
      vendor
      model
      firmwareVersion
      criticality
      lastSeen
      ips(first: 5) { nodes }
      risk { totalRisk pluginCount unresolvedEvents }
    }
  }
}
"""

_CRITICALITY_ORDER = {"none": 0, "low": 1, "medium": 2, "high": 3}


class AssetInventoryModule(_base.ReportModule):
    template_name = "template.md.j2"

    def validate_params(self, params: dict[str, Any]) -> dict[str, Any]:
        limit = params.get("limit", 100)
        try:
            limit = int(limit)
        except (TypeError, ValueError) as e:
            raise ValueError(f"limit must be an integer, got {params.get('limit')!r}") from e
        limit = max(1, min(limit, 500))

        criticality_at_least = params.get("criticality_at_least")
        if criticality_at_least is not None and criticality_at_least not in _CRITICALITY_ORDER:
            raise ValueError(
                f"criticality_at_least must be one of {sorted(_CRITICALITY_ORDER)}, "
                f"got {criticality_at_least!r}"
            )
        return {"limit": limit, "criticality_at_least": criticality_at_least}

    async def fetch_data(self, client: TenableClient, params: dict[str, Any]) -> dict[str, Any]:
        # Phase 0: single connection, no cursor pagination yet. A `limit`
        # beyond one page's worth of assets will need the cursor-following
        # loop flagged in design-notes.md §4.5 before this module can be
        # trusted at 10k-asset scale.
        data = await client.query(_QUERY_ASSETS, variables={"pageSize": params["limit"]})
        connection = data.get("assets") or {}
        return {
            "total_count": connection.get("totalCount") or 0,
            "nodes": connection.get("nodes") or [],
        }

    def to_markdown_context(self, data: dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
        min_level = _CRITICALITY_ORDER.get(params.get("criticality_at_least") or "none", 0)
        assets = []
        for node in data.get("nodes") or []:
            criticality = (node.get("criticality") or "none").lower()
            if _CRITICALITY_ORDER.get(criticality, 0) < min_level:
                continue
            ips = (node.get("ips") or {}).get("nodes") or []
            risk = node.get("risk") or {}
            assets.append(
                {
                    "name": node.get("name") or "(unnamed)",
                    "vendor": node.get("vendor") or "",
                    "model": node.get("model") or "",
                    "firmware_version": node.get("firmwareVersion") or "",
                    "criticality": criticality,
                    "ip": ips[0] if ips else "",
                    "last_seen": node.get("lastSeen") or "",
                    "total_risk": risk.get("totalRisk"),
                    "unresolved_events": risk.get("unresolvedEvents"),
                }
            )
        return {
            "report_title": "Asset Inventory",
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "total_count": data.get("total_count", 0),
            "returned_count": len(assets),
            "assets": assets,
        }


MODULE = AssetInventoryModule()
