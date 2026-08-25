"""Sample Phase 0 report module: asset_inventory.

GraphQL field selection mirrors EM-MCP's tools/assets.py `_ASSET_BASE`
fragment (trimmed to what a print report needs) so this module stays
consistent with the real, working schema rather than inventing field
names. See ../../../../EM-MCP/tenable-ot-mcp/src/tenable_ot_mcp/tools/assets.py.

The `criticality_at_least` and `subnet` filters are pushed down into
the GraphQL `filter: AssetExpressionsParams` argument rather than
applied client-side after fetch, mirroring EM-MCP's
`tools/_enums.py` (`expr`/`expr_and`) + `tools/assets.py`
(`_build_asset_filter`) exactly -- same field names ("criticality",
"ips"), same ops ("In" for criticality-at-least, "Between" for
subnet), same enum strings (e.g. "MediumCriticality"). This matters
at scale: Phase 0 has no cursor-pagination loop yet (see
design-notes.md Sec 4), so a client-side filter would only ever see
whatever fit in the single fetched page -- pushing the filter into
the query itself means the whole EM/ICP inventory gets filtered
before the page-size cap applies.
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from typing import Any

from ...tenable_client import TenableClient
from .. import _base

# Two variants of the same field selection, differing only in whether
# the operation declares a `$filter` variable at all. Kept genuinely
# separate (not "one query, sometimes-omitted variable") because we
# saw live evidence that merely *declaring* $filter -- even when the
# call supplies no value for it -- is enough to change Tenable's
# server-side routing for this query on this deployment (see
# design-notes.md Sec 0.5): the unfiltered case regressed to a 404
# GraphQL error the moment $filter appeared in the query text, even
# after variables stopped sending an explicit null. Unfiltered calls
# get the exact query text that was confirmed working against real
# data; filtered calls get the EM-MCP-equivalent query with $filter.
_ASSET_FIELDS = """
      id
      name
      vendor
      model
      firmwareVersion
      criticality
      lastSeen
      ips(first: 5) { nodes }
      risk { totalRisk pluginCount unresolvedEvents }
"""

_QUERY_ASSETS_PLAIN = (
    "query Q($pageSize: Int!) { assets(first: $pageSize) { totalCount nodes { "
    + _ASSET_FIELDS
    + " } } }"
)

_QUERY_ASSETS_FILTERED = (
    "query Q($pageSize: Int!, $filter: AssetExpressionsParams) { "
    "assets(first: $pageSize, filter: $filter) { totalCount nodes { "
    + _ASSET_FIELDS
    + " } } }"
)

# Tenable's AssetExpressionsParams op vocabulary (see EM-MCP's
# tools/_enums.py) -- only the two ops this module needs.
_EXPR_IN = "In"
_EXPR_BETWEEN = "Between"
_EXPR_AND = "And"

_CRITICALITY_ENUM = {
    "none": "NoneCriticality",
    "low": "LowCriticality",
    "medium": "MediumCriticality",
    "high": "HighCriticality",
}
_CRITICALITY_ORDINAL = ["none", "low", "medium", "high"]


def _build_filter(params: dict[str, Any]) -> dict | None:
    """Translate this module's natural-language params into Tenable's
    `AssetExpressionsParams` expression tree. Returns None when no
    filter is needed (an unfiltered `assets(first: N)` fetch)."""
    parts: list[dict] = []

    criticality_at_least = params.get("criticality_at_least")
    if criticality_at_least:
        idx = _CRITICALITY_ORDINAL.index(criticality_at_least)
        values = [_CRITICALITY_ENUM[level] for level in _CRITICALITY_ORDINAL[idx:]]
        parts.append({"field": "criticality", "op": _EXPR_IN, "values": values})

    subnet = params.get("subnet")
    if subnet:
        network = ipaddress.ip_network(subnet, strict=False)
        parts.append(
            {
                "field": "ips",
                "op": _EXPR_BETWEEN,
                "values": [str(network.network_address), str(network.broadcast_address)],
            }
        )

    if not parts:
        return None
    if len(parts) == 1:
        return parts[0]
    return {"op": _EXPR_AND, "expressions": parts}


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
        if criticality_at_least is not None and criticality_at_least not in _CRITICALITY_ORDINAL:
            raise ValueError(
                f"criticality_at_least must be one of {_CRITICALITY_ORDINAL}, "
                f"got {criticality_at_least!r}"
            )

        subnet = params.get("subnet")
        if subnet is not None:
            try:
                ipaddress.ip_network(subnet, strict=False)
            except ValueError as e:
                raise ValueError(f"invalid subnet CIDR {subnet!r}: {e}") from e

        site_uuid = params.get("site_uuid")
        site_name = params.get("site_name")

        return {
            "limit": limit,
            "criticality_at_least": criticality_at_least,
            "subnet": subnet,
            "site_uuid": site_uuid,
            "site_name": site_name,
        }

    async def _resolve_icp_machine_id(self, client: TenableClient, params: dict[str, Any]) -> str:
        """Assets live on paired ICPs, not the EM root -- resolve which
        ICP to query rather than ever hitting `<base>/graphql` for
        asset data (that was confirmed live to fail with a
        GraphQL-wrapped 404; see design-notes.md Sec 0.6)."""
        site_uuid = params.get("site_uuid")
        site_name = params.get("site_name")
        if site_uuid or site_name:
            return await client.resolve_site_machine_id(site_uuid=site_uuid, site_name=site_name)

        icps = await client.list_paired_icps()
        if not icps:
            raise ValueError(
                "No paired ICPs found on this Enterprise Manager. Asset data lives on "
                "paired ICPs, not the EM root, so at least one ICP must be paired before "
                "this report can run."
            )
        if len(icps) > 1:
            names = ", ".join(sorted(i["name"] for i in icps))
            raise ValueError(
                f"Multiple paired ICPs found ({names}); pass `site_uuid` or `site_name` "
                "to pick which one this report should query."
            )
        return icps[0]["machine_id"]

    async def fetch_data(self, client: TenableClient, params: dict[str, Any]) -> dict[str, Any]:
        # Phase 0: single connection, no cursor pagination yet. A `limit`
        # beyond one page's worth of matching assets will need the
        # cursor-following loop flagged in design-notes.md Sec 4 before
        # this module can be trusted at 10k-asset scale. The filter
        # (criticality/subnet) is applied server-side via GraphQL, so at
        # least it's the *matching* assets that get capped by `limit`,
        # not an arbitrary first page of the whole inventory.
        icp_machine_id = await self._resolve_icp_machine_id(client, params)
        filt = _build_filter(params)
        if filt is not None:
            data = await client.query(
                _QUERY_ASSETS_FILTERED,
                variables={"pageSize": params["limit"], "filter": filt},
                icp_machine_id=icp_machine_id,
            )
        else:
            data = await client.query(
                _QUERY_ASSETS_PLAIN,
                variables={"pageSize": params["limit"]},
                icp_machine_id=icp_machine_id,
            )
        connection = data.get("assets") or {}
        return {
            "total_count": connection.get("totalCount") or 0,
            "nodes": connection.get("nodes") or [],
        }

    def to_markdown_context(self, data: dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
        assets = []
        for node in data.get("nodes") or []:
            ips = (node.get("ips") or {}).get("nodes") or []
            risk = node.get("risk") or {}
            assets.append(
                {
                    "name": node.get("name") or "(unnamed)",
                    "vendor": node.get("vendor") or "",
                    "model": node.get("model") or "",
                    "firmware_version": node.get("firmwareVersion") or "",
                    "criticality": (node.get("criticality") or "none").lower(),
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
