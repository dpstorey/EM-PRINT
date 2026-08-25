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
at scale: fetch_data() below follows `pageInfo.hasNextPage` +
`endCursor` to collect up to `limit` matching assets across as many
requests as needed, so pushing the filter into the query itself means
the whole EM/ICP inventory gets filtered before that cap applies --
not just whatever happened to fit in one page.
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from typing import Any

from ...tenable_client import TenableClient
from .. import _base

# Matches EM-MCP's real, production-proven `_QUERY_ASSETS` shape
# (tools/assets.py) exactly: $filter and $search both declared, values
# omitted from `variables` (not sent as null) when not supplied. An
# earlier revision of this module split this into two separate query
# strings after live 404s that looked like they were caused by merely
# declaring $filter -- that theory didn't survive further testing
# (design-notes.md Sec 0.4/0.6): the real cause was querying EM root
# instead of a paired ICP, and once that was fixed, there was no
# further evidence the declared-but-unused $filter mattered at all.
# Reunified back to one query to match EM-MCP's real, working shape
# rather than carrying forward an unnecessary workaround.
_QUERY_ASSETS = """
query Q($pageSize: Int!, $after: String, $filter: AssetExpressionsParams, $search: String) {
  assets(first: $pageSize, after: $after, filter: $filter, search: $search) {
    totalCount
    pageInfo { hasNextPage endCursor }
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

# Tenable's AssetExpressionsParams op vocabulary (see EM-MCP's
# tools/_enums.py) -- only the two ops this module needs.
_EXPR_IN = "In"
_EXPR_BETWEEN = "Between"
_EXPR_AND = "And"

# Per-request page size used while following pageInfo/endCursor (§0.9:
# Dom's explicit call -- "there's no point in having a report if it
# doesn't list all the assets" -- retired the old 500-asset hard cap;
# `limit` is now optional and omitting it means "fetch every matching
# asset"). _SAFETY_MAX_ASSETS is *not* a product limit the caller can
# reach intentionally -- it's a circuit breaker so a malformed
# `pageInfo` response (hasNextPage stuck true) can't spin this loop
# forever. No real OT deployment should ever approach it.
_PAGE_CHUNK = 500
_SAFETY_MAX_ASSETS = 50_000

_CRITICALITY_ENUM = {
    "none": "NoneCriticality",
    "low": "LowCriticality",
    "medium": "MediumCriticality",
    "high": "HighCriticality",
}
_CRITICALITY_ORDINAL = ["none", "low", "medium", "high"]

# Display labels for the report table -- Tenable's ..Criticality enum
# ("LowCriticality" etc.), matched case-insensitively, mapped to the
# same Low/Medium/High/None wording used in Tenable's own interface
# (rather than the lowercased-enum-string "lowcriticality" this used
# to render as).
_CRITICALITY_DISPLAY = {
    "nonecriticality": "None",
    "lowcriticality": "Low",
    "mediumcriticality": "Medium",
    "highcriticality": "High",
}


def _display_criticality(raw: str | None) -> str:
    return _CRITICALITY_DISPLAY.get((raw or "").strip().lower(), "None")


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

    _KNOWN_PARAMS = frozenset(
        {"limit", "criticality_at_least", "subnet", "site_uuid", "site_name", "search"}
    )

    def validate_params(self, params: dict[str, Any]) -> dict[str, Any]:
        unknown = set(params) - self._KNOWN_PARAMS
        if unknown:
            # Fail loudly rather than silently ignore a param name the
            # caller (often an LLM guessing) invented. A silently-dropped
            # filter still returns a "successful" report -- just not the
            # one that was asked for, which is worse than an error. Seen
            # live: a `search` param was invented before this module
            # supported it, silently ignored, and returned an unfiltered
            # first-`limit` page while claiming to match a location.
            raise ValueError(
                f"Unknown param(s) for asset_inventory: {sorted(unknown)}. "
                f"Supported params: {sorted(self._KNOWN_PARAMS)}."
            )

        # `limit` is optional and now uncapped by default: omitting it
        # means "fetch every matching asset" (§0.9). When given, it must
        # be a positive integer; only clamped against the
        # _SAFETY_MAX_ASSETS circuit breaker, not an artificial product
        # ceiling.
        limit = params.get("limit")
        if limit is not None:
            try:
                limit = int(limit)
            except (TypeError, ValueError) as e:
                raise ValueError(f"limit must be an integer, got {params.get('limit')!r}") from e
            if limit < 1:
                raise ValueError(f"limit must be >= 1, got {limit}")
            limit = min(limit, _SAFETY_MAX_ASSETS)

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
        search = params.get("search")

        return {
            "limit": limit,
            "criticality_at_least": criticality_at_least,
            "subnet": subnet,
            "site_uuid": site_uuid,
            "site_name": site_name,
            "search": search,
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
        # Cursor-following pagination: a single GraphQL request's
        # `first: N` is not guaranteed to return N nodes in one round
        # trip (seen live: a job with the default limit=100 stopped
        # after exactly 100 nodes even though 3,461 assets matched), so
        # this loops on `pageInfo.hasNextPage` + `endCursor` -- the same
        # pattern EM-MCP's real tools/assets.py exposes to its LLM
        # caller ("keep paging while has_more is true") -- until either
        # `limit` matching assets have been collected or the server
        # reports no more pages. As of §0.9, `limit` defaults to None
        # (no cap): "there's no point in having a report if it doesn't
        # list all the assets" (Dom). Only the _SAFETY_MAX_ASSETS
        # circuit breaker bounds the unlimited case -- it exists purely
        # to stop a malformed `pageInfo` response from looping forever,
        # not as a product ceiling. The filter (criticality/subnet/
        # search) is applied server-side via GraphQL, so it's the
        # *matching* assets that get paged through, not an arbitrary
        # slice of the whole inventory.
        icp_machine_id = await self._resolve_icp_machine_id(client, params)
        filt = _build_filter(params)
        search = params.get("search")
        limit = params["limit"]  # None means "no cap -- fetch every match"

        nodes: list[dict[str, Any]] = []
        total_count = 0
        cursor: str | None = None

        while limit is None or len(nodes) < limit:
            page_size = _PAGE_CHUNK if limit is None else min(_PAGE_CHUNK, limit - len(nodes))
            variables: dict[str, Any] = {"pageSize": page_size}
            if cursor is not None:
                variables["after"] = cursor
            if filt is not None:
                variables["filter"] = filt
            if search:
                variables["search"] = search

            data = await client.query(
                _QUERY_ASSETS, variables=variables, icp_machine_id=icp_machine_id
            )
            connection = data.get("assets") or {}
            total_count = connection.get("totalCount") or 0
            page_nodes = connection.get("nodes") or []
            nodes.extend(page_nodes)

            page_info = connection.get("pageInfo") or {}
            cursor = page_info.get("endCursor")
            # Defensive stop: no next page, or a page claiming more but
            # returning neither nodes nor a cursor to follow -- avoid an
            # infinite loop on a malformed response.
            if not page_info.get("hasNextPage") or not page_nodes or not cursor:
                break
            # Circuit breaker: stop even if the server still claims more
            # pages exist. Not a real product ceiling -- see the
            # _SAFETY_MAX_ASSETS comment above.
            if len(nodes) >= _SAFETY_MAX_ASSETS:
                break

        return {
            "total_count": total_count,
            "nodes": nodes if limit is None else nodes[:limit],
        }

    def to_markdown_context(self, data: dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
        assets = []
        for node in data.get("nodes") or []:
            ips = (node.get("ips") or {}).get("nodes") or []
            risk = node.get("risk") or {}
            total_risk = risk.get("totalRisk")
            assets.append(
                {
                    "name": node.get("name") or "(unnamed)",
                    "vendor": node.get("vendor") or "",
                    "model": node.get("model") or "",
                    "firmware_version": node.get("firmwareVersion") or "",
                    "criticality": _display_criticality(node.get("criticality")),
                    # An asset can legitimately have several NICs/IPs; showing
                    # only ips[0] silently dropped the rest. Space-joined so
                    # the cell wraps on word boundaries in the HTML output
                    # (the theme's CSS never sets white-space: nowrap on
                    # table cells -- see _HTML_SHELL in render.py) rather than
                    # overflowing the column. A plain space needs no Markdown
                    # escaping, unlike a literal "|" would (render.py produces
                    # the HTML by running this Markdown through
                    # python-markdown's `tables` extension, so an unescaped
                    # "|" in a cell would be misread as a column separator).
                    # GraphQL fetch is still capped at the first 5 IPs (see
                    # _QUERY_ASSETS* above) -- fine for Phase 0, but an asset
                    # with more than 5 interfaces would still be truncated.
                    "ip": " ".join(ips) if ips else "",
                    "last_seen": node.get("lastSeen") or "",
                    "total_risk": f"{total_risk:.1f}" if isinstance(total_risk, (int, float)) else "",
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
