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

`columns` (§0.10) lets a caller pick which fields show up in the
report and in what order, out of every field this module knows how to
project (`_COLUMN_REGISTRY` below). The GraphQL query always fetches
the full registry's worth of fields regardless of which columns were
actually requested -- `columns` is a *display* projection, not a
*fetch* filter, which keeps the query static and avoids the risk of
dynamically assembling GraphQL query text per request.
"""

from __future__ import annotations

import ipaddress
from datetime import UTC, datetime
from typing import Any, Callable

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
#
# Field selection (§0.10, corrected against Dom's real schema paste in
# §0.11) starts from EM-MCP's real, production `_ASSET_BASE` fragment
# (id/name/type/superType/category/vendor/model/firmwareVersion/os/
# family/description/location/purdueLevel/criticality/hidden/
# runStatus/extendedRunStatus/firstSeen/lastSeen/lastUpdate/
# lifecycleStatus/ips/macs/segments/risk/customField1-10 -- confirmed
# working in EM-MCP's daily production use) plus every additional
# scalar/StringConnection field Dom's own GraphQL schema paste (§0.11)
# confirms actually exists on the Asset type: `serial`, `slot`,
# `backplane { name size }`, `osDetails { name architecture version }`,
# `runStatusTime`, `attackVector`, `hardwareState`, `discontinuedDate`,
# `replacementProduct`, `lastHit`, `lastSnapshot`, `subnets`, `tags`.
# Deliberately NOT selected despite existing on the schema: `sources`
# (a `LeanSourceConnection` whose node shape isn't confirmed -- adding
# it blind risks breaking every report if the guessed sub-field name
# is wrong, since GraphQL failures are all-or-nothing per request);
# `directIps`/`directMacs`/`networkInterfaces`/`directNetworkInterfaces`/
# `ipSegments`/`relationships`/`detailedSources` (richer/relationship
# data, not a flat tabulatable asset attribute); `events*`/`plugins*`/
# `revision*` (separate entities -- vulnerabilities and history, not
# asset attributes); `details`/`layout` (opaque JSON/UI-layout blobs).
# `ips`/`macs` raised to `first: 50` (from the earlier `first: 5`) to
# match EM-MCP's real fragment -- incidentally closes the "an asset
# with >5 NICs gets truncated" gap flagged in design-notes.md §4.
_QUERY_ASSETS = """
query Q($pageSize: Int!, $after: String, $filter: AssetExpressionsParams, $search: String) {
  assets(first: $pageSize, after: $after, filter: $filter, search: $search) {
    totalCount
    pageInfo { hasNextPage endCursor }
    nodes {
      id
      name
      type
      superType
      category
      vendor
      model
      firmwareVersion
      os
      osDetails { name architecture version }
      family
      description
      location
      purdueLevel
      criticality
      hidden
      runStatus
      runStatusTime
      extendedRunStatus
      lifecycleStatus
      firstSeen
      lastSeen
      lastHit
      lastSnapshot
      lastUpdate
      serial
      slot
      backplane { name size }
      hardwareState
      discontinuedDate
      replacementProduct
      ips(first: 50) { nodes }
      macs(first: 50) { nodes }
      subnets(first: 50) { nodes }
      tags(first: 50) { nodes }
      segments(first: 50) { nodes { name } }
      attackVector
      risk { totalRisk pluginCount unresolvedEvents }
      customField1
      customField2
      customField3
      customField4
      customField5
      customField6
      customField7
      customField8
      customField9
      customField10
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


def _fmt_risk(value: Any) -> Any:
    return f"{value:.1f}" if isinstance(value, (int, float)) else value


def _join_nodes(connection: dict[str, Any] | None) -> str:
    return " ".join((connection or {}).get("nodes") or [])


def _join_segment_names(connection: dict[str, Any] | None) -> str:
    names = [s.get("name") for s in (connection or {}).get("nodes") or [] if s.get("name")]
    return " ".join(names)


def _yes_no(value: Any) -> Any:
    if value is None:
        return value
    return "Yes" if value else "No"


def _render_cell(value: Any) -> str:
    """Final str-and-escape pass applied to every table cell,
    regardless of which column it came from.

    render.py generates report HTML by running this module's rendered
    Markdown through python-markdown's `tables` extension (see
    render.py's docstring), not a separate HTML template -- so an
    unescaped literal "|" in a cell gets misread as a column
    separator, and an embedded newline breaks the one-row-per-line
    table format. That was already handled for the hand-picked
    original 9 columns (none of which could realistically contain
    either); now that `columns` (§0.10) opens up free-text fields
    like `description` and the 10 custom-field slots -- values real
    operators type themselves -- both are realistic enough to guard
    against here, once, for every column, rather than per-getter.
    """
    if value is None or value == "":
        return ""
    text = str(value).replace("|", "\|")
    return " ".join(text.split())


# Column registry (§0.10): every field this module can project into a
# report column, keyed by a stable name a caller passes via `columns`.
# Each entry is (display label, getter(raw GraphQL asset node) -> raw
# value | None) -- getters return an unformatted value (or None/""),
# and `_render_cell` above does the final str-and-escape pass uniformly
# for every column afterwards.
_COLUMN_REGISTRY: dict[str, tuple[str, Callable[[dict[str, Any]], Any]]] = {
    "asset_id": ("Asset ID", lambda n: n.get("id")),
    "name": ("Asset", lambda n: n.get("name") or "(unnamed)"),
    "type": ("Type", lambda n: n.get("type")),
    "super_type": ("Super Type", lambda n: n.get("superType")),
    "category": ("Category", lambda n: n.get("category")),
    "vendor": ("Vendor", lambda n: n.get("vendor")),
    "model": ("Model", lambda n: n.get("model")),
    "firmware_version": ("Firmware", lambda n: n.get("firmwareVersion")),
    "os": ("OS", lambda n: n.get("os")),
    "os_version": ("OS Version", lambda n: (n.get("osDetails") or {}).get("version")),
    "os_architecture": ("OS Architecture", lambda n: (n.get("osDetails") or {}).get("architecture")),
    "family": ("Family", lambda n: n.get("family")),
    "description": ("Description", lambda n: n.get("description")),
    "location": ("Location", lambda n: n.get("location")),
    "purdue_level": ("Purdue Level", lambda n: n.get("purdueLevel")),
    "criticality": ("Criticality", lambda n: _display_criticality(n.get("criticality"))),
    "hidden": ("Hidden", lambda n: _yes_no(n.get("hidden"))),
    "run_status": ("Run Status", lambda n: n.get("runStatus")),
    "run_status_time": ("Run Status Time", lambda n: n.get("runStatusTime")),
    "extended_run_status": ("Extended Run Status", lambda n: n.get("extendedRunStatus")),
    "lifecycle_status": ("Lifecycle Status", lambda n: n.get("lifecycleStatus")),
    "first_seen": ("First Seen", lambda n: n.get("firstSeen")),
    "last_seen": ("Last Seen", lambda n: n.get("lastSeen")),
    "last_update": ("Last Update", lambda n: n.get("lastUpdate")),
    "serial": ("Serial Number", lambda n: n.get("serial")),
    "slot": ("Slot", lambda n: n.get("slot")),
    "backplane_name": ("Backplane", lambda n: (n.get("backplane") or {}).get("name")),
    "backplane_size": ("Backplane Size", lambda n: (n.get("backplane") or {}).get("size")),
    "hardware_state": ("Hardware State", lambda n: n.get("hardwareState")),
    "discontinued_date": ("Discontinued At", lambda n: n.get("discontinuedDate")),
    "replacement_product": ("Replacement Product", lambda n: n.get("replacementProduct")),
    "last_hit": ("Last Hit", lambda n: n.get("lastHit")),
    "last_snapshot": ("Last Snapshot", lambda n: n.get("lastSnapshot")),
    "ip": ("IPs", lambda n: _join_nodes(n.get("ips"))),
    "mac": ("MACs", lambda n: _join_nodes(n.get("macs"))),
    "subnets": ("Subnets", lambda n: _join_nodes(n.get("subnets"))),
    "tags": ("Tags", lambda n: _join_nodes(n.get("tags"))),
    "segments": ("Segments", lambda n: _join_segment_names(n.get("segments"))),
    "attack_vector": ("Attack Vector", lambda n: n.get("attackVector")),
    "total_risk": ("Risk", lambda n: _fmt_risk((n.get("risk") or {}).get("totalRisk"))),
    "plugin_count": ("Plugin Count", lambda n: (n.get("risk") or {}).get("pluginCount")),
    "unresolved_events": ("Unresolved Events", lambda n: (n.get("risk") or {}).get("unresolvedEvents")),
    "custom_field_1": ("Custom Field 1", lambda n: n.get("customField1")),
    "custom_field_2": ("Custom Field 2", lambda n: n.get("customField2")),
    "custom_field_3": ("Custom Field 3", lambda n: n.get("customField3")),
    "custom_field_4": ("Custom Field 4", lambda n: n.get("customField4")),
    "custom_field_5": ("Custom Field 5", lambda n: n.get("customField5")),
    "custom_field_6": ("Custom Field 6", lambda n: n.get("customField6")),
    "custom_field_7": ("Custom Field 7", lambda n: n.get("customField7")),
    "custom_field_8": ("Custom Field 8", lambda n: n.get("customField8")),
    "custom_field_9": ("Custom Field 9", lambda n: n.get("customField9")),
    "custom_field_10": ("Custom Field 10", lambda n: n.get("customField10")),
}

_KNOWN_COLUMNS = frozenset(_COLUMN_REGISTRY)

# Omitting `columns` must reproduce exactly the report shape every
# earlier §0.x entry in design-notes.md was tested against -- this is
# that original hand-picked 9-column set, unchanged.
_DEFAULT_COLUMNS = (
    "name",
    "vendor",
    "model",
    "firmware_version",
    "criticality",
    "ip",
    "last_seen",
    "total_risk",
    "unresolved_events",
)


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
        {
            "limit",
            "criticality_at_least",
            "subnet",
            "site_uuid",
            "site_name",
            "search",
            "columns",
        }
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

        # `columns` (§0.10): optional list of column names (or a
        # comma-separated string -- LLM callers sometimes serialize
        # arrays that way), validated against the full _COLUMN_REGISTRY,
        # deduped, and order-preserving so a caller can also control
        # column order. Omitting it reproduces the original 9-column
        # report (_DEFAULT_COLUMNS) so existing callers see no change.
        columns_param = params.get("columns")
        if columns_param is None:
            columns = list(_DEFAULT_COLUMNS)
        else:
            if isinstance(columns_param, str):
                columns_param = [c.strip() for c in columns_param.split(",")]
            if not isinstance(columns_param, (list, tuple)):
                raise ValueError(
                    f"columns must be a list of column names, got {columns_param!r}"
                )
            seen: set[str] = set()
            columns = []
            for raw in columns_param:
                key = str(raw).strip().lower()
                if not key:
                    continue
                if key not in _KNOWN_COLUMNS:
                    raise ValueError(
                        f"Unknown column {key!r}. Available columns: {sorted(_KNOWN_COLUMNS)}."
                    )
                if key not in seen:
                    seen.add(key)
                    columns.append(key)
            if not columns:
                raise ValueError(
                    "columns must not be empty; omit it entirely to use the default columns "
                    f"{list(_DEFAULT_COLUMNS)}."
                )

        return {
            "limit": limit,
            "criticality_at_least": criticality_at_least,
            "subnet": subnet,
            "site_uuid": site_uuid,
            "site_name": site_name,
            "search": search,
            "columns": columns,
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
        # slice of the whole inventory. `columns` (§0.10) doesn't
        # change this query at all -- every registry field is always
        # fetched; column selection is applied later, in
        # to_markdown_context, as a display projection.
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

    def list_columns(self) -> list[dict[str, str]]:
        """Every column this module can project via `columns`, in
        registry order -- not part of the ReportModule ABC (only this
        module supports column selection so far); the MCP-side
        `list_available_columns` tool checks for this method with
        `getattr(..., None)` rather than requiring every module to
        implement it."""
        return [{"key": key, "label": label} for key, (label, _getter) in _COLUMN_REGISTRY.items()]

    def default_columns(self) -> list[str]:
        """Columns used when `columns` is omitted -- see `list_available_columns`."""
        return list(_DEFAULT_COLUMNS)

    def to_markdown_context(self, data: dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
        column_keys: list[str] = params["columns"]
        columns = [{"key": key, "label": _COLUMN_REGISTRY[key][0]} for key in column_keys]

        assets = []
        for node in data.get("nodes") or []:
            cells = [_render_cell(_COLUMN_REGISTRY[key][1](node)) for key in column_keys]
            assets.append({"cells": cells})

        return {
            "report_title": "Asset Inventory",
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "total_count": data.get("total_count", 0),
            "returned_count": len(assets),
            "columns": columns,
            "assets": assets,
        }


MODULE = AssetInventoryModule()
