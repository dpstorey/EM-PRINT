# SPDX-License-Identifier: Apache-2.0
"""policy_findings report module.

GraphQL surface confirmed against EM-MCP's real, production
`tools/policies.py` (see ../../../../../EM-MCP/tenable-ot-mcp/src/tenable_ot_mcp/tools/policies.py)
rather than guessed. This is `policyFindings` -- a per-(policy x
asset) hit record -- and is a *different* GraphQL type from
`findings` (the vulnerability_findings module's per-(asset x plugin)
instance record), even though both surface as "findings" in plain
English. Unlike vulnerability_findings, this surface's filter field
names match the returned field names directly (no `pluginSeverity`-
style prefixing quirk).

This is also the answer to Dom's compliance-page question
(design-notes.md / phase2-plan.md "Compliance-page question,
answered"): there is no `complianceChecks`/`violations` GraphQL type
anywhere in EM-MCP's surface. The GUI's "Compliance"/"Policy
Violations" pages are backed by this same `policyFindings` query,
just under a different UI label -- real, queryable data, nothing
cobbled together, just not named "compliance" at the schema level.

Sort (added 2026-08-26, §0.20): a real schema introspection query Dom
ran shows `PolicyFindingsSortParams.field` is typed exactly
`PolicyFindingFilterField` -- the SAME enum that backs
`PolicyFindingsExpressionsParams`'s filter `field` argument. That
means the complete field list is schema-confirmed for both filtering
and sorting at once, not something to infer from a capture (unlike
vulnerability_findings, which only got this same treatment after an
earlier, more conservative revision -- see that module's docstring).
`_POLICY_SORT_FIELD` below maps every `_COLUMN_REGISTRY` column that
has a matching enum value; a few real, displayed columns
(`resolved_hits`, `active_policy_hits`, `policy_level`,
`policy_enabled`, and the `event_type_*` sub-fields) are excluded
because the enum has no matching entry for them specifically (the
enum's `eventType` value refers to sorting by the whole nested object,
not one of its sub-fields, so it isn't mapped to any of this module's
`event_type_*` columns to avoid overclaiming what that would do).
Omitting `sort` still returns rows most-recently-hit first
(`lastHitTime DescNullLast`), unchanged from before.

`status` (revised 2026-08-26, §0.20): the same introspection query
also settles a real error inherited from EM-MCP's own uncertain
docstring. `query_policy_findings`'s docstring only gave examples
("Open"/"Resolved") without a closed list, so this module treated
`status` as an arbitrary unvalidated string -- but the schema shows
`PolicyFinding.status` is typed exactly `FindingStatus`, the same
strict 3-value enum (`Active`/`Resolved`/`Resurfaced`) vulnerability_
findings already validates against. "Open" was never a real value.
`status` is now validated the same way vulnerability_findings does
(one or more of active/resolved/resurfaced, `In` filter), replacing
the old unvalidated-string behavior.
"""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any, Callable

from ...tenable_client import TenableClient
from .. import _base

# Field selection mirrors EM-MCP's policy-findings `_FINDING_FIELDS`
# (tools/policies.py) exactly: id/policyTitle/severity/status/
# firstHitTime/lastHitTime/activeHits/resolvedHits/activePolicyHits/
# pluginId/pluginName/category on the finding itself, `eventType
# {type group description category family}`, `policy {id title level
# disabled}`, and `srcAssets`/`dstAssets` (each `first: 5`, matching
# EM-MCP's own cap -- not raised here since that cap's rationale
# wasn't documented and this project doesn't guess past confirmed
# usage). $sort is declared as a variable and now populated either
# from a caller's resolved `sort` param or the fixed `_DEFAULT_SORT`
# fallback.
#
# Dom's introspection query (2026-08-26) also confirmed a much richer
# real field set on `PolicyFinding` not selected here yet: flat
# (non-nested) `srcNames`/`srcIps`/`srcMacs`/`dstNames`/`dstIps`/
# `dstMacs`, `assetsTypes`/`assetsCriticalities`/`assetsVendors`/
# `assetsFamilies`/`assetsModels`/`assetsPurdueLevels`/
# `assetsLocations`, `protocols`, `mitreTechniques`/`mitreTactics`,
# `resolvedOn`/`resolvedUser`, `pluginSynopsis`/`pluginDescription`/
# `pluginSolution`, `comment`, `trend`, and `lastHitId`. Not added as
# columns now -- out of scope for this revision -- but confirmed real
# and safe to add in a future pass without needing a fresh schema
# check. Also confirmed: `policy` is a GraphQL *interface* (implemented
# by 8 concrete policy types), not a plain object type -- the
# `{id title level disabled}` selection below has been used
# successfully in EM-MCP's own daily production queries, which is why
# it was trusted originally, but this project hasn't independently
# schema-verified those 4 fields are on the `Policy` interface itself
# (vs. only certain implementations) -- worth a targeted check if this
# selection ever errors live.
_QUERY_POLICY_FINDINGS = """
query Q($pageSize: Int!, $after: String, $filter: PolicyFindingsExpressionsParams, $search: String, $sort: [PolicyFindingsSortParams!]) {
  policyFindings(first: $pageSize, after: $after, filter: $filter, search: $search, sort: $sort) {
    totalCount
    pageInfo { hasNextPage endCursor }
    nodes {
      id
      policyTitle
      severity
      status
      firstHitTime
      lastHitTime
      activeHits
      resolvedHits
      activePolicyHits
      pluginId
      pluginName
      category
      eventType { type group description category family }
      policy { id title level disabled }
      srcAssets(first: 5) { nodes { id name type } }
      dstAssets(first: 5) { nodes { id name type } }
    }
  }
}
"""

# Fixed fallback sort, used when a caller omits `sort` entirely --
# same value this module always sent before `sort` was customizable.
_DEFAULT_SORT = [{"field": "lastHitTime", "direction": "DescNullLast"}]

# Same canonical op vocabulary as the other two modules.
_EXPR_EQUAL = "Equal"
_EXPR_IN = "In"
_EXPR_AND = "And"

# Confirmed via EM-MCP's tools/_enums.py (_POLICY_LEVEL /
# to_policy_level()) -- note the different casing convention from
# vulnerability_findings' Criticality-style enum: no "...Level" or
# "...Criticality" suffix here, just "None"/"Low"/"Medium"/"High".
_POLICY_LEVEL_ORDINAL = ["none", "low", "medium", "high"]
_POLICY_LEVEL_ENUM = {"none": "None", "low": "Low", "medium": "Medium", "high": "High"}
_POLICY_LEVEL_DISPLAY = {"none": "None", "low": "Low", "medium": "Medium", "high": "High"}

# Confirmed via Dom's introspection query (2026-08-26, §0.20):
# `PolicyFinding.status` is typed `FindingStatus`, the exact same
# strict 3-value enum vulnerability_findings validates against --
# EM-MCP's own docstring examples ("Open"/"Resolved") were misleading;
# "Open" is not a real value. Replaces the earlier unvalidated-raw-
# string behavior.
_FINDING_STATUS_ENUM = {
    "active": "Active",
    "resolved": "Resolved",
    "resurfaced": "Resurfaced",
}

_PAGE_CHUNK = 500
_SAFETY_MAX_FINDINGS = 50_000


def _display_policy_level(raw: str | None) -> str:
    return _POLICY_LEVEL_DISPLAY.get((raw or "").strip().lower(), raw or "")


def _join_asset_names(connection: dict[str, Any] | None) -> str:
    names = [n.get("name") for n in (connection or {}).get("nodes") or [] if n.get("name")]
    return " ".join(names)


def _yes_no(value: Any) -> Any:
    if value is None:
        return value
    return "Yes" if value else "No"


def _render_cell(value: Any) -> str:
    """Same final str-and-escape pass as asset_inventory's/
    vulnerability_findings' `_render_cell` (duplicated, not shared --
    see design-notes.md). `policy_title`/`plugin_name` are the
    realistic free-text candidates here."""
    if value is None or value == "":
        return ""
    text = str(value).replace("|", "\\|")
    return " ".join(text.split())


# Column registry -- purely static, no custom-field-name resolution
# needed (unlike asset_inventory), so `columns` resolves fully inside
# validate_params().
_COLUMN_REGISTRY: dict[str, tuple[str, Callable[[dict[str, Any]], Any]]] = {
    "finding_id": ("Finding ID", lambda n: n.get("id")),
    "policy_title": ("Policy", lambda n: n.get("policyTitle")),
    "severity": ("Severity", lambda n: _display_policy_level(n.get("severity"))),
    "status": ("Status", lambda n: n.get("status")),
    "first_hit": ("First Hit", lambda n: n.get("firstHitTime")),
    "last_hit": ("Last Hit", lambda n: n.get("lastHitTime")),
    "active_hits": ("Active Hits", lambda n: n.get("activeHits")),
    "resolved_hits": ("Resolved Hits", lambda n: n.get("resolvedHits")),
    "active_policy_hits": ("Active Policy Hits", lambda n: n.get("activePolicyHits")),
    "plugin_id": ("Plugin ID", lambda n: n.get("pluginId")),
    "plugin_name": ("Plugin", lambda n: n.get("pluginName")),
    "category": ("Category", lambda n: n.get("category")),
    "event_type": ("Event Type", lambda n: (n.get("eventType") or {}).get("type")),
    "event_type_group": ("Event Type Group", lambda n: (n.get("eventType") or {}).get("group")),
    "event_type_family": ("Event Type Family", lambda n: (n.get("eventType") or {}).get("family")),
    "event_type_description": ("Event Type Description", lambda n: (n.get("eventType") or {}).get("description")),
    "policy_id": ("Policy ID", lambda n: (n.get("policy") or {}).get("id")),
    "policy_level": ("Policy Level", lambda n: _display_policy_level((n.get("policy") or {}).get("level"))),
    "policy_enabled": ("Policy Enabled", lambda n: _yes_no(not (n.get("policy") or {}).get("disabled")) if n.get("policy") else None),
    "src_assets": ("Source Assets", lambda n: _join_asset_names(n.get("srcAssets"))),
    "dst_assets": ("Destination Assets", lambda n: _join_asset_names(n.get("dstAssets"))),
}

_DEFAULT_COLUMNS = (
    "policy_title",
    "severity",
    "status",
    "category",
    "active_hits",
    "first_hit",
    "last_hit",
    "src_assets",
    "dst_assets",
)


def _resolve_columns(requested: list[str]) -> list[str]:
    name_to_key = {key.lower(): key for key in _COLUMN_REGISTRY}
    resolved: list[str] = []
    seen: set[str] = set()
    for raw in requested:
        key = name_to_key.get(raw.strip().lower())
        if key is None:
            raise ValueError(
                f"Unknown column {raw!r}. Available columns: {sorted(_COLUMN_REGISTRY)}."
            )
        if key not in seen:
            seen.add(key)
            resolved.append(key)
    if not resolved:
        raise ValueError(
            "columns must not be empty; omit it entirely to use the default columns "
            f"{list(_DEFAULT_COLUMNS)}."
        )
    return resolved


# Sort (2026-08-26, §0.20): which `_COLUMN_REGISTRY` columns can be
# passed to `sort`, mapped to the real GraphQL sort field name.
# Schema-confirmed via `PolicyFindingsSortParams.field`'s type
# (`PolicyFindingFilterField`) -- see module docstring. Excluded:
# `resolved_hits`/`active_policy_hits` (real display fields, but no
# matching enum value -- not filterable/sortable at all on this
# surface), `policy_level`/`policy_enabled` (derived from the nested
# `policy` interface, no matching flat enum value), and every
# `event_type_*` column (the enum's `eventType` value sorts by the
# whole nested object, not a specific sub-field, so mapping any single
# `event_type_*` column to it would overclaim what it actually does).
_POLICY_SORT_FIELD: dict[str, str] = {
    "finding_id": "id",
    "policy_title": "policyTitle",
    "severity": "severity",
    "status": "status",
    "first_hit": "firstHitTime",
    "last_hit": "lastHitTime",
    "active_hits": "activeHits",
    "plugin_id": "pluginId",
    "plugin_name": "pluginName",
    "category": "category",
    # "policyId" is a real, separate enum value from the nested
    # `policy.id` this column's getter reads -- almost certainly the
    # same underlying value exposed as a flat filter/sort key. Mapped
    # here on that basis; if that assumption is ever wrong, this is
    # the one entry to double-check first.
    "policy_id": "policyId",
    # "srcAssets"/"dstAssets" are literally valid enum values despite
    # being connections -- same precedent as asset_inventory's
    # confirmed-sortable `macs`/`ips` connections.
    "src_assets": "srcAssets",
    "dst_assets": "dstAssets",
}

_POLICY_SORT_DIRECTIONS = {"asc": "AscNullLast", "desc": "DescNullLast"}


def _resolve_sort(requested: list[str]) -> list[dict[str, str]]:
    """Resolve a caller's raw `sort` request into Tenable's real
    `[{"field": ..., "direction": "AscNullLast"|"DescNullLast"}]`
    shape for the `policyFindings` query's `sort` argument. Same
    selector language as the other modules (stable column key,
    optionally prefixed `-` for descending) -- purely static, no
    per-ICP resolution needed, so this runs entirely inside
    validate_params()."""
    name_to_key = {key.lower(): key for key in _COLUMN_REGISTRY}
    resolved: list[dict[str, str]] = []
    for raw in requested:
        spec = raw.strip()
        if spec.startswith("-"):
            direction_word, spec = "desc", spec[1:].strip()
        else:
            direction_word = "asc"
        key = name_to_key.get(spec.lower())
        if key is None:
            raise ValueError(f"Unknown column {spec!r}. Available columns: {sorted(_COLUMN_REGISTRY)}.")
        sort_field = _POLICY_SORT_FIELD.get(key)
        if sort_field is None:
            raise ValueError(
                f"Column {spec!r} can't be sorted on (no matching field on this GraphQL "
                f"surface's sort/filter enum). Sortable columns: {sorted(_POLICY_SORT_FIELD)}."
            )
        resolved.append({"field": sort_field, "direction": _POLICY_SORT_DIRECTIONS[direction_word]})
    return resolved


def _build_filter(params: dict[str, Any]) -> dict | None:
    """Translate this module's natural-language params into Tenable's
    `PolicyFindingsExpressionsParams` expression tree. Returns None
    when no filter is needed."""
    parts: list[dict] = []

    severity_at_least = params.get("severity_at_least")
    if severity_at_least:
        idx = _POLICY_LEVEL_ORDINAL.index(severity_at_least)
        values = [_POLICY_LEVEL_ENUM[level] for level in _POLICY_LEVEL_ORDINAL[idx:]]
        parts.append({"field": "severity", "op": _EXPR_IN, "values": values})

    status = params.get("status")
    if status:
        values = [_FINDING_STATUS_ENUM[s] for s in status]
        parts.append({"field": "status", "op": _EXPR_IN, "values": values})

    policy_id = params.get("policy_id")
    if policy_id:
        parts.append({"field": "policyId", "op": _EXPR_EQUAL, "values": [policy_id]})

    plugin_id = params.get("plugin_id")
    if plugin_id:
        parts.append({"field": "pluginId", "op": _EXPR_EQUAL, "values": [plugin_id]})

    mitre_technique = params.get("mitre_technique")
    if mitre_technique:
        parts.append({"field": "mitreTechniques", "op": _EXPR_EQUAL, "values": [mitre_technique]})

    if not parts:
        return None
    if len(parts) == 1:
        return parts[0]
    return {"op": _EXPR_AND, "expressions": parts}


class PolicyFindingsModule(_base.ReportModule):
    template_name = "template.md.j2"

    _KNOWN_PARAMS = frozenset(
        {
            "limit",
            "severity_at_least",
            "status",
            "policy_id",
            "plugin_id",
            "mitre_technique",
            "site_uuid",
            "site_name",
            "search",
            "columns",
            "sort",
        }
    )

    def validate_params(self, params: dict[str, Any]) -> dict[str, Any]:
        unknown = set(params) - self._KNOWN_PARAMS
        if unknown:
            raise ValueError(
                f"Unknown param(s) for policy_findings: {sorted(unknown)}. "
                f"Supported params: {sorted(self._KNOWN_PARAMS)}."
            )

        limit = params.get("limit")
        if limit is not None:
            try:
                limit = int(limit)
            except (TypeError, ValueError) as e:
                raise ValueError(f"limit must be an integer, got {params.get('limit')!r}") from e
            if limit < 1:
                raise ValueError(f"limit must be >= 1, got {limit}")
            limit = min(limit, _SAFETY_MAX_FINDINGS)

        severity_at_least = params.get("severity_at_least")
        if severity_at_least is not None and severity_at_least not in _POLICY_LEVEL_ORDINAL:
            raise ValueError(
                f"severity_at_least must be one of {_POLICY_LEVEL_ORDINAL}, got {severity_at_least!r}"
            )

        # `status` (revised 2026-08-26, §0.20): now validated against
        # the real `FindingStatus` enum (active/resolved/resurfaced),
        # same as vulnerability_findings -- see module docstring for
        # why the old unvalidated-raw-string behavior was wrong.
        # Accepts one value, several values, or a comma-separated
        # string, same shape as vulnerability_findings' `status`.
        status_param = params.get("status")
        if status_param is None:
            status = None
        else:
            if isinstance(status_param, str):
                status_param = [s.strip() for s in status_param.split(",")]
            if not isinstance(status_param, (list, tuple)):
                raise ValueError(f"status must be a string or list of strings, got {status_param!r}")
            status_list = [str(s).strip() for s in status_param if str(s).strip()]
            invalid = [s for s in status_list if s not in _FINDING_STATUS_ENUM]
            if invalid:
                raise ValueError(
                    f"status must be one or more of {sorted(_FINDING_STATUS_ENUM)}, got {invalid!r}"
                )
            status = status_list or None

        policy_id = params.get("policy_id")
        plugin_id = params.get("plugin_id")
        mitre_technique = params.get("mitre_technique")
        site_uuid = params.get("site_uuid")
        site_name = params.get("site_name")
        search = params.get("search")

        columns_param = params.get("columns")
        if columns_param is None:
            columns = list(_DEFAULT_COLUMNS)
        else:
            if isinstance(columns_param, str):
                columns_param = [c.strip() for c in columns_param.split(",")]
            if not isinstance(columns_param, (list, tuple)):
                raise ValueError(f"columns must be a list of column names, got {columns_param!r}")
            raw_columns = [str(raw).strip() for raw in columns_param if str(raw).strip()]
            if not raw_columns:
                raise ValueError(
                    "columns must not be empty; omit it entirely to use the default columns "
                    f"{list(_DEFAULT_COLUMNS)}."
                )
            columns = _resolve_columns(raw_columns)

        # `sort` (new 2026-08-26, §0.20): optional list of column
        # selectors (or a comma-separated string), each optionally
        # prefixed `-` for descending. Only the columns in
        # `_POLICY_SORT_FIELD` are accepted -- see that dict's comment
        # for what's excluded and why. Omitting `sort` keeps the fixed
        # `lastHitTime DescNullLast` default.
        sort_param = params.get("sort")
        if sort_param is None:
            sort = None
        else:
            if isinstance(sort_param, str):
                sort_param = [c.strip() for c in sort_param.split(",")]
            if not isinstance(sort_param, (list, tuple)):
                raise ValueError(f"sort must be a list of column names, got {sort_param!r}")
            raw_sort = [str(raw).strip() for raw in sort_param if str(raw).strip()]
            if not raw_sort:
                raise ValueError("sort must not be empty; omit it entirely for the default order.")
            sort = _resolve_sort(raw_sort)

        return {
            "limit": limit,
            "severity_at_least": severity_at_least,
            "status": status,
            "policy_id": policy_id,
            "plugin_id": plugin_id,
            "mitre_technique": mitre_technique,
            "site_uuid": site_uuid,
            "site_name": site_name,
            "search": search,
            "columns": columns,
            "sort": sort,
        }

    async def _resolve_icp_machine_id(self, client: TenableClient, params: dict[str, Any]) -> str:
        """Policy findings live on paired ICPs, not the EM root -- same
        resolution as asset_inventory's/vulnerability_findings'
        `_resolve_icp_machine_id` (duplicated rather than shared, see
        module docstring)."""
        site_uuid = params.get("site_uuid")
        site_name = params.get("site_name")
        if site_uuid or site_name:
            return await client.resolve_site_machine_id(site_uuid=site_uuid, site_name=site_name)

        icps = await client.list_paired_icps()
        if not icps:
            raise ValueError(
                "No paired ICPs found on this Enterprise Manager. Policy finding data "
                "lives on paired ICPs, not the EM root, so at least one ICP must be "
                "paired before this report can run."
            )
        if len(icps) > 1:
            names = ", ".join(sorted(i["name"] for i in icps))
            raise ValueError(
                f"Multiple paired ICPs found ({names}); pass `site_uuid` or `site_name` "
                "to pick which one this report should query."
            )
        return icps[0]["machine_id"]

    async def fetch_data(self, client: TenableClient, params: dict[str, Any]) -> dict[str, Any]:
        icp_machine_id = await self._resolve_icp_machine_id(client, params)

        filt = _build_filter(params)
        search = params.get("search")
        limit = params["limit"]  # None means "no cap -- fetch every match"
        resolved_sort = params["sort"] if params["sort"] is not None else _DEFAULT_SORT

        nodes: list[dict[str, Any]] = []
        total_count = 0
        cursor: str | None = None

        while limit is None or len(nodes) < limit:
            page_size = _PAGE_CHUNK if limit is None else min(_PAGE_CHUNK, limit - len(nodes))
            variables: dict[str, Any] = {"pageSize": page_size, "sort": resolved_sort}
            if cursor is not None:
                variables["after"] = cursor
            if filt is not None:
                variables["filter"] = filt
            if search:
                variables["search"] = search

            data = await client.query(
                _QUERY_POLICY_FINDINGS, variables=variables, icp_machine_id=icp_machine_id
            )
            connection = data.get("policyFindings") or {}
            total_count = connection.get("totalCount") or 0
            page_nodes = connection.get("nodes") or []
            nodes.extend(page_nodes)

            page_info = connection.get("pageInfo") or {}
            cursor = page_info.get("endCursor")
            if not page_info.get("hasNextPage") or not page_nodes or not cursor:
                break
            if len(nodes) >= _SAFETY_MAX_FINDINGS:
                break

        return {
            "total_count": total_count,
            "nodes": nodes if limit is None else nodes[:limit],
            "columns": params["columns"],
        }

    async def list_columns(
        self,
        client: TenableClient | None = None,
        site_uuid: str | None = None,
        site_name: str | None = None,
    ) -> list[dict[str, str]]:
        """Every column this module can project via `columns`, in
        registry order. `client`/`site_uuid`/`site_name` accepted for
        signature parity with the other modules' `list_columns` but
        unused -- no custom fields or per-ICP labels on this surface.

        Each entry also reports `sortable` -- whether this column can
        be passed to `sort`. See `_POLICY_SORT_FIELD`'s comment for
        which columns aren't and why."""
        return [
            {"key": key, "label": label, "sortable": key in _POLICY_SORT_FIELD}
            for key, (label, _getter) in _COLUMN_REGISTRY.items()
        ]

    def default_columns(self) -> list[str]:
        return list(_DEFAULT_COLUMNS)

    def to_markdown_context(self, data: dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
        column_keys: list[str] = data["columns"]
        columns = [{"key": key, "label": _render_cell(_COLUMN_REGISTRY[key][0])} for key in column_keys]

        findings = []
        for node in data.get("nodes") or []:
            cells = [_render_cell(_COLUMN_REGISTRY[key][1](node)) for key in column_keys]
            findings.append({"cells": cells})

        return {
            "report_title": "Policy Findings",
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "total_count": data.get("total_count", 0),
            "returned_count": len(findings),
            "columns": columns,
            "findings": findings,
        }


MODULE = PolicyFindingsModule()
