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

Sort: same deliberate simplification as vulnerability_findings (see
that module's docstring for the full reasoning) -- fixed, unconditional
`lastHitTime DescNullLast`, matching EM-MCP's own proven usage,
no caller-customizable `sort` param yet.

`status` here is intentionally NOT validated against a fixed enum:
EM-MCP's own docstring for `query_policy_findings` only gives examples
("Open"/"Resolved") without a closed list, and its implementation
passes the value straight through unvalidated. Inventing a strict
enum here would risk rejecting a real, valid status EM-MCP itself
doesn't pretend to know the full set of.
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
# usage). $sort is declared as a variable (matching EM-MCP's own query
# shape) but always sent as the fixed `_DEFAULT_SORT` below.
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

# Fixed, unconditional sort -- see module docstring.
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
        # Unvalidated raw string -- see module docstring.
        parts.append({"field": "status", "op": _EXPR_EQUAL, "values": [status]})

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

        status = params.get("status")  # unvalidated raw string, see module docstring
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

        nodes: list[dict[str, Any]] = []
        total_count = 0
        cursor: str | None = None

        while limit is None or len(nodes) < limit:
            page_size = _PAGE_CHUNK if limit is None else min(_PAGE_CHUNK, limit - len(nodes))
            variables: dict[str, Any] = {"pageSize": page_size, "sort": _DEFAULT_SORT}
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
        unused -- no custom fields or per-ICP labels on this surface."""
        return [{"key": key, "label": label} for key, (label, _getter) in _COLUMN_REGISTRY.items()]

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
