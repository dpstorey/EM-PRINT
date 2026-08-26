"""risk_profile report module — a single-asset risk-profile dossier.

Built 2026-08-26 in response to Dom pointing at EM-MCP's `prompt/AGENT.md`:
~43% of that system prompt (the "HTML Report Workflow" section, plus
several "Common Mistakes" bullets that exist only to police it) is
scaffolding to make an LLM-authored, from-scratch Python/HTML-generation
pipeline reliable -- write a script via `fs_write_file`, base64-embed a
banner, verify it landed first in `<body>` via `grep`/`sed`, check the
file is >10KB, etc. This module replaces that pipeline's job (assembling
one asset's data into a themed report) with the same deterministic
module+render+theme architecture every other report in this project
already uses -- no LLM-generated code, no banner-verification dance.

What did NOT get simpler, and why this is a new module shape rather than
a copy of asset_inventory/vulnerability_findings/policy_findings:

1. This is a synthesis report, not one GraphQL list rendered as a table.
   It stitches together `asset(id)` core fields, `asset(id).plugins`
   (vulnerabilities), `asset(id).events`, and `links` (1-hop comms/
   attack-pathway neighborhood) -- four separate queries against one
   asset, mirroring EM-MCP's own `get_asset_intelligence` bundle
   (tools/correlation.py) plus `get_communication_paths`
   (tools/topology.py), which already join exactly this data server-side
   for the same reason. Field selections below are copied from those
   tools' own GraphQL text (already "verified live" per their comments),
   not reinvented -- except `_QUERY_ASSET_VULNS`, which merges two of
   EM-MCP's own confirmed shapes (assets.py's richer field selection +
   correlation.py's `$filter: PluginExpressionsParams` argument on the
   same `asset(id).plugins` traversal) -- a safe combination of two
   already-confirmed shapes, but not itself independently re-verified
   against a schema introspection query the way this project's other
   sort/filter work was. Flag this if a live run against it errors.

2. Risk grades are explicitly NOT derivable from a GraphQL field the way
   this project's other data is -- there's no `raiseScore` field on
   `Asset`. Instead there are two real sources, and this module supports
   both:

   a. Already assigned in Tenable itself. Per Dom (2026-08-26): "we can
      still use the custom fields as the means of getting the grades
      assigned to the assets" -- Tenable's asset-level custom fields
      (`customField1`..`customField10`, the same operator-labelled slots
      asset_inventory already exposes as columns) are a real place an
      operator can have already typed a grade per asset, per dimension,
      through Tenable's own UI. `risk_grade_fields` maps a dimension
      code to the custom field that holds it (by the operator's live
      label, e.g. "RAISE-R", or the stable slot name) -- resolved the
      same way asset_inventory resolves a custom-field column name,
      against the same live `customFields` query (duplicated here, not
      shared -- see design-notes.md). When configured, this module reads
      those values straight off the asset record it already fetched; no
      extra round trip beyond the one label-lookup query.

   b. Supplied fresh by the calling LLM/analyst for this report,
      overriding whatever's in Tenable (`risk_grades`, keyed the same
      way). Merge order: custom-field values first, then `risk_grades`
      overrides per dimension -- same "explicit override always wins"
      convention this project already uses for `theme_overrides`.

   Deliberately rubric-agnostic either way (revised same day, per Dom:
   "the grade system ... should be flexible to accommodate other models
   than my RAISE model -- deeper risk modelling is the kind of thing
   many customers implement", and separately: "I use letters but it's
   probably even better to use numbers"). Nothing here hardcodes RAISE's
   five dimensions, a letter scale, or RAISE's own "Grade A vs Category
   A" caveat -- `risk_model` (display name), `risk_grades` /
   `risk_grade_fields` (arbitrary dimension codes, letters or numbers or
   words), `risk_dimension_labels` (short code -> long display name),
   and `risk_scale_note` (freeform caveat text) are all caller-supplied.
   This module validates shape only -- string keys, scalar values -- and
   never validates against or computes a specific scale. RAISE is simply
   what Dom's own callers pass today, not something this module assumes.

3. "Attack pathways" in EM-MCP's own tools (`query_attack_pathways`) is,
   by its own docstring, just the 1-hop `links` neighborhood -- "the
   server does NOT compute paths ... that's the AI's job." So
   `comm_peers` below IS the attack-pathway data; there's no separate,
   more-complex graph-walk query to replicate.

4. Communication peers are enriched with the peer asset's own name/IPs
   (2026-08-26 revision, per Dom's review of the first report: the
   "Name/IP" column needs actual identity, not a bare id the caller has
   to separately look up). `_QUERY_ASSET_LINKS` only returns
   `asset1`/`asset2` as scalar ids (confirmed -- neither EM-MCP's
   topology.py nor this module's own `_LINK_FIELDS` selects a nested
   object off them), so `fetch_data` does one batched follow-up lookup
   -- `_QUERY_PEER_ASSETS`, filtering the *plural* `assets(...)` query
   by `field: "id", op: In` against the distinct peer ids from the
   links page. That reuses asset_inventory's own confirmed
   `assets(filter: AssetExpressionsParams)` shape (see its
   `_QUERY_ASSETS`), but filtering `assets` *by id* specifically has not
   itself been confirmed against a schema introspection query --
   unlike every other filter field this module uses, which were each
   copied from an already-proven EM-MCP call site. It's about as safe
   an assumption as GraphQL filtering gets (id-list filtering is
   close to universal), but flag it and verify against a live EM/ICP
   before relying on it, same as `_QUERY_ASSET_VULNS` above.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from typing import Any

from ...tenable_client import TenableClient
from .. import _base

# ----------------------------------------------------------------------
# GraphQL — field selections and queries, copied from EM-MCP's own
# confirmed shapes (tools/assets.py, tools/correlation.py,
# tools/topology.py) rather than reinvented. See module docstring
# point 1 for the one exception (`_QUERY_ASSET_VULNS`).
# ----------------------------------------------------------------------

_ASSET_FIELDS = """
  id
  name
  type
  superType
  category
  vendor
  model
  firmwareVersion
  os
  family
  description
  location
  purdueLevel
  criticality
  hidden
  runStatus
  extendedRunStatus
  firstSeen
  lastSeen
  lastUpdate
  lifecycleStatus
  ips(first: 50) { nodes }
  macs(first: 50) { nodes }
  segments(first: 50) { nodes { id name type } }
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
"""

_QUERY_ASSET = "query Q($id: ID!) { asset(id: $id) { " + _ASSET_FIELDS + " } }"

_VULN_FIELDS = """
  id
  name
  source
  family
  severity
  vprScore
  vprLevel
  cvss3Score
  totalAffectedAssets
  details {
    description
    solution
    cves
    cvssV3BaseScore
    cvssV3Vector
    exploitAvailable
    exploitedByMalware
    cisaKnownExploitedDates
    exploitCodeMaturity
    vulnPubDate
  }
"""

_QUERY_ASSET_VULNS = (
    "query Q($id: ID!, $pageSize: Int!, $filter: PluginExpressionsParams) {"
    "  asset(id: $id) {"
    "    plugins(first: $pageSize, filter: $filter) {"
    "      totalCount"
    "      nodes { " + _VULN_FIELDS + " }"
    "    }"
    "  }"
    "}"
)

_EVENT_FIELDS = """
  id
  time
  severity
  eventType { type group description category family }
  type
  srcIP
  dstIP
  protocolNiceName
  protocol
  port
  srcAssets(first: 5) { nodes { id name } }
  dstAssets(first: 5) { nodes { id name } }
  policy { id title level }
  resolved
  resolvedTs
"""

# Per-asset events must traverse asset(id).events (the top-level `events`
# filter doesn't include srcAssets/dstAssets) -- same note as EM-MCP's
# correlation.py._QUERY_EVENTS_FOR_ASSET, copied here for the same reason.
_QUERY_ASSET_EVENTS = (
    "query Q($id: ID!, $pageSize: Int!, $filter: EventsExpressionsParams, "
    "$sort: [EventsSortParams!]) {"
    "  asset(id: $id) {"
    "    events(first: $pageSize, filter: $filter, sort: $sort) {"
    "      totalCount"
    "      nodes { " + _EVENT_FIELDS + " }"
    "    }"
    "  }"
    "}"
)

_LINK_FIELDS = """
  id
  asset1
  asset2
  traffic
  convCount
  firstConv
  lastConv
  protocols(first: 20) { nodes { name ics } }
"""

# A link is keyed by asset1/asset2, either of which might be the queried
# asset -- OR the two equality clauses, same as EM-MCP's topology.py.
_QUERY_ASSET_LINKS = (
    "query Q($pageSize: Int!, $filter: LinkExpressionsParams, $sort: [LinkSortParams!]) {"
    "  links(first: $pageSize, filter: $filter, sort: $sort) {"
    "    totalCount"
    "    nodes { " + _LINK_FIELDS + " }"
    "  }"
    "}"
)

# Batched name/IP lookup for communication peers -- see module docstring
# point 4 for why this is a separate follow-up query (links only carry
# the peer's bare id) and the one unverified assumption it rests on
# (filtering `assets` by `id`).
_PEER_ASSET_FIELDS = """
  id
  name
  ips(first: 5) { nodes }
"""

_QUERY_PEER_ASSETS = (
    "query Q($pageSize: Int!, $filter: AssetExpressionsParams) {"
    "  assets(first: $pageSize, filter: $filter) {"
    "    nodes { " + _PEER_ASSET_FIELDS + " }"
    "  }"
    "}"
)

# Custom-field slot -> operator-configured label, resolved live. Mirrors
# asset_inventory's `_CustomFieldLabelCache` exactly (same query, same
# TTL, same icp-scoped cache key) -- duplicated rather than shared, same
# convention this project already uses (see design-notes.md).
_QUERY_CUSTOM_FIELDS = "query Q { customFields { fieldId userDefinedName valueType } }"

_CUSTOM_FIELD_SLOTS = [f"customField{i}" for i in range(1, 11)]


class _CustomFieldLabelCache:
    """Module-level {slot -> label} cache, scoped per ICP."""

    _TTL_SECONDS = 60.0
    _slot_to_label: dict[str, str] | None = None
    _cache_scope: str | None = None
    _ts: float = 0.0

    @classmethod
    async def get_or_fetch(cls, client: TenableClient, icp_machine_id: str | None) -> dict[str, str]:
        cache_scope = (icp_machine_id or "").strip("/")
        now = time.monotonic()
        if (
            cls._slot_to_label is not None
            and cls._cache_scope == cache_scope
            and (now - cls._ts) < cls._TTL_SECONDS
        ):
            return cls._slot_to_label
        data = await client.query(_QUERY_CUSTOM_FIELDS, icp_machine_id=icp_machine_id)
        slot_to_label: dict[str, str] = {}
        for entry in data.get("customFields") or []:
            slot = entry.get("fieldId")
            label = entry.get("userDefinedName")
            if slot and label:
                slot_to_label[slot] = label
        cls._slot_to_label = slot_to_label
        cls._cache_scope = cache_scope
        cls._ts = now
        return slot_to_label


_EXPR_EQUAL = "Equal"
_EXPR_GREATER_EQUAL = "GreaterEqual"
_EXPR_IN = "In"
_EXPR_AND = "And"
_EXPR_OR = "Or"

_SEVERITY_ORDINAL = ["info", "low", "medium", "high", "critical"]
_SEVERITY_ENUM = {
    "info": "Info",
    "low": "Low",
    "medium": "Medium",
    "high": "High",
    "critical": "Critical",
}

_DEFAULT_VULN_LIMIT = 100
_DEFAULT_EVENT_LIMIT = 20
_DEFAULT_PEER_LIMIT = 50
_MAX_LIMIT = 500

# Risk grading is intentionally rubric-agnostic -- see module docstring
# point 2. This module has NO concept of RAISE, or any other specific
# rubric or scale (letters, numbers, whatever); it only bounds the
# *shape* of whatever a caller supplies or a custom field already holds.
_MAX_RISK_DIMENSIONS = 20
_DEFAULT_RISK_MODEL_LABEL = "Risk Assessment"


def _unwrap_nodes(connection: dict[str, Any] | None) -> list[Any]:
    if not connection:
        return []
    return connection.get("nodes") or []


def _render_cell(value: Any) -> str:
    """Same final str-and-escape pass every other module's `_render_cell`
    uses (duplicated, not shared -- see design-notes.md)."""
    if value is None or value == "":
        return ""
    text = str(value).replace("|", "\\|")
    return " ".join(text.split())


def _project_asset(node: dict[str, Any]) -> dict[str, Any]:
    risk = node.get("risk") or {}
    return {
        "id": node.get("id"),
        "name": node.get("name") or "(unnamed)",
        "type": node.get("type"),
        "super_type": node.get("superType"),
        "category": node.get("category"),
        "vendor": node.get("vendor"),
        "model": node.get("model"),
        "firmware_version": node.get("firmwareVersion"),
        "os": node.get("os"),
        "family": node.get("family"),
        "description": _render_cell(node.get("description")),
        "location": node.get("location"),
        "purdue_level": node.get("purdueLevel"),
        "criticality": node.get("criticality"),
        "hidden": node.get("hidden"),
        "run_status": node.get("runStatus"),
        "extended_run_status": node.get("extendedRunStatus"),
        "first_seen": node.get("firstSeen"),
        "last_seen": node.get("lastSeen"),
        "last_update": node.get("lastUpdate"),
        "lifecycle_status": node.get("lifecycleStatus"),
        "ips": _unwrap_nodes(node.get("ips")),
        "macs": _unwrap_nodes(node.get("macs")),
        "segments": [s.get("name") for s in _unwrap_nodes(node.get("segments")) if s.get("name")],
        "total_risk": risk.get("totalRisk"),
        "plugin_count": risk.get("pluginCount"),
        "unresolved_events": risk.get("unresolvedEvents"),
    }


def _project_vuln(node: dict[str, Any]) -> dict[str, Any]:
    details = node.get("details") or {}
    cves = details.get("cves") or []
    return {
        "plugin_id": node.get("id"),
        "plugin_name": _render_cell(node.get("name")),
        "severity": node.get("severity"),
        "vpr_score": node.get("vprScore"),
        "vpr_level": node.get("vprLevel"),
        "cvss3_score": node.get("cvss3Score"),
        "cves": " ".join(cves) if isinstance(cves, list) else "",
        "exploit_available": bool(details.get("exploitAvailable")),
        "exploited_by_malware": bool(details.get("exploitedByMalware")),
        "kev": bool(details.get("cisaKnownExploitedDates")),
        "solution": _render_cell(details.get("solution")),
    }


def _project_event(node: dict[str, Any]) -> dict[str, Any]:
    event_type = node.get("eventType") or {}
    policy = node.get("policy") or {}
    src_assets = _unwrap_nodes(node.get("srcAssets"))
    dst_assets = _unwrap_nodes(node.get("dstAssets"))
    return {
        "id": node.get("id"),
        "time": node.get("time"),
        "type": event_type.get("type") or node.get("type"),
        "severity": node.get("severity"),
        "src_ip": node.get("srcIP"),
        "dst_ip": node.get("dstIP"),
        "protocol": node.get("protocolNiceName") or node.get("protocol"),
        "port": node.get("port"),
        "policy_title": _render_cell((policy or {}).get("title")),
        "resolved": node.get("resolved"),
        "src_names": ", ".join(a.get("name") or a.get("id") or "" for a in src_assets),
        "dst_names": ", ".join(a.get("name") or a.get("id") or "" for a in dst_assets),
    }


def _project_peer(
    link: dict[str, Any], self_id: str, peer_assets: dict[str, dict[str, Any]] | None = None
) -> dict[str, Any]:
    a1 = link.get("asset1")
    a2 = link.get("asset2")
    peer_id = a2 if a1 == self_id else a1
    protos = _unwrap_nodes(link.get("protocols"))
    peer_info = (peer_assets or {}).get(peer_id) or {}
    peer_name = peer_info.get("name") or peer_id
    peer_ips = _unwrap_nodes(peer_info.get("ips"))
    peer_display = f"{peer_name} ({', '.join(peer_ips)})" if peer_ips else (peer_name or "")
    return {
        "peer_asset_id": peer_id,
        "peer_display": _render_cell(peer_display),
        "protocols": ", ".join(p.get("name") for p in protos if p.get("name")),
        "industrial_protocols": ", ".join(p.get("name") for p in protos if p.get("ics")),
        "traffic": link.get("traffic"),
        "conversation_count": link.get("convCount"),
        "first_conversation": link.get("firstConv"),
        "last_conversation": link.get("lastConv"),
    }


def _clamp(value: int | None, default: int) -> int:
    if value is None:
        return default
    return max(1, min(int(value), _MAX_LIMIT))


def _normalize_str_list(value: Any, *, field: str) -> list[str]:
    if value is None:
        return []
    if isinstance(value, str):
        return [line.strip() for line in value.splitlines() if line.strip()]
    if isinstance(value, (list, tuple)):
        return [str(v).strip() for v in value if str(v).strip()]
    raise ValueError(f"{field} must be a string or list of strings, got {value!r}")


def _validate_risk_grades(value: Any) -> dict[str, str]:
    """Normalize an arbitrary risk rubric's grade dict to {str: str}.

    Deliberately rubric-agnostic (see module docstring point 2): this
    validates shape only -- non-empty string keys, scalar values
    coerced to display strings ("-" for missing/empty), a sane
    dimension-count cap against a malformed payload. Letters, numbers,
    or words are all just strings here; it never checks values against
    a specific scale and never computes a grade -- that judgment call
    belongs to whatever is guiding the calling LLM/analyst, or to
    whatever an operator already typed into Tenable's custom fields
    (see `risk_grade_fields`), not this module.
    """
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"risk_grades must be an object of {{dimension: value}}, got {value!r}")
    if len(value) > _MAX_RISK_DIMENSIONS:
        raise ValueError(f"risk_grades has {len(value)} dimensions; max {_MAX_RISK_DIMENSIONS}.")
    grades: dict[str, str] = {}
    for key, raw in value.items():
        key = str(key).strip()
        if not key:
            raise ValueError("risk_grades keys must be non-empty strings.")
        grades[key] = "-" if raw is None or raw == "" else str(raw).strip()
    return grades


def _validate_str_map(value: Any, *, field: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object of {{key: value}}, got {value!r}")
    return {str(k).strip(): str(v).strip() for k, v in value.items() if str(k).strip()}


def _resolve_custom_field_slot(spec: str, label_to_slot: dict[str, str]) -> str:
    """Resolve a `risk_grade_fields` value to a `customFieldN` slot.

    Accepts either the operator's live label (matched case-insensitively
    against the current `customFields` configuration, same as
    asset_inventory's column-name resolution) or the stable slot name
    directly (`customField3`, case-insensitive) -- the latter always
    works even if that slot has no configured label yet.
    """
    normalized = spec.strip()
    for slot, label in label_to_slot.items():
        if label.lower() == normalized.lower():
            return slot
    candidate = normalized[0].lower() + normalized[1:] if normalized else normalized
    if candidate in _CUSTOM_FIELD_SLOTS:
        return candidate
    known_labels = sorted(label_to_slot.values())
    raise ValueError(
        f"risk_grade_fields value {spec!r} does not match a configured custom-field label "
        f"({known_labels}) or a slot name (customField1..customField10)."
    )


class RiskProfileModule(_base.ReportModule):
    template_name = "template.md.j2"

    _KNOWN_PARAMS = frozenset(
        {
            "asset_id",
            "site_uuid",
            "site_name",
            "vuln_limit",
            "vuln_severity_at_least",
            "event_limit",
            "event_since",
            "event_resolved",
            "peer_limit",
            "peer_since",
            "risk_model",
            "risk_grades",
            "risk_grade_fields",
            "risk_dimension_labels",
            "risk_scale_note",
            "analyst_assessment",
            "data_limitations",
        }
    )

    def validate_params(self, params: dict[str, Any]) -> dict[str, Any]:
        unknown = set(params) - self._KNOWN_PARAMS
        if unknown:
            raise ValueError(
                f"Unknown param(s) for risk_profile: {sorted(unknown)}. "
                f"Supported params: {sorted(self._KNOWN_PARAMS)}."
            )

        asset_id = params.get("asset_id")
        if not asset_id or not isinstance(asset_id, str):
            raise ValueError("asset_id is required and must be a non-empty string.")

        vuln_severity_at_least = params.get("vuln_severity_at_least")
        if vuln_severity_at_least is not None and vuln_severity_at_least not in _SEVERITY_ORDINAL:
            raise ValueError(f"vuln_severity_at_least must be one of {_SEVERITY_ORDINAL}, got {vuln_severity_at_least!r}")

        event_resolved = params.get("event_resolved")
        if event_resolved is not None and not isinstance(event_resolved, bool):
            raise ValueError(f"event_resolved must be a boolean, got {event_resolved!r}")

        risk_model = params.get("risk_model")
        if risk_model is not None and not isinstance(risk_model, str):
            raise ValueError(f"risk_model must be a string, got {risk_model!r}")

        return {
            "asset_id": asset_id,
            "site_uuid": params.get("site_uuid"),
            "site_name": params.get("site_name"),
            "vuln_limit": _clamp(params.get("vuln_limit"), _DEFAULT_VULN_LIMIT),
            "vuln_severity_at_least": vuln_severity_at_least,
            "event_limit": _clamp(params.get("event_limit"), _DEFAULT_EVENT_LIMIT),
            "event_since": params.get("event_since"),
            "event_resolved": event_resolved,
            "peer_limit": _clamp(params.get("peer_limit"), _DEFAULT_PEER_LIMIT),
            "peer_since": params.get("peer_since"),
            "risk_model": (risk_model or _DEFAULT_RISK_MODEL_LABEL).strip() or _DEFAULT_RISK_MODEL_LABEL,
            "risk_grades": _validate_risk_grades(params.get("risk_grades")),
            "risk_grade_fields": _validate_str_map(params.get("risk_grade_fields"), field="risk_grade_fields"),
            "risk_dimension_labels": _validate_str_map(params.get("risk_dimension_labels"), field="risk_dimension_labels"),
            "risk_scale_note": _normalize_str_list(params.get("risk_scale_note"), field="risk_scale_note"),
            "analyst_assessment": _normalize_str_list(params.get("analyst_assessment"), field="analyst_assessment"),
            "data_limitations": _normalize_str_list(params.get("data_limitations"), field="data_limitations"),
        }

    async def _resolve_icp_machine_id(self, client: TenableClient, params: dict[str, Any]) -> str:
        """Same auto-resolve pattern as every other module here
        (duplicated, not shared -- see design-notes.md)."""
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
        icp_machine_id = await self._resolve_icp_machine_id(client, params)
        asset_id = params["asset_id"]

        asset_data = await client.query(_QUERY_ASSET, variables={"id": asset_id}, icp_machine_id=icp_machine_id)
        asset_node = asset_data.get("asset")
        if not asset_node:
            raise ValueError(f"No asset with id {asset_id!r} on this ICP.")

        # Risk grades already assigned in Tenable via custom fields
        # (module docstring point 2a) -- only fetched when the caller
        # configured `risk_grade_fields`, so a report that doesn't use
        # this feature costs nothing extra.
        custom_field_grades: dict[str, str] = {}
        risk_grade_fields = params.get("risk_grade_fields") or {}
        if risk_grade_fields:
            label_to_slot = await _CustomFieldLabelCache.get_or_fetch(client, icp_machine_id)
            for dimension, spec in risk_grade_fields.items():
                slot = _resolve_custom_field_slot(spec, label_to_slot)
                raw_value = asset_node.get(slot)
                custom_field_grades[dimension] = str(raw_value).strip() if raw_value else "-"

        vuln_filter = None
        severity_at_least = params.get("vuln_severity_at_least")
        if severity_at_least:
            idx = _SEVERITY_ORDINAL.index(severity_at_least)
            values = [_SEVERITY_ENUM[level] for level in _SEVERITY_ORDINAL[idx:]]
            vuln_filter = {"field": "severity", "op": _EXPR_IN, "values": values}
        vuln_data = await client.query(
            _QUERY_ASSET_VULNS,
            variables={"id": asset_id, "pageSize": params["vuln_limit"], "filter": vuln_filter},
            icp_machine_id=icp_machine_id,
        )
        vuln_block = (vuln_data.get("asset") or {}).get("plugins") or {}

        event_filter_parts = []
        if params.get("event_since"):
            event_filter_parts.append({"field": "time", "op": _EXPR_GREATER_EQUAL, "values": params["event_since"]})
        if params.get("event_resolved") is not None:
            event_filter_parts.append({"field": "resolved", "op": _EXPR_EQUAL, "values": [params["event_resolved"]]})
        event_filter = None
        if len(event_filter_parts) == 1:
            event_filter = event_filter_parts[0]
        elif len(event_filter_parts) > 1:
            event_filter = {"op": _EXPR_AND, "expressions": event_filter_parts}
        event_data = await client.query(
            _QUERY_ASSET_EVENTS,
            variables={
                "id": asset_id,
                "pageSize": params["event_limit"],
                "filter": event_filter,
                "sort": [{"field": "time", "direction": "DescNullLast"}],
            },
            icp_machine_id=icp_machine_id,
        )
        event_block = (event_data.get("asset") or {}).get("events") or {}

        side_match = {
            "op": _EXPR_OR,
            "expressions": [
                {"field": "asset1", "op": _EXPR_EQUAL, "values": [asset_id]},
                {"field": "asset2", "op": _EXPR_EQUAL, "values": [asset_id]},
            ],
        }
        if params.get("peer_since"):
            peer_filter = {
                "op": _EXPR_AND,
                "expressions": [side_match, {"field": "lastConv", "op": _EXPR_GREATER_EQUAL, "values": params["peer_since"]}],
            }
        else:
            peer_filter = side_match
        peer_data = await client.query(
            _QUERY_ASSET_LINKS,
            variables={
                "pageSize": params["peer_limit"],
                "filter": peer_filter,
                "sort": [{"field": "lastConv", "direction": "DescNullLast"}],
            },
            icp_machine_id=icp_machine_id,
        )
        peer_block = peer_data.get("links") or {}
        peer_nodes = peer_block.get("nodes") or []

        # Batched name/IP lookup for whatever peers came back -- see
        # module docstring point 4. Costs nothing extra when there are
        # no peers (e.g. an isolated asset).
        peer_ids = sorted(
            {
                (n.get("asset2") if n.get("asset1") == asset_id else n.get("asset1"))
                for n in peer_nodes
                if n.get("asset1") and n.get("asset2")
            }
        )
        peer_assets: dict[str, dict[str, Any]] = {}
        if peer_ids:
            peer_asset_data = await client.query(
                _QUERY_PEER_ASSETS,
                variables={
                    "pageSize": len(peer_ids),
                    "filter": {"field": "id", "op": _EXPR_IN, "values": peer_ids},
                },
                icp_machine_id=icp_machine_id,
            )
            for n in (peer_asset_data.get("assets") or {}).get("nodes") or []:
                if n.get("id"):
                    peer_assets[n["id"]] = n

        return {
            "asset": asset_node,
            "custom_field_grades": custom_field_grades,
            "vuln_nodes": vuln_block.get("nodes") or [],
            "vuln_total": vuln_block.get("totalCount") or 0,
            "event_nodes": event_block.get("nodes") or [],
            "event_total": event_block.get("totalCount") or 0,
            "peer_nodes": peer_nodes,
            "peer_total": peer_block.get("totalCount") or 0,
            "peer_assets": peer_assets,
        }

    def to_markdown_context(self, data: dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
        asset_id = params["asset_id"]
        asset = _project_asset(data["asset"])
        vulns = [_project_vuln(n) for n in data["vuln_nodes"]]
        events = [_project_event(n) for n in data["event_nodes"]]
        peers = [_project_peer(n, asset_id, data.get("peer_assets")) for n in data["peer_nodes"]]

        # Merge order: whatever's already assigned in Tenable via custom
        # fields first, then the caller's own `risk_grades` overrides
        # per dimension -- "explicit override always wins", the same
        # convention `theme_overrides` already uses in this project.
        risk_grades = dict(data.get("custom_field_grades") or {})
        risk_grades.update(params["risk_grades"])

        # Auto-disclose truncation on top of whatever the caller already
        # supplied in `data_limitations` -- doesn't depend on the caller
        # remembering to say so every time.
        auto_limitations: list[str] = []
        if len(vulns) < data["vuln_total"]:
            auto_limitations.append(f"Vulnerabilities: showing {len(vulns)} of {data['vuln_total']} total.")
        if len(events) < data["event_total"]:
            auto_limitations.append(f"Events: showing {len(events)} of {data['event_total']} total.")
        if len(peers) < data["peer_total"]:
            auto_limitations.append(f"Communication peers: showing {len(peers)} of {data['peer_total']} total.")

        return {
            "report_title": f"Asset Risk Profile — {asset['name']}",
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "asset": asset,
            "risk_model": params["risk_model"],
            "risk_grades": risk_grades,
            "risk_dimension_labels": params["risk_dimension_labels"],
            "risk_scale_note": params["risk_scale_note"],
            "vulnerabilities": vulns,
            "vuln_returned_count": len(vulns),
            "vuln_total_count": data["vuln_total"],
            "events": events,
            "event_returned_count": len(events),
            "event_total_count": data["event_total"],
            "peers": peers,
            "peer_returned_count": len(peers),
            "peer_total_count": data["peer_total"],
            "analyst_assessment": params["analyst_assessment"],
            "data_limitations": params["data_limitations"] + auto_limitations,
        }


MODULE = RiskProfileModule()
