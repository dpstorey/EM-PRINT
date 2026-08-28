# SPDX-License-Identifier: Apache-2.0
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
   (vulnerability findings), `policyFindings` (policy violation
   findings, see point 6), and `links` (1-hop comms/attack-pathway
   neighborhood) -- four separate queries against/about one asset,
   mirroring EM-MCP's own `get_asset_intelligence` bundle
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
   `risk_grade_descriptions` (short code -> freeform text explaining
   what this asset's assigned grade means for that dimension), and
   `risk_scale_note` (freeform caveat text) are all caller-supplied.
   This module validates shape only -- string keys, scalar values -- and
   never validates against or computes a specific scale. RAISE is simply
   what Dom's own callers pass today, not something this module assumes.

   **Table restructured to long form (2026-08-26, per Dom, who shared a
   reference screenshot).** The grade table was one wide row (each
   dimension code its own column, one shared row of grade letters) --
   Dom asked for a per-dimension row instead: `Category` | `Grade` |
   `Detail`, so the grade sits directly next to a description of what
   it means for that dimension, rather than requiring a reader to
   cross-reference a `risk_scale_note` written separately. `Category`
   reuses the exact same "{code} ({label})" formatting the old header
   row used; `Detail` is new -- there was no per-dimension description
   text anywhere in this module before, so `risk_grade_descriptions`
   is a new caller-supplied param (same shape as `risk_dimension_labels`
   -- {dimension: text}), not derived or computed. A dimension with no
   configured description renders a blank `Detail` cell, same as a
   `risk_grades` dimension with no configured label renders its bare
   code -- missing optional annotations degrade gracefully rather than
   erroring.

   **`Detail` lookup made deterministic, not caller-interpreted
   (2026-08-26, per Dom).** Dom asked directly: "is it clear to the
   model that the detail cells would refer to coordinates in this
   lookup table?", after sharing a full RAISE reference table (5 grades
   x 5 dimensions). It wasn't -- `risk_grade_descriptions` as it stood
   only said the text was "caller-supplied", nothing told a calling LLM
   it was supposed to be a (dimension, grade) lookup into a fixed table
   it would have to read correctly across five separate dimensions
   every report. Rather than just wording the docs better and hoping
   an LLM applies that consistently, the lookup itself moved into this
   module: `risk_grade_scale` takes the whole reference table once, as
   {dimension: {grade: description}}, and `to_markdown_context` indexes
   into it using `risk_grades`' already-resolved values -- the module
   does the coordinate lookup, not the calling model. Still fully
   rubric-agnostic (§ above) -- an object of objects, no fixed grade set
   or dimension set assumed, so a different methodology (numeric scale,
   different dimension codes, more or fewer grades) is just a
   differently-shaped table passed to the same param. `risk_grade_descriptions`
   still exists, now as a per-dimension override on top of whatever
   `risk_grade_scale` looked up -- same "explicit override always wins"
   merge order `risk_grades` itself already uses against custom fields.

   **Stored scale tables, so the calling LLM doesn't retype one every
   report (2026-08-26, per Dom).** Dom asked, reasonably, how a
   calling LLM (via LibreChat) is actually supposed to "use" a
   `risk_grade_scale` table day to day -- and pointed out the real
   problem himself: relying on an LLM to correctly paste a 25-cell
   reference table into every single `submit_report_job` call is
   exactly the kind of "trust the LLM to reproduce this exactly" risk
   this whole module exists to design around, just moved one step
   earlier than the lookup itself. `risk_grade_scale_name` fixes that:
   a caller saves a table *once* (`save_risk_grade_scale`, a new
   mcp_app.py tool -- see there) to this server's own writable /data
   mount, at `<data_dir>/risk_grade_scales/<name>.json` -- the exact
   same "drop a file at a known path on the bind mount, no code change
   or redeploy needed" pattern `get_ca_bundle_path` already uses for
   the TLS CA bundle (config.py). Every later report just passes
   `risk_grade_scale_name: "raise"` and the server resolves it from
   disk -- no table text in that call's arguments at all.

   This resolution happens in a new `resolve_stored_params` method,
   deliberately **not** part of the `ReportModule` ABC -- called by
   mcp_app.py via the same `getattr(instance, ..., None)` optional-hook
   pattern already used for asset_inventory's `list_columns`/
   `default_columns` (§0.10), so no other module is forced to support
   it. It runs *after* `validate_params` (so `risk_grade_scale_name`
   still gets a plain structural check there) and *before*
   `fetch_data` -- disk I/O has no natural home in either of those
   methods' existing contracts (`validate_params` is deliberately
   synchronous/I-O-free; `fetch_data` is for Tenable GraphQL, not
   local files), so this is a third, module-specific step slotted
   between them, only for modules that define it.

   Merge order, same "explicit override always wins" convention as
   everywhere else here: the stored table is the base, and an inline
   `risk_grade_scale` passed in *that same call* overrides it per
   (dimension, grade) -- lets a caller use the saved table for
   everything except a one-off correction, without touching the saved
   file. A `risk_grade_scale_name` that doesn't match a saved file
   raises naming the path it looked for and listing what *is* saved,
   rather than silently falling back to nothing.

3. "Attack pathways" in EM-MCP's own tools (`query_attack_pathways`) is,
   by its own docstring, just the 1-hop `links` neighborhood -- "the
   server does NOT compute paths ... that's the AI's job." So
   `comm_peers` below IS the attack-pathway data; there's no separate,
   more-complex graph-walk query to replicate.

4. Communication peers are enriched with the peer asset's own name/IPs
   (2026-08-26 revision, per Dom's review of the first report: the
   "Peer" column needs actual identity, not a bare id the caller has
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

   `_project_peer`'s display fallback (also 2026-08-26, same review
   round): name first; if no name but IPs exist, show the bare id
   alongside them (an id next to real IPs still has some anchoring
   value); if neither name nor IPs exist, fall back to the peer's MAC
   address(es) rather than a meaningless bare id; only fall all the way
   back to the id when the peer asset has none of name/IP/MAC.

5. Vulnerability findings are sorted by VPR score, highest first
   (2026-08-26, per Dom). Done client-side on the already-fetched page
   in Python, not via a GraphQL `sort` argument on `asset(id).plugins`
   -- unlike the top-level `findings` query the separate
   `vulnerability_findings` module queries (which does have a
   schema-confirmed `sort`), no sort argument on this nested `plugins`
   traversal has ever been confirmed in this project or in EM-MCP's own
   correlation.py, so sorting in Python avoids adding an unverified
   GraphQL assumption for a purely cosmetic ordering.

6. "Recent Events" was replaced with "Policy Violation Findings"
   (2026-08-26, per Dom, who asked directly whether a real
   asset-scoped `policyFindings` query existed). It does: Dom supplied
   a real browser network capture of Tenable OT's own UI querying
   `policyFindings(filter, search, sort, after, first)` scoped to one
   asset via `{"field": "srcNames", "op": "Contains", "values":
   ["attacker-pi"]}` -- a name-substring match against the finding's
   source-asset names, not an id filter. This is now the strongest kind
   of evidence this project uses (a live capture, same tier as the
   `assets` multi-key sort and `findingId`/`pluginVprScore` sort-field
   discoveries in design-notes.md §0.17/§0.19) and it directly
   contradicts the narrower picture from EM-MCP's own tool code alone
   (`tools/policies.py`'s `query_policy_findings` only exposes
   `policyId`/`severity`/`status`/`mitreTechniques`/`pluginId`/
   `lastHitTime` as filters, no `srcNames`, and has no `asset_id`
   param at all) -- the same recurring lesson this project keeps
   relearning: a production tool's own surface underclaims what its
   schema actually supports. `_QUERY_POLICY_FINDINGS` below reuses the
   capture's exact field selection (the `policyFinding` fragment, a
   rich set of real fields) and its exact multi-key sort
   (`severity`/`lastHitTime`/`id`, all `DescNullLast`/`DescNullLast`/
   `AscNullLast`).

   **`dstNames` confirmed and wired in (2026-08-26, second capture).**
   The first capture only proved `srcNames`; this module flagged
   `dstNames` as an unconfirmed sibling per §0.12's "don't guess a
   GraphQL field" lesson. Dom then supplied a second real capture --
   `policyFindings` filtered by `{"op": "And", "expressions":
   [{"field": "status", "op": "In", "values": ["Active",
   "Resurfaced"]}, {"field": "dstNames", "op": "Contains", "values":
   ["attacker-pi"]}]}` -- proving `dstNames Contains` is a real,
   independently-usable filter field, not a guess. The scoping filter
   below is now `Or(srcNames Contains <name>, dstNames Contains
   <name>)`, ANDed with `status`/`policy_since` when supplied (same
   `And`/`Or` composition Dom's own capture uses, just with the two
   name-fields under the Or instead of one name-field ANDed with
   status) -- so a report now surfaces policy violation findings where
   this asset was either the source or the destination of the flagged
   traffic, not source-only as before. The second capture's sort
   (`severity`/`lastHitTime`/`id`) is identical to the first capture's
   and to `_POLICY_FINDING_SORT` already in use here -- no change
   needed there. It also uses `slowCount: true` on the `policyFindings`
   call (for an exact rather than approximate `totalCount`), now added
   here too since this module's own truncation disclosure depends on
   an accurate total.

   Still a name-substring match, not an id-exact match, on both sides
   now -- an asset renamed since a finding was last hit, or another
   asset whose name happens to contain this one's name as a substring,
   remain real (if probably rare) edge cases on either the src or dst
   side.

   The second capture's richer field selection (`mitreTactics`,
   `srcIps`/`srcMacs`/`dstIps`/`dstMacs`, `eventType { type category
   exclusion actions canCapture }`, `assetsTypes`/`assetsCriticalities`/
   `assetsVendors`/`assetsFamilies`/`assetsModels`/`assetsPurdueLevels`/
   `assetsLocations`, `resolvedUser`/`resolvedOn`, `lastHitId`, and
   `type`/`vendor` on `srcAssets`/`dstAssets` nodes) is now confirmed
   live but deliberately not all pulled into `_POLICY_FINDING_FIELDS`
   below -- none of it is needed to fix the one limitation this round
   targeted (dst-side scoping), and adding unused columns just to prove
   a point isn't this module's job. Worth a follow-up if Dom wants any
   of it surfaced (e.g. `resolvedOn`/`resolvedUser` for resolved
   findings, or the asset-level `type`/`vendor`/`criticality` rollups
   for a multi-asset finding).

   The table now shows which side of the traffic this asset matched on
   (`src_names`/`dst_names`, both already projected by
   `_project_policy_finding` but previously unused by the template) --
   worth surfacing now that a finding can appear here purely because
   this asset was the *destination*, not the source, of the flagged
   traffic; showing only "Policy"/"Plugin" without that distinction
   would leave a reader guessing which role this asset played.
"""

from __future__ import annotations

import json
import re
import time
from datetime import UTC, datetime
from pathlib import Path
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

# Confirmed via two of Dom's own real browser network captures of
# Tenable OT's UI (2026-08-26, see module docstring point 6) -- field
# selection is the first capture's exact `policyFinding` fragment
# (trimmed to the subset useful for a single-asset table; every field
# kept below was in the real capture, none guessed), and the sort is
# both captures' identical multi-key sort. `Or(srcNames Contains
# <name>, dstNames Contains <name>)` (srcNames from the first capture,
# dstNames confirmed by the second) is how this module scopes an
# otherwise asset-agnostic query to one asset, on either side of the
# traffic.
_POLICY_FINDING_FIELDS = """
  id
  status
  severity
  policy { id title }
  pluginName
  mitreTechniques
  srcAssets(first: 5) { nodes { id name } }
  dstAssets(first: 5) { nodes { id name } }
  protocols
  firstHitTime
  lastHitTime
  activeHits
  resolvedHits
  comment
"""

# `slowCount: true` (also confirmed by the second capture) asks for an
# exact rather than approximate `totalCount` -- this module's own
# truncation disclosure ("showing N of M total") depends on that count
# being right, so it's worth the extra query cost the real UI already
# pays.
_QUERY_POLICY_FINDINGS = (
    "query Q($pageSize: Int!, $filter: PolicyFindingsExpressionsParams, "
    "$sort: [PolicyFindingsSortParams!]!) {"
    "  policyFindings(first: $pageSize, filter: $filter, sort: $sort, slowCount: true) {"
    "    totalCount"
    "    nodes { " + _POLICY_FINDING_FIELDS + " }"
    "  }"
    "}"
)

# The capture's exact multi-key sort (severity, then most-recent hit,
# then id as a stable tiebreaker) -- ranked by severity, per Dom.
_POLICY_FINDING_SORT = [
    {"field": "severity", "direction": "DescNullLast"},
    {"field": "lastHitTime", "direction": "DescNullLast"},
    {"field": "id", "direction": "AscNullLast"},
]

_POLICY_STATUS_ENUM = {"active": "Active", "resolved": "Resolved", "resurfaced": "Resurfaced"}

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
  macs(first: 5) { nodes }
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
_DEFAULT_POLICY_FINDING_LIMIT = 20
_DEFAULT_PEER_LIMIT = 50
_MAX_LIMIT = 500

# Risk grading is intentionally rubric-agnostic -- see module docstring
# point 2. This module has NO concept of RAISE, or any other specific
# rubric or scale (letters, numbers, whatever); it only bounds the
# *shape* of whatever a caller supplies or a custom field already holds.
_MAX_RISK_DIMENSIONS = 20
# 2026-08-26, per Dom's own live report: this used to be the string
# "Risk Assessment" -- which, combined with the heading template's own
# fixed "Risk Assessment" suffix, rendered "Risk Assessment Risk
# Assessment" whenever a caller omitted `risk_model` (every report so
# far had passed one, so this went unnoticed until now). Empty string
# is the correct default: it means "no display-name prefix", and the
# template (see template.md.j2) only adds a prefix + space when
# `risk_model` is non-empty, so an omitted `risk_model` now renders
# the heading as just "Risk Assessment", not doubled.
_DEFAULT_RISK_MODEL_LABEL = ""


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


def _project_policy_finding(node: dict[str, Any]) -> dict[str, Any]:
    policy = node.get("policy") or {}
    src_assets = _unwrap_nodes(node.get("srcAssets"))
    dst_assets = _unwrap_nodes(node.get("dstAssets"))
    mitre = node.get("mitreTechniques") or []
    protocols = node.get("protocols") or []
    return {
        "id": node.get("id"),
        "status": node.get("status"),
        "severity": node.get("severity"),
        "policy_title": _render_cell(policy.get("title")),
        "plugin_name": _render_cell(node.get("pluginName")),
        "mitre_techniques": ", ".join(mitre) if isinstance(mitre, list) else "",
        "src_names": ", ".join(a.get("name") or a.get("id") or "" for a in src_assets),
        "dst_names": ", ".join(a.get("name") or a.get("id") or "" for a in dst_assets),
        "protocols": ", ".join(protocols) if isinstance(protocols, list) else "",
        "first_hit_time": node.get("firstHitTime"),
        "last_hit_time": node.get("lastHitTime"),
        "active_hits": node.get("activeHits"),
        "resolved_hits": node.get("resolvedHits"),
        "comment": _render_cell(node.get("comment")),
    }


def _project_peer(
    link: dict[str, Any], self_id: str, peer_assets: dict[str, dict[str, Any]] | None = None
) -> dict[str, Any]:
    a1 = link.get("asset1")
    a2 = link.get("asset2")
    peer_id = a2 if a1 == self_id else a1
    protos = _unwrap_nodes(link.get("protocols"))
    peer_info = (peer_assets or {}).get(peer_id) or {}
    peer_name = peer_info.get("name")
    peer_ips = _unwrap_nodes(peer_info.get("ips"))
    peer_macs = _unwrap_nodes(peer_info.get("macs"))
    # Identity fallback chain, per Dom (2026-08-26): name > id, and when
    # there's neither a name nor an IP to show, a MAC address is a more
    # useful identifier than the bare asset id -- only fall all the way
    # back to the id when the peer asset has none of the three.
    if peer_name:
        base = peer_name
    elif peer_ips:
        base = peer_id
    elif peer_macs:
        base = ", ".join(peer_macs)
    else:
        base = peer_id
    peer_display = f"{base} ({', '.join(peer_ips)})" if peer_ips else base
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


def _normalize_policy_status(value: Any) -> list[str] | None:
    """`policy_status` -- one value, several, or a comma-separated
    string, always building an `In` filter. Same multi-value pattern
    `vulnerability_findings`/`policy_findings` already use for their
    own `status` param (design-notes.md §0.18/§0.20), against the same
    3-value `FindingStatus` enum (active/resolved/resurfaced)."""
    if value is None:
        return None
    if isinstance(value, str):
        raw = [v.strip() for v in value.split(",") if v.strip()]
    elif isinstance(value, (list, tuple)):
        raw = [str(v).strip() for v in value if str(v).strip()]
    else:
        raise ValueError(f"policy_status must be a string or list of strings, got {value!r}")
    if not raw:
        return None
    values: list[str] = []
    for v in raw:
        key = v.lower()
        if key not in _POLICY_STATUS_ENUM:
            raise ValueError(f"policy_status value {v!r} must be one of {sorted(_POLICY_STATUS_ENUM)}.")
        values.append(_POLICY_STATUS_ENUM[key])
    return values


def _validate_str_map(value: Any, *, field: str) -> dict[str, str]:
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"{field} must be an object of {{key: value}}, got {value!r}")
    return {str(k).strip(): str(v).strip() for k, v in value.items() if str(k).strip()}


def _validate_risk_grade_scale(value: Any) -> dict[str, dict[str, str]]:
    """Optional full grade-scale reference table: {dimension: {grade:
    description}}, e.g. an organization's own RAISE A-E x R/A/I/S/E
    matrix. Deliberately rubric-agnostic like every other risk-grading
    input here (§0.22) -- an object of objects, string keys/values
    only, no fixed grade set or dimension set assumed.

    2026-08-26, per Dom, who asked directly whether it was clear to a
    calling LLM that a `risk_grade_descriptions` entry was supposed to
    be a lookup into a fixed table like this one, keyed by dimension
    and this asset's own assigned grade -- it wasn't; nothing said so.
    Rather than trying to word that instruction well enough that an
    LLM reliably picks the right row/column every time across several
    dimensions, `risk_grade_scale` lets the module do that lookup
    itself in `to_markdown_context` (using `risk_grades`' already-
    validated values as the row key) -- the same "don't trust an LLM
    to do mechanically-checkable work" principle this whole project's
    module+render+theme architecture already runs on (see the module
    docstring's opening paragraph). `risk_grade_descriptions` still
    exists too, now as an explicit per-dimension override on top of
    whatever this lookup produces -- same "explicit override always
    wins" convention `risk_grades`/`risk_grade_fields` already use.
    """
    if value is None:
        return {}
    if not isinstance(value, dict):
        raise ValueError(f"risk_grade_scale must be an object of {{dimension: {{grade: description}}}}, got {value!r}")
    scale: dict[str, dict[str, str]] = {}
    for dim, row in value.items():
        dim = str(dim).strip()
        if not dim:
            raise ValueError("risk_grade_scale dimension keys must be non-empty strings.")
        if not isinstance(row, dict):
            raise ValueError(f"risk_grade_scale[{dim!r}] must be an object of {{grade: description}}, got {row!r}")
        scale[dim] = {str(g).strip(): str(d).strip() for g, d in row.items() if str(g).strip()}
    return scale


# ----------------------------------------------------------------------
# Stored risk_grade_scale tables, saved once to this server's own
# writable /data mount so a calling LLM can reference one by name
# instead of retyping a whole reference table into every report
# request (2026-08-26, per Dom). Same bind-mount pattern config.py's
# `get_ca_bundle_path` already uses for the TLS CA bundle: a fixed
# subdirectory under `data_dir`, no code change or redeploy needed to
# add/update one -- just a file written to a known path.

_SCALE_NAME_RE = re.compile(r"^[A-Za-z0-9_-]+$")


def _scales_dir(data_dir: Path) -> Path:
    return data_dir / "risk_grade_scales"


def _validate_scale_name(name: str) -> str:
    name = str(name).strip()
    if not name or not _SCALE_NAME_RE.match(name):
        raise ValueError(
            f"risk_grade_scale_name {name!r} must be non-empty and contain only "
            "letters, digits, '-', and '_' -- it's used directly as a filename, "
            "not a path (no '/', '..', etc.)."
        )
    return name


def _load_stored_risk_grade_scale(data_dir: Path, name: str) -> dict[str, dict[str, str]]:
    name = _validate_scale_name(name)
    scales_dir = _scales_dir(data_dir)
    path = scales_dir / f"{name}.json"
    if not path.is_file():
        available = sorted(p.stem for p in scales_dir.glob("*.json")) if scales_dir.is_dir() else []
        raise ValueError(
            f"No stored risk_grade_scale named {name!r} -- looked for {path}. "
            f"Available: {available if available else '(none saved yet)'}. "
            "Save one first with the save_risk_grade_scale tool."
        )
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        raise ValueError(f"Stored risk_grade_scale {name!r} at {path} is not valid JSON: {e}") from e
    return _validate_risk_grade_scale(raw)


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
            "policy_finding_limit",
            "policy_status",
            "policy_since",
            "peer_limit",
            "peer_since",
            "risk_model",
            "risk_grades",
            "risk_grade_fields",
            "risk_dimension_labels",
            "risk_grade_descriptions",
            "risk_grade_scale",
            "risk_grade_scale_name",
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

        policy_status = _normalize_policy_status(params.get("policy_status"))

        risk_model = params.get("risk_model")
        if risk_model is not None and not isinstance(risk_model, str):
            raise ValueError(f"risk_model must be a string, got {risk_model!r}")

        risk_grade_scale_name = params.get("risk_grade_scale_name")
        if risk_grade_scale_name is not None and not isinstance(risk_grade_scale_name, str):
            raise ValueError(f"risk_grade_scale_name must be a string, got {risk_grade_scale_name!r}")

        return {
            "asset_id": asset_id,
            "site_uuid": params.get("site_uuid"),
            "site_name": params.get("site_name"),
            "vuln_limit": _clamp(params.get("vuln_limit"), _DEFAULT_VULN_LIMIT),
            "vuln_severity_at_least": vuln_severity_at_least,
            "policy_finding_limit": _clamp(params.get("policy_finding_limit"), _DEFAULT_POLICY_FINDING_LIMIT),
            "policy_status": policy_status,
            "policy_since": params.get("policy_since"),
            "peer_limit": _clamp(params.get("peer_limit"), _DEFAULT_PEER_LIMIT),
            "peer_since": params.get("peer_since"),
            "risk_model": (risk_model or _DEFAULT_RISK_MODEL_LABEL).strip(),
            "risk_grades": _validate_risk_grades(params.get("risk_grades")),
            "risk_grade_fields": _validate_str_map(params.get("risk_grade_fields"), field="risk_grade_fields"),
            "risk_dimension_labels": _validate_str_map(params.get("risk_dimension_labels"), field="risk_dimension_labels"),
            "risk_grade_descriptions": _validate_str_map(params.get("risk_grade_descriptions"), field="risk_grade_descriptions"),
            "risk_grade_scale": _validate_risk_grade_scale(params.get("risk_grade_scale")),
            "risk_grade_scale_name": risk_grade_scale_name,
            "risk_scale_note": _normalize_str_list(params.get("risk_scale_note"), field="risk_scale_note"),
            "analyst_assessment": _normalize_str_list(params.get("analyst_assessment"), field="analyst_assessment"),
            "data_limitations": _normalize_str_list(params.get("data_limitations"), field="data_limitations"),
        }

    def resolve_stored_params(self, params: dict[str, Any], data_dir: Path) -> dict[str, Any]:
        """Optional hook -- deliberately NOT part of the `ReportModule`
        ABC, same "not every module needs this" reasoning as
        `list_columns`/`default_columns` (§0.10). Called by
        mcp_app.py's `submit_report_job` via `getattr(instance, ...,
        None)`, after `validate_params` and before `fetch_data`: disk
        I/O for a *stored* `risk_grade_scale` has no natural home in
        either of those methods' existing contracts, so this is a
        third step, only for modules that define it.

        2026-08-26, per Dom: resolves `risk_grade_scale_name` into a
        table saved once via `save_risk_grade_scale` (see
        `save_stored_scale` below) at `<data_dir>/risk_grade_scales/
        <name>.json`, so a calling LLM references a table by name
        instead of retyping the whole thing into every report request.
        Merge order, same "explicit override always wins" convention
        as everywhere else in this module: the stored table is the
        base, an inline `risk_grade_scale` passed in this same call
        overrides it per (dimension, grade).
        """
        name = params.get("risk_grade_scale_name")
        if not name:
            return params
        stored = _load_stored_risk_grade_scale(data_dir, name)
        merged: dict[str, dict[str, str]] = {dim: dict(row) for dim, row in stored.items()}
        for dim, row in params["risk_grade_scale"].items():
            merged.setdefault(dim, {}).update(row)
        resolved = dict(params)
        resolved["risk_grade_scale"] = merged
        return resolved

    def save_stored_scale(self, data_dir: Path, name: str, scale: Any) -> None:
        """Validates `scale` with the same rules `risk_grade_scale`
        itself is validated against, then writes it to
        `<data_dir>/risk_grade_scales/<name>.json` -- creating that
        directory on first use. Overwrites an existing file of the
        same name (updating a saved table is meant to be this easy;
        there's no versioning here, same as any other config file on
        this bind mount)."""
        name = _validate_scale_name(name)
        validated = _validate_risk_grade_scale(scale)
        scales_dir = _scales_dir(data_dir)
        scales_dir.mkdir(parents=True, exist_ok=True)
        path = scales_dir / f"{name}.json"
        path.write_text(json.dumps(validated, indent=2, sort_keys=True), encoding="utf-8")

    def list_stored_scales(self, data_dir: Path) -> list[str]:
        scales_dir = _scales_dir(data_dir)
        if not scales_dir.is_dir():
            return []
        return sorted(p.stem for p in scales_dir.glob("*.json"))

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

        # Scoped to this asset via Or(srcNames Contains <name>, dstNames
        # Contains <name>) -- see module docstring point 6. Both fields
        # are now confirmed by live captures (srcNames first, dstNames
        # in a second capture), so this catches findings where the
        # asset was either the source or the destination of the
        # flagged traffic, not source-only as in the previous round.
        asset_name = asset_node.get("name") or asset_id
        name_match = {
            "op": _EXPR_OR,
            "expressions": [
                {"field": "srcNames", "op": "Contains", "values": [asset_name]},
                {"field": "dstNames", "op": "Contains", "values": [asset_name]},
            ],
        }
        policy_filter_parts = [name_match]
        if params.get("policy_status"):
            policy_filter_parts.append({"field": "status", "op": _EXPR_IN, "values": params["policy_status"]})
        if params.get("policy_since"):
            policy_filter_parts.append(
                {"field": "lastHitTime", "op": _EXPR_GREATER_EQUAL, "values": params["policy_since"]}
            )
        policy_filter = (
            policy_filter_parts[0]
            if len(policy_filter_parts) == 1
            else {"op": _EXPR_AND, "expressions": policy_filter_parts}
        )
        policy_data = await client.query(
            _QUERY_POLICY_FINDINGS,
            variables={
                "pageSize": params["policy_finding_limit"],
                "filter": policy_filter,
                "sort": _POLICY_FINDING_SORT,
            },
            icp_machine_id=icp_machine_id,
        )
        policy_block = policy_data.get("policyFindings") or {}

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
            "policy_finding_nodes": policy_block.get("nodes") or [],
            "policy_finding_total": policy_block.get("totalCount") or 0,
            "peer_nodes": peer_nodes,
            "peer_total": peer_block.get("totalCount") or 0,
            "peer_assets": peer_assets,
        }

    def to_markdown_context(self, data: dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
        asset_id = params["asset_id"]
        asset = _project_asset(data["asset"])
        vulns = [_project_vuln(n) for n in data["vuln_nodes"]]
        # Ranked by VPR, highest first -- client-side sort (2026-08-26,
        # per Dom), not a GraphQL `sort` argument: `asset(id).plugins`
        # has no confirmed sort argument anywhere this project or
        # EM-MCP's own correlation.py has used, unlike the top-level
        # `findings` query the separate vulnerability_findings module
        # queries. Sorting the already-fetched page in Python needs no
        # new schema assumption. Missing VPR scores sort last, not first.
        vulns.sort(key=lambda v: (v["vpr_score"] is None, -(v["vpr_score"] or 0)))
        # Policy violation findings already come back ranked by severity
        # (the query's own `sort`, see `_POLICY_FINDING_SORT`) -- no
        # client-side re-sort needed, unlike vulnerabilities above.
        policy_findings = [_project_policy_finding(n) for n in data["policy_finding_nodes"]]
        peers = [_project_peer(n, asset_id, data.get("peer_assets")) for n in data["peer_nodes"]]

        # Merge order: whatever's already assigned in Tenable via custom
        # fields first, then the caller's own `risk_grades` overrides
        # per dimension -- "explicit override always wins", the same
        # convention `theme_overrides` already uses in this project.
        risk_grades = dict(data.get("custom_field_grades") or {})
        risk_grades.update(params["risk_grades"])

        # Detail text: look up each dimension's already-resolved grade
        # in the caller's `risk_grade_scale` reference table (if any),
        # then let a same-dimension `risk_grade_descriptions` entry
        # override that looked-up value -- same "explicit override
        # always wins" merge order as `risk_grades` just above. A
        # dimension missing from the scale, or whose grade isn't a key
        # in that dimension's row, simply has no looked-up value (not
        # an error) -- it renders blank unless `risk_grade_descriptions`
        # fills it in directly. 2026-08-26, per Dom (see
        # `_validate_risk_grade_scale`'s docstring).
        risk_grade_scale = params["risk_grade_scale"]
        risk_grade_descriptions = {
            dim: risk_grade_scale[dim][grade]
            for dim, grade in risk_grades.items()
            if dim in risk_grade_scale and grade in risk_grade_scale[dim]
        }
        risk_grade_descriptions.update(params["risk_grade_descriptions"])

        # Auto-disclose truncation on top of whatever the caller already
        # supplied in `data_limitations` -- doesn't depend on the caller
        # remembering to say so every time.
        auto_limitations: list[str] = []
        if len(vulns) < data["vuln_total"]:
            auto_limitations.append(f"Vulnerability findings: showing {len(vulns)} of {data['vuln_total']} total.")
        if len(policy_findings) < data["policy_finding_total"]:
            auto_limitations.append(
                f"Policy violation findings: showing {len(policy_findings)} of {data['policy_finding_total']} total."
            )
        if len(peers) < data["peer_total"]:
            auto_limitations.append(f"Communication peers: showing {len(peers)} of {data['peer_total']} total.")

        return {
            "report_title": f"Asset Risk Profile — {asset['name']}",
            "generated_at": datetime.now(UTC).isoformat(timespec="seconds"),
            "asset": asset,
            "risk_model": params["risk_model"],
            "risk_grades": risk_grades,
            "risk_dimension_labels": params["risk_dimension_labels"],
            "risk_grade_descriptions": risk_grade_descriptions,
            "risk_scale_note": params["risk_scale_note"],
            "vulnerabilities": vulns,
            "vuln_returned_count": len(vulns),
            "vuln_total_count": data["vuln_total"],
            "policy_findings": policy_findings,
            "policy_finding_returned_count": len(policy_findings),
            "policy_finding_total_count": data["policy_finding_total"],
            "peers": peers,
            "peer_returned_count": len(peers),
            "peer_total_count": data["peer_total"],
            "analyst_assessment": params["analyst_assessment"],
            "data_limitations": params["data_limitations"] + auto_limitations,
        }


MODULE = RiskProfileModule()
