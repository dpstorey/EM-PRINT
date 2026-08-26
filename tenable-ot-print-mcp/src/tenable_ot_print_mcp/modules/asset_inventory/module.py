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
import time
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
# §0.11, corrected again in §0.12) starts from EM-MCP's real,
# production `_ASSET_BASE` fragment
# (id/name/type/superType/category/vendor/model/firmwareVersion/os/
# family/description/location/purdueLevel/criticality/hidden/
# runStatus/extendedRunStatus/firstSeen/lastSeen/lastUpdate/
# lifecycleStatus/ips/macs/segments/risk/customField1-10 -- confirmed
# working in EM-MCP's daily production use) plus every additional
# scalar/StringConnection field Dom's own GraphQL schema paste (§0.11)
# confirms actually exists on the Asset type: `serial`, `slot`,
# `backplane { name size }`, `osDetails { name architecture version }`,
# `runStatusTime`, `hardwareState`, `discontinuedDate`,
# `replacementProduct`, `lastHit`, `lastSnapshot`, `subnets`, `tags`.
#
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
#
# `attackVector` was here too, briefly (§0.11) -- REMOVED in §0.12
# after a live test showed it's an object type requiring subfield
# selection ("Field 'attackVector' of type 'AttackVector' must have a
# selection of subfields"), not the leaf scalar pyTenable's marshmallow
# schema (`fields.String(data_key="attackVector")`) implied. Because
# this query fetches the same field superset on EVERY request
# regardless of which `columns` were asked for, that one bad field
# broke 100% of asset_inventory reports -- including default-columns
# ones that never mentioned attack_vector at all. Re-add only once its
# real subfields are known (needs schema introspection or another
# schema paste); don't guess at a subfield selection the way the bare
# field name itself was guessed.
_QUERY_ASSETS = """
query Q($pageSize: Int!, $after: String, $filter: AssetExpressionsParams, $search: String, $sort: [AssetSortParams!]) {
  assets(first: $pageSize, after: $after, filter: $filter, search: $search, sort: $sort) {
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

# Custom-field slot -> operator-configured label, resolved live
# (2026-08-25, per Dom's explicit ask: "I'd like to use their names,
# not customfield1 etc."). Mirrors EM-MCP's real
# `CustomFieldLabelCache` (tools/assets.py) exactly -- same query,
# same TTL, same icp-scoped cache key -- rather than inventing a
# different caching scheme for the same underlying Tenable feature.
#
# Labels are used for *display* (report column headers,
# `list_available_columns`'s reported label) AND, as of 2026-08-26,
# for *selection* too: Dom pointed out Tenable's own UI never shows
# the `custom_field_N` <-> live-name mapping at all (a custom field
# there is just "Owner" or "Geotag", never "Custom Field 5" -- see the
# GREEN-COMMS asset-detail screenshot), so a caller working from what
# the product actually shows has no way to discover the stable key
# exists. `columns` now accepts either: the stable `custom_field_1`..
# `custom_field_10` key (unaffected by a later rename, and the only
# option if a slot has no configured label at all) or the slot's live
# name, matched case-insensitively. See `_resolve_columns` below.
_QUERY_CUSTOM_FIELDS = "query Q { customFields { fieldId userDefinedName valueType } }"


class _CustomFieldLabelCache:
    """Module-level {slot -> label} cache, scoped per ICP.

    No lock -- a duplicate cold-cache fetch from concurrent report
    jobs is harmless (both just do the same read).
    """

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


def _custom_field_slot(column_key: str) -> str | None:
    """`"custom_field_3"` -> `"customField3"`, or None if not one of these keys."""
    prefix = "custom_field_"
    if not column_key.startswith(prefix):
        return None
    return "customField" + column_key[len(prefix) :]


def _custom_field_key_for_slot(slot: str) -> str | None:
    """`"customField3"` -> `"custom_field_3"` -- the reverse of `_custom_field_slot`,
    used to turn a live-resolved custom-field label back into its internal
    `_COLUMN_REGISTRY` key."""
    prefix = "customField"
    if not slot.startswith(prefix):
        return None
    return "custom_field_" + slot[len(prefix) :]


# Tenable's AssetExpressionsParams op vocabulary (see EM-MCP's
# tools/_enums.py) -- only the two ops this module needs.
_EXPR_IN = "In"

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


def _build_name_to_key(custom_field_labels: dict[str, str]) -> dict[str, str]:
    """Case-insensitive {selector name -> internal `_COLUMN_REGISTRY`
    key}, covering every static column's stable key plus, for the 10
    `custom_field_N` slots, this ICP's live operator-configured name
    (2026-08-25, §0.14 -- Tenable's own UI never shows the stable key,
    so a caller working from what the product shows needs the name
    form to work too). Shared by `_resolve_columns` (which fields to
    show) and `_resolve_sort` (§0.17 -- which field(s) to sort by) so
    the two selector languages can't drift apart.
    """
    name_to_key: dict[str, str] = {key.lower(): key for key in _COLUMN_REGISTRY}
    for slot, label in custom_field_labels.items():
        key = _custom_field_key_for_slot(slot)
        norm_label = (label or "").strip().lower()
        if key and norm_label:
            # A later slot silently wins a same-named collision --
            # two custom fields sharing one operator-typed name is an
            # edge case not worth failing every report over.
            name_to_key[norm_label] = key
    return name_to_key


def _unknown_column_error(raw: str, custom_field_labels: dict[str, str]) -> ValueError:
    static_names = sorted(k for k in _COLUMN_REGISTRY if _custom_field_slot(k) is None)
    custom_names = []
    for i in range(1, 11):
        slot_key = f"custom_field_{i}"
        label = custom_field_labels.get(_custom_field_slot(slot_key))
        custom_names.append(f"{slot_key} ({label!r})" if label else slot_key)
    return ValueError(f"Unknown column {raw!r}. Available columns: {static_names + custom_names}.")


def _resolve_columns(requested: list[str], custom_field_labels: dict[str, str]) -> list[str]:
    """Resolve a caller's raw `columns` request into final internal
    `_COLUMN_REGISTRY` keys.

    Every static column is still selected by its stable key
    (case-insensitive), same as always. The 10 `custom_field_N` slots
    additionally accept their live operator-configured name (also
    case-insensitive) as of 2026-08-26 -- see the comment above
    `_QUERY_CUSTOM_FIELDS` for why the stable-key-only rule from
    section 0.13 didn't survive contact with Tenable's real UI. Both
    forms resolve to the same internal key, so `to_markdown_context`
    and `_COLUMN_REGISTRY` don't need to know which form was used.

    Needs `custom_field_labels` (this ICP's live {slot: label} map)
    to recognize the name form at all -- which means, unlike the
    purely-structural checks in `validate_params`, this can only run
    after a client is available (see `fetch_data`), so a bad column
    name is now only caught after that live lookup rather than
    immediately at job submission.
    """
    name_to_key = _build_name_to_key(custom_field_labels)

    resolved: list[str] = []
    seen: set[str] = set()
    for raw in requested:
        key = name_to_key.get(raw.strip().lower())
        if key is None:
            raise _unknown_column_error(raw, custom_field_labels)
        if key not in seen:
            seen.add(key)
            resolved.append(key)
    if not resolved:
        raise ValueError(
            "columns must not be empty; omit it entirely to use the default columns "
            f"{list(_DEFAULT_COLUMNS)}."
        )
    return resolved


# Sort (§0.17, 2026-08-26): which `_COLUMN_REGISTRY` columns can be
# passed to Tenable's real `sort: [AssetSortParams!]` argument, mapped
# to the GraphQL field name each one sorts by. Confirmed against a
# live browser network capture Dom shared of the product's own
# inventory-table sort UI -- notably proving connection fields like
# `macs` are valid sort fields too, not just scalars, and that
# multiple {field, direction} entries are honored in order (the exact
# capture: `sort: [{"field": "macs", "direction": "DescNullLast"},
# {"field": "id", "direction": "AscNullLast"}]`). This directly
# contradicts what EM-MCP's own `assets.py` implies (`assets` has no
# `$sort` variable declared there at all) -- that only proves EM-MCP's
# tool never needed sorting, not that the schema lacks it; the real
# schema wins, same lesson as every other "trust the live evidence"
# correction in this project's history (attackVector, custom-field UI
# mapping, etc).
#
# Deliberately excluded: columns computed from a nested object rather
# than one top-level Asset field -- `os_version`/`os_architecture`
# (from `osDetails`), `backplane_name`/`backplane_size` (from
# `backplane`), `segments` (a joined connection of objects, not a
# flat string list like `macs`/`tags`), and `total_risk`/
# `plugin_count`/`unresolved_events` (from `risk`). Tenable's sort
# schema was not confirmed to accept a nested/dotted field path, and
# guessing one risks the exact all-or-nothing GraphQL failure
# `attackVector` caused (design-notes.md §0.12) rather than a clean
# rejection here.
_ASSET_SORT_FIELD: dict[str, str] = {
    "asset_id": "id",
    "name": "name",
    "type": "type",
    "super_type": "superType",
    "category": "category",
    "vendor": "vendor",
    "model": "model",
    "firmware_version": "firmwareVersion",
    "os": "os",
    "family": "family",
    "description": "description",
    "location": "location",
    "purdue_level": "purdueLevel",
    "criticality": "criticality",
    "hidden": "hidden",
    "run_status": "runStatus",
    "run_status_time": "runStatusTime",
    "extended_run_status": "extendedRunStatus",
    "lifecycle_status": "lifecycleStatus",
    "first_seen": "firstSeen",
    "last_seen": "lastSeen",
    "last_update": "lastUpdate",
    "serial": "serial",
    "slot": "slot",
    "hardware_state": "hardwareState",
    "discontinued_date": "discontinuedDate",
    "replacement_product": "replacementProduct",
    "last_hit": "lastHit",
    "last_snapshot": "lastSnapshot",
    "ip": "ips",
    "mac": "macs",
    "subnets": "subnets",
    "tags": "tags",
    "custom_field_1": "customField1",
    "custom_field_2": "customField2",
    "custom_field_3": "customField3",
    "custom_field_4": "customField4",
    "custom_field_5": "customField5",
    "custom_field_6": "customField6",
    "custom_field_7": "customField7",
    "custom_field_8": "customField8",
    "custom_field_9": "customField9",
    "custom_field_10": "customField10",
}

# Only the two direction values seen in the live capture -- not
# guessing at AscNullFirst/DescNullFirst without evidence either way.
_ASSET_SORT_DIRECTIONS = {"asc": "AscNullLast", "desc": "DescNullLast"}


def _resolve_sort(requested: list[str], custom_field_labels: dict[str, str]) -> list[dict[str, str]]:
    """Resolve a caller's raw `sort` request into Tenable's real
    `[{"field": ..., "direction": "AscNullLast"|"DescNullLast"}]`
    shape for the `assets` query's `sort` argument.

    Each entry is a column selector -- the same stable-key-or-live-
    custom-field-name language `columns` uses, via the same
    `_build_name_to_key` -- optionally prefixed with `-` for
    descending (ascending is the default). Multiple entries sort in
    the order given, exactly matching how Tenable's own UI builds this
    argument (see the comment above `_ASSET_SORT_FIELD`).

    Raises on any column that either doesn't resolve at all or
    resolves to a real column that isn't in `_ASSET_SORT_FIELD` (i.e.
    exists for display but has no confirmed top-level sort field) --
    either way, a clear error here beats a live GraphQL failure.
    """
    name_to_key = _build_name_to_key(custom_field_labels)
    resolved: list[dict[str, str]] = []
    for raw in requested:
        spec = raw.strip()
        if spec.startswith("-"):
            direction_word, spec = "desc", spec[1:].strip()
        else:
            direction_word = "asc"
        key = name_to_key.get(spec.lower())
        if key is None:
            raise _unknown_column_error(spec, custom_field_labels)
        sort_field = _ASSET_SORT_FIELD.get(key)
        if sort_field is None:
            raise ValueError(
                f"Column {spec!r} can't be sorted on (it's computed from a nested "
                f"field with no single sortable GraphQL field). Sortable columns: "
                f"{sorted(_ASSET_SORT_FIELD)}."
            )
        resolved.append({"field": sort_field, "direction": _ASSET_SORT_DIRECTIONS[direction_word]})
    return resolved


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
            "sort",
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

        # `columns` (§0.10, revised §0.14): optional list of column
        # names (or a comma-separated string -- LLM callers sometimes
        # serialize arrays that way), order-preserving so a caller can
        # also control column order. Omitting it reproduces the
        # original 9-column report (_DEFAULT_COLUMNS) so existing
        # callers see no change.
        #
        # Only *structural* validation happens here -- this method has
        # no `client`, and as of §0.14 a custom-field slot can be named
        # by its live operator-configured label as well as its stable
        # `custom_field_N` key, and that label can only be checked once
        # it's fetched. Final resolution against the full known-column
        # set (static keys + this ICP's live custom-field names)
        # happens in `fetch_data` via `_resolve_columns`, so an
        # unknown/misspelled name is still rejected outright -- just a
        # bit later in the pipeline than before.
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
            columns = [str(raw).strip() for raw in columns_param if str(raw).strip()]
            if not columns:
                raise ValueError(
                    "columns must not be empty; omit it entirely to use the default columns "
                    f"{list(_DEFAULT_COLUMNS)}."
                )

        # `sort` (§0.17, 2026-08-26): optional list of column selectors
        # (or a comma-separated string), each optionally prefixed with
        # `-` for descending -- e.g. `["-total_risk", "name"]`. Same
        # split as `columns`: only structural validation here (list-
        # or-comma-string, non-empty entries); resolving a selector to
        # a real sortable GraphQL field -- and rejecting a column that
        # exists but isn't sortable -- needs the live custom-field
        # labels, so that happens in `fetch_data` via `_resolve_sort`.
        # Omitting `sort` entirely means "no sort" -- the `$sort`
        # GraphQL variable is left out of the request rather than sent
        # as an empty list, matching how `$filter`/`$search` are
        # already only sent when actually used.
        sort_param = params.get("sort")
        if sort_param is None:
            sort = None
        else:
            if isinstance(sort_param, str):
                sort_param = [c.strip() for c in sort_param.split(",")]
            if not isinstance(sort_param, (list, tuple)):
                raise ValueError(f"sort must be a list of column names, got {sort_param!r}")
            sort = [str(raw).strip() for raw in sort_param if str(raw).strip()]
            if not sort:
                raise ValueError("sort must not be empty; omit it entirely for the default order.")

        return {
            "limit": limit,
            "criticality_at_least": criticality_at_least,
            "subnet": subnet,
            "site_uuid": site_uuid,
            "site_name": site_name,
            "search": search,
            "columns": columns,
            "sort": sort,
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

        # Resolve `columns` before paginating through assets -- both
        # for a fast failure on a bad column name (no point fetching
        # pages of assets for a request that's going to fail
        # validation anyway) and because custom-field name resolution
        # (§0.14) needs these labels regardless.
        custom_field_labels = await _CustomFieldLabelCache.get_or_fetch(client, icp_machine_id)
        resolved_columns = _resolve_columns(params["columns"], custom_field_labels)
        # `sort` (§0.17): resolved here too, same reason as `columns`
        # above -- needs the live custom-field labels to recognize a
        # custom field sorted by its live name, and needs to happen
        # before the first page is fetched since it's sent on every
        # page request (a cursor's meaning depends on a stable sort
        # order across the whole paginated walk).
        resolved_sort = _resolve_sort(params["sort"], custom_field_labels) if params["sort"] else None

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
            if resolved_sort is not None:
                variables["sort"] = resolved_sort

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
            "custom_field_labels": custom_field_labels,
            "columns": resolved_columns,
        }

    async def list_columns(
        self,
        client: TenableClient | None = None,
        site_uuid: str | None = None,
        site_name: str | None = None,
    ) -> list[dict[str, str]]:
        """Every column this module can project via `columns`, in
        registry order -- not part of the ReportModule ABC (only this
        module supports column selection so far); the MCP-side
        `list_available_columns` tool checks for this method with
        `getattr(..., None)` rather than requiring every module to
        implement it.

        When `client` is given, resolves live custom-field labels
        ("Plant ID" instead of "Custom Field 3") the same way a real
        report would, so discovery matches what the report will
        actually show. Falls back to the generic "Custom Field N"
        labels if resolution fails for any reason (e.g. no `client`,
        or an ambiguous multi-ICP EM with no `site_uuid`/`site_name`
        given) -- this is a discovery/listing call, so it degrades
        gracefully rather than erroring.

        Each entry also reports `sortable` (§0.17) -- whether this
        column's key (or, for a custom field, its live name) can be
        passed to `sort`. Not every displayable column is sortable;
        see `_ASSET_SORT_FIELD`'s docstring for why.
        """
        labels = {key: label for key, (label, _getter) in _COLUMN_REGISTRY.items()}
        if client is not None:
            try:
                icp_machine_id = await self._resolve_icp_machine_id(
                    client, {"site_uuid": site_uuid, "site_name": site_name}
                )
                field_labels = await _CustomFieldLabelCache.get_or_fetch(client, icp_machine_id)
                for key in labels:
                    slot = _custom_field_slot(key)
                    if slot and field_labels.get(slot):
                        labels[key] = field_labels[slot]
            except Exception:
                pass  # nothing resolvable right now -- generic labels are still useful
        return [
            {"key": key, "label": labels[key], "sortable": key in _ASSET_SORT_FIELD}
            for key in _COLUMN_REGISTRY
        ]

    def default_columns(self) -> list[str]:
        """Columns used when `columns` is omitted -- see `list_available_columns`."""
        return list(_DEFAULT_COLUMNS)

    def to_markdown_context(self, data: dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
        # Resolved by `_resolve_columns` in fetch_data (§0.14) -- by
        # this point a custom-field slot named by its live label has
        # already been turned into its internal `custom_field_N` key,
        # so this is always a list of _COLUMN_REGISTRY keys, never a
        # raw caller-supplied name.
        column_keys: list[str] = data["columns"]
        custom_field_labels: dict[str, str] = data.get("custom_field_labels") or {}

        columns = []
        for key in column_keys:
            label = _COLUMN_REGISTRY[key][0]
            slot = _custom_field_slot(key)
            if slot and custom_field_labels.get(slot):
                label = custom_field_labels[slot]
            # Registry labels are hardcoded and never contain "|" or a
            # newline, so this is a no-op for them -- but a resolved
            # custom-field label is operator-typed free text (like
            # `description`, §0.10) and just as capable of containing
            # either. Found live: an operator-configured label with a
            # "|" in it corrupted the header row exactly the way an
            # unescaped data cell would have. Same _render_cell() pass,
            # applied to the header this time.
            columns.append({"key": key, "label": _render_cell(label)})

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
