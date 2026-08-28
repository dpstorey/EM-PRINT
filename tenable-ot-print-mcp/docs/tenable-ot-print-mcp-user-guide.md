# Tenable OT Print MCP — User Guide

_Reference for every tool and option `tenable-ot-print-mcp` exposes. Current as of 2026-08-27 (design-notes.md v1.25)._

This server generates reports (Markdown + themed HTML) from live Tenable One OT Exposure / Enterprise Manager data and writes them to its own filestore — it never returns report content directly, only file paths and small summaries, so a large report doesn't burn a calling LLM's context window.

The normal workflow is:

1. `list_report_types` — see what report modules exist and what each one accepts.
2. (Optional) `list_available_columns` — for a module that supports column selection, see the full column list, the default set, and which columns are sortable, before guessing a name.
3. `submit_report_job` — actually generate a report.
4. `list_recent_report_jobs` — if a result seemed to go missing (dropped connection, client-side error), check whether the job actually completed server-side before resubmitting.

Everything below is organized by tool, then by report module.

---

## `submit_report_job` — generate a report

```
submit_report_job(module, params={}, theme="default", theme_overrides=None)
```

| Argument | Type | Required | Notes |
|---|---|---|---|
| `module` | string | yes | One of `asset_inventory`, `vulnerability_findings`, `policy_findings`, `risk_profile` |
| `params` | object | no | Module-specific — see the per-module sections below. An unrecognized param name is rejected outright, not silently dropped. |
| `theme` | string | no, default `"default"` | Visual layout/branding only — see "Themes" below. Never affects what data is queried or how it's worded. |
| `theme_overrides` | object | no | Per-report overrides on top of the theme's defaults — see "Theme overrides" below. |

Returns `module`, `output_paths` (the `.md` and `.html` file paths), `markdown_bytes`/`html_bytes`, and `returned_count`/`total_count` (so you can tell whether the report is complete or truncated) — never the rendered content itself.

Runs synchronously today (no job queue yet) — a very large, uncapped fetch on a data-heavy module can take a while with no cancel/poll; keep `limit`-style params modest until an async queue lands in a later phase. In practice, an unfiltered ~3,500-asset fetch has been live-confirmed to complete in a few seconds, so this is a theoretical caution more than a current problem.

---

## Discovery tools

### `list_report_types()`

Lists every report module with its `title`, `description`, full `params` list (as documented in each module's manifest — the same detail reproduced below), and `output_formats`. Call this first if you're not sure which module fits a request.

### `list_available_columns(module, site_uuid=None, site_name=None)`

For a module that supports column selection (`asset_inventory`, `vulnerability_findings`, `policy_findings` — not `risk_profile`, which isn't a tabular list report), returns:

- `columns`: every selectable column, as `{key, label, sortable}`.
- `default_columns`: which columns render when `columns` is omitted from `submit_report_job`.

For `asset_inventory` specifically, pass `site_uuid` or `site_name` to also see each custom-field slot's *live*, operator-configured label (e.g. `"Owner"`, `"Geotag"`) instead of the generic `"Custom Field 5"` — Tenable's own UI never shows the stable slot name, so this is how you find out what to actually type. Omit both on a single-ICP EM; it auto-resolves.

A module with no column support at all (`risk_profile`) returns `columns: null`.

### `list_themes()`

Lists the theme names available in this deployment (see "Themes" below).

### `list_recent_report_jobs(limit=10)`

Lists the most recent jobs from the audit log, newest first: outcome (`ok`/`error`), module, params, and output paths. This reads *past* jobs only — since job submission is currently synchronous, there's no separate "still running" state to poll.

---

## Report modules

### `asset_inventory` — list OT assets

A tabular asset inventory from a paired ICP. 51 selectable columns covering identity, classification, network, lifecycle, risk, and all 10 custom-field slots; a 9-column default (vendor, model, firmware, criticality, IPs, last seen, risk, unresolved events) when `columns` is omitted.

| Param | Type | Default | Notes |
|---|---|---|---|
| `limit` | integer | none (uncapped) | Omit to fetch every matching asset (server-side paged, no artificial cap) — bounded only by an internal 50,000-asset circuit breaker against a malformed paginated response, not a real ceiling. |
| `criticality_at_least` | string | — | `none`\|`low`\|`medium`\|`high`. Server-side filter. |
| `subnet` | string | — | CIDR, e.g. `10.253.10.128/25`. Server-side filter. |
| `search` | string | — | Free-text match against Tenable's native `search` argument (can match location/zone tags, e.g. `"PAINT SHOP"`) — this is a substring/text match, **not** a strict `Location`-column filter, so it can return assets outside an exact location match. |
| `site_uuid` / `site_name` | string | — | Target ICP. Auto-resolves if only one ICP is paired; required (either one) if several are paired. |
| `columns` | array or comma-string | the 9-column default | Column names, in display order (case-insensitive, deduped). A custom-field slot works by either its stable key (`custom_field_1`..`custom_field_10`) or its live UI label. Unknown name → rejected outright. |
| `sort` | array or comma-string | server default (unspecified order) | Column selectors, `-` prefix for descending, multi-key, priority order (e.g. `["-total_risk", "name"]`). 43 of 51 columns are sortable — the 8 excluded are computed from a nested object with no single sortable field (`os_version`, `os_architecture`, `backplane_name`/`size`, `segments`, `total_risk`, `plugin_count`, `unresolved_events`). Check the `sortable` flag from `list_available_columns` before guessing. |

### `vulnerability_findings` — per-asset × plugin findings

Tenable's `findings` GraphQL surface (vulnerability instances) — distinct from `policy_findings` despite the similar name. 19 columns; a 9-column default (asset, plugin, severity, VPR score, status, first/last hit, port, CVEs).

| Param | Type | Default | Notes |
|---|---|---|---|
| `limit` | integer | none (uncapped) | Same uncapped-by-default behavior as `asset_inventory`, same 50,000-item safety ceiling. |
| `severity_at_least` | string | — | `info`\|`low`\|`medium`\|`high`\|`critical`. Server-side. |
| `status` | string, or array/comma-string | — | One or more of `active`\|`resolved`\|`resurfaced`, OR'd together. Server-side. |
| `asset_id` | string | — | Exact-match on the affected asset's id. |
| `plugin_id` | string | — | Exact-match on the plugin id. |
| `cve` | string | — | Substring match against the plugin name (e.g. a CVE id). |
| `search` | string | — | Free-text, native GraphQL `search` argument. |
| `site_uuid` / `site_name` | string | — | Same ICP-targeting rule as `asset_inventory`. |
| `columns` | array or comma-string | the 9-column default | Same case-insensitive/dedup rules. |
| `sort` | array or comma-string | most-recently-hit first (`last_hit` desc) | Every column is sortable **except `cves`** (a joined list of nested strings, no single backing scalar) — confirmed against the live GraphQL schema's sort/filter enum, not inferred. |

### `policy_findings` — per-policy × asset compliance hits

Tenable's `policyFindings` GraphQL surface — the real data behind the GUI's "Compliance"/"Policy Violations" pages, under a different label. 20 columns; a 9-column default (policy, severity, status, category, active hits, first/last hit, source/destination assets).

| Param | Type | Default | Notes |
|---|---|---|---|
| `limit` | integer | none (uncapped) | Same uncapped-by-default behavior, same safety ceiling. |
| `severity_at_least` | string | — | `none`\|`low`\|`medium`\|`high` — **a different 4-value enum** from `vulnerability_findings`' 5-value severity, don't conflate them. |
| `status` | string, or array/comma-string | — | `active`\|`resolved`\|`resurfaced` — same 3-value enum as `vulnerability_findings`. |
| `policy_id` | string | — | Exact-match on the policy's id. |
| `plugin_id` | string | — | Exact-match on the associated plugin id. |
| `mitre_technique` | string | — | Exact-match on an associated MITRE ATT&CK technique. Filter-only — no matching display column. |
| `search` | string | — | Free-text, native GraphQL `search` argument. |
| `site_uuid` / `site_name` | string | — | Same ICP-targeting rule. |
| `columns` | array or comma-string | the 9-column default | Same rules as the other list modules. |
| `sort` | array or comma-string | most-recently-hit first (`last_hit` desc) | Not sortable: `resolved_hits`, `active_policy_hits`, `policy_level`, `policy_enabled`, and the `event_type_*` columns (no matching field on this surface's sort/filter enum). |

### `risk_profile` — single-asset risk dossier

A deep-dive report for **one asset**: identity/classification, vulnerability findings (ranked by VPR), policy violation findings (ranked by severity), a 1-hop communication/attack-pathway neighborhood, and a risk-grade table. This is the deterministic replacement for the old ad hoc LLM-authored HTML report workflow — see "Grading a report in chat" below for the boundary between this and freeform conversation.

**Risk grading is entirely caller-defined — nothing here hardcodes RAISE or any other rubric.** A grade for each dimension comes from a Tenable asset custom field (`risk_grade_fields`), from an explicit per-report value (`risk_grades`, which overrides a custom-field value for the same dimension), or from neither (renders `-`). Dimension codes, labels, and value scale (letters, numbers, words) are whatever your organization's model uses.

| Param | Type | Default | Notes |
|---|---|---|---|
| `asset_id` | string | **required** | From `asset_inventory` or any EM-MCP asset tool. |
| `site_uuid` / `site_name` | string | — | Same ICP-targeting rule as the list modules. |
| `vuln_limit` | integer | 100 (max 500) | One capped page, not a full paginated walk — this is a detail bundle, not a list report. |
| `vuln_severity_at_least` | string | — | `info`\|`low`\|`medium`\|`high`\|`critical`. |
| `policy_finding_limit` | integer | 20 (max 500) | Ranked by severity, then most-recent hit. |
| `policy_status` | string or array | — | `active`\|`resolved`\|`resurfaced`, one/several/comma-string. |
| `policy_since` | ISO-8601 string | — | Only findings hit at/after this time. Omit → no time window is invented. |
| `peer_limit` | integer | 50 (max 500) | Communication/attack-pathway neighbors, most-recently-seen first. |
| `peer_since` | ISO-8601 string | — | Only peer links seen at/after this time. |
| `risk_model` | string | `"Risk Assessment"` | Display name for the grade section (e.g. `"RAISE"`). Cosmetic only. |
| `risk_grades` | object | — | Per-dimension grade for this report only, e.g. `{"R": "B", "A": "C"}`. Overrides `risk_grade_fields` for the same dimension. |
| `risk_grade_fields` | object | — | Maps a dimension code to a Tenable custom field already holding its grade — by live label (e.g. `{"R": "RAISE-R"}`) or stable slot name. |
| `risk_dimension_labels` | object | — | Cosmetic column-header labels for dimension codes, e.g. `{"R": "Reputational"}`. |
| `risk_grade_scale` | object | — | A full `{dimension: {grade: description}}` lookup table (e.g. a whole RAISE matrix). The module looks up each dimension's "Detail" text automatically from its already-resolved grade. Merges **under** `risk_grade_scale_name` if both are passed (a one-off correction on top of a saved table). |
| `risk_grade_scale_name` | string | — | References a table already saved via `save_risk_grade_scale` — see below. Preferred over resending `risk_grade_scale` every call. |
| `risk_grade_descriptions` | object | — | Per-dimension override of "Detail" text — wins over anything `risk_grade_scale`/`risk_grade_scale_name` would have looked up. |
| `risk_scale_note` | array or string | — | Freeform caveat text rendered under the grade table (e.g. "grade letter vs. dimension code" caution). |
| `analyst_assessment` | array or string | — | Freeform analyst narrative — this module never generates narrative itself. |
| `data_limitations` | array or string | — | Freeform data-limitation notes. The module auto-appends its own truncation disclosures on top of whatever you supply (e.g. "Vulnerability findings: showing 100 of 340 total."). |

#### Saving a risk-grade scale once, instead of every call

- **`save_risk_grade_scale(module, name, scale)`** — saves a `risk_grade_scale`-shaped table under a name, once. Overwrites an existing table of the same name.
- **`list_risk_grade_scales(module)`** — lists names already saved for that module. Check this before guessing a name or resaving a duplicate.
- Then pass `risk_grade_scale_name="<name>"` on every later `risk_profile` call instead of resending the whole table.

---

## Report retention / purge

Rendered reports accumulate on the filestore with no automatic cleanup unless you set a rule. **One global rule across every module**, not per-module.

- **`set_report_retention_policy(mode, value)`** — `mode` is `"count"`, `"days"`, `"weeks"`, or `"months"`; `value` a positive integer. E.g. `mode="count", value=10` keeps the newest 10 reports; `mode="days", value=30` keeps the last 30 days. `"months"` is approximated as 30-day blocks, not calendar months. Overwrites any previously saved rule.
- **`get_report_retention_policy()`** — returns the currently saved rule, or `null`.
- **`purge_reports(dry_run=true)`** — applies the saved rule. **Defaults to preview-only** (`dry_run=true`): reports what *would* be deleted without deleting anything. Pass `dry_run=false` only after confirming the preview — a delete is a write, same "confirm before any write" rule as everywhere else. Errors (naming `set_report_retention_policy`) if no rule has been saved yet.

A "report" here is one `submit_report_job` call's `.md`+`.html` pair — always kept or deleted together as one unit. Purge only ever touches files matching this server's own report-filename convention; anything else sitting in the filestore (a stray file, manual addition) is never touched regardless of the rule in force.

---

## Themes

`theme` (on `submit_report_job`) controls visual layout/branding only — colors, fonts, header/footer content and images. It never changes what data is queried or how it's worded; there's no AI-authored narrative content anywhere in this pipeline.

Two themes ship today (`list_themes` confirms what's actually available in a given deployment):

- **`default`** — standard layout, bundled logo.
- **`dark-banner`** — dark background (`#192224`), high-contrast accent (`#ecff53`), a large banner-style header logo. Built for `risk_profile`-style reports that want a distinct look.

A theme directory can bundle a default logo (`assets/logo.<ext>`, shown in the header) and a mini logo (`assets/logo-mini.<ext>`, shown in the footer), plus optional `styles.css` for full color/typography control (layered on top of, not replacing, the base stylesheet).

### `theme_overrides` (per-report, on `submit_report_job`)

Wins over the theme's own defaults for that one report only — doesn't touch the theme itself:

| Key | Effect |
|---|---|
| `logo_data_uri` | Replace the main header logo, e.g. `"data:image/png;base64,..."`. |
| `mini_logo_data_uri` | Replace the footer mini-logo. |
| `header_message` | Extra text line shown in the header. |
| `footer_message` | Extra text line shown in the footer. |

---

## Grading a report in chat vs. through `risk_profile`

`risk_profile` is the deterministic path for a fully rendered report. Separately, if you're just asking a connected LLM (via AGENT.md/LibreChat) for a quick chat summary of RAISE grades across several assets, that path is **not** routed through this MCP's deterministic code today — it's the calling model looking at raw asset data and applying rules from its own system prompt. That's been a reliable place to fix table-formatting issues (see AGENT.md's "Asset summary" rules), but has proven **not reliable** for a rule that requires checking every row against a specific condition (e.g. "flag any asset graded S:D or S:E") — the model can state the rule correctly without consistently applying it row-by-row. If you need that guaranteed correct, use `risk_profile` (or ask for `asset_inventory`-style deterministic support to be built for it — currently an open, deferred item).

---

## Known gotchas, worth remembering

- **Unknown params/columns are rejected outright**, never silently dropped or ignored — if a report comes back looking wrong, check for a typo before assuming a data problem.
- **`limit` defaults to uncapped** on every list module — a report is meant to show everything that matches, not a first page. Pass an explicit `limit` if you want a capped preview.
- **Not every column is sortable** — always check `list_available_columns`' `sortable` flag rather than guessing; an unsortable/unknown sort target is rejected with the sortable list included in the error.
- **`search` is free text, not an exact filter** — it can return results outside a strict column match (e.g. a location-adjacent asset whose description mentions the search term).
- **`risk_profile`'s policy-finding scoping is a name-substring match** on either side of traffic (`srcNames`/`dstNames Contains <asset name>`), not an id filter — can in principle over/under-match on renames or substring collisions.
- **`purge_reports` is a write** — always confirm the `dry_run=true` preview with the user before calling it again with `dry_run=false`.
