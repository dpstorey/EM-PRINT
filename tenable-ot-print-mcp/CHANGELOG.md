# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Fixed
- **Licensing** — corrected the copyright holder in `LICENSE`'s filled-in
  appendix (was copied from the sibling EM-MCP project and pointed at
  the wrong entity), added a copyright line to `NOTICE`, added
  `SPDX-License-Identifier: Apache-2.0` headers to every source and
  test file, and copied `LICENSE`/`NOTICE` to the repo root so license
  detection actually picks them up.
- **Docs** — `README.md` no longer undersells the tool surface as "one
  tool against a sample module"; it now reflects all nine MCP tools
  across four report modules, and a top-level orientation `README.md`
  was restored at the true repo root.

## [0.1.0] - 2026-08-28

### Added
- Phase 0 skeleton: report module framework, setup wizard, MCP tool
  registration, `asset_inventory` sample module.
- Custom CA bundle support for self-signed/internal-CA Enterprise
  Manager deployments; `ai-services` Docker network attachment.
- Site/subnet filtering on `asset_inventory`.
- Query routing to individual ICPs.
- Strict param validation, free-text `search`, and cursor pagination
  on list-style modules; uncapped-by-default fetch (fetch every
  matching record unless `limit` is given, same convention as
  EM-MCP).
- `list_available_columns` tool; flexible, selectable column output
  (up to 45 columns across modules).
- Custom asset-field labels, selectable by their live UI name instead
  of just the stable slot key.
- `vulnerability_findings` and `policy_findings` report modules, with
  sortable findings and per-module column defaults.
- `risk_profile` module — the deterministic, RAISE-style risk-grading
  print report: per-asset vulnerability and policy-finding rollups, a
  1-hop communication/attack-pathway neighborhood, and a caller-defined
  risk-grade table (`risk_grades` / `risk_grade_fields` /
  `risk_grade_scale`).
- `save_risk_grade_scale` / `list_risk_grade_scales` — persist a named
  risk-grade table once instead of resending it on every
  `risk_profile` call.
- `list_recent_report_jobs` tool.
- Report retention: `set_report_retention_policy` /
  `get_report_retention_policy` / `purge_reports` (dry-run by
  default).
- Two themes (`default`, `dark-banner`) with per-report
  `theme_overrides` for logos and header/footer text.

### Changed
- Reunified split filtered/unfiltered asset queries back into one,
  isolating and fixing a live 404.
- Omit GraphQL filter arguments instead of sending `null`.
- Polish pass: space-joined IPs (word-wrap safe in rendered reports),
  Low/Medium/High/None criticality labels, risk score to one decimal.
