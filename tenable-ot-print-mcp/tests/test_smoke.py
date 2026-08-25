"""Phase 0 smoke test: module discovery + end-to-end render, no live EM needed."""

from __future__ import annotations

import tempfile
from pathlib import Path

from tenable_ot_print_mcp.modules import _MODULES_DIR, discover_manifests, load_module
from tenable_ot_print_mcp.render import render_report


def test_discover_manifests_finds_asset_inventory():
    manifests = discover_manifests()
    assert "asset_inventory" in manifests
    assert manifests["asset_inventory"].output_formats == ["markdown", "html"]


def test_asset_inventory_validate_params_defaults():
    module = load_module("asset_inventory")
    normalized = module.validate_params({})
    assert normalized == {"limit": 100, "criticality_at_least": None}


def test_asset_inventory_validate_params_rejects_bad_criticality():
    module = load_module("asset_inventory")
    try:
        module.validate_params({"criticality_at_least": "extreme"})
    except ValueError:
        pass
    else:
        raise AssertionError("expected ValueError for invalid criticality_at_least")


def test_render_report_end_to_end_no_live_em():
    """Fabricates fetch_data's output directly -- proves the module ->
    template -> theme -> filestore pipeline without needing a live
    Tenable OT/EM connection."""
    module = load_module("asset_inventory")
    fake_data = {
        "total_count": 2,
        "nodes": [
            {
                "name": "plc-101",
                "vendor": "Siemens",
                "model": "S7-1200",
                "firmwareVersion": "4.5.0",
                "criticality": "high",
                "lastSeen": "2026-08-20T00:00:00Z",
                "ips": {"nodes": ["10.0.0.5"]},
                "risk": {"totalRisk": 82, "pluginCount": 3, "unresolvedEvents": 1},
            },
            {
                "name": "hmi-old",
                "vendor": "Rockwell",
                "model": "PanelView",
                "firmwareVersion": "2.1",
                "criticality": "none",
                "lastSeen": "2026-08-19T00:00:00Z",
                "ips": {"nodes": []},
                "risk": {},
            },
        ],
    }
    context = module.to_markdown_context(fake_data, {"limit": 100, "criticality_at_least": None})

    with tempfile.TemporaryDirectory() as tmp:
        output_dir = Path(tmp)
        result = render_report(
            module_name="asset_inventory",
            module_template_dir=_MODULES_DIR / "asset_inventory",
            template_name=module.template_name,
            context=context,
            theme_name="default",
            theme_overrides=None,
            output_dir=output_dir,
            formats=["markdown", "html"],
        )
        assert result.markdown_path.is_file()
        assert result.html_path.is_file()
        md_text = result.markdown_path.read_text()
        html_text = result.html_path.read_text()
        assert "plc-101" in md_text
        assert "hmi-old" in md_text
        assert "plc-101" in html_text
        assert "<table>" in html_text
        assert "Asset Inventory" in html_text  # header theme rendered report_title
