"""Report module registry: discovers modules/<name>/manifest.yaml + module.py.

In-house-only plugin trust model (see design-notes.md §4): modules are
dynamically imported, not sandboxed. A manifest is validated before
import so a broken module fails loudly at discovery time rather than
mid-job.
"""

from __future__ import annotations

import importlib
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from ._base import ReportModule

_MODULES_DIR = Path(__file__).parent


@dataclass(frozen=True)
class ModuleManifest:
    name: str
    title: str
    description: str
    params: list[dict[str, Any]]
    output_formats: list[str]


def _load_manifest(path: Path) -> ModuleManifest:
    raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    required = {"name", "title", "description"}
    missing = required - raw.keys()
    if missing:
        raise ValueError(f"{path}: manifest missing required field(s): {sorted(missing)}")
    return ModuleManifest(
        name=raw["name"],
        title=raw["title"],
        description=raw["description"],
        params=raw.get("params", []),
        output_formats=raw.get("output_formats", ["markdown", "html"]),
    )


def discover_manifests() -> dict[str, ModuleManifest]:
    """Scan modules/*/manifest.yaml. Raises on a malformed manifest —
    fail startup loudly rather than silently drop a broken module."""
    manifests: dict[str, ModuleManifest] = {}
    for child in sorted(_MODULES_DIR.iterdir()):
        manifest_path = child / "manifest.yaml"
        if child.is_dir() and manifest_path.is_file():
            manifest = _load_manifest(manifest_path)
            if manifest.name in manifests:
                raise ValueError(f"Duplicate module name {manifest.name!r} in {child}")
            manifests[manifest.name] = manifest
    return manifests


def load_module(name: str) -> ReportModule:
    """Dynamically import modules/<name>/module.py and return its ReportModule instance.

    Convention: module.py must define a module-level `MODULE` instance
    of a ReportModule subclass.
    """
    manifests = discover_manifests()
    if name not in manifests:
        raise ValueError(f"Unknown report module {name!r}. Known modules: {sorted(manifests)}")
    mod = importlib.import_module(f".{name}.module", package=__name__)
    instance = getattr(mod, "MODULE", None)
    if not isinstance(instance, ReportModule):
        raise ValueError(f"modules/{name}/module.py must define MODULE = <ReportModule instance>")
    return instance
