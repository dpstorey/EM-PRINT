# SPDX-License-Identifier: Apache-2.0
"""Report module contract.

Each module under modules/<name>/ implements ReportModule and ships a
manifest.yaml (name, title, description, params, output_formats). The
worker (Phase 0: submit_report_job calls this inline; Phase 2: an
async job worker) is the only thing that touches rendering, the
filestore, or audit logging — modules just fetch data and shape it
into a template context.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any

from ..tenable_client import TenableClient


class ReportModule(ABC):
    """Base class every report module must implement."""

    #: Jinja2 template file, relative to this module's own directory.
    template_name: str = "template.md.j2"

    @abstractmethod
    def validate_params(self, params: dict[str, Any]) -> dict[str, Any]:
        """Validate and normalize job params against this module's manifest.

        Raise ValueError with an actionable message on invalid input.
        Return the normalized params dict to use for fetch_data.
        """

    @abstractmethod
    async def fetch_data(self, client: TenableClient, params: dict[str, Any]) -> dict[str, Any]:
        """Fetch whatever GraphQL data this report needs.

        Multi-ICP fan-out (bounded concurrency, partial success) is a
        Phase 2 concern layered in here later — see EM-MCP's
        tools/_sites.py for the pattern to reuse. Phase 0 modules query
        a single configured EM/ICP connection.
        """

    @abstractmethod
    def to_markdown_context(self, data: dict[str, Any], params: dict[str, Any]) -> dict[str, Any]:
        """Shape fetched data into the dict passed to this module's Jinja2 template."""
