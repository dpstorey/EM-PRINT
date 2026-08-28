# SPDX-License-Identifier: Apache-2.0
"""Minimal async GraphQL client for Tenable One OT Exposure / Enterprise Manager.

Adapted from EM-MCP's tenable_client.py
(../../EM-MCP/tenable-ot-mcp/src/tenable_ot_mcp/tenable_client.py) — this
is domain logic (GraphQL endpoint construction, machine-id validation,
EM root vs ICP-relay queries) that both this repo and EM-MCP need
identically. Right now it's a duplicated copy, not a shared import —
see design-notes.md §6 for the open decision on how to actually share it
(a private package, a git submodule, or a path dependency in the
Docker build). Trimmed to what the report modules need for Phase 0;
re-add site-name resolution helpers if a module needs them.
"""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

import httpx

logger = logging.getLogger(__name__)

_MACHINE_ID_RE = re.compile(
    r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}$"
)


def validate_machine_id(value: str, *, field: str = "site_uuid") -> str:
    """Validate a Tenable site/ICP machine id and return it unchanged.

    A malformed id gets silently relayed to <base>/<machine_id>/graphql
    and answered with an HTML page instead of a GraphQL error — catching
    the bad shape here, before any network call, produces an actionable
    error instead of an opaque "non-JSON response" transport failure.
    """
    candidate = (value or "").strip()
    if not _MACHINE_ID_RE.match(candidate):
        raise ValueError(
            f"{field}={value!r} is not a valid Tenable site/ICP machine id. "
            "Expected a complete UUID in 8-4-4-4-12 hex form. Call "
            "`list_paired_icps` (once implemented) to get the exact machine "
            "id rather than guessing or truncating this value."
        )
    return candidate


_QUERY_EM_PAIRED_ICPS = """
query Q($pageSize: Int!) {
    emPairedIcps(first: $pageSize) {
        edges {
            node {
                site { machineId name }
            }
        }
    }
}
"""


class TenableError(Exception):
    """Raised on a Tenable One OT Exposure GraphQL error or transport failure."""

    def __init__(self, message: str, status: int | None = None) -> None:
        super().__init__(message)
        self.status = status


class TenableClient:
    """Issues authenticated GraphQL POSTs to appliance or EM-relayed ICP endpoints."""

    def __init__(
        self,
        base_url: str,
        api_key: str,
        icp_machine_id: str | None = None,
        tls_verify: bool = True,
        timeout: float = 30.0,
        ca_bundle: str | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self._api_key = api_key
        self._icp_machine_id = icp_machine_id.strip("/") if icp_machine_id else None
        self._tls_verify = tls_verify
        self._timeout = timeout
        # httpx's `verify` accepts a bool OR a path to a custom CA bundle.
        # A configured ca_bundle path always wins over the tls_verify flag --
        # see config.get_ca_bundle_path() for how it's resolved.
        self._verify: bool | str = ca_bundle if ca_bundle else tls_verify
        self._site_name_to_machine_id: dict[str, str] = {}

    def _endpoint_for(self, *, use_em_root: bool = False, icp_machine_id: str | None = None) -> str:
        if use_em_root:
            return f"{self.base_url}/graphql"
        target_icp = icp_machine_id.strip("/") if icp_machine_id else self._icp_machine_id
        if target_icp:
            return f"{self.base_url}/{target_icp}/graphql"
        return f"{self.base_url}/graphql"

    def _headers(self) -> dict[str, str]:
        return {
            "X-APIKeys": f"key={self._api_key}",
            "Content-Type": "application/json",
            "Accept": "application/json",
        }

    async def query(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
        operation_name: str | None = None,
        *,
        use_em_root: bool = False,
        icp_machine_id: str | None = None,
    ) -> dict[str, Any]:
        """Execute a GraphQL operation and return the `data` payload."""
        payload: dict[str, Any] = {"query": query}
        if variables:
            payload["variables"] = variables
        if operation_name:
            payload["operationName"] = operation_name

        endpoint = self._endpoint_for(use_em_root=use_em_root, icp_machine_id=icp_machine_id)

        try:
            async with httpx.AsyncClient(verify=self._verify, timeout=self._timeout) as client:
                resp = await client.post(endpoint, headers=self._headers(), json=payload)
        except httpx.HTTPError as e:
            raise TenableError(f"Transport error talking to T1OE/EM: {e}") from e

        if resp.status_code >= 400:
            raise TenableError(
                f"T1OE/EM returned HTTP {resp.status_code} from {endpoint}: {resp.text[:500]}",
                status=resp.status_code,
            )

        try:
            body = resp.json()
        except json.JSONDecodeError as e:
            content_type = resp.headers.get("content-type", "unknown")
            snippet = " ".join(resp.text[:200].split())
            raise TenableError(
                f"T1OE/EM returned a non-JSON response (HTTP {resp.status_code}, "
                f"content-type={content_type!r}) from {endpoint}. First bytes: {snippet!r}. "
                "If this was an ICP-relay query, the machine id likely does not match a "
                "currently paired site.",
                status=resp.status_code,
            ) from e

        if isinstance(body, dict) and body.get("errors"):
            messages = "; ".join(e.get("message", str(e)) for e in body["errors"])
            raise TenableError(f"T1OE/EM GraphQL errors: {messages}", status=resp.status_code)

        return body.get("data") or {}

    async def healthcheck(self) -> bool:
        """Trivial query used by the setup wizard to validate operator input."""
        try:
            data = await self.query("{ __typename }")
            return bool(data)
        except TenableError:
            return False

    async def connection_status(self) -> dict[str, Any]:
        started = time.perf_counter()
        try:
            await self.query("{ __typename }")
        except TenableError as e:
            return {
                "connected": False,
                "tenable_url": self.base_url,
                "latency_ms": round((time.perf_counter() - started) * 1000),
                "error": str(e),
            }
        return {
            "connected": True,
            "tenable_url": self.base_url,
            "latency_ms": round((time.perf_counter() - started) * 1000),
            "error": None,
        }

    async def query_em(
        self,
        query: str,
        variables: dict[str, Any] | None = None,
        operation_name: str | None = None,
    ) -> dict[str, Any]:
        """Run a query against EM's root GraphQL endpoint (control-plane data)."""
        return await self.query(query=query, variables=variables, operation_name=operation_name, use_em_root=True)

    async def _refresh_site_cache(self) -> None:
        data = await self.query_em(_QUERY_EM_PAIRED_ICPS, variables={"pageSize": 500})
        conn = (data or {}).get("emPairedIcps") or {}
        mapping: dict[str, str] = {}
        for edge in conn.get("edges") or []:
            node = (edge or {}).get("node") or {}
            site = node.get("site") or {}
            machine_id = site.get("machineId")
            site_name = site.get("name")
            if isinstance(machine_id, str) and isinstance(site_name, str):
                if machine_id.strip() and site_name.strip():
                    mapping[site_name.strip().lower()] = machine_id.strip("/")
        self._site_name_to_machine_id = mapping

    async def list_paired_icps(self) -> list[dict[str, str]]:
        """List EM-paired ICPs as [{"name": ..., "machine_id": ...}, ...].

        Assets, vulns, events, etc. live on paired ICPs, not the EM
        root -- an unfiltered `assets` query against `<base>/graphql`
        (no icp_machine_id) is not a lighter/simpler version of a
        per-ICP query, it's a query against the wrong endpoint
        entirely and was seen live to fail with a GraphQL-wrapped
        404. Callers that need asset-level data must resolve an ICP
        machine id first (see `resolve_site_machine_id`) and pass it
        as `icp_machine_id` to `query()`.
        """
        data = await self.query_em(_QUERY_EM_PAIRED_ICPS, variables={"pageSize": 500})
        conn = (data or {}).get("emPairedIcps") or {}
        result: list[dict[str, str]] = []
        for edge in conn.get("edges") or []:
            node = (edge or {}).get("node") or {}
            site = node.get("site") or {}
            machine_id = site.get("machineId")
            name = site.get("name")
            if isinstance(machine_id, str) and isinstance(name, str) and machine_id.strip() and name.strip():
                result.append({"name": name.strip(), "machine_id": machine_id.strip("/")})
        return result

    async def resolve_site_machine_id(self, *, site_uuid: str | None, site_name: str | None) -> str:
        if site_uuid:
            return validate_machine_id(site_uuid.strip("/"), field="site_uuid")
        if not site_name:
            raise ValueError("site_uuid or site_name is required")
        key = site_name.strip().lower()
        if not key:
            raise ValueError("site_uuid or site_name is required")
        machine_id = self._site_name_to_machine_id.get(key)
        if machine_id:
            return machine_id
        await self._refresh_site_cache()
        machine_id = self._site_name_to_machine_id.get(key)
        if not machine_id:
            raise ValueError("site not found")
        return machine_id
