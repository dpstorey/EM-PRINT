"""Bearer-token authentication for the MCP endpoint.

Identical pattern to EM-MCP's auth.py: one token issued at setup,
presented as `Authorization: Bearer <token>`, constant-time compared.
`/setup` and `/healthz` are unauthenticated; `/mcp` checks the header.
"""

from __future__ import annotations

import hmac
from dataclasses import dataclass

from .config import Config


@dataclass(frozen=True)
class Principal:
    authenticated: bool = True


class AuthError(Exception):
    """Raised when a request fails bearer-token authentication."""


def _extract_bearer(authorization_header: str | None) -> str | None:
    if not authorization_header:
        return None
    parts = authorization_header.split(None, 1)
    if len(parts) != 2 or parts[0].lower() != "bearer":
        return None
    return parts[1].strip()


def authenticate(authorization_header: str | None, cfg: Config) -> Principal:
    presented = _extract_bearer(authorization_header)
    if not presented:
        raise AuthError("Missing or malformed Authorization header")
    if hmac.compare_digest(presented, cfg.bearer_token):
        return Principal()
    raise AuthError("Bearer token does not match the configured token")
