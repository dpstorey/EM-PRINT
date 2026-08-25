"""Starlette app exposing /healthz, /setup, /.well-known/*, and /mcp.

Adapted from EM-MCP's server.py — same setup-wizard-then-restart model:
absent config -> only /healthz and /setup work, /mcp returns 503;
present config -> FastMCP sub-app built eagerly and mounted under /mcp
behind the bearer-auth gate.
"""

from __future__ import annotations

import contextlib
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

from jinja2 import Environment, PackageLoader, select_autoescape
from starlette.applications import Starlette
from starlette.datastructures import Headers
from starlette.requests import Request
from starlette.responses import HTMLResponse, JSONResponse, Response
from starlette.routing import Route

from . import __version__
from .audit import AuditLog
from .auth import AuthError, authenticate
from .config import Config, ConfigStore, generate_bearer_token, get_ca_bundle_path
from .tenable_client import TenableClient


class AppState:
    def __init__(self, data_dir: Path) -> None:
        self.data_dir = data_dir
        self.store = ConfigStore(data_dir)
        self.audit = AuditLog(data_dir)
        self._config: Config | None = None
        self.mcp_app: Any | None = None
        if self.store.is_configured():
            self._config = self.store.load()
            from .mcp_app import build_mcp_app

            self.mcp_app = build_mcp_app(self._config, self.audit, self.data_dir)

    def get_config(self) -> Config | None:
        return self._config

    def set_config(self, cfg: Config) -> None:
        self._config = cfg


def _jinja() -> Environment:
    return Environment(
        loader=PackageLoader("tenable_ot_print_mcp", "templates"),
        autoescape=select_autoescape(["html"]),
    )


async def healthz(request: Request) -> JSONResponse:
    state: AppState = request.app.state.app_state
    return JSONResponse({"status": "ok", "configured": state.get_config() is not None, "version": __version__})


async def setup_get(request: Request) -> Response:
    state: AppState = request.app.state.app_state
    env = request.app.state.jinja
    if state.get_config() is not None:
        return JSONResponse(
            {
                "error": "Server is already configured.",
                "hint": "Delete config.enc and config.key on the data volume to re-run setup.",
            },
            status_code=409,
        )
    tmpl = env.get_template("setup.html")
    return HTMLResponse(tmpl.render(form={"tls_verify": True}, error=None))


async def setup_post(request: Request) -> Response:
    state: AppState = request.app.state.app_state
    env = request.app.state.jinja
    if state.get_config() is not None:
        return JSONResponse({"error": "Server is already configured."}, status_code=409)

    form = await request.form()

    def _form_str(name: str) -> str:
        val = form.get(name)
        return val.strip() if isinstance(val, str) else ""

    tenable_url = _form_str("tenable_url")
    tenable_api_key = _form_str("tenable_api_key")
    tls_verify = "tls_verify" in form

    form_state = {"tenable_url": tenable_url, "tls_verify": tls_verify, "tenable_api_key": ""}

    def _render_error(msg: str, status: int = 400) -> HTMLResponse:
        tmpl = env.get_template("setup.html")
        return HTMLResponse(tmpl.render(form=form_state, error=msg), status_code=status)

    if not tenable_url or not tenable_api_key:
        return _render_error("Both URL and API key are required.")
    if not tenable_url.lower().startswith(("http://", "https://")):
        return _render_error("URL must start with http:// or https://.")

    ca_bundle = get_ca_bundle_path(state.data_dir)
    client = TenableClient(
        tenable_url,
        tenable_api_key,
        tls_verify=tls_verify,
        ca_bundle=str(ca_bundle) if ca_bundle else None,
    )
    ok = await client.healthcheck()
    if not ok:
        hint = (
            f" A custom CA bundle is configured at {ca_bundle}; if this deployment uses an "
            "internal/private CA, confirm that file has the right cert."
            if ca_bundle
            else " If your EM/ICP's TLS cert is signed by an internal/private CA, drop it "
            "(PEM format) at MCP_TENABLE_CA_BUNDLE, or ./data/tenable-ca.pem, and retry."
        )
        return _render_error(
            "Could not reach Tenable OT/EM or authenticate. Check URL, API key, and TLS settings."
            + hint,
            status=502,
        )

    bearer_token = generate_bearer_token()
    cfg = Config(
        tenable_url=tenable_url,
        tenable_api_key=tenable_api_key,
        tls_verify=tls_verify,
        bearer_token=bearer_token,
    )
    state.store.save(cfg)
    state.set_config(cfg)

    scheme = request.url.scheme
    netloc = request.url.netloc
    mcp_url = f"{scheme}://{netloc}/mcp"

    tmpl = env.get_template("setup_done.html")
    return HTMLResponse(tmpl.render(bearer_token=bearer_token, mcp_url=mcp_url))


async def well_known_protected_resource(request: Request) -> JSONResponse:
    state: AppState = request.app.state.app_state
    if state.get_config() is None:
        return JSONResponse({"error": "Server not configured."}, status_code=503)
    base = f"{request.url.scheme}://{request.url.netloc}"
    return JSONResponse(
        {
            "resource": f"{base}/mcp",
            "authorization_servers": [],
            "bearer_methods_supported": ["header"],
        }
    )


async def mcp_unconfigured(request: Request) -> Response:
    return JSONResponse(
        {"error": "Server not configured. Visit /setup, then restart the container."},
        status_code=503,
    )


class McpAuthGate:
    """Bearer-auth gate in front of the FastMCP Streamable HTTP app.

    Raw ASGI callable (not a Starlette request/response endpoint) —
    same reasoning as EM-MCP: the FastMCP sub-app owns the whole
    response lifecycle including long-lived SSE streams.
    """

    def __init__(self, state: AppState) -> None:
        self._state = state

    async def __call__(self, scope: Any, receive: Any, send: Any) -> None:
        state = self._state
        cfg = state.get_config()
        if cfg is None or state.mcp_app is None:
            await JSONResponse({"error": "Server not configured. Visit /setup."}, status_code=503)(scope, receive, send)
            return
        try:
            authenticate(Headers(scope=scope).get("authorization"), cfg)
        except AuthError as e:
            await JSONResponse(
                {"error": str(e)},
                status_code=401,
                headers={"WWW-Authenticate": 'Bearer realm="tenable-ot-print-mcp"'},
            )(scope, receive, send)
            return
        await state.mcp_app(scope, receive, send)


def create_app(data_dir: Path) -> Starlette:
    state = AppState(data_dir)

    routes: list[Any] = [
        Route("/healthz", healthz, methods=["GET"]),
        Route("/setup", setup_get, methods=["GET"]),
        Route("/setup", setup_post, methods=["POST"]),
        Route("/.well-known/oauth-protected-resource", well_known_protected_resource, methods=["GET"]),
    ]
    if state.mcp_app is not None:
        routes.append(Route("/mcp", McpAuthGate(state), methods=["GET", "POST", "DELETE"]))
    else:
        routes.append(Route("/mcp", mcp_unconfigured, methods=["GET", "POST", "DELETE"]))

    @contextlib.asynccontextmanager
    async def lifespan(_app: Starlette) -> AsyncIterator[None]:
        if state.mcp_app is not None:
            async with state.mcp_app.router.lifespan_context(state.mcp_app):
                yield
        else:
            yield

    app = Starlette(routes=routes, lifespan=lifespan)
    app.state.app_state = state
    app.state.jinja = _jinja()
    return app
