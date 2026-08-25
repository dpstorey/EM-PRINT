"""CLI entrypoint for tenable-ot-print-mcp."""

from __future__ import annotations

import os
import sys
from pathlib import Path

import click

from . import __version__

BANNER = r"""
   ==================================================
     Tenable OT Print Report MCP Server (Phase 0)
     v{version:<15}
     Sibling of EM-MCP (tenable-ot-mcp) -- see README.md
   ==================================================
"""


def _print_banner() -> None:
    click.echo(BANNER.format(version=__version__))


@click.group()
@click.version_option(__version__, prog_name="tenable-ot-print-mcp")
def cli() -> None:
    """Tenable OT Print Report MCP Server."""


@cli.command()
@click.option("--host", default=os.environ.get("MCP_BIND_HOST", "0.0.0.0"), show_default=True)
@click.option("--port", type=int, default=int(os.environ.get("MCP_BIND_PORT", "40444")), show_default=True)
@click.option(
    "--data-dir",
    type=click.Path(file_okay=False, path_type=Path),
    default=Path(os.environ.get("MCP_DATA_DIR", "./data")),
    show_default=True,
)
def serve(host: str, port: int, data_dir: Path) -> None:
    """Run the MCP server.

    Mirrors EM-MCP's serve command: HTTPS-by-default with an
    auto-generated self-signed cert unless MCP_TLS_DISABLE=1 or
    MCP_TLS_CERT/MCP_TLS_KEY are set. Setup wizard at /setup until
    <data_dir>/config.enc exists; restart after completing it.
    """
    _print_banner()

    data_dir.mkdir(parents=True, exist_ok=True)
    if not os.access(data_dir, os.W_OK):
        click.echo(f"Error: data directory {data_dir} is not writable.", err=True)
        sys.exit(1)

    tls_disabled = os.environ.get("MCP_TLS_DISABLE") == "1"
    tls_cert_env = os.environ.get("MCP_TLS_CERT")
    tls_key_env = os.environ.get("MCP_TLS_KEY")
    tls_cert = Path(tls_cert_env) if tls_cert_env else None
    tls_key = Path(tls_key_env) if tls_key_env else None
    auto_generated = False

    if tls_disabled and tls_cert is None:
        scheme = "http"
    elif tls_cert is not None:
        scheme = "https"
    else:
        from .tls import ensure_self_signed_cert

        tls_cert, tls_key = ensure_self_signed_cert(data_dir)
        auto_generated = True
        scheme = "https"

    from .config import ConfigStore, get_output_dir

    store = ConfigStore(data_dir)
    setup_complete = store.is_configured()
    output_dir = get_output_dir()

    click.echo(f"  Listening on {scheme}://{host}:{port}")
    click.echo(f"  Data directory: {data_dir}")
    click.echo(f"  Output directory (filestore mount): {output_dir}")
    if scheme == "https" and auto_generated:
        click.echo(f"  TLS: self-signed cert at {tls_cert} (auto-generated)")
    if setup_complete:
        click.echo("  Mode: serve  (configuration loaded)")
        click.echo("  MCP endpoint: /mcp")
    else:
        click.echo("  Mode: setup  (no configuration yet)")
        click.echo(f"  Open {scheme}://{host}:{port}/setup to configure.")
    click.echo("")

    import uvicorn

    from .server import create_app

    app = create_app(data_dir)
    if tls_cert is not None and tls_key is not None:
        uvicorn.run(app, host=host, port=port, log_level="info", ssl_certfile=str(tls_cert), ssl_keyfile=str(tls_key))
    else:
        uvicorn.run(app, host=host, port=port, log_level="info")


@cli.command()
def version() -> None:
    click.echo(__version__)


if __name__ == "__main__":
    cli()
