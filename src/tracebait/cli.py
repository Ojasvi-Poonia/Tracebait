"""Command-line entry point (``tracebait``)."""

from pathlib import Path
from typing import Annotated

import typer

from tracebait import __version__
from tracebait.honeypot.inventory import Inventory, InventoryError, load_inventory
from tracebait.honeypot.recorder import ActionLog
from tracebait.honeypot.server import build_server
from tracebait.honeypot.session import SessionError, resolve_incident

app = typer.Typer(
    name="tracebait",
    help="Test whether attacker-written log fields can steer AI SOC agents.",
    no_args_is_help=True,
    add_completion=False,
)


def _print_version(value: bool) -> None:
    if value:
        typer.echo(f"tracebait {__version__}")
        raise typer.Exit


@app.callback()
def main(
    version: Annotated[
        bool,
        typer.Option(
            "--version", callback=_print_version, is_eager=True, help="Show the version and exit."
        ),
    ] = False,
) -> None:
    """Test whether attacker-written log fields can steer AI SOC agents."""


@app.command()
def honeypot(
    pack: Annotated[str, typer.Option(help="Built-in pack name, or a path to a pack .json file.")],
    incident: Annotated[str, typer.Option(help="Id of the incident in the pack to serve.")],
    actions: Annotated[
        Path, typer.Option(help="JSON Lines file to record response actions to (replaced).")
    ],
    payload: Annotated[
        Path | None, typer.Option(help="Payload .json file: serve the poisoned twin instead.")
    ] = None,
    entry_index: Annotated[
        int | None, typer.Option(help="Entry to poison, if not the first with the field.")
    ] = None,
    inventory: Annotated[
        Path | None, typer.Option(help="Asset inventory .json file for lookup_asset.")
    ] = None,
) -> None:
    """Serve one incident to an agent as an MCP server over stdio."""
    try:
        served = resolve_incident(pack, incident, payload_path=payload, entry_index=entry_index)
        assets = load_inventory(inventory) if inventory else Inventory()
    except (SessionError, InventoryError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    build_server(served, inventory=assets, log=ActionLog(actions)).run("stdio")
