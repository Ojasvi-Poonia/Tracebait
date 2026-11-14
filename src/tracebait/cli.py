"""Command-line entry point (``tracebait``)."""

from typing import Annotated

import typer

from tracebait import __version__

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
