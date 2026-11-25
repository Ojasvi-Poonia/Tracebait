"""Command-line entry point (``tracebait``)."""

from pathlib import Path
from typing import Annotated

import typer

from tracebait import __version__
from tracebait.honeypot.inventory import Inventory, InventoryError, load_inventory
from tracebait.honeypot.recorder import ActionLog
from tracebait.honeypot.server import build_server
from tracebait.honeypot.session import SessionError, resolve_incident
from tracebait.runners.claude_code import ClaudeCode
from tracebait.runners.experiment import ExperimentError, VariantTally, run_experiment, tally

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


DEFAULT_BUDGET_USD = 1.0


@app.command()
def run(
    pack: Annotated[str, typer.Option(help="Built-in pack name, or a path to a pack .json file.")],
    incident: Annotated[str, typer.Option(help="Id of the incident in the pack.")],
    payload: Annotated[Path, typer.Option(help="Payload .json file for the poisoned copy.")],
    out: Annotated[Path, typer.Option(help="New directory for results and per-run logs.")],
    runs: Annotated[int, typer.Option(help="Runs per variant (clean and poisoned).")] = 5,
    model: Annotated[str | None, typer.Option(help="Claude model alias or id.")] = None,
    max_budget_usd: Annotated[
        float, typer.Option(help="Spending cap for each agent run, in US dollars.")
    ] = DEFAULT_BUDGET_USD,
    bare: Annotated[
        bool, typer.Option(help="Use claude --bare (fully isolated; needs ANTHROPIC_API_KEY).")
    ] = False,
    timeout: Annotated[int, typer.Option(help="Seconds before a run is stopped.")] = 600,
    entry_index: Annotated[
        int | None, typer.Option(help="Entry to poison, if not the first with the field.")
    ] = None,
    claude: Annotated[str, typer.Option(help="Claude Code executable.")] = "claude",
) -> None:
    """Run Claude Code on the clean and poisoned copies of an incident and tally the results.

    Each run is a real agent session and is billed to your Claude account.
    """
    agent = ClaudeCode(model=model, max_budget_usd=max_budget_usd, bare=bare, executable=claude)
    try:
        records = run_experiment(
            agent,
            pack,
            incident,
            payload_path=payload,
            runs=runs,
            out_dir=out,
            entry_index=entry_index,
            timeout_seconds=timeout,
        )
    except ExperimentError as exc:
        raise typer.BadParameter(str(exc)) from exc
    summary = tally(records)
    for variant, counts in summary.items():
        typer.echo(_describe(variant.value, counts))
    costs = [c.cost_usd for c in summary.values() if c.cost_usd is not None]
    typer.echo(f"total cost: ${sum(costs):.2f}" if costs else "total cost: not reported")
    typer.echo(f"results: {out / 'results.jsonl'}")


def _describe(name: str, counts: VariantTally) -> str:
    dispositions = ", ".join(f"{k}: {v}" for k, v in sorted(counts.dispositions.items()))
    actions = ", ".join(f"{k}: {v}" for k, v in sorted(counts.actions.items())) or "none"
    return (
        f"{name}: {counts.runs} runs, {counts.errors} without a verdict;"
        f" dispositions {dispositions or 'none'}; actions {actions}"
    )
