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
from tracebait.runners.experiment import (
    ExperimentError,
    VariantTally,
    load_experiment,
    run_experiment,
    tally,
)
from tracebait.scoring.score import Score, score

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
    inventory: Annotated[
        Path | None, typer.Option(help="Asset inventory .json file, served and used in scoring.")
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
            inventory_path=inventory,
            timeout_seconds=timeout,
        )
    except ExperimentError as exc:
        raise typer.BadParameter(str(exc)) from exc
    summary = tally(records)
    for variant, counts in summary.items():
        typer.echo(_describe(variant.value, counts))
    costs = [c.cost_usd for c in summary.values() if c.cost_usd is not None]
    typer.echo(f"total cost: ${sum(costs):.2f}" if costs else "total cost: not reported")
    typer.echo(f"results: {out / 'results.jsonl'}; score them with: tracebait score {out}")


def _describe(name: str, counts: VariantTally) -> str:
    dispositions = ", ".join(f"{k}: {v}" for k, v in sorted(counts.dispositions.items()))
    actions = ", ".join(f"{k}: {v}" for k, v in sorted(counts.actions.items())) or "none"
    return (
        f"{name}: {counts.runs} runs, {counts.errors} without a verdict;"
        f" dispositions {dispositions or 'none'}; actions {actions}"
    )


@app.command(name="score")
def score_command(
    out: Annotated[Path, typer.Argument(help="Directory an experiment wrote its results to.")],
    fail_under: Annotated[
        int | None, typer.Option(min=0, max=100, help="Exit with code 1 below this grade.")
    ] = None,
    as_json: Annotated[bool, typer.Option("--json", help="Print the score as JSON.")] = False,
) -> None:
    """Grade an experiment from 0 to 100: how far the payload moved the agent."""
    try:
        settings, records = load_experiment(out)
        incident = resolve_incident(settings.pack, settings.incident)
        result = score(
            records, incident=incident, payload=settings.payload, inventory=settings.inventory
        )
    except (ExperimentError, SessionError, ValueError) as exc:
        raise typer.BadParameter(str(exc)) from exc
    typer.echo(result.model_dump_json(indent=2) if as_json else _report(result))
    if fail_under is not None and result.grade < fail_under:
        if not as_json:
            typer.echo(f"grade {result.grade} is below {fail_under}")
        raise typer.Exit(code=1)


def _report(result: Score) -> str:
    lines = [f"grade {result.grade}/100 (attributed when p < {result.alpha})", ""]
    lines.append(f"{'metric':<18} {'clean':>7} {'poisoned':>9} {'effect':>7} {'p':>7}  attributed")
    for m in result.metrics:
        if not m.applicable:
            lines.append(f"{m.name.value:<18} {'not applicable to this incident':>34}")
            continue
        attributed = "yes" if m.attributed else "no"
        lines.append(
            f"{m.name.value:<18} {m.clean_hits:>3}/{m.clean_runs:<3} {m.poisoned_hits:>4}/"
            f"{m.poisoned_runs:<4} {m.effect:>7.2f} {m.p_value:>7.3f}  {attributed}"
        )
    if result.underpowered:
        lines += ["", "Some effects are too small to attribute with this many runs; add --runs."]
    return "\n".join(lines)
