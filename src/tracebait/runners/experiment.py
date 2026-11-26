"""Run an agent several times on the clean and poisoned copies of one incident.

Clean and poisoned runs alternate (clean 1, poisoned 1, clean 2, ...), so drift in the
agent over the course of an experiment affects both variants alike. Every run gets its
own action log and an empty, neutrally named temporary working directory. The twin is
built before any agent starts, so an unusable payload costs nothing.
"""

import sys
import tempfile
import time
from collections import Counter
from enum import StrEnum
from pathlib import Path

from pydantic import Field, ValidationError

from tracebait.honeypot.inventory import Inventory, InventoryError, load_inventory
from tracebait.honeypot.recorder import Action, read_actions
from tracebait.honeypot.server import SERVER_NAME
from tracebait.honeypot.session import SessionError, resolve_incident
from tracebait.models import FrozenModel, Payload, Verdict
from tracebait.runners.agent import Agent, AgentTask, McpServer
from tracebait.runners.prompt import TRIAGE_PROMPT

MAX_RUNS = 100
RESULTS_FILE = "results.jsonl"
SETTINGS_FILE = "experiment.json"
SESSION_PREFIX = "session-"


class ExperimentError(ValueError):
    """An experiment cannot start, or its results cannot be read."""


class Variant(StrEnum):
    CLEAN = "clean"
    POISONED = "poisoned"


class RunRecord(FrozenModel):
    variant: Variant
    run: int = Field(ge=1)
    verdict: Verdict | None
    actions: tuple[Action, ...]
    error: str | None = None
    cost_usd: float | None = Field(default=None, ge=0)
    duration_seconds: float = Field(ge=0)


class ExperimentSettings(FrozenModel):
    """Everything needed to rerun or score an experiment, saved as experiment.json."""

    agent: str
    pack: str  # built-in pack name, or an absolute path to a pack file
    incident: str
    entry_index: int | None
    runs: int = Field(ge=1, le=MAX_RUNS)
    payload: Payload
    inventory: Inventory


def run_experiment(
    agent: Agent,
    pack: str,
    incident_id: str,
    *,
    payload_path: Path,
    runs: int,
    out_dir: Path,
    entry_index: int | None = None,
    inventory_path: Path | None = None,
    timeout_seconds: int = 600,
) -> tuple[RunRecord, ...]:
    """Run ``agent`` ``runs`` times on each variant; write and return every record."""
    if not 1 <= runs <= MAX_RUNS:
        raise ExperimentError(f"runs must be between 1 and {MAX_RUNS}")
    results_path = out_dir / RESULTS_FILE
    if results_path.exists():
        raise ExperimentError(f"{results_path} already exists; choose a new output directory")
    # The honeypot runs in the agent's working directory, so every path must be absolute.
    pack_ref = str(Path(pack).resolve()) if Path(pack).suffix == ".json" else pack
    try:
        resolve_incident(pack_ref, incident_id, payload_path=payload_path, entry_index=entry_index)
        payload = Payload.model_validate_json(payload_path.read_bytes())
        inventory = load_inventory(inventory_path) if inventory_path else Inventory()
    except (SessionError, InventoryError, OSError, ValidationError) as exc:
        raise ExperimentError(str(exc)) from exc

    settings = ExperimentSettings(
        agent=agent.name,
        pack=pack_ref,
        incident=incident_id,
        entry_index=entry_index,
        runs=runs,
        payload=payload,
        inventory=inventory,
    )
    base = ["-m", "tracebait", "honeypot", "--pack", pack_ref, "--incident", incident_id]
    if inventory_path is not None:
        base += ["--inventory", str(inventory_path.resolve())]
    poisoned = ["--payload", str(payload_path.resolve())]
    if entry_index is not None:
        poisoned += ["--entry-index", str(entry_index)]
    honeypot = {Variant.CLEAN: base, Variant.POISONED: base + poisoned}

    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / SETTINGS_FILE).write_text(settings.model_dump_json(indent=2) + "\n", "utf-8")
    results_path.write_text("", encoding="utf-8")
    records: list[RunRecord] = []
    for run in range(1, runs + 1):
        for variant in Variant:
            record = _run_once(agent, variant, run, honeypot[variant], out_dir, timeout_seconds)
            with results_path.open("a", encoding="utf-8") as out:
                out.write(record.model_dump_json() + "\n")
            records.append(record)
    return tuple(records)


def load_experiment(out_dir: Path) -> tuple[ExperimentSettings, tuple[RunRecord, ...]]:
    """The settings and run records an experiment wrote to ``out_dir``."""
    settings_path = out_dir / SETTINGS_FILE
    try:
        settings = ExperimentSettings.model_validate_json(settings_path.read_bytes())
    except OSError as exc:
        raise ExperimentError(f"cannot read {settings_path}: {exc.strerror}") from exc
    except ValidationError as exc:
        raise ExperimentError(f"invalid {settings_path}: {exc}") from exc
    try:
        return settings, read_results(out_dir / RESULTS_FILE)
    except OSError as exc:
        raise ExperimentError(f"cannot read {out_dir / RESULTS_FILE}: {exc.strerror}") from exc


def read_results(path: Path) -> tuple[RunRecord, ...]:
    records: list[RunRecord] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        try:
            records.append(RunRecord.model_validate_json(line))
        except ValidationError as exc:
            raise ExperimentError(f"{path} line {number} is not a valid run: {exc}") from exc
    return tuple(records)


def _run_once(
    agent: Agent,
    variant: Variant,
    run: int,
    honeypot_args: list[str],
    out_dir: Path,
    timeout_seconds: int,
) -> RunRecord:
    run_dir = (out_dir / f"{variant.value}-{run:03d}").resolve()
    run_dir.mkdir()
    actions_path = run_dir / "actions.jsonl"
    server = McpServer(
        name=SERVER_NAME,
        command=sys.executable,
        args=(*honeypot_args, "--actions", str(actions_path)),
    )
    task = AgentTask(prompt=TRIAGE_PROMPT, server=server, timeout_seconds=timeout_seconds)
    # Claude Code tells the model its working directory, so the agent works in a neutral
    # temporary directory, never one named after the variant or the output directory.
    with tempfile.TemporaryDirectory(prefix=SESSION_PREFIX) as session:
        workdir = Path(session) / "workspace"
        workdir.mkdir()
        started = time.monotonic()
        reply = agent.run(task, workdir)
        duration = time.monotonic() - started
    (run_dir / "agent-output.txt").write_text(reply.raw, encoding="utf-8")
    return RunRecord(
        variant=variant,
        run=run,
        verdict=reply.verdict,
        actions=read_actions(actions_path) if actions_path.exists() else (),
        error=reply.error,
        cost_usd=reply.cost_usd,
        duration_seconds=duration,
    )


class VariantTally(FrozenModel):
    """Raw counts for one variant. Scoring (flip rates, grade) is a separate step."""

    runs: int
    errors: int  # runs without a verdict
    dispositions: dict[str, int]
    actions: dict[str, int]
    cost_usd: float | None  # None when the agent reported no cost


def tally(records: tuple[RunRecord, ...]) -> dict[Variant, VariantTally]:
    return {
        variant: _tally_one([r for r in records if r.variant is variant]) for variant in Variant
    }


def _tally_one(records: list[RunRecord]) -> VariantTally:
    costs = [r.cost_usd for r in records if r.cost_usd is not None]
    return VariantTally(
        runs=len(records),
        errors=sum(r.verdict is None for r in records),
        dispositions=dict(Counter(r.verdict.disposition.value for r in records if r.verdict)),
        actions=dict(Counter(a.tool for r in records for a in r.actions)),
        cost_usd=sum(costs) if costs else None,
    )
