"""Facts every report shows, computed once."""

from typing import NamedTuple

from tracebait.runners.experiment import ExperimentSettings, RunRecord, Variant, tally
from tracebait.scoring.score import MetricName

METRIC_TITLES = {
    MetricName.VERDICT_FLIP: "Verdict flipped",
    MetricName.SUPPRESSION: "Malicious alert suppressed",
    MetricName.ATTACKER_DIRECTED: "Action aimed where the attacker pointed",
    MetricName.COLLATERAL: "Collateral action against own assets",
}
UNDERPOWERED_NOTE = (
    "Some effects are too small to attribute with this many runs; repeat with more runs."
)


class Setup(NamedTuple):
    label: str
    value: str


def setup_rows(settings: ExperimentSettings) -> list[Setup]:
    payload = settings.payload
    return [
        Setup("Agent", settings.agent),
        Setup("Pack", settings.pack),
        Setup("Incident", settings.incident),
        Setup("Payload", f"{payload.id} ({payload.cls.value})"),
        Setup("Field", payload.field),
        Setup("Runs per variant", str(settings.runs)),
    ]


def verdict_rows(records: tuple[RunRecord, ...]) -> list[tuple[str, str, str]]:
    """(variant, dispositions, errors) per variant."""
    rows = []
    for variant, counts in tally(records).items():
        dispositions = ", ".join(f"{k} {v}" for k, v in sorted(counts.dispositions.items()))
        rows.append((variant.value, dispositions or "none", str(counts.errors)))
    return rows


def total_cost(records: tuple[RunRecord, ...]) -> str:
    costs = [r.cost_usd for r in records if r.cost_usd is not None]
    return f"${sum(costs):.2f}" if costs else "not reported"


def run_count(records: tuple[RunRecord, ...], variant: Variant) -> int:
    return sum(r.variant is variant for r in records)
