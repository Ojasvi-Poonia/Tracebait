"""A Markdown report sized for a pull-request comment."""

import re

from tracebait.reports.common import (
    METRIC_TITLES,
    UNDERPOWERED_NOTE,
    setup_rows,
    total_cost,
    verdict_rows,
)
from tracebait.runners.experiment import ExperimentSettings, RunRecord
from tracebait.scoring.score import Score

_BACKTICK_RUN = re.compile(r"`+")
MIN_FENCE = 3


def render(settings: ExperimentSettings, records: tuple[RunRecord, ...], result: Score) -> str:
    lines = [
        f"## tracebait: **{result.grade}/100**",
        "",
        "| Metric | Clean | Poisoned | Effect | p | Attributed |",
        "|---|---|---|---|---|---|",
    ]
    for m in result.metrics:
        if not m.applicable:
            lines.append(f"| {m.name.value} | n/a | n/a | | | not applicable |")
            continue
        lines.append(
            f"| {m.name.value} | {m.clean_hits}/{m.clean_runs} | {m.poisoned_hits}/"
            f"{m.poisoned_runs} | {m.effect:.2f} | {m.p_value:.3f} |"
            f" {'**yes**: ' + METRIC_TITLES[m.name] if m.attributed else 'no'} |"
        )
    lines += ["", f"Effects count when p < {result.alpha} (one-sided Fisher exact test)."]
    if result.underpowered:
        lines += ["", f"> [!NOTE]\n> {UNDERPOWERED_NOTE}"]
    lines += ["", "| Setup | |", "|---|---|"]
    lines += [f"| {row.label} | `{_inline(row.value)}` |" for row in setup_rows(settings)]
    lines += ["", "| Variant | Dispositions | Runs without a verdict |", "|---|---|---|"]
    lines += [f"| {v} | {d} | {e} |" for v, d, e in verdict_rows(records)]
    lines += ["", f"Total agent cost: {total_cost(records)}", ""]
    lines += ["<details><summary>Payload text</summary>", "", *_fenced(settings.payload.text)]
    lines += ["", "</details>", ""]
    return "\n".join(lines)


def _fenced(text: str) -> list[str]:
    """A code fence longer than any backtick run in ``text``, so the text cannot end it."""
    longest = max((len(run) for run in _BACKTICK_RUN.findall(text)), default=0)
    fence = "`" * max(MIN_FENCE, longest + 1)
    return [f"{fence}text", text, fence]


def _inline(value: str) -> str:
    # Setup values are ids and names from validated models; strip backticks and pipes
    # anyway so a table cell can never be broken.
    return value.replace("`", "'").replace("|", "/")
