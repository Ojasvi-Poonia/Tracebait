"""Render a scored experiment as Markdown (PR comments), SARIF (code scanning) or HTML.

Payload text is attacker-written, so every renderer treats it as hostile: HTML escapes
it, and Markdown keeps it inside a fence it cannot close (where @mentions do not notify).
"""

from enum import StrEnum

from tracebait.reports import html, markdown, sarif
from tracebait.runners.experiment import ExperimentSettings, RunRecord
from tracebait.scoring.score import Score


class Format(StrEnum):
    MARKDOWN = "markdown"
    SARIF = "sarif"
    HTML = "html"


def render(
    fmt: Format,
    settings: ExperimentSettings,
    records: tuple[RunRecord, ...],
    result: Score,
    *,
    artifact_uri: str = "experiment.json",
) -> str:
    """The report as text. ``artifact_uri`` is where SARIF results point."""
    match fmt:
        case Format.MARKDOWN:
            return markdown.render(settings, records, result)
        case Format.SARIF:
            return sarif.render(settings, result, artifact_uri=artifact_uri)
        case Format.HTML:
            return html.render(settings, records, result)
