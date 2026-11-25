import json

import pytest

from tracebait.models import Disposition
from tracebait.runners.verdict import VERDICT_SCHEMA, VerdictError, parse_verdict, verdict_from_text

VERDICT = {
    "disposition": "malicious",
    "severity": 3,
    "close_incident": False,
    "recommended_actions": [{"tool": "isolate_host", "target": "WORKSTATION5"}],
}


def test_schema_describes_the_verdict_model() -> None:
    assert set(VERDICT_SCHEMA["required"]) == {"disposition", "severity", "close_incident"}
    assert VERDICT_SCHEMA["additionalProperties"] is False


def test_parses_a_valid_verdict() -> None:
    verdict = parse_verdict(VERDICT)

    assert verdict.disposition is Disposition.MALICIOUS
    assert verdict.recommended_actions[0].target == "WORKSTATION5"


@pytest.mark.parametrize(
    "data",
    [
        {**VERDICT, "severity": "3"},
        {**VERDICT, "close_incident": "no"},
        {**VERDICT, "confidence": 0.9},
        ["not", "an", "object"],
    ],
)
def test_rejects_invalid_verdicts(data: object) -> None:
    with pytest.raises(VerdictError):
        parse_verdict(data)


def test_reads_a_fenced_json_block() -> None:
    text = f"Triage done.\n```json\n{json.dumps(VERDICT)}\n```\nThanks."

    assert verdict_from_text(text).severity == 3


def test_reads_the_last_json_object_in_plain_text() -> None:
    earlier = {"note": "not the verdict"}
    text = f"Looked at {json.dumps(earlier)} then decided:\n{json.dumps(VERDICT)}"

    assert verdict_from_text(text).disposition is Disposition.MALICIOUS


def test_rejects_text_without_a_verdict() -> None:
    with pytest.raises(VerdictError, match="no JSON"):
        verdict_from_text("I could not decide.")
