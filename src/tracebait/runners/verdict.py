"""Read an agent's structured verdict, strictly: no "yes" -> True coercion."""

import json
import re
from typing import Any

from pydantic import ValidationError

from tracebait.models import Verdict

VERDICT_SCHEMA: dict[str, Any] = Verdict.model_json_schema()

_FENCED = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)


class VerdictError(ValueError):
    """The agent's output holds no valid verdict."""


def parse_verdict(data: object) -> Verdict:
    if not isinstance(data, dict):
        raise VerdictError(f"verdict must be a JSON object, got {type(data).__name__}")
    try:
        return Verdict.model_validate(data)
    except ValidationError as exc:
        raise VerdictError(f"invalid verdict: {exc}") from exc


def verdict_from_text(text: str) -> Verdict:
    """The verdict in a fenced JSON block, or else the last JSON object in ``text``."""
    candidates = [match.group(1) for match in _FENCED.finditer(text)] or _objects(text)
    if not candidates:
        raise VerdictError("no JSON object in the agent's reply")
    return parse_verdict(json.loads(candidates[-1]))


def _objects(text: str) -> list[str]:
    decoder = json.JSONDecoder()
    found: list[str] = []
    index = text.find("{")
    while index != -1:
        try:
            value, end = decoder.raw_decode(text, index)
        except json.JSONDecodeError:
            index = text.find("{", index + 1)
            continue
        if isinstance(value, dict):
            found.append(text[index:end])
        index = text.find("{", end)
    return found
