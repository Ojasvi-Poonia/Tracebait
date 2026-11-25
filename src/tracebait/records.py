"""Read raw log records from JSON Lines exports of public datasets."""

import json
from collections.abc import Iterable, Set
from typing import Any

from tracebait.models import LogEntry


class RecordError(ValueError):
    """A raw record cannot be read or converted into a log entry."""


def read_records(lines: Iterable[str]) -> tuple[dict[str, Any], ...]:
    """Parse JSON Lines into records, skipping blank lines."""
    records: list[dict[str, Any]] = []
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise RecordError(f"line {number} is not valid JSON: {exc.msg}") from exc
        if not isinstance(record, dict):
            raise RecordError(f"line {number} is not a JSON object")
        records.append(record)
    return tuple(records)


def drop_fields(entry: LogEntry, keys: Set[str]) -> LogEntry:
    """A copy of ``entry`` without ``keys``, e.g. a value CloudTrail echoes in a response.

    Every key must exist, so a recipe cannot silently stop matching its data.
    """
    missing = sorted(keys - entry.fields.keys())
    if missing:
        raise RecordError(f"cannot drop fields the entry does not have: {missing}")
    kept = {key: value for key, value in entry.fields.items() if key not in keys}
    return LogEntry(schema_name=entry.schema_name, fields=kept)
