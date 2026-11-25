"""Read OTRF Security-Datasets records and turn Sysmon events into log entries.

OTRF host datasets are JSON Lines exports of Windows event logs. Each record carries the
event data as flat keys plus a rendered ``Message`` that repeats every value; the message
is dropped so a poisoned field is never contradicted by an untouched copy.
"""

import json
from collections.abc import Iterable, Mapping
from typing import Any

from tracebait.models import LogEntry, LogSchema

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
DROPPED_FIELDS = frozenset({"Message"})


class OtrfRecordError(ValueError):
    """An OTRF record cannot be read or converted."""


def read_records(lines: Iterable[str]) -> tuple[dict[str, Any], ...]:
    """Parse JSON Lines into records, skipping blank lines."""
    records: list[dict[str, Any]] = []
    for number, line in enumerate(lines, start=1):
        if not line.strip():
            continue
        try:
            record = json.loads(line)
        except json.JSONDecodeError as exc:
            raise OtrfRecordError(f"line {number} is not valid JSON: {exc.msg}") from exc
        if not isinstance(record, dict):
            raise OtrfRecordError(f"line {number} is not a JSON object")
        records.append(record)
    return tuple(records)


def sysmon_entry(record: Mapping[str, Any]) -> LogEntry:
    """A Sysmon log entry with the record's fields as strings, in their original order."""
    channel = record.get("Channel")
    if channel != SYSMON_CHANNEL:
        raise OtrfRecordError(f"record is from channel {channel!r}, not {SYSMON_CHANNEL!r}")
    fields = {
        key: _as_text(key, value)
        for key, value in record.items()
        if key not in DROPPED_FIELDS and value is not None
    }
    return LogEntry(schema_name=LogSchema.SYSMON, fields=fields)


def _as_text(key: str, value: object) -> str:
    if isinstance(value, str):
        return value
    # bool is a subclass of int; Windows event data never holds JSON booleans.
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    raise OtrfRecordError(f"field {key!r} has unsupported value type {type(value).__name__}")
