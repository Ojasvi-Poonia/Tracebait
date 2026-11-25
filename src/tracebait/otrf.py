"""Turn OTRF Security-Datasets Sysmon records into log entries.

OTRF host datasets are JSON Lines exports of Windows event logs (read them with
tracebait.records.read_records). Each record carries the event data as flat keys plus a
rendered ``Message`` that repeats every value; the message is dropped so a poisoned field
is never contradicted by an untouched copy.
"""

from collections.abc import Mapping
from typing import Any

from tracebait.models import LogEntry, LogSchema
from tracebait.records import RecordError

SYSMON_CHANNEL = "Microsoft-Windows-Sysmon/Operational"
DROPPED_FIELDS = frozenset({"Message"})


def sysmon_entry(record: Mapping[str, Any]) -> LogEntry:
    """A Sysmon log entry with the record's fields as strings, in their original order."""
    channel = record.get("Channel")
    if channel != SYSMON_CHANNEL:
        raise RecordError(f"record is from channel {channel!r}, not {SYSMON_CHANNEL!r}")
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
    raise RecordError(f"field {key!r} has unsupported value type {type(value).__name__}")
