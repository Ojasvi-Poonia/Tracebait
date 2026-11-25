"""Turn AWS CloudTrail records into log entries with dotted keys.

Nested objects become dotted keys (``requestParameters.userName``), matching the
cloudtrail aliases in the field registry. Strings are kept as they are; other scalars
and lists are written as compact JSON, so ``false`` stays ``false``. Nulls and empty
objects are dropped, as they carry no value an agent could read.
"""

import json
from collections.abc import Iterator, Mapping
from typing import Any

from tracebait.models import LogEntry, LogSchema
from tracebait.records import RecordError


def cloudtrail_entry(record: Mapping[str, Any]) -> LogEntry:
    """A CloudTrail log entry with every leaf value under its dotted key."""
    fields: dict[str, str] = {}
    for key, value in _flatten(record, ""):
        if key in fields:
            raise RecordError(f"key {key!r} appears twice after flattening")
        fields[key] = value
    return LogEntry(schema_name=LogSchema.CLOUDTRAIL, fields=fields)


def _flatten(value: Mapping[str, Any], prefix: str) -> Iterator[tuple[str, str]]:
    for key, item in value.items():
        name = f"{prefix}{key}"
        if item is None:
            continue
        if isinstance(item, Mapping):
            yield from _flatten(item, f"{name}.")
        elif isinstance(item, str):
            yield name, item
        else:
            yield name, json.dumps(item, separators=(",", ":"), ensure_ascii=False)
