import json

import pytest

from tracebait.models import LogEntry, LogSchema
from tracebait.records import RecordError, drop_fields, read_records


def test_reads_one_json_object_per_line() -> None:
    lines = [json.dumps({"EventID": 1}), "", json.dumps({"EventID": 4688})]

    records = read_records(lines)

    assert [r["EventID"] for r in records] == [1, 4688]


def test_rejects_a_line_that_is_not_an_object() -> None:
    with pytest.raises(RecordError, match="line 2"):
        read_records([json.dumps({"EventID": 1}), "[1, 2]"])


def test_rejects_invalid_json() -> None:
    with pytest.raises(RecordError, match="line 1"):
        read_records(["{not json"])


ECHO = LogEntry(
    schema_name=LogSchema.CLOUDTRAIL,
    fields={
        "requestParameters.userName": "AtomicRedTeam",
        "responseElements.accessKey.userName": "AtomicRedTeam",
        "responseElements.accessKey.status": "Active",
    },
)


def test_drop_fields_removes_only_the_named_keys() -> None:
    entry = drop_fields(ECHO, {"responseElements.accessKey.userName"})

    assert dict(entry.fields) == {
        "requestParameters.userName": "AtomicRedTeam",
        "responseElements.accessKey.status": "Active",
    }
    assert entry.schema_name is LogSchema.CLOUDTRAIL
    assert "responseElements.accessKey.userName" in ECHO.fields


def test_drop_fields_rejects_a_missing_key() -> None:
    with pytest.raises(RecordError, match="noSuchKey"):
        drop_fields(ECHO, {"noSuchKey"})
