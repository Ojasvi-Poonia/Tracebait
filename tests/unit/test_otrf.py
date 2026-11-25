import json

import pytest

from tracebait.models import LogSchema
from tracebait.otrf import SYSMON_CHANNEL, OtrfRecordError, read_records, sysmon_entry

PROCESS_CREATE = {
    "Channel": SYSMON_CHANNEL,
    "EventID": 1,
    "Image": "C:\\Windows\\System32\\rundll32.exe",
    "CommandLine": "rundll32.exe comsvcs.dll MiniDump 756 lsass.dmp full",
    "Message": "Process Create:\r\nCommandLine: rundll32.exe comsvcs.dll MiniDump 756 ...",
}


class TestSysmonEntry:
    def test_keeps_event_fields_as_strings(self) -> None:
        entry = sysmon_entry(PROCESS_CREATE)

        assert entry.schema_name is LogSchema.SYSMON
        assert entry.fields["EventID"] == "1"
        assert entry.fields["CommandLine"] == PROCESS_CREATE["CommandLine"]

    def test_drops_the_rendered_message(self) -> None:
        assert "Message" not in sysmon_entry(PROCESS_CREATE).fields

    def test_drops_null_values(self) -> None:
        entry = sysmon_entry({**PROCESS_CREATE, "RuleName": None})

        assert "RuleName" not in entry.fields

    def test_keeps_the_record_order(self) -> None:
        assert list(sysmon_entry(PROCESS_CREATE).fields) == [
            "Channel",
            "EventID",
            "Image",
            "CommandLine",
        ]

    def test_rejects_other_channels(self) -> None:
        with pytest.raises(OtrfRecordError, match="Security"):
            sysmon_entry({**PROCESS_CREATE, "Channel": "Security"})

    @pytest.mark.parametrize("value", [True, 1.5, ["a"], {"a": 1}])
    def test_rejects_values_that_are_not_strings_or_integers(self, value: object) -> None:
        with pytest.raises(OtrfRecordError, match="Image"):
            sysmon_entry({**PROCESS_CREATE, "Image": value})


class TestReadRecords:
    def test_reads_one_json_object_per_line(self) -> None:
        lines = [json.dumps(PROCESS_CREATE), "", json.dumps({"EventID": 4688})]

        records = read_records(lines)

        assert [r["EventID"] for r in records] == [1, 4688]

    def test_rejects_a_line_that_is_not_an_object(self) -> None:
        with pytest.raises(OtrfRecordError, match="line 2"):
            read_records([json.dumps(PROCESS_CREATE), "[1, 2]"])

    def test_rejects_invalid_json(self) -> None:
        with pytest.raises(OtrfRecordError, match="line 1"):
            read_records(["{not json"])
