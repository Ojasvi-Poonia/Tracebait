import pytest

from tracebait.models import LogSchema
from tracebait.otrf import SYSMON_CHANNEL, sysmon_entry
from tracebait.records import RecordError

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
        with pytest.raises(RecordError, match="Security"):
            sysmon_entry({**PROCESS_CREATE, "Channel": "Security"})

    @pytest.mark.parametrize("value", [True, 1.5, ["a"], {"a": 1}])
    def test_rejects_values_that_are_not_strings_or_integers(self, value: object) -> None:
        with pytest.raises(RecordError, match="Image"):
            sysmon_entry({**PROCESS_CREATE, "Image": value})
