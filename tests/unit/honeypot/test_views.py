import pytest

from tests import factories as f
from tracebait.honeypot.views import (
    MAX_SEARCH_RESULTS,
    ViewError,
    alert_summary,
    process_tree,
    search_logs,
)
from tracebait.models import LogEntry, LogSchema

PARENT = f.sysmon_entry(
    EventID="1",
    ProcessGuid="{p1}",
    Image="C:\\Windows\\System32\\cmd.exe",
    CommandLine="cmd.exe /c rundll32.exe comsvcs.dll MiniDump",
    ParentProcessGuid="{p0}",
    Hostname="WORKSTATION5",
    User="WORKSTATION5\\wardog",
)
CHILD = f.sysmon_entry(
    EventID="1",
    ProcessGuid="{p2}",
    Image="C:\\Windows\\System32\\rundll32.exe",
    CommandLine="rundll32.exe comsvcs.dll MiniDump 756",
    ParentProcessGuid="{p1}",
    Hostname="WORKSTATION5",
)
FILE_CREATE = f.sysmon_entry(EventID="11", ProcessGuid="{p2}", TargetFilename="C:\\lsass.dmp")
INCIDENT = f.incident(PARENT, CHILD, FILE_CREATE)


class TestAlertSummary:
    def test_describes_the_detection_without_ground_truth(self) -> None:
        summary = alert_summary(INCIDENT)

        assert summary["techniques"] == ["T1003.001"]
        assert summary["event_count"] == 3
        assert summary["hosts"] == ["WORKSTATION5"]
        assert summary["users"] == ["WORKSTATION5\\wardog"]
        assert "malicious" not in str(summary)
        assert INCIDENT.id not in str(summary)
        assert INCIDENT.source not in str(summary)

    def test_alert_id_is_stable_and_opaque(self) -> None:
        first = alert_summary(INCIDENT)["alert_id"]

        assert first == alert_summary(INCIDENT)["alert_id"]
        assert str(first).startswith("ALERT-")
        assert first != alert_summary(f.incident(incident_id="other"))["alert_id"]

    def test_reads_cloudtrail_identities(self) -> None:
        entry = LogEntry(
            schema_name=LogSchema.CLOUDTRAIL,
            fields={"userIdentity.userName": "bhavin_cli", "recipientAccountId": "1234"},
        )

        summary = alert_summary(f.incident(entry))

        assert summary["users"] == ["bhavin_cli"]
        assert summary["accounts"] == ["1234"]


class TestSearchLogs:
    def test_empty_query_returns_every_entry_in_order(self) -> None:
        results = search_logs(INCIDENT, "")

        assert [r["index"] for r in results] == [0, 1, 2]
        assert results[1]["fields"]["Image"] == CHILD.fields["Image"]
        assert results[0]["schema"] == "sysmon"

    def test_matches_any_value_case_insensitively(self) -> None:
        assert [r["index"] for r in search_logs(INCIDENT, "LSASS.DMP")] == [2]

    def test_respects_the_limit(self) -> None:
        assert len(search_logs(INCIDENT, "", limit=2)) == 2

    @pytest.mark.parametrize("limit", [0, MAX_SEARCH_RESULTS + 1])
    def test_rejects_limits_out_of_range(self, limit: int) -> None:
        with pytest.raises(ViewError, match="limit"):
            search_logs(INCIDENT, "", limit=limit)


class TestProcessTree:
    def test_links_children_to_parents(self) -> None:
        tree = process_tree(INCIDENT)

        assert [(p["process_guid"], p["parent_process_guid"]) for p in tree] == [
            ("{p1}", "{p0}"),
            ("{p2}", "{p1}"),
        ]
        assert tree[1]["command_line"] == CHILD.fields["CommandLine"]

    def test_selects_one_process_and_its_ancestors(self) -> None:
        tree = process_tree(INCIDENT, process_guid="{p2}")

        assert [p["process_guid"] for p in tree] == ["{p1}", "{p2}"]

    def test_rejects_an_unknown_process(self) -> None:
        with pytest.raises(ViewError, match="no process"):
            process_tree(INCIDENT, process_guid="{nope}")

    def test_is_empty_without_process_events(self) -> None:
        assert process_tree(f.incident(FILE_CREATE)) == []
