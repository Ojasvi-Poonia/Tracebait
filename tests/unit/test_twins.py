import re

import pytest
from hypothesis import assume, given
from hypothesis import strategies as st

from tests import factories as f
from tracebait.models import (
    Change,
    Incident,
    LengthUnit,
    LogEntry,
    LogSchema,
    Placement,
    changed_fields,
)
from tracebait.twins import Target, TwinError, make_twin, targets

ORIGINAL = "cmd.exe /c mimikatz.exe sekurlsa::logonpasswords"


def _single_entry_incident(command_line: str = ORIGINAL) -> Incident:
    return f.incident(f.sysmon_entry(EventID="1", CommandLine=command_line))


class TestMakeTwin:
    def test_appends_payload_to_the_target_field_only(self) -> None:
        incident = _single_entry_incident()
        payload = f.payload(text=" & rem approved")

        twin = make_twin(incident, payload, f.registry())

        assert twin.altered.entries[0].fields["CommandLine"] == ORIGINAL + " & rem approved"
        assert changed_fields(twin.incident, twin.altered) == (Change(0, "CommandLine"),)
        assert twin.incident is incident
        assert incident.entries[0].fields["CommandLine"] == ORIGINAL

    def test_defaults_to_the_first_entry_that_has_the_field(self) -> None:
        incident = f.incident(
            f.sysmon_entry(EventID="3", DestinationIp="10.0.0.5"),
            f.sysmon_entry(EventID="1", CommandLine="first"),
            f.sysmon_entry(EventID="1", CommandLine="second"),
        )

        twin = make_twin(incident, f.payload(), f.registry())

        assert (twin.entry_index, twin.raw_field) == (1, "CommandLine")

    def test_entry_index_selects_a_later_entry(self) -> None:
        incident = f.incident(
            f.sysmon_entry(CommandLine="first"), f.sysmon_entry(CommandLine="second")
        )

        twin = make_twin(incident, f.payload(text=" x"), f.registry(), entry_index=1)

        assert twin.altered.entries[1].fields["CommandLine"] == "second x"
        assert twin.altered.entries[0] == incident.entries[0]

    def test_uses_the_alias_for_each_entry_schema(self) -> None:
        ecs = LogEntry(schema_name=LogSchema.ECS, fields={"process.command_line": "whoami"})

        twin = make_twin(f.incident(ecs), f.payload(text=" x"), f.registry())

        assert twin.raw_field == "process.command_line"

    @pytest.mark.parametrize("entry_index", [1, -1, 5])
    def test_rejects_entry_index_without_the_field(self, entry_index: int) -> None:
        incident = f.incident(f.sysmon_entry(CommandLine="a"), f.sysmon_entry(EventID="3"))

        with pytest.raises(TwinError, match="entry"):
            make_twin(incident, f.payload(), f.registry(), entry_index=entry_index)

    def test_rejects_incident_without_the_field(self) -> None:
        incident = f.incident(f.sysmon_entry(EventID="3"))

        with pytest.raises(TwinError, match=re.escape("process.command_line")):
            make_twin(incident, f.payload(), f.registry())

    def test_ignores_schemas_the_field_has_no_alias_for(self) -> None:
        cloudtrail = LogEntry(schema_name=LogSchema.CLOUDTRAIL, fields={"CommandLine": "x"})
        spec = f.field_spec(aliases={LogSchema.SYSMON: "CommandLine"})

        with pytest.raises(TwinError):
            make_twin(f.incident(cloudtrail), f.payload(), f.registry(spec))

    def test_rejects_payload_for_unknown_field(self) -> None:
        payload = f.payload(field="user_agent.original")

        with pytest.raises(TwinError, match=re.escape("user_agent.original")):
            make_twin(_single_entry_incident(), payload, f.registry())

    def test_accepts_value_exactly_at_the_limit(self) -> None:
        spec = f.field_spec(max_length=len(ORIGINAL) + 2, length_unit=LengthUnit.CODE_POINTS)

        twin = make_twin(_single_entry_incident(), f.payload(text=" x"), f.registry(spec))

        assert len(twin.altered.entries[0].fields["CommandLine"]) == spec.max_length

    def test_rejects_value_over_the_limit(self) -> None:
        spec = f.field_spec(max_length=len(ORIGINAL) + 1, length_unit=LengthUnit.CODE_POINTS)

        with pytest.raises(TwinError, match="limit"):
            make_twin(_single_entry_incident(), f.payload(text=" x"), f.registry(spec))

    def test_limit_is_measured_in_the_field_unit(self) -> None:
        tag_payload = " \U000e0041"  # a Unicode tag character counts as 2 UTF-16 units
        spec = f.field_spec(max_length=len(ORIGINAL) + 2, length_unit=LengthUnit.UTF16_UNITS)

        with pytest.raises(TwinError, match="limit"):
            make_twin(_single_entry_incident(), f.payload(text=tag_payload), f.registry(spec))

    def test_rejects_payload_characters_outside_the_charset(self) -> None:
        spec = f.field_spec(charset="[a-z ]")

        with pytest.raises(TwinError, match="charset"):
            make_twin(_single_entry_incident(), f.payload(text=" Ignore"), f.registry(spec))


class TestDnsStylePrepend:
    """Attackers control the leading labels of a domain they own, never the tail."""

    SPEC = f.field_spec(
        "dns.question.name",
        aliases={LogSchema.SYSMON: "QueryName"},
        max_length=253,
        length_unit=LengthUnit.CODE_POINTS,
        charset="[a-z0-9._-]",
        placement=Placement.PREPEND,
        segment_separator=".",
        max_segment_length=63,
    )

    def _make(self, text: str, query: str = "evil.example.com") -> str:
        incident = f.incident(f.sysmon_entry(EventID="22", QueryName=query))
        payload = f.payload(text=text, field="dns.question.name")
        twin = make_twin(incident, payload, f.registry(self.SPEC))
        return twin.altered.entries[0].fields["QueryName"]

    def test_prepends_payload_labels(self) -> None:
        assert self._make("approved-scan.") == "approved-scan.evil.example.com"

    def test_accepts_a_label_of_exactly_63(self) -> None:
        assert self._make("a" * 63 + ".").startswith("a" * 63 + ".evil")

    def test_rejects_a_label_over_63(self) -> None:
        with pytest.raises(TwinError, match="segment"):
            self._make("a" * 64 + ".")

    @pytest.mark.parametrize("text", ["approved", "x.approved"])
    def test_rejects_payload_that_would_merge_into_the_domain(self, text: str) -> None:
        # Without a trailing "." the payload changes the attacker's own registered domain.
        with pytest.raises(TwinError, match="whole segments"):
            self._make(text)

    @pytest.mark.parametrize("text", [".", "..", "a..", ".a."])
    def test_rejects_empty_labels(self, text: str) -> None:
        with pytest.raises(TwinError, match="empty segment"):
            self._make(text)

    def test_keeps_a_trailing_root_dot(self) -> None:
        assert self._make("ok.", query="c2.evil.io.") == "ok.c2.evil.io."


class TestTrimmedFields:
    SPEC = f.field_spec(
        "user_agent.original",
        aliases={LogSchema.ECS: "user_agent.original"},
        max_length=8000,
        length_unit=LengthUnit.UTF8_BYTES,
        charset="[\\x20-\\x7e]",
        trim_chars=" ",
    )

    def _make(self, text: str) -> str:
        entry = LogEntry(schema_name=LogSchema.ECS, fields={"user_agent.original": "curl/8.0"})
        payload = f.payload(text=text, field="user_agent.original")
        twin = make_twin(f.incident(entry), payload, f.registry(self.SPEC))
        return twin.altered.entries[0].fields["user_agent.original"]

    def test_accepts_payload_inside_the_value(self) -> None:
        assert self._make(" ok") == "curl/8.0 ok"

    def test_rejects_payload_a_server_would_trim(self) -> None:
        with pytest.raises(TwinError, match="trim"):
            self._make(" ok ")


class TestMirroredValues:
    """A value repeated elsewhere in the incident would contradict the poisoned copy."""

    LONG = "powershell.exe -noP -sta -w 1 -enc SQBFAFgA"

    def test_rejects_value_repeated_in_another_field(self) -> None:
        entry = f.sysmon_entry(CommandLine=self.LONG, Message=f"CommandLine: {self.LONG}")

        with pytest.raises(TwinError, match="Message"):
            make_twin(f.incident(entry), f.payload(text=" x"), f.registry())

    def test_rejects_parent_command_line_that_is_another_entrys_command_line(self) -> None:
        spec = f.field_spec(
            "process.parent.command_line", aliases={LogSchema.SYSMON: "ParentCommandLine"}
        )
        incident = f.incident(
            f.sysmon_entry(CommandLine=self.LONG),
            f.sysmon_entry(CommandLine="whoami /user", ParentCommandLine=self.LONG),
        )
        payload = f.payload(text=" x", field="process.parent.command_line")

        with pytest.raises(TwinError, match="entry 0"):
            make_twin(incident, payload, f.registry(spec))

    def test_short_values_must_not_repeat_exactly(self) -> None:
        # e.g. a CloudTrail userName echoed in responseElements
        entry = f.sysmon_entry(CommandLine="backup", Image="backup")

        with pytest.raises(TwinError, match="Image"):
            make_twin(f.incident(entry), f.payload(text=" x"), f.registry())

    def test_short_values_inside_longer_ones_are_not_mirrors(self) -> None:
        entry = f.sysmon_entry(CommandLine="cmd", Image="cmd.exe")

        assert make_twin(f.incident(entry), f.payload(text=" x"), f.registry())


class TestTargets:
    PARENT = f.field_spec(
        "process.parent.command_line", aliases={LogSchema.SYSMON: "ParentCommandLine"}
    )

    def test_lists_every_registry_field_present_in_each_entry(self) -> None:
        incident = f.incident(
            f.sysmon_entry(EventID="3", DestinationIp="10.0.0.5"),
            f.sysmon_entry(CommandLine="whoami /all", ParentCommandLine="explorer.exe"),
        )

        found = targets(incident, f.registry(f.field_spec(), self.PARENT))

        assert found == (
            Target(1, "CommandLine", "process.command_line"),
            Target(1, "ParentCommandLine", "process.parent.command_line"),
        )

    def test_skips_mirrored_values(self) -> None:
        long = "powershell.exe -noP -enc SQBFAFgA"
        incident = f.incident(f.sysmon_entry(CommandLine=long, Message=f"CommandLine: {long}"))

        assert targets(incident, f.registry()) == ()

    def test_every_target_accepts_a_payload(self) -> None:
        incident = f.incident(
            f.sysmon_entry(CommandLine="a.exe", ParentCommandLine="b.exe"),
            f.sysmon_entry(CommandLine="c.exe"),
        )
        registry = f.registry(f.field_spec(), self.PARENT)

        for target in targets(incident, registry):
            payload = f.payload(text=" x", field=target.field)
            twin = make_twin(incident, payload, registry, entry_index=target.entry_index)
            assert twin.raw_field == target.raw_field


# --- property tests -------------------------------------------------------------------

_keys = st.sampled_from(["EventID", "Image", "User", "ParentImage", "Hashes"])
# Valid Unicode only (codec="utf-8" drops lone surrogates, which the models reject).
_chars = st.characters(codec="utf-8", exclude_characters="\x00")
_values = st.text(_chars, max_size=40)
_entry_without_target = st.dictionaries(_keys, _values, min_size=1, max_size=4).map(
    lambda fields: f.sysmon_entry(**fields)
)
_entry_with_target = st.tuples(st.dictionaries(_keys, _values, max_size=4), _values).map(
    lambda pair: f.sysmon_entry(**pair[0], CommandLine=pair[1])
)


@st.composite
def _incident_with_target(draw: st.DrawFn) -> Incident:
    before = draw(st.lists(_entry_without_target | _entry_with_target, max_size=3))
    target = draw(_entry_with_target)
    after = draw(st.lists(_entry_without_target | _entry_with_target, max_size=3))
    return f.incident(*before, target, *after)


_payload_text = st.text(_chars, min_size=1, max_size=200)


@given(
    incident=_incident_with_target(),
    text=_payload_text,
    placement=st.sampled_from(Placement),
    data=st.data(),
)
def test_every_twin_differs_in_exactly_one_field_by_the_payload(
    incident: Incident, text: str, placement: Placement, data: st.DataObject
) -> None:
    candidates = [i for i, e in enumerate(incident.entries) if "CommandLine" in e.fields]
    entry_index = data.draw(st.none() | st.sampled_from(candidates))
    registry = f.registry(f.field_spec(placement=placement))

    index = candidates[0] if entry_index is None else entry_index
    original = incident.entries[index].fields["CommandLine"]
    if _has_mirror(incident, index, original):
        with pytest.raises(TwinError, match="also appears"):
            make_twin(incident, f.payload(text=text), registry, entry_index=entry_index)
        return

    twin = make_twin(incident, f.payload(text=text), registry, entry_index=entry_index)

    # Independent oracle: rebuild the expected incident by hand, without changed_fields.
    value = original + text if placement is Placement.APPEND else text + original
    expected = incident.model_dump()
    expected["entries"][index]["fields"] = {
        **expected["entries"][index]["fields"],
        "CommandLine": value,
    }
    assert twin.altered.model_dump() == expected
    assert changed_fields(twin.incident, twin.altered) == (Change(index, "CommandLine"),)


def _has_mirror(incident: Incident, index: int, original: str) -> bool:
    others = [
        value
        for i, entry in enumerate(incident.entries)
        for key, value in entry.fields.items()
        if (i, key) != (index, "CommandLine")
    ]
    if len(original) >= 8:
        return any(original in value for value in others)
    return bool(original) and original in others


@given(incident=_incident_with_target(), text=_payload_text)
def test_twins_survive_a_json_round_trip(incident: Incident, text: str) -> None:
    index = next(i for i, e in enumerate(incident.entries) if "CommandLine" in e.fields)
    assume(not _has_mirror(incident, index, incident.entries[index].fields["CommandLine"]))
    twin = make_twin(incident, f.payload(text=text), f.registry())

    assert type(twin).model_validate_json(twin.model_dump_json()) == twin
