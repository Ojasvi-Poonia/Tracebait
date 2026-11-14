import copy
import pickle

import pytest
from pydantic import ValidationError

from tests import factories as f
from tracebait.field_registry import FieldRegistry, load_registry
from tracebait.models import (
    Change,
    Disposition,
    FieldSpec,
    Incident,
    LengthUnit,
    LogEntry,
    LogSchema,
    Payload,
    PayloadClass,
    Placement,
    RecommendedAction,
    Twin,
    Verdict,
    changed_fields,
)


class TestLogEntry:
    def test_fields_mapping_cannot_be_mutated(self) -> None:
        entry = f.sysmon_entry(CommandLine="cmd.exe")

        with pytest.raises(TypeError):
            entry.fields["CommandLine"] = "evil"  # type: ignore[index]

    def test_model_is_frozen(self) -> None:
        entry = f.sysmon_entry()

        with pytest.raises(ValidationError):
            entry.schema_name = LogSchema.ECS  # type: ignore[misc]

    def test_rejects_unknown_schema(self) -> None:
        with pytest.raises(ValidationError):
            LogEntry.model_validate({"schema_name": "splunk", "fields": {"a": "b"}})

    def test_rejects_non_string_values(self) -> None:
        with pytest.raises(ValidationError):
            LogEntry.model_validate({"schema_name": "sysmon", "fields": {"EventID": 1}})

    def test_rejects_empty_fields(self) -> None:
        with pytest.raises(ValidationError):
            LogEntry(schema_name=LogSchema.SYSMON, fields={})

    def test_rejects_unknown_keys(self) -> None:
        with pytest.raises(ValidationError):
            LogEntry.model_validate({"schema_name": "sysmon", "fields": {"a": "b"}, "extra": 1})

    @pytest.mark.parametrize("fields", [{"CommandLine": "cmd\ud800"}, {"Command\udfffLine": "cmd"}])
    def test_rejects_lone_surrogates(self, fields: dict[str, str]) -> None:
        # Untrusted JSON can carry \ud800 escapes; they cannot be encoded or measured.
        with pytest.raises(ValidationError):
            LogEntry(schema_name=LogSchema.SYSMON, fields=fields)

    def test_rejects_lone_surrogates_from_json(self) -> None:
        with pytest.raises(ValidationError):
            LogEntry.model_validate_json('{"schema_name": "sysmon", "fields": {"A": "\\ud800"}}')

    def test_json_round_trip(self) -> None:
        entry = f.sysmon_entry(CommandLine="cmd.exe /c whoami")

        assert LogEntry.model_validate_json(entry.model_dump_json()) == entry


class TestIncident:
    def test_requires_at_least_one_entry(self) -> None:
        data = f.incident().model_dump()

        with pytest.raises(ValidationError):
            Incident.model_validate({**data, "entries": []})

    @pytest.mark.parametrize("bad_id", ["Has Space", "UPPER", "", "-leading-dash", "x" * 129])
    def test_rejects_bad_ids(self, bad_id: str) -> None:
        data = f.incident().model_dump()

        with pytest.raises(ValidationError):
            Incident.model_validate({**data, "id": bad_id})

    @pytest.mark.parametrize("technique", ["T1003", "T1003.001"])
    def test_accepts_attack_technique_ids(self, technique: str) -> None:
        data = f.incident().model_dump()

        assert Incident.model_validate({**data, "attack_technique": [technique]})

    @pytest.mark.parametrize("technique", ["1003", "T1003.1", "t1003", "T1003.001x"])
    def test_rejects_malformed_attack_technique_ids(self, technique: str) -> None:
        data = f.incident().model_dump()

        with pytest.raises(ValidationError):
            Incident.model_validate({**data, "attack_technique": [technique]})


class TestPayload:
    def test_has_the_five_planned_classes(self) -> None:
        assert {c.value for c in PayloadClass} == {
            "authority_spoofing",
            "benign_explanation",
            "task_plausible",
            "persona_hijack",
            "encoding_shortfield",
        }

    def test_rejects_empty_text(self) -> None:
        with pytest.raises(ValidationError):
            f.payload(text="")

    @pytest.mark.parametrize(
        ("key", "value"), [("atlas", ["T0051"]), ("asi", ["ASI1"]), ("field", "not a field")]
    )
    def test_rejects_malformed_tags_and_field_names(self, key: str, value: object) -> None:
        data = f.payload().model_dump()

        with pytest.raises(ValidationError):
            Payload.model_validate({**data, key: value})


class TestFieldSpec:
    @pytest.mark.parametrize(
        "charset",
        [
            "abc",  # not a bracket class
            "[a-",  # does not compile
            "[a]*",  # quantified: not a single class
            "[a]|[b]",  # alternation of classes
            "[a](x)",  # groups
            "[[]",  # nested set: Python plans to change its meaning
            "[a&&b]",  # set operations, same reason
            "[a--b]",
            "[a||b]",
            "[a~~b]",
            "(" * 500 + ")" * 500,  # would raise RecursionError in re.compile
            "a{4294967296}",  # would raise OverflowError in re.compile
        ],
    )
    def test_rejects_charsets_that_are_not_one_character_class(self, charset: str) -> None:
        with pytest.raises(ValidationError):
            f.field_spec(charset=charset)

    def test_allows_checks_every_character(self) -> None:
        spec = f.field_spec(charset="[a-z0-9.-]")

        assert spec.allows("evil-host.example")
        assert not spec.allows("evil host")
        assert spec.allows("")

    def test_raw_name_is_none_for_schema_without_alias(self) -> None:
        spec = f.field_spec(aliases={LogSchema.SYSMON: "CommandLine"})

        assert spec.raw_name(LogSchema.SYSMON) == "CommandLine"
        assert spec.raw_name(LogSchema.CLOUDTRAIL) is None

    def test_requires_an_alias_and_a_https_source(self) -> None:
        data = f.field_spec().model_dump()

        with pytest.raises(ValidationError):
            FieldSpec.model_validate({**data, "aliases": {}})
        with pytest.raises(ValidationError):
            FieldSpec.model_validate({**data, "sources": ["http://insecure.example"]})

    def test_shipped_aliases_cannot_be_mutated(self) -> None:
        spec = load_registry().get("dns.question.name")

        with pytest.raises(TypeError):
            spec.aliases[LogSchema.SYSMON] = "x"  # type: ignore[index]

    def test_rejects_non_positive_max_length(self) -> None:
        with pytest.raises(ValidationError):
            f.field_spec(max_length=0)

    @pytest.mark.parametrize(
        ("unit", "text", "expected"),
        [
            (LengthUnit.CODE_POINTS, "a\U000e0041", 2),
            (LengthUnit.UTF16_UNITS, "a\U000e0041", 3),  # tag character is a surrogate pair
            (LengthUnit.UTF8_BYTES, "a\U000e0041", 5),
            (LengthUnit.UTF8_BYTES, "é", 2),
        ],
    )
    def test_measure_uses_the_field_unit(self, unit: LengthUnit, text: str, expected: int) -> None:
        assert f.field_spec(length_unit=unit).measure(text) == expected

    @pytest.mark.parametrize(
        ("placement", "expected"),
        [(Placement.APPEND, "evil.example x"), (Placement.PREPEND, "x evil.example")],
    )
    def test_place_puts_payload_on_the_attacker_controlled_side(
        self, placement: Placement, expected: str
    ) -> None:
        spec = f.field_spec(placement=placement)

        assert spec.place("evil.example", " x" if placement is Placement.APPEND else "x ") == (
            expected
        )

    @pytest.mark.parametrize(("separator", "limit"), [(".", None), (None, 63), ("", 63), (".", 0)])
    def test_segment_limit_needs_a_separator_and_a_positive_length(
        self, separator: str | None, limit: int | None
    ) -> None:
        with pytest.raises(ValidationError):
            f.field_spec(segment_separator=separator, max_segment_length=limit)


class TestUntrustedInputBounds:
    @pytest.mark.parametrize("tool", ["", "Block_IP", "x" * 65, "rm -rf"])
    def test_rejects_malformed_action_tools(self, tool: str) -> None:
        with pytest.raises(ValidationError):
            RecommendedAction(tool=tool, target="WS-042")

    @pytest.mark.parametrize("target", ["", "x" * 1025])
    def test_rejects_empty_or_oversized_action_targets(self, target: str) -> None:
        with pytest.raises(ValidationError):
            RecommendedAction(tool="isolate_host", target=target)

    @pytest.mark.parametrize("source", ["", "x" * 257])
    def test_rejects_bad_incident_sources(self, source: str) -> None:
        with pytest.raises(ValidationError):
            Incident.model_validate({**f.incident().model_dump(), "source": source})

    def test_rejects_bad_payload_ids_and_oversized_payloads(self) -> None:
        data = f.payload().model_dump()

        with pytest.raises(ValidationError):
            Payload.model_validate({**data, "id": "Bad Id"})
        with pytest.raises(ValidationError):
            Payload.model_validate({**data, "text": "x" * 8192})
        with pytest.raises(ValidationError):
            Payload.model_validate({**data, "field": "a" * 257})

    def test_rejects_an_empty_registry(self) -> None:
        with pytest.raises(ValidationError):
            FieldRegistry(version=1, fields=())


class TestImmutability:
    def test_frozen_models_hash_pickle_and_deepcopy(self) -> None:
        incident = f.incident()

        assert hash(incident) == hash(f.incident())
        assert hash(f.field_spec()) == hash(f.field_spec())
        # Round-trips our own object, never untrusted bytes.
        assert pickle.loads(pickle.dumps(incident)) == incident  # noqa: S301
        assert copy.deepcopy(incident) == incident

    def test_model_copy_with_update_is_validated(self) -> None:
        entry = f.sysmon_entry(CommandLine="cmd")
        copied = entry.model_copy(update={"fields": {"CommandLine": "x"}})

        with pytest.raises(TypeError):
            copied.fields["CommandLine"] = "y"  # type: ignore[index]
        with pytest.raises(ValidationError):
            entry.model_copy(update={"fields": {}})


class TestVerdict:
    @pytest.mark.parametrize("severity", [0, 4])
    def test_accepts_severity_bounds(self, severity: int) -> None:
        verdict = Verdict(
            disposition=Disposition.MALICIOUS, severity=severity, close_incident=False
        )

        assert verdict.recommended_actions == ()

    @pytest.mark.parametrize("severity", [-1, 5, "3", 2.0, True])
    def test_rejects_out_of_range_or_non_integer_severity(self, severity: object) -> None:
        with pytest.raises(ValidationError):
            Verdict.model_validate(
                {"disposition": "malicious", "severity": severity, "close_incident": False}
            )

    def test_rejects_non_boolean_close_flag(self) -> None:
        with pytest.raises(ValidationError):
            Verdict.model_validate(
                {"disposition": "benign", "severity": 1, "close_incident": "yes"}
            )

    def test_parses_agent_json(self) -> None:
        raw = (
            '{"disposition": "needs_review", "severity": 2, "close_incident": false,'
            ' "recommended_actions": [{"tool": "isolate_host", "target": "WS-042"}]}'
        )

        verdict = Verdict.model_validate_json(raw)

        assert verdict.recommended_actions == (
            RecommendedAction(tool="isolate_host", target="WS-042"),
        )


class TestChangedFields:
    def test_identical_incidents_have_no_changes(self) -> None:
        assert changed_fields(f.incident(), f.incident()) == ()

    def test_reports_added_removed_and_changed_keys(self) -> None:
        before = f.incident(f.sysmon_entry(A="1", B="2", D="5"))
        after = f.incident(f.sysmon_entry(A="1", B="3", C="4"))

        assert changed_fields(before, after) == (
            Change(0, "B"),
            Change(0, "C"),
            Change(0, "D"),
        )

    def test_reports_incident_level_and_structural_changes(self) -> None:
        base = f.incident()
        other = Incident.model_validate(
            {**dict(base), "ground_truth_disposition": Disposition.BENIGN}
        )
        longer = f.incident(f.sysmon_entry(), f.sysmon_entry())
        ecs = f.incident(LogEntry(schema_name=LogSchema.ECS, fields={"EventID": "1"}))

        assert changed_fields(base, other) == (Change(None, "ground_truth_disposition"),)
        assert changed_fields(f.incident(f.sysmon_entry()), longer) == (Change(None, "entries"),)
        assert changed_fields(f.incident(f.sysmon_entry()), ecs) == (Change(0, "schema_name"),)


class TestTwinInvariant:
    def _twin(
        self,
        altered: Incident,
        *,
        entry_index: int = 0,
        placement: Placement = Placement.APPEND,
    ) -> Twin:
        return Twin(
            incident=f.incident(f.sysmon_entry(CommandLine="cmd", Image="cmd.exe")),
            payload=f.payload(text=" x"),
            altered=altered,
            entry_index=entry_index,
            raw_field="CommandLine",
            placement=placement,
        )

    def test_accepts_exactly_one_appended_field(self) -> None:
        twin = self._twin(f.incident(f.sysmon_entry(CommandLine="cmd x", Image="cmd.exe")))

        assert twin.id == "otrf-mimikatz:benign-explanation-cmdline-001"

    @pytest.mark.parametrize(
        "altered_fields",
        [
            {"CommandLine": "cmd", "Image": "cmd.exe"},  # nothing changed
            {"CommandLine": "cmd x", "Image": "evil.exe"},  # two fields changed
            {"CommandLine": "cmd", "Image": "cmd.exe x"},  # wrong field changed
            {"CommandLine": "x cmd", "Image": "cmd.exe"},  # prepended, not appended
            {"CommandLine": " x", "Image": "cmd.exe"},  # original evidence replaced
            {"CommandLine": "cmd x"},  # other evidence dropped
        ],
    )
    def test_rejects_anything_but_one_appended_field(self, altered_fields: dict[str, str]) -> None:
        with pytest.raises(ValidationError):
            self._twin(f.incident(f.sysmon_entry(**altered_fields)))

    def test_prepend_twin_needs_the_payload_in_front(self) -> None:
        prepended = f.incident(f.sysmon_entry(CommandLine=" xcmd", Image="cmd.exe"))
        appended = f.incident(f.sysmon_entry(CommandLine="cmd x", Image="cmd.exe"))

        assert self._twin(prepended, placement=Placement.PREPEND)
        with pytest.raises(ValidationError):
            self._twin(appended, placement=Placement.PREPEND)

    def test_rejects_a_schema_change_even_with_a_field_named_schema_name(self) -> None:
        clean = f.incident(f.sysmon_entry(schema_name="a", CommandLine="cmd"))
        altered = f.incident(
            LogEntry(schema_name=LogSchema.ECS, fields={"schema_name": "a x", "CommandLine": "z"})
        )

        with pytest.raises(ValidationError):
            Twin(
                incident=clean,
                payload=f.payload(text=" x"),
                altered=altered,
                entry_index=0,
                raw_field="schema_name",
                placement=Placement.APPEND,
            )

    @pytest.mark.parametrize(
        ("clean", "altered"),
        [({"A": "1"}, {"A": "1", "B": " x"}), ({"A": "1", "B": ""}, {"A": "1"})],
        ids=["field-added", "field-removed"],
    )
    def test_rejects_added_or_removed_target_field_from_json(
        self, clean: dict[str, str], altered: dict[str, str]
    ) -> None:
        twin_json = {
            "incident": f.incident(f.sysmon_entry(**clean)).model_dump(mode="json"),
            "payload": f.payload(text=" x").model_dump(mode="json"),
            "altered": f.incident(f.sysmon_entry(**altered)).model_dump(mode="json"),
            "entry_index": 0,
            "raw_field": "B",
            "placement": "append",
        }

        with pytest.raises(ValidationError):
            Twin.model_validate(twin_json)

    def test_rejects_wrong_entry_index(self) -> None:
        with pytest.raises(ValidationError):
            self._twin(
                f.incident(f.sysmon_entry(CommandLine="cmd x", Image="cmd.exe")), entry_index=1
            )
