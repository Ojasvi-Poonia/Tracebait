import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from tests import factories as f
from tracebait.field_registry import FieldRegistry, UnknownFieldError, load_registry
from tracebait.models import LengthUnit, LogSchema, Placement

DOCS = Path(__file__).resolve().parents[2] / "docs" / "field-limits.md"

# Fields the v0.1 payload corpus is expected to target. M2 replaces this with a check that
# every targeted field occurs in at least one shipped pack entry.
REQUIRED_FIELDS = {
    "process.command_line",
    "process.parent.command_line",
    "user_agent.original",
    "aws.cloudtrail.user_agent",
    "dns.question.name",
    "file.name",
    "aws.cloudtrail.request_parameters.roleSessionName",
}


class TestShippedRegistry:
    def test_loads_and_covers_the_v0_1_fields(self) -> None:
        registry = load_registry()

        assert set(registry.names) >= REQUIRED_FIELDS

    def test_is_loaded_once(self) -> None:
        assert load_registry() is load_registry()

    def test_every_field_has_a_known_schema_alias_and_https_source(self) -> None:
        for spec in load_registry().fields:
            assert spec.aliases, spec.name
            assert all(isinstance(schema, LogSchema) for schema in spec.aliases), spec.name
            assert all(src.startswith("https://") for src in spec.sources), spec.name

    def test_every_charset_is_a_single_character_class(self) -> None:
        for spec in load_registry().fields:
            compiled = re.compile(spec.charset)
            assert compiled.groups == 0, spec.name
            assert spec.allows("a"), f"{spec.name} should allow a plain ASCII letter"
            assert not spec.allows("\x00"), f"{spec.name} must never allow NUL"

    def test_charsets_are_written_as_ascii_escapes(self) -> None:
        # Literal noncharacters (U+FFFE, U+FFFF) get mangled by editors and transports.
        for spec in load_registry().fields:
            assert spec.charset.isascii(), spec.name

    def test_command_lines_reject_characters_loggers_rewrite(self) -> None:
        spec = load_registry().get("process.command_line")

        assert spec.allows("cmd.exe /c whoami\t& rem ok\n")
        for rewritten in ("\r", "\x1b", "\x85", "\ufffd", "\uffff"):
            assert not spec.allows(rewritten), repr(rewritten)

    def test_file_names_reject_characters_loggers_rewrite(self) -> None:
        spec = load_registry().get("file.name")

        assert spec.allows("r\u00e9sum\u00e9 \U0001f4c4.pdf")
        for rewritten in ("\x7f", "\x9b", "\ufffd", "\uffff", "\\", ":"):
            assert not spec.allows(rewritten), repr(rewritten)

    @pytest.mark.parametrize("name", ["user_agent.original", "aws.cloudtrail.user_agent"])
    def test_user_agents_must_not_end_in_trimmed_space(self, name: str) -> None:
        assert load_registry().get(name).trim_chars == " "

    def test_docs_table_matches_the_registry(self) -> None:
        text = DOCS.read_text(encoding="utf-8")
        rows = re.findall(r"^\| `([^`]+)` \| (\d+)[^|]*\| (\w+) \| (\w+) \|", text, re.M)
        classes = dict(
            re.findall(r"^### `([^`]+)`.*?\*\*Character class:\*\* `(.+?)`$", text, re.M | re.S)
        )
        registry = load_registry()

        assert {row[0] for row in rows} == set(registry.names)
        for name, limit, unit, placement in rows:
            spec = registry.get(name)
            assert (int(limit), unit, placement) == (
                spec.max_length,
                spec.length_unit.value,
                spec.placement.value,
            ), name
            assert classes[name] == spec.charset, name

    def test_no_field_is_still_provisional(self) -> None:
        for spec in load_registry().fields:
            assert "PROVISIONAL" not in spec.basis, spec.name

    def test_dns_names_take_payloads_as_leading_labels(self) -> None:
        spec = load_registry().get("dns.question.name")

        assert spec.placement is Placement.PREPEND
        assert (spec.segment_separator, spec.max_segment_length) == (".", 63)
        assert spec.max_length == 253

    def test_windows_command_lines_are_measured_in_utf16_units(self) -> None:
        assert load_registry().get("process.command_line").length_unit is LengthUnit.UTF16_UNITS

    def test_raw_names_are_unique_per_schema(self) -> None:
        seen: dict[tuple[LogSchema, str], str] = {}
        for spec in load_registry().fields:
            for schema, raw in spec.aliases.items():
                assert (schema, raw) not in seen, f"{raw} mapped by {seen.get((schema, raw))}"
                seen[(schema, raw)] = spec.name


class TestFieldRegistry:
    def test_get_returns_the_named_spec(self) -> None:
        spec = f.field_spec("dns.question.name", aliases={LogSchema.SYSMON: "QueryName"})

        assert f.registry(spec).get("dns.question.name") is spec

    def test_get_unknown_field_raises(self) -> None:
        with pytest.raises(UnknownFieldError, match=re.escape("no.such.field")):
            f.registry().get("no.such.field")

    def test_rejects_duplicate_names(self) -> None:
        with pytest.raises(ValidationError, match="duplicate"):
            f.registry(f.field_spec(), f.field_spec())

    def test_rejects_unknown_version(self) -> None:
        with pytest.raises(ValidationError):
            FieldRegistry.model_validate({"version": 2, "fields": [f.field_spec().model_dump()]})
