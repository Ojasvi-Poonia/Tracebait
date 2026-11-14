"""Frozen data models shared across tracebait.

Incidents, payloads and verdicts come from untrusted files and agents, so every model is
immutable and rejects unknown keys. Mappings are exposed read-only, and model_copy(update=)
re-validates instead of bypassing the validators.
"""

import re
from collections.abc import Mapping
from enum import StrEnum
from typing import Annotated, Any, NamedTuple, Self, TypeVar

from pydantic import (
    AfterValidator,
    BaseModel,
    ConfigDict,
    Field,
    PlainSerializer,
    StringConstraints,
    field_validator,
    model_validator,
)

from tracebait.frozen import FrozenMap

_K = TypeVar("_K")
_V = TypeVar("_V")

# The largest max_length in the shipped field registry; no payload can be longer.
MAX_PAYLOAD_LENGTH = 8191


def _freeze(mapping: Mapping[_K, _V]) -> Mapping[_K, _V]:
    return FrozenMap(mapping)


def _valid_unicode(text: str) -> str:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError as exc:
        raise ValueError("text must be valid Unicode (no lone surrogates)") from exc
    return text


# Lone surrogates can arrive through JSON escapes; they cannot be encoded or measured.
UnicodeText = Annotated[str, AfterValidator(_valid_unicode)]
Slug = Annotated[str, StringConstraints(pattern=r"^[a-z0-9][a-z0-9._-]{0,127}$")]
FieldName = Annotated[
    str,
    StringConstraints(pattern=r"^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)*$", max_length=256),
]
RawFieldName = Annotated[UnicodeText, StringConstraints(min_length=1, max_length=256)]
AttackTechnique = Annotated[str, StringConstraints(pattern=r"^T\d{4}(\.\d{3})?$")]
AtlasId = Annotated[str, StringConstraints(pattern=r"^AML\.T\d{4}(\.\d{3})?$")]
AsiId = Annotated[str, StringConstraints(pattern=r"^ASI\d{2}$")]
HttpsUrl = Annotated[str, StringConstraints(pattern=r"^https://\S+$", max_length=2048)]


class FrozenModel(BaseModel):
    model_config = ConfigDict(frozen=True, extra="forbid")

    def model_copy(self, *, update: Mapping[str, Any] | None = None, deep: bool = False) -> Self:
        """Copy, re-validating any update (pydantic's default skips validation)."""
        if update:
            return self.model_validate({**dict(self), **update})
        return super().model_copy(deep=deep)


class LogSchema(StrEnum):
    ECS = "ecs"
    SYSMON = "sysmon"
    CLOUDTRAIL = "cloudtrail"


class LengthUnit(StrEnum):
    """How a source system counts a field's length."""

    CODE_POINTS = "code_points"
    UTF16_UNITS = "utf16_units"  # Windows strings (CreateProcess, NTFS names)
    UTF8_BYTES = "utf8_bytes"  # bytes on the wire or in UTF-8 storage


class Placement(StrEnum):
    """Which end of a field's value the attacker controls."""

    APPEND = "append"  # trailing arguments, header text
    PREPEND = "prepend"  # leading DNS labels of a domain the attacker owns

    def apply(self, original: str, text: str) -> str:
        return original + text if self is Placement.APPEND else text + original


class FieldSpec(FrozenModel):
    """Limits on what an attacker can write into one log field and have stored intact."""

    name: FieldName
    aliases: Annotated[
        Mapping[LogSchema, RawFieldName],
        Field(min_length=1),
        AfterValidator(_freeze),
        PlainSerializer(dict, return_type=dict[LogSchema, str]),
    ]
    max_length: int = Field(gt=0)
    length_unit: LengthUnit
    charset: str
    placement: Placement = Placement.APPEND
    # Optional per-segment limit, e.g. 63-octet DNS labels separated by ".".
    segment_separator: str | None = Field(default=None, min_length=1, max_length=1)
    max_segment_length: int | None = Field(default=None, gt=0)
    # Characters a server strips from the ends of the value before logging it.
    trim_chars: str | None = Field(default=None, min_length=1)
    basis: str = Field(min_length=1)
    sources: tuple[HttpsUrl, ...] = Field(min_length=1)

    @field_validator("charset")
    @classmethod
    def _single_character_class(cls, charset: str) -> str:
        # Check the shape first: compiling arbitrary patterns can raise RecursionError.
        if not _is_one_bracket_class(charset):
            raise ValueError(f"charset {charset!r} must be one character class like [a-z]")
        try:
            re.compile(charset)
        except re.error as exc:
            raise ValueError(f"charset {charset!r} does not compile: {exc}") from exc
        return charset

    @model_validator(mode="after")
    def _segment_limit_is_complete(self) -> Self:
        if (self.segment_separator is None) != (self.max_segment_length is None):
            raise ValueError("segment_separator and max_segment_length must be set together")
        return self

    def place(self, original: str, text: str) -> str:
        """The value after the attacker adds ``text`` on the side they control."""
        return self.placement.apply(original, text)

    def longest_segment(self, value: str) -> int:
        """Length of the longest separator-delimited segment of ``value``, in the field unit."""
        if self.segment_separator is None:
            return self.measure(value)
        return max(self.measure(part) for part in value.split(self.segment_separator))

    def raw_name(self, schema: LogSchema) -> str | None:
        """The field's name in a schema's records, or None if the schema lacks it."""
        return self.aliases.get(schema)

    def allows(self, text: str) -> bool:
        """True when every character of ``text`` is in the charset."""
        return re.fullmatch(f"(?:{self.charset})*", text) is not None

    def measure(self, text: str) -> int:
        """Length of ``text`` in this field's unit."""
        match self.length_unit:
            case LengthUnit.CODE_POINTS:
                return len(text)
            case LengthUnit.UTF16_UNITS:
                return len(text.encode("utf-16-le")) // 2
            case LengthUnit.UTF8_BYTES:
                return len(text.encode("utf-8"))


# Nested sets and set operations: Python warns that their meaning will change.
_AMBIGUOUS_SET_SYNTAX = ("[", "&&", "--", "||", "~~")


def _is_one_bracket_class(pattern: str) -> bool:
    """True if ``pattern`` is exactly one ``[...]`` set (escapes and a leading ``]`` allowed)."""
    if not pattern.startswith("["):
        return False
    i = 2 if pattern.startswith("[^") else 1
    if pattern[i : i + 1] == "]":
        i += 1  # a leading ] is a literal member of the set
    while i < len(pattern):
        if pattern[i] == "\\":
            i += 2
            continue
        if pattern[i] == "]":
            return i == len(pattern) - 1
        if pattern.startswith(_AMBIGUOUS_SET_SYNTAX, i):
            return False
        i += 1
    return False


class LogEntry(FrozenModel):
    """One log record, flattened to string values under the schema's own field names."""

    schema_name: LogSchema
    fields: Annotated[
        Mapping[RawFieldName, UnicodeText],
        Field(min_length=1),
        AfterValidator(_freeze),
        PlainSerializer(dict, return_type=dict[str, str]),
    ]


class Disposition(StrEnum):
    MALICIOUS = "malicious"
    BENIGN = "benign"
    NEEDS_REVIEW = "needs_review"


class Incident(FrozenModel):
    id: Slug
    source: str = Field(min_length=1, max_length=256)  # e.g. "OTRF:SDWIN-190518202151"
    attack_technique: tuple[AttackTechnique, ...]
    entries: tuple[LogEntry, ...] = Field(min_length=1)
    ground_truth_disposition: Disposition


class PayloadClass(StrEnum):
    AUTHORITY_SPOOFING = "authority_spoofing"  # control: direct overrides, ~0% expected
    BENIGN_EXPLANATION = "benign_explanation"  # e.g. "authorised test" framing
    TASK_PLAUSIBLE = "task_plausible"  # context-manipulation style
    PERSONA_HIJACK = "persona_hijack"
    ENCODING_SHORTFIELD = "encoding_shortfield"  # encoding and short-field variants


class Payload(FrozenModel):
    id: Slug
    cls: PayloadClass
    field: FieldName  # the FieldSpec.name it targets
    text: str = Field(min_length=1, max_length=MAX_PAYLOAD_LENGTH)
    atlas: tuple[AtlasId, ...]
    asi: tuple[AsiId, ...]


class Change(NamedTuple):
    """One difference between two incidents. ``entry`` is None for incident-level keys."""

    entry: int | None
    key: str


def changed_fields(before: Incident, after: Incident) -> tuple[Change, ...]:
    """Every difference between two incidents, in a stable order."""
    top = tuple(
        Change(None, name)
        for name in type(before).model_fields
        if name != "entries" and getattr(before, name) != getattr(after, name)
    )
    if len(before.entries) != len(after.entries):
        return (*top, Change(None, "entries"))
    return top + tuple(
        change
        for index, (old, new) in enumerate(zip(before.entries, after.entries, strict=True))
        for change in _entry_changes(index, old, new)
    )


def _entry_changes(index: int, old: LogEntry, new: LogEntry) -> tuple[Change, ...]:
    if old.schema_name != new.schema_name:
        return (Change(index, "schema_name"),)
    keys = sorted(old.fields.keys() | new.fields.keys())
    return tuple(Change(index, k) for k in keys if old.fields.get(k) != new.fields.get(k))


class Twin(FrozenModel):
    """A clean incident and a copy with a payload added to exactly one field.

    This validator checks the structure only. The registry checks (alias, placement,
    charset and limits) live in twins.make_twin, so rebuild a Twin read from disk with
    make_twin instead of trusting it.
    """

    incident: Incident
    payload: Payload
    altered: Incident
    entry_index: int = Field(ge=0)
    raw_field: RawFieldName
    placement: Placement

    @property
    def id(self) -> str:
        return f"{self.incident.id}:{self.payload.id}"

    @model_validator(mode="after")
    def _differs_in_exactly_one_field_by_the_payload(self) -> Self:
        expected = (Change(self.entry_index, self.raw_field),)
        found = changed_fields(self.incident, self.altered)
        if found != expected:
            raise ValueError(f"twin must change only {expected[0]}, found {found}")
        old = self.incident.entries[self.entry_index]
        new = self.altered.entries[self.entry_index]
        if old.schema_name != new.schema_name:
            raise ValueError("twin must not change an entry's schema")
        original = old.fields.get(self.raw_field)
        altered = new.fields.get(self.raw_field)
        if original is None or altered is None:
            raise ValueError(f"{self.raw_field!r} must exist in both the clean and altered entry")
        if altered != self.placement.apply(original, self.payload.text):
            raise ValueError(
                f"altered value must be the original with the payload {self.placement}ed"
            )
        return self


class RecommendedAction(FrozenModel):
    tool: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    target: str = Field(min_length=1, max_length=1024)


class Verdict(FrozenModel):
    """An agent's structured triage decision. Strict types: no "yes" -> True coercion."""

    disposition: Disposition
    severity: int = Field(ge=0, le=4, strict=True)
    close_incident: bool = Field(strict=True)
    recommended_actions: tuple[RecommendedAction, ...] = ()
