"""Build twins: a clean incident plus a copy with one payload added to one field."""

from typing import NamedTuple

from tracebait.field_registry import FieldRegistry, UnknownFieldError
from tracebait.models import Change, FieldSpec, Incident, LogEntry, Payload, Placement, Twin

# Values at least this long are mirrored by any field that contains them (see find_mirror).
MIN_MIRROR_LENGTH = 8


class TwinError(ValueError):
    """The payload cannot be placed in this incident as requested."""


class Target(NamedTuple):
    """A place in an incident a payload can be added to."""

    entry_index: int
    raw_field: str
    field: str  # the FieldSpec.name


def targets(incident: Incident, registry: FieldRegistry) -> tuple[Target, ...]:
    """Every registry field present in an entry whose value is not repeated elsewhere."""
    return tuple(
        Target(index, raw, spec.name)
        for index, entry in enumerate(incident.entries)
        for spec in registry.fields
        if (raw := spec.raw_name(entry.schema_name)) is not None
        and raw in entry.fields
        and find_mirror(incident, index, raw) is None
    )


def find_mirror(incident: Incident, index: int, raw_field: str) -> Change | None:
    """The first other field that repeats this field's value, if any.

    A value of MIN_MIRROR_LENGTH or more is repeated if it appears inside another field;
    a shorter (non-empty) one only if another field equals it exactly.
    """
    original = incident.entries[index].fields[raw_field]
    if not original:
        return None
    long_value = len(original) >= MIN_MIRROR_LENGTH
    for i, entry in enumerate(incident.entries):
        for key, other in entry.fields.items():
            if (i, key) == (index, raw_field):
                continue
            if (original in other) if long_value else (original == other):
                return Change(i, key)
    return None


def make_twin(
    incident: Incident,
    payload: Payload,
    registry: FieldRegistry,
    *,
    entry_index: int | None = None,
) -> Twin:
    """Add ``payload.text`` to its target field in one entry of ``incident``.

    The payload goes on the side of the value the attacker controls (the field's
    placement). By default the first entry that has the field is used; ``entry_index``
    picks another. The payload must fit the field's charset, and the combined value must
    fit its length, segment and trim rules, so the poisoned record is one an attacker could
    actually produce. The original value must not be repeated elsewhere in the incident
    (for example in a rendered Message): that copy would contradict the poisoned one.
    """
    try:
        spec = registry.get(payload.field)
    except UnknownFieldError as exc:
        raise TwinError(str(exc)) from exc
    index, raw_field = _locate(incident, spec, entry_index)
    _check_no_mirrors(incident, index, raw_field)
    original = incident.entries[index].fields[raw_field]
    value = spec.place(original, payload.text)
    _check_fits(spec, payload, value)
    return Twin(
        incident=incident,
        payload=payload,
        altered=_with_value(incident, index, raw_field, value),
        entry_index=index,
        raw_field=raw_field,
        placement=spec.placement,
    )


def _locate(incident: Incident, spec: FieldSpec, entry_index: int | None) -> tuple[int, str]:
    candidates = {
        i: raw
        for i, entry in enumerate(incident.entries)
        if (raw := spec.raw_name(entry.schema_name)) is not None and raw in entry.fields
    }
    if not candidates:
        raise TwinError(f"incident {incident.id!r} has no entry with field {spec.name!r}")
    if entry_index is None:
        index = min(candidates)
    elif entry_index in candidates:
        index = entry_index
    else:
        raise TwinError(
            f"entry {entry_index} of incident {incident.id!r} has no field {spec.name!r};"
            f" entries with it: {sorted(candidates)}"
        )
    return index, candidates[index]


def _check_no_mirrors(incident: Incident, index: int, raw_field: str) -> None:
    mirror = find_mirror(incident, index, raw_field)
    if mirror is not None:
        raise TwinError(
            f"value of {raw_field!r} in entry {index} also appears in entry {mirror.entry}"
            f" field {mirror.key!r}; drop that copy from the pack"
        )


def _check_fits(spec: FieldSpec, payload: Payload, value: str) -> None:
    if not spec.allows(payload.text):
        raise TwinError(f"payload {payload.id!r} has characters outside {spec.name} charset")
    if spec.trim_chars is not None and value != value.strip(spec.trim_chars):
        raise TwinError(f"{spec.name} would be trimmed by the server before logging")
    if spec.segment_separator is not None:
        _check_segments(spec, payload, value, spec.segment_separator)
    length = spec.measure(value)
    if length > spec.max_length:
        raise TwinError(
            f"{spec.name} would be {length} {spec.length_unit.value}, over the"
            f" {spec.max_length} limit"
        )
    if spec.max_segment_length is not None:
        longest = spec.longest_segment(value)
        if longest > spec.max_segment_length:
            raise TwinError(
                f"{spec.name} would have a {longest}-{spec.length_unit.value} segment, over"
                f" the {spec.max_segment_length} limit"
            )


def _with_value(incident: Incident, index: int, raw_field: str, value: str) -> Incident:
    entry = incident.entries[index]
    replaced = LogEntry(schema_name=entry.schema_name, fields={**entry.fields, raw_field: value})
    entries = (*incident.entries[:index], replaced, *incident.entries[index + 1 :])
    return Incident.model_validate({**dict(incident), "entries": entries})


def _check_segments(spec: FieldSpec, payload: Payload, value: str, separator: str) -> None:
    # A prepended payload must be whole segments, or it would merge into (and change) the
    # first original segment, e.g. the attacker's own registered domain.
    if spec.placement is Placement.PREPEND and not payload.text.endswith(separator):
        raise TwinError(f"{spec.name} payloads must be whole segments ending in {separator!r}")
    # One trailing empty segment is allowed: Sysmon keeps the DNS root dot.
    if "" in value.split(separator)[:-1]:
        raise TwinError(f"{spec.name} would have an empty segment: {value!r}")
