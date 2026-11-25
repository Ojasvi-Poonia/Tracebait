"""Incident packs: attributed slices of public datasets, shipped under data/packs/.

A pack is one JSON file holding its provenance (where each incident came from, under
which licence, at which upstream commit) and the incidents themselves.
"""

from importlib.resources import files
from pathlib import Path
from typing import Annotated, Literal, Self

from pydantic import Field, StringConstraints, ValidationError, model_validator

from tracebait.field_registry import FieldRegistry
from tracebait.models import FrozenModel, HttpsUrl, Incident, Slug
from tracebait.twins import find_mirror, targets

PACKS_RESOURCE = "data/packs"

Sha256 = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{64}$")]
GitCommit = Annotated[str, StringConstraints(pattern=r"^[0-9a-f]{40}$")]
SpdxId = Annotated[str, StringConstraints(pattern=r"^[A-Za-z0-9.+-]{1,64}$")]


class PackError(ValueError):
    """A pack file is missing, unreadable or invalid."""


class PackSource(FrozenModel):
    """One upstream dataset that incidents in a pack were sliced from."""

    id: str = Field(min_length=1, max_length=256)  # matches Incident.source
    title: str = Field(min_length=1, max_length=256)
    url: HttpsUrl  # the archive, at a pinned commit
    sha256: Sha256  # of the archive at url
    commit: GitCommit  # upstream repository commit
    licence: SpdxId


class Pack(FrozenModel):
    version: Literal[1]
    id: Slug
    title: str = Field(min_length=1, max_length=256)
    sources: tuple[PackSource, ...] = Field(min_length=1)
    incidents: tuple[Incident, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _ids_and_sources_are_consistent(self) -> Self:
        _require_unique("incident ids", [incident.id for incident in self.incidents])
        _require_unique("source ids", [source.id for source in self.sources])
        listed = {source.id for source in self.sources}
        used = {incident.source for incident in self.incidents}
        if used - listed:
            raise ValueError(f"incidents cite unlisted sources: {sorted(used - listed)}")
        if listed - used:
            raise ValueError(f"unused sources: {sorted(listed - used)}")
        return self


def _require_unique(what: str, values: list[str]) -> None:
    duplicates = sorted({v for v in values if values.count(v) > 1})
    if duplicates:
        raise ValueError(f"duplicate {what}: {duplicates}")


def load_pack(path: Path) -> Pack:
    """Read and validate a pack file."""
    try:
        return Pack.model_validate_json(path.read_bytes())
    except OSError as exc:
        raise PackError(f"cannot read pack {path}: {exc.strerror}") from exc
    except ValidationError as exc:
        raise PackError(f"invalid pack {path}: {exc}") from exc


def builtin_packs() -> tuple[str, ...]:
    """Names of the packs that ship inside the package, sorted."""
    directory = files("tracebait").joinpath(PACKS_RESOURCE)
    return tuple(
        sorted(
            item.name.removesuffix(".json")
            for item in directory.iterdir()
            if item.name.endswith(".json")
        )
    )


def load_builtin_pack(name: str) -> Pack:
    """Load a pack that ships inside the package, by name."""
    if name not in builtin_packs():
        raise PackError(f"no built-in pack {name!r}; available: {list(builtin_packs())}")
    text = files("tracebait").joinpath(PACKS_RESOURCE, f"{name}.json").read_text(encoding="utf-8")
    return Pack.model_validate_json(text)


def pack_problems(pack: Pack, registry: FieldRegistry) -> tuple[str, ...]:
    """Reasons a pack cannot be used for fair twins; empty when it is ready."""
    problems: list[str] = []
    for incident in pack.incidents:
        if not targets(incident, registry):
            problems.append(f"{incident.id}: no field a payload can target")
        for index, entry in enumerate(incident.entries):
            for spec in registry.fields:
                raw = spec.raw_name(entry.schema_name)
                if raw is None or raw not in entry.fields:
                    continue
                mirror = find_mirror(incident, index, raw)
                if mirror is not None:
                    problems.append(
                        f"{incident.id}: entry {index} {raw} is repeated in entry"
                        f" {mirror.entry} {mirror.key}"
                    )
    return tuple(problems)
