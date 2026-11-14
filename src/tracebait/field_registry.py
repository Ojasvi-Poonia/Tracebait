"""The registry of attacker-controllable log fields, shipped as data/fields.json."""

from functools import cache
from importlib.resources import files
from typing import Literal, Self

from pydantic import Field, model_validator

from tracebait.models import FieldSpec, FrozenModel

REGISTRY_RESOURCE = "data/fields.json"


class UnknownFieldError(LookupError):
    """Raised when a payload or pack names a field the registry does not define."""


class FieldRegistry(FrozenModel):
    version: Literal[1]
    fields: tuple[FieldSpec, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _unique_names(self) -> Self:
        names = [spec.name for spec in self.fields]
        duplicates = sorted({n for n in names if names.count(n) > 1})
        if duplicates:
            raise ValueError(f"duplicate field names: {duplicates}")
        return self

    @property
    def names(self) -> tuple[str, ...]:
        return tuple(spec.name for spec in self.fields)

    def get(self, name: str) -> FieldSpec:
        for spec in self.fields:
            if spec.name == name:
                return spec
        raise UnknownFieldError(f"field {name!r} is not in the field registry")


@cache
def load_registry() -> FieldRegistry:
    """Load and validate the registry that ships inside the package."""
    text = files("tracebait").joinpath(REGISTRY_RESOURCE).read_text(encoding="utf-8")
    return FieldRegistry.model_validate_json(text)
