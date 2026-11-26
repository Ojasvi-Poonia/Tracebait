"""The shipped payload corpus (data/payloads.json), and payloads read from files.

Every shipped payload is original text written for tracebait (see NOTICE). Payloads are
validated as data here; whether one fits a field is checked by make_twin when a twin is
built.
"""

from functools import cache
from importlib.resources import files
from pathlib import Path
from typing import Literal, Self

from pydantic import Field, ValidationError, model_validator

from tracebait.models import FrozenModel, Payload

PAYLOADS_RESOURCE = "data/payloads.json"


class PayloadError(ValueError):
    """A payload id is unknown, or a payload file is missing or invalid."""


class PayloadCorpus(FrozenModel):
    version: Literal[1]
    payloads: tuple[Payload, ...] = Field(min_length=1)

    @model_validator(mode="after")
    def _unique_ids(self) -> Self:
        ids = [payload.id for payload in self.payloads]
        duplicates = sorted({i for i in ids if ids.count(i) > 1})
        if duplicates:
            raise ValueError(f"duplicate payload ids: {duplicates}")
        return self


@cache
def load_payloads() -> PayloadCorpus:
    """Load and validate the corpus that ships inside the package."""
    text = files("tracebait").joinpath(PAYLOADS_RESOURCE).read_text(encoding="utf-8")
    return PayloadCorpus.model_validate_json(text)


def get_payload(payload_id: str) -> Payload:
    for payload in load_payloads().payloads:
        if payload.id == payload_id:
            return payload
    raise PayloadError(f"no built-in payload {payload_id!r}; see `tracebait list`")


def resolve_payload(ref: str) -> Payload:
    """A built-in payload by id, or one read from a ``.json`` file path."""
    path = Path(ref)
    if path.suffix != ".json":
        return get_payload(ref)
    try:
        return Payload.model_validate_json(path.read_bytes())
    except OSError as exc:
        raise PayloadError(f"cannot read payload {path}: {exc.strerror}") from exc
    except ValidationError as exc:
        raise PayloadError(f"invalid payload {path}: {exc}") from exc
