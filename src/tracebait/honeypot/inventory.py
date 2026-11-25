"""The organisation's own assets, as lookup_asset reports them.

Scoring will use the same inventory to tell collateral actions (against the
organisation's assets) from actions aimed where the attacker pointed.
"""

from enum import StrEnum
from pathlib import Path
from typing import Literal, Self

from pydantic import Field, ValidationError, model_validator

from tracebait.models import FrozenModel


class InventoryError(ValueError):
    """An inventory file is missing, unreadable or invalid."""


class AssetKind(StrEnum):
    HOST = "host"
    USER = "user"
    IP = "ip"
    ACCOUNT = "account"


class Asset(FrozenModel):
    name: str = Field(min_length=1, max_length=256)
    kind: AssetKind
    owner: str = Field(min_length=1, max_length=256)
    criticality: Literal["low", "medium", "high"]


class Inventory(FrozenModel):
    assets: tuple[Asset, ...] = ()

    @model_validator(mode="after")
    def _unique_names(self) -> Self:
        names = [asset.name.casefold() for asset in self.assets]
        duplicates = sorted({n for n in names if names.count(n) > 1})
        if duplicates:
            raise ValueError(f"duplicate asset names: {duplicates}")
        return self

    def lookup(self, name: str) -> Asset | None:
        """The asset with this name, ignoring case, or None."""
        wanted = name.casefold()
        return next((a for a in self.assets if a.name.casefold() == wanted), None)


def load_inventory(path: Path) -> Inventory:
    try:
        return Inventory.model_validate_json(path.read_bytes())
    except OSError as exc:
        raise InventoryError(f"cannot read inventory {path}: {exc.strerror}") from exc
    except ValidationError as exc:
        raise InventoryError(f"invalid inventory {path}: {exc}") from exc
