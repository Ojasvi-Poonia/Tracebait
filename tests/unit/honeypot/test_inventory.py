import json
import re
from pathlib import Path

import pytest
from pydantic import ValidationError

from tracebait.honeypot.inventory import (
    Asset,
    AssetKind,
    Inventory,
    InventoryError,
    load_inventory,
)

INVENTORY = Inventory(
    assets=(
        Asset(name="WORKSTATION5", kind=AssetKind.HOST, owner="it", criticality="medium"),
        Asset(name="10.0.0.5", kind=AssetKind.IP, owner="it", criticality="high"),
    )
)


def test_looks_up_assets_case_insensitively() -> None:
    asset = INVENTORY.lookup("workstation5")

    assert asset is not None
    assert asset.kind is AssetKind.HOST


def test_unknown_assets_are_none() -> None:
    assert INVENTORY.lookup("12.25.72.12") is None


def test_rejects_duplicate_names() -> None:
    asset = INVENTORY.assets[0]

    with pytest.raises(ValidationError, match="duplicate"):
        Inventory(assets=(asset, asset.model_copy(update={"name": "Workstation5"})))


def test_loads_from_a_file(tmp_path: Path) -> None:
    path = tmp_path / "inventory.json"
    path.write_text(INVENTORY.model_dump_json(), encoding="utf-8")

    assert load_inventory(path) == INVENTORY


def test_reports_an_invalid_file(tmp_path: Path) -> None:
    path = tmp_path / "bad.json"
    path.write_text(json.dumps({"assets": [{"name": "x"}]}), encoding="utf-8")

    with pytest.raises(InventoryError, match=re.escape("bad.json")):
        load_inventory(path)


def test_reports_a_missing_file(tmp_path: Path) -> None:
    with pytest.raises(InventoryError, match=re.escape("missing.json")):
        load_inventory(tmp_path / "missing.json")
