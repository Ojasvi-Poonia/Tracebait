import json
import re
from pathlib import Path
from typing import Any

import pytest
from pydantic import ValidationError

from tests import factories as f
from tracebait.field_registry import load_registry
from tracebait.models import Placement
from tracebait.packs import (
    Pack,
    PackError,
    builtin_packs,
    load_builtin_pack,
    load_pack,
    pack_problems,
)
from tracebait.twins import make_twin, targets


def _pack_data(**overrides: Any) -> dict[str, Any]:
    data: dict[str, Any] = {
        "version": 1,
        "id": "test-pack",
        "title": "Test pack",
        "sources": [f.pack_source().model_dump()],
        "incidents": [f.incident().model_dump()],
    }
    return {**data, **overrides}


class TestPackModel:
    def test_accepts_a_valid_pack(self) -> None:
        pack = Pack.model_validate(_pack_data())

        assert pack.incidents[0].source == "OTRF:SDWIN-190518202151"

    def test_rejects_duplicate_incident_ids(self) -> None:
        incident = f.incident().model_dump()

        with pytest.raises(ValidationError, match="duplicate incident ids"):
            Pack.model_validate(_pack_data(incidents=[incident, incident]))

    def test_rejects_duplicate_source_ids(self) -> None:
        source = f.pack_source().model_dump()

        with pytest.raises(ValidationError, match="duplicate source ids"):
            Pack.model_validate(_pack_data(sources=[source, source]))

    def test_rejects_incident_from_an_unlisted_source(self) -> None:
        stray = f.incident(incident_id="stray").model_copy(update={"source": "OTRF:other"})

        with pytest.raises(ValidationError, match="unlisted sources"):
            Pack.model_validate(_pack_data(incidents=[stray.model_dump()]))

    def test_rejects_a_source_no_incident_uses(self) -> None:
        unused = f.pack_source(source_id="OTRF:unused").model_dump()

        with pytest.raises(ValidationError, match="unused sources"):
            Pack.model_validate(_pack_data(sources=[f.pack_source().model_dump(), unused]))

    @pytest.mark.parametrize(
        ("key", "value"),
        [
            ("sha256", "ABC"),
            ("commit", "d9d40ef"),
            ("url", "http://example.org/data.zip"),
            ("licence", "MIT License"),
        ],
    )
    def test_rejects_malformed_provenance(self, key: str, value: str) -> None:
        source = {**f.pack_source().model_dump(), key: value}

        with pytest.raises(ValidationError, match=key):
            Pack.model_validate(_pack_data(sources=[source]))


class TestLoadPack:
    def test_round_trips_through_a_file(self, tmp_path: Path) -> None:
        pack = Pack.model_validate(_pack_data())
        path = tmp_path / "pack.json"
        path.write_text(pack.model_dump_json(), encoding="utf-8")

        assert load_pack(path) == pack

    def test_reports_the_file_for_invalid_json(self, tmp_path: Path) -> None:
        path = tmp_path / "broken.json"
        path.write_text(json.dumps(_pack_data(version=2)), encoding="utf-8")

        with pytest.raises(PackError, match=re.escape("broken.json")):
            load_pack(path)

    def test_reports_a_missing_file(self, tmp_path: Path) -> None:
        with pytest.raises(PackError, match=re.escape("missing.json")):
            load_pack(tmp_path / "missing.json")


class TestPackProblems:
    def test_clean_pack_has_no_problems(self) -> None:
        pack = Pack.model_validate(_pack_data())

        assert pack_problems(pack, f.registry()) == ()

    def test_reports_an_incident_without_targets(self) -> None:
        incident = f.incident(f.sysmon_entry(EventID="3", DestinationIp="10.0.0.5"))
        pack = Pack.model_validate(_pack_data(incidents=[incident.model_dump()]))

        assert pack_problems(pack, f.registry()) == (
            "otrf-mimikatz: no field a payload can target",
        )

    def test_reports_a_mirrored_target_value(self) -> None:
        long = "powershell.exe -noP -enc SQBFAFgA"
        entry = f.sysmon_entry(CommandLine=long, Message=f"CommandLine: {long}")
        pack = Pack.model_validate(_pack_data(incidents=[f.incident(entry).model_dump()]))

        problems = pack_problems(pack, f.registry())

        assert "otrf-mimikatz: entry 0 CommandLine is repeated in entry 0 Message" in problems


class TestShippedPacks:
    def test_at_least_one_pack_ships(self) -> None:
        assert builtin_packs()

    @pytest.mark.parametrize("name", builtin_packs())
    def test_loads_and_has_no_problems(self, name: str) -> None:
        pack = load_builtin_pack(name)

        assert pack.id == name
        assert pack_problems(pack, load_registry()) == ()

    @pytest.mark.parametrize("name", builtin_packs())
    def test_every_target_accepts_a_payload(self, name: str) -> None:
        registry = load_registry()
        for incident in load_builtin_pack(name).incidents:
            for target in targets(incident, registry):
                prepend = registry.get(target.field).placement is Placement.PREPEND
                payload = f.payload(text="x." if prepend else " x", field=target.field)
                make_twin(incident, payload, registry, entry_index=target.entry_index)

    def test_packs_never_ship_rendered_messages(self) -> None:
        for name in builtin_packs():
            for incident in load_builtin_pack(name).incidents:
                for entry in incident.entries:
                    assert "Message" not in entry.fields, incident.id

    def test_rejects_an_unknown_pack_name(self) -> None:
        with pytest.raises(PackError, match="no-such-pack"):
            load_builtin_pack("no-such-pack")
