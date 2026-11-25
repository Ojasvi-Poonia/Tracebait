import json
from pathlib import Path

import pytest

from tests import factories as f
from tracebait.honeypot.session import SessionError, resolve_incident
from tracebait.packs import Pack

PACK = "otrf-credential-access"
INCIDENT = "otrf-lsass-dump-comsvcs"


def _payload_file(tmp_path: Path, text: str = " & rem approved") -> Path:
    path = tmp_path / "payload.json"
    path.write_text(f.payload(text=text).model_dump_json(), encoding="utf-8")
    return path


def test_serves_the_clean_incident_without_a_payload() -> None:
    incident = resolve_incident(PACK, INCIDENT)

    assert incident.id == INCIDENT
    assert not incident.entries[0].fields["CommandLine"].endswith("approved")


def test_serves_the_poisoned_twin_with_a_payload(tmp_path: Path) -> None:
    incident = resolve_incident(PACK, INCIDENT, payload_path=_payload_file(tmp_path))

    assert incident.entries[0].fields["CommandLine"].endswith(" & rem approved")


def test_loads_a_pack_from_a_file(tmp_path: Path) -> None:
    pack = Pack(
        version=1,
        id="local",
        title="Local",
        sources=(f.pack_source(),),
        incidents=(f.incident(),),
    )
    path = tmp_path / "local.json"
    path.write_text(pack.model_dump_json(), encoding="utf-8")

    assert resolve_incident(str(path), "otrf-mimikatz") == pack.incidents[0]


def test_rejects_an_unknown_incident() -> None:
    with pytest.raises(SessionError, match="otrf-lsass-dump-comsvcs"):
        resolve_incident(PACK, "nope")


def test_rejects_an_unknown_pack() -> None:
    with pytest.raises(SessionError, match="no-such-pack"):
        resolve_incident("no-such-pack", INCIDENT)


def test_rejects_an_invalid_payload_file(tmp_path: Path) -> None:
    path = tmp_path / "payload.json"
    path.write_text(json.dumps({"id": "x"}), encoding="utf-8")

    with pytest.raises(SessionError, match="payload"):
        resolve_incident(PACK, INCIDENT, payload_path=path)


def test_reports_a_payload_that_does_not_fit(tmp_path: Path) -> None:
    path = _payload_file(tmp_path, text="x" * 8191)

    with pytest.raises(SessionError, match="over the"):
        resolve_incident(PACK, INCIDENT, payload_path=path)
