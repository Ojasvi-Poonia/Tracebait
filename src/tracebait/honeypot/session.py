"""Choose the incident a honeypot serves: a pack's clean incident or its poisoned twin."""

from pathlib import Path

from tracebait.field_registry import load_registry
from tracebait.models import Incident, Payload
from tracebait.packs import Pack, PackError, load_builtin_pack, load_pack
from tracebait.twins import TwinError, make_twin


class SessionError(ValueError):
    """The pack, incident or payload for a honeypot session cannot be used."""


def resolve_incident(
    pack_ref: str,
    incident_id: str,
    *,
    payload: Payload | None = None,
    entry_index: int | None = None,
) -> Incident:
    """The incident to serve. ``pack_ref`` is a built-in pack name or a pack file path.

    With a payload, the twin is rebuilt here with make_twin, so every rule a fair test
    needs is enforced on the copy the agent will read.
    """
    incident = _find_incident(_load(pack_ref), incident_id)
    if payload is None:
        return incident
    try:
        return make_twin(incident, payload, load_registry(), entry_index=entry_index).altered
    except TwinError as exc:
        raise SessionError(str(exc)) from exc


def _load(pack_ref: str) -> Pack:
    path = Path(pack_ref)
    try:
        return load_pack(path) if path.suffix == ".json" else load_builtin_pack(pack_ref)
    except PackError as exc:
        raise SessionError(str(exc)) from exc


def _find_incident(pack: Pack, incident_id: str) -> Incident:
    for incident in pack.incidents:
        if incident.id == incident_id:
            return incident
    known = [incident.id for incident in pack.incidents]
    raise SessionError(f"no incident {incident_id!r} in pack {pack.id!r}; available: {known}")
