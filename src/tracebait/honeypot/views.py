"""What the read tools show: views of an incident's entries, never its ground truth.

Views take only the entries and ATT&CK techniques a detection would carry. The incident
id, source, disposition and any payload metadata stay out, so the agent cannot tell a
clean incident from its poisoned twin except by reading the poisoned field.
"""

import hashlib
from collections.abc import Mapping
from typing import Any

from tracebait.models import Incident, LogEntry, LogSchema

MAX_SEARCH_RESULTS = 200
ALERT_ID_HEX_DIGITS = 10

# Raw field names that identify hosts, users and cloud accounts in each schema.
_HOST_FIELDS = {LogSchema.SYSMON: ("Hostname",), LogSchema.ECS: ("host.name",)}
_USER_FIELDS = {
    LogSchema.SYSMON: ("User",),
    LogSchema.ECS: ("user.name",),
    LogSchema.CLOUDTRAIL: ("userIdentity.userName",),
}
_ACCOUNT_FIELDS = {LogSchema.CLOUDTRAIL: ("recipientAccountId",)}
_PROCESS_CREATE_EVENT_ID = "1"


class ViewError(ValueError):
    """A read tool was called with arguments it cannot answer."""


def alert_summary(incident: Incident) -> dict[str, Any]:
    """The alert an analyst would start from: id, techniques and the entities involved."""
    digest = hashlib.sha256(incident.id.encode("utf-8")).hexdigest()
    return {
        "alert_id": f"ALERT-{digest[:ALERT_ID_HEX_DIGITS].upper()}",
        "techniques": list(incident.attack_technique),
        "event_count": len(incident.entries),
        "hosts": _values(incident, _HOST_FIELDS),
        "users": _values(incident, _USER_FIELDS),
        "accounts": _values(incident, _ACCOUNT_FIELDS),
    }


def search_logs(incident: Incident, query: str, limit: int = 50) -> list[dict[str, Any]]:
    """Entries with a field value containing ``query`` (case-insensitive), in log order."""
    if not 1 <= limit <= MAX_SEARCH_RESULTS:
        raise ViewError(f"limit must be between 1 and {MAX_SEARCH_RESULTS}")
    needle = query.casefold()
    matches = (
        _entry_view(index, entry)
        for index, entry in enumerate(incident.entries)
        if any(needle in value.casefold() for value in entry.fields.values())
    )
    return [view for view, _ in zip(matches, range(limit), strict=False)]


def process_tree(incident: Incident, process_guid: str | None = None) -> list[dict[str, str]]:
    """Process-creation events as parent/child links, optionally one process's ancestry."""
    processes = [
        _process_view(entry)
        for entry in incident.entries
        if entry.schema_name is LogSchema.SYSMON
        and entry.fields.get("EventID") == _PROCESS_CREATE_EVENT_ID
        and "ProcessGuid" in entry.fields
    ]
    if process_guid is None:
        return processes
    by_guid = {p["process_guid"]: p for p in processes}
    if process_guid not in by_guid:
        raise ViewError(f"no process {process_guid!r} in this alert")
    chain = [by_guid[process_guid]]
    while (parent := by_guid.get(chain[0]["parent_process_guid"])) and parent not in chain:
        chain.insert(0, parent)
    return chain


def _entry_view(index: int, entry: LogEntry) -> dict[str, Any]:
    return {"index": index, "schema": entry.schema_name.value, "fields": dict(entry.fields)}


def _process_view(entry: LogEntry) -> dict[str, str]:
    fields = entry.fields
    return {
        "process_guid": fields["ProcessGuid"],
        "image": fields.get("Image", ""),
        "command_line": fields.get("CommandLine", ""),
        "user": fields.get("User", ""),
        "parent_process_guid": fields.get("ParentProcessGuid", ""),
        "parent_image": fields.get("ParentImage", ""),
        "parent_command_line": fields.get("ParentCommandLine", ""),
    }


def _values(incident: Incident, fields_by_schema: Mapping[LogSchema, tuple[str, ...]]) -> list[str]:
    found = (
        entry.fields[key]
        for entry in incident.entries
        for key in fields_by_schema.get(entry.schema_name, ())
        if entry.fields.get(key)
    )
    return list(dict.fromkeys(found))
