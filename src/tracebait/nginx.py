"""Turn nginx access logs in splunk's key="value" format into ECS log entries.

splunk/attack_data web datasets log each request as ``key="value"`` pairs. The mapping
to ECS keeps the request, response and client fields an analyst reads, drops nginx's
"-" placeholders, and leaves out ``src`` because it repeats ``src_ip`` (a repeated value
would make the twin builder refuse the record).
"""

import re
from collections.abc import Mapping
from datetime import datetime

from tracebait.models import LogEntry, LogSchema
from tracebait.records import RecordError

_PAIR = re.compile(r'(\w+)="((?:[^"\\]|\\.)*)"')
_TIME_FORMAT = "%d/%b/%Y:%H:%M:%S %z"
NGINX_EMPTY = "-"
ECS_FIELDS = {
    "src_ip": "source.ip",
    "dest_ip": "destination.ip",
    "dest_port": "destination.port",
    "server": "server.address",
    "user": "user.name",
    "protocol": "http.version",
    "http_method": "http.request.method",
    "uri_path": "url.path",
    "uri_query": "url.query",
    "status": "http.response.status_code",
    "bytes_out": "http.response.bytes",
    "bytes_in": "http.request.bytes",
    "http_referer": "http.request.referrer",
    "http_user_agent": "user_agent.original",
    "http_x_forwarded_for": "network.forwarded_ip",
}


def parse_kv_line(line: str) -> dict[str, str]:
    """The ``key="value"`` pairs of one line, values kept exactly as logged."""
    pairs = _PAIR.findall(line)
    if not pairs:
        raise RecordError(f'no key="value" pairs in line {line[:80]!r}')
    fields: dict[str, str] = {}
    for key, value in pairs:
        if key in fields:
            raise RecordError(f"key {key!r} appears twice in one line")
        fields[key] = value
    return fields


def ecs_entry(fields: Mapping[str, str]) -> LogEntry:
    """An ECS log entry for one access-log line parsed by parse_kv_line."""
    ecs = {"@timestamp": _timestamp(fields), "event.dataset": "nginx.access"}
    for raw, name in ECS_FIELDS.items():
        value = fields.get(raw, "")
        if value in ("", NGINX_EMPTY):
            continue
        ecs[name] = value.removeprefix("HTTP/") if raw == "protocol" else value
    return LogEntry(schema_name=LogSchema.ECS, fields=ecs)


def _timestamp(fields: Mapping[str, str]) -> str:
    raw = fields.get("time_local", "")
    try:
        return datetime.strptime(raw, _TIME_FORMAT).isoformat()
    except ValueError as exc:
        raise RecordError(f"time_local {raw!r} is not an nginx timestamp") from exc
