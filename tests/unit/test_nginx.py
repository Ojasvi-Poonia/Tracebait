import pytest

from tracebait.models import LogSchema
from tracebait.nginx import ecs_entry, parse_kv_line
from tracebait.records import RecordError

LINE = (
    'site="localhost" server="34.211.116.74" dest_port="80" dest_ip="172.31.4.228"'
    ' src="162.142.125.57" src_ip="162.142.125.57" user="-"'
    ' time_local="15/Dec/2021:01:34:46 +0000" protocol="HTTP/1.1" status="502"'
    ' bytes_out="676" bytes_in="0" http_referer="-"'
    ' http_user_agent="Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)"'
    ' nginx_version="1.21.3" http_x_forwarded_for="-" uri_query="-" uri_path="/50x.html"'
    ' http_method="GET" request_time="0.001" category="text/html" https=""'
)


class TestParseKvLine:
    def test_reads_every_quoted_pair(self) -> None:
        fields = parse_kv_line(LINE)

        assert fields["src_ip"] == "162.142.125.57"
        assert fields["https"] == ""
        assert fields["http_user_agent"].startswith("Mozilla/5.0 (compatible; CensysInspect")

    def test_keeps_escaped_quotes(self) -> None:
        assert parse_kv_line(r'a="say \"hi\"" b="x"') == {"a": r"say \"hi\"", "b": "x"}

    @pytest.mark.parametrize("line", ["", "not a kv line", 'a="1" a="2"'])
    def test_rejects_malformed_lines(self, line: str) -> None:
        with pytest.raises(RecordError):
            parse_kv_line(line)


class TestEcsEntry:
    def test_maps_access_fields_to_ecs(self) -> None:
        entry = ecs_entry(parse_kv_line(LINE))

        assert entry.schema_name is LogSchema.ECS
        assert dict(entry.fields) == {
            "@timestamp": "2021-12-15T01:34:46+00:00",
            "event.dataset": "nginx.access",
            "source.ip": "162.142.125.57",
            "destination.ip": "172.31.4.228",
            "destination.port": "80",
            "server.address": "34.211.116.74",
            "http.version": "1.1",
            "http.request.method": "GET",
            "url.path": "/50x.html",
            "http.response.status_code": "502",
            "http.response.bytes": "676",
            "http.request.bytes": "0",
            "user_agent.original": (
                "Mozilla/5.0 (compatible; CensysInspect/1.1; +https://about.censys.io/)"
            ),
        }

    def test_drops_nginx_placeholders_and_duplicates(self) -> None:
        fields = ecs_entry(parse_kv_line(LINE)).fields

        assert "user.name" not in fields  # user="-"
        assert "url.query" not in fields  # uri_query="-"
        assert "162.142.125.57" not in [v for k, v in fields.items() if k != "source.ip"]

    def test_rejects_an_unreadable_timestamp(self) -> None:
        with pytest.raises(RecordError, match="time_local"):
            ecs_entry({**parse_kv_line(LINE), "time_local": "yesterday"})
