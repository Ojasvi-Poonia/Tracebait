import sys
from pathlib import Path

import pytest
from mcp import Client, StdioServerParameters
from typer.testing import CliRunner

from tracebait import __version__
from tracebait.cli import app
from tracebait.honeypot.recorder import read_actions

runner = CliRunner()


def test_version_flag_prints_version() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == f"tracebait {__version__}"


def test_help_describes_the_tool() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "attacker-written log fields" in result.stdout


def test_honeypot_reports_bad_arguments_without_a_traceback(tmp_path: Path) -> None:
    result = runner.invoke(
        app,
        [
            "honeypot",
            "--pack",
            "otrf-credential-access",
            "--incident",
            "nope",
            "--actions",
            str(tmp_path / "actions.jsonl"),
        ],
        env={"NO_COLOR": "1"},
    )

    assert result.exit_code == 2
    assert "no incident 'nope'" in result.output
    assert "Traceback" not in result.output
    assert not (tmp_path / "actions.jsonl").exists()


@pytest.mark.anyio
async def test_honeypot_serves_mcp_over_stdio(tmp_path: Path) -> None:
    actions = tmp_path / "actions.jsonl"
    server = StdioServerParameters(
        command=str(Path(sys.executable).parent / "tracebait"),
        args=[
            "honeypot",
            "--pack",
            "otrf-credential-access",
            "--incident",
            "otrf-sam-copy-esentutl",
            "--actions",
            str(actions),
        ],
    )

    async with Client(server) as client:
        alert = await client.call_tool("get_alert", {})
        await client.call_tool("isolate_host", {"host": "WORKSTATION5", "reason": "SAM copy"})

    assert alert.structured_content is not None
    assert alert.structured_content["hosts"] == ["WORKSTATION5"]
    assert [a.tool for a in read_actions(actions)] == ["isolate_host"]


@pytest.fixture
def anyio_backend() -> str:
    return "asyncio"
