from typer.testing import CliRunner

from tracebait import __version__
from tracebait.cli import app

runner = CliRunner()


def test_version_flag_prints_version() -> None:
    result = runner.invoke(app, ["--version"])

    assert result.exit_code == 0
    assert result.stdout.strip() == f"tracebait {__version__}"


def test_help_describes_the_tool() -> None:
    result = runner.invoke(app, ["--help"])

    assert result.exit_code == 0
    assert "attacker-written log fields" in result.stdout
