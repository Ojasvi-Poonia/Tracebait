"""Build the wheel, install it into a fresh venv and use the shipped data from there.

uv_build only packages files under src/tracebait/, so data placed anywhere else would be
silently missing from the wheel. This test catches that.
"""

import shutil
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from tracebait import __version__
from tracebait.field_registry import load_registry

ROOT = Path(__file__).resolve().parent.parent
UV = shutil.which("uv")

pytestmark = [
    pytest.mark.packaging,
    pytest.mark.skipif(UV is None, reason="uv is not installed"),
]


def _run(*args: str | Path) -> str:
    proc = subprocess.run(
        [str(a) for a in args], check=False, capture_output=True, text=True, cwd=ROOT
    )
    assert proc.returncode == 0, f"{args} failed:\n{proc.stderr}"
    return proc.stdout


@pytest.fixture(scope="module")
def wheel(tmp_path_factory: pytest.TempPathFactory) -> Path:
    out = tmp_path_factory.mktemp("dist")
    assert UV is not None
    _run(UV, "build", "--wheel", "--out-dir", out)
    (built,) = out.glob("tracebait-*.whl")
    return built


def test_wheel_ships_package_data(wheel: Path) -> None:
    names = set(zipfile.ZipFile(wheel).namelist())

    assert "tracebait/data/fields.json" in names
    assert "tracebait/py.typed" in names


def test_installed_wheel_loads_registry_and_runs_cli(wheel: Path, tmp_path: Path) -> None:
    assert UV is not None
    venv = tmp_path / "venv"
    _run(UV, "venv", "--quiet", "--python", sys.executable, venv)
    python = venv / "bin" / "python"
    _run(UV, "pip", "install", "--quiet", "--python", python, wheel)

    count = _run(
        python,
        "-I",
        "-c",
        "from tracebait.field_registry import load_registry; print(len(load_registry().fields))",
    )
    version = _run(venv / "bin" / "tracebait", "--version")

    assert int(count) == len(load_registry().fields)
    assert version.strip() == f"tracebait {__version__}"
