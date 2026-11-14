"""Keep README.md honest: its examples run, its links resolve and it lists every field."""

import re
from pathlib import Path

import pytest

from tracebait.field_registry import load_registry

ROOT = Path(__file__).resolve().parent.parent
README = (ROOT / "README.md").read_text(encoding="utf-8")
PYTHON_BLOCKS = re.findall(r"```python\n(.*?)```", README, re.S)
RELATIVE_LINKS = re.findall(r"\]\((?!https?://|#|mailto:)([^)#\s]+)", README)


def test_readme_has_python_examples() -> None:
    assert PYTHON_BLOCKS


@pytest.mark.parametrize(
    "block", PYTHON_BLOCKS, ids=[f"example-{i}" for i in range(1, len(PYTHON_BLOCKS) + 1)]
)
def test_python_examples_print_what_the_readme_shows(
    block: str, capsys: pytest.CaptureFixture[str]
) -> None:
    exec(compile(block, "README.md", "exec"), {})  # noqa: S102 - our own README examples

    shown = [line[2:] for line in block.splitlines() if line.startswith("# ")]
    assert capsys.readouterr().out.splitlines() == shown


def test_lists_every_registry_field() -> None:
    for name in load_registry().names:
        assert f"`{name}`" in README, name


def test_relative_links_resolve() -> None:
    assert RELATIVE_LINKS
    for target in RELATIVE_LINKS:
        assert (ROOT / target).exists(), target
