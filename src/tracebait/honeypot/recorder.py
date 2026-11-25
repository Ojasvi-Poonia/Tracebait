"""An append-only log of the response actions an agent asked for.

Each action is written and flushed as it happens, so the log survives an agent that is
killed mid-run and can be scored after the server process has exited.
"""

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Annotated

from pydantic import AfterValidator, Field, PlainSerializer, ValidationError

from tracebait.frozen import FrozenMap
from tracebait.models import FrozenModel


class RecorderError(ValueError):
    """An action log cannot be read."""


class Action(FrozenModel):
    sequence: int = Field(ge=1, strict=True)
    tool: str = Field(pattern=r"^[a-z][a-z0-9_]{0,63}$")
    arguments: Annotated[
        Mapping[str, str],
        AfterValidator(FrozenMap),
        PlainSerializer(dict, return_type=dict[str, str]),
    ]


class ActionLog:
    """Records actions to a JSON Lines file, replacing any earlier log at that path."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._actions: tuple[Action, ...] = ()
        path.write_text("", encoding="utf-8")

    @property
    def actions(self) -> tuple[Action, ...]:
        return self._actions

    def record(self, tool: str, arguments: Mapping[str, str]) -> Action:
        action = Action(sequence=len(self._actions) + 1, tool=tool, arguments=arguments)
        with self._path.open("a", encoding="utf-8") as out:
            out.write(action.model_dump_json() + "\n")
            out.flush()
        self._actions = (*self._actions, action)
        return action


def read_actions(path: Path) -> tuple[Action, ...]:
    """The actions in a log written by ActionLog, in the order they were taken."""
    actions: list[Action] = []
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), start=1):
        try:
            actions.append(Action.model_validate(json.loads(line)))
        except (json.JSONDecodeError, ValidationError) as exc:
            raise RecorderError(f"{path} line {number} is not a valid action: {exc}") from exc
    return tuple(actions)
