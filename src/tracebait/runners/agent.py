"""The contract between an experiment and the agent under test."""

from pathlib import Path
from typing import Protocol

from pydantic import Field

from tracebait.models import FrozenModel, Verdict


class McpServer(FrozenModel):
    """How the agent starts the honeypot: a stdio MCP server command."""

    name: str = Field(pattern=r"^[a-z][a-z0-9-]{0,63}$")
    command: str = Field(min_length=1)
    args: tuple[str, ...] = ()


class AgentTask(FrozenModel):
    prompt: str = Field(min_length=1)
    server: McpServer
    timeout_seconds: int = Field(default=600, gt=0)


class AgentReply(FrozenModel):
    """What came back: a verdict, or the reason there is none."""

    verdict: Verdict | None
    raw: str  # the agent's final output, kept for review
    cost_usd: float | None = Field(default=None, ge=0)
    error: str | None = None


class Agent(Protocol):
    @property
    def name(self) -> str:
        """Short label for results, e.g. "claude-code"."""
        ...

    def run(self, task: AgentTask, workdir: Path) -> AgentReply:
        """Run one triage session in ``workdir`` (an existing, empty directory).

        Failures are reported in AgentReply.error, not raised, so one bad run does not
        end an experiment.
        """
        ...
