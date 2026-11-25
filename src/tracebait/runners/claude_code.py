"""Run Claude Code headless (``claude -p``) as the agent under test.

The session is isolated so the result measures the model and the honeypot, not the
operator's own setup. Claude starts in an empty directory, so no project CLAUDE.md is
found. Its only MCP server is the honeypot (--strict-mcp-config), built-in tools are
switched off (--tools ""), only honeypot tools are allowed and anything else is denied
(--permission-mode dontAsk). No settings files are read (--setting-sources ""), and the
session is not saved. --bare also skips user memory files, hooks and plugins, but it
skips keychain reads too, so it needs ANTHROPIC_API_KEY; it is therefore opt-in.
"""

import json
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from tracebait.runners.agent import AgentReply, AgentTask, McpServer
from tracebait.runners.verdict import VERDICT_SCHEMA, VerdictError, parse_verdict, verdict_from_text

MCP_CONFIG_NAME = "mcp.json"
STDERR_EXCERPT_CHARS = 500


@dataclass(frozen=True)
class ClaudeCode:
    model: str | None = None
    max_budget_usd: float | None = None
    bare: bool = False
    executable: str = "claude"
    name: str = "claude-code"

    @staticmethod
    def mcp_config(server: McpServer) -> dict[str, Any]:
        entry = {"type": "stdio", "command": server.command, "args": list(server.args)}
        return {"mcpServers": {server.name: entry}}

    def command(self, task: AgentTask, mcp_config_path: Path) -> list[str]:
        command = [
            self.executable,
            "-p",
            task.prompt,
            "--output-format",
            "json",
            "--json-schema",
            json.dumps(VERDICT_SCHEMA),
            "--mcp-config",
            str(mcp_config_path),
            "--strict-mcp-config",
            "--tools",
            "",
            "--allowedTools",
            f"mcp__{task.server.name}",
            "--permission-mode",
            "dontAsk",
            "--setting-sources",
            "",
            "--no-session-persistence",
        ]
        if self.model is not None:
            command += ["--model", self.model]
        if self.max_budget_usd is not None:
            command += ["--max-budget-usd", str(self.max_budget_usd)]
        if self.bare:
            command.append("--bare")
        return command

    def run(self, task: AgentTask, workdir: Path) -> AgentReply:
        # The config lives beside workdir, so Claude starts in an empty directory.
        workdir.mkdir(parents=True, exist_ok=True)
        config_path = workdir.parent / f"{workdir.name}-{MCP_CONFIG_NAME}"
        config_path.write_text(json.dumps(self.mcp_config(task.server)), encoding="utf-8")
        try:
            proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
                self.command(task, config_path),
                cwd=workdir,
                capture_output=True,
                text=True,
                timeout=task.timeout_seconds,
                check=False,
            )
        except FileNotFoundError:
            return _failed(f"{self.executable!r} not found; install Claude Code first")
        except subprocess.TimeoutExpired:
            return _failed(f"timed out after {task.timeout_seconds} s")
        if proc.returncode != 0:
            excerpt = proc.stderr.strip()[-STDERR_EXCERPT_CHARS:]
            return _failed(f"exit code {proc.returncode}: {excerpt}", proc.stdout)
        return parse_output(proc.stdout)


def parse_output(stdout: str) -> AgentReply:
    """Read the single JSON result that ``claude -p --output-format json`` prints."""
    try:
        result = json.loads(stdout)
    except json.JSONDecodeError:
        return _failed("output is not JSON", stdout)
    if not isinstance(result, dict):
        return _failed("output is not a JSON object", stdout)
    cost = result.get("total_cost_usd")
    cost_usd = float(cost) if isinstance(cost, int | float) and cost >= 0 else None
    if result.get("is_error"):
        return _failed(
            f"agent reported an error: {result.get('subtype', 'unknown')}", stdout, cost_usd
        )
    try:
        structured = result.get("structured_output")
        verdict = (
            parse_verdict(structured)
            if structured is not None
            else verdict_from_text(str(result.get("result", "")))
        )
    except VerdictError as exc:
        return _failed(f"no valid verdict: {exc}", stdout, cost_usd)
    return AgentReply(verdict=verdict, raw=stdout, cost_usd=cost_usd)


def _failed(error: str, raw: str = "", cost_usd: float | None = None) -> AgentReply:
    return AgentReply(verdict=None, raw=raw, cost_usd=cost_usd, error=error)
