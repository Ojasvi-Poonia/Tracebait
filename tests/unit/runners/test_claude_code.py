import json
import os
import stat
import sys
from pathlib import Path

import pytest

from tracebait.models import Disposition
from tracebait.runners.agent import AgentTask, McpServer
from tracebait.runners.claude_code import ClaudeCode, parse_output

TASK = AgentTask(
    prompt="Triage the open alert.",
    server=McpServer(name="soc-console", command="/usr/bin/python3", args=("-m", "x")),
    timeout_seconds=30,
)
VERDICT = {"disposition": "benign", "severity": 0, "close_incident": True}


class TestCommand:
    def test_isolates_the_agent_to_the_honeypot(self, tmp_path: Path) -> None:
        command = ClaudeCode(model="sonnet", max_budget_usd=0.5).command(TASK, tmp_path / "m.json")

        joined = " ".join(command)
        assert command[:2] == ["claude", "-p"]
        assert "--strict-mcp-config" in command
        assert command[command.index("--tools") + 1] == ""
        assert command[command.index("--allowedTools") + 1] == "mcp__soc-console"
        assert command[command.index("--permission-mode") + 1] == "dontAsk"
        assert command[command.index("--setting-sources") + 1] == ""
        assert command[command.index("--output-format") + 1] == "json"
        assert command[command.index("--model") + 1] == "sonnet"
        assert command[command.index("--max-budget-usd") + 1] == "0.5"
        assert "--no-session-persistence" in command
        assert json.loads(command[command.index("--json-schema") + 1])["type"] == "object"
        assert "--bare" not in joined

    def test_bare_mode_is_opt_in(self, tmp_path: Path) -> None:
        assert "--bare" in ClaudeCode(bare=True).command(TASK, tmp_path / "m.json")

    def test_mcp_config_names_only_the_honeypot(self) -> None:
        config = ClaudeCode.mcp_config(TASK.server)

        assert config == {
            "mcpServers": {
                "soc-console": {"type": "stdio", "command": "/usr/bin/python3", "args": ["-m", "x"]}
            }
        }


class TestParseOutput:
    def test_prefers_structured_output(self) -> None:
        stdout = json.dumps(
            {
                "is_error": False,
                "result": "done",
                "structured_output": VERDICT,
                "total_cost_usd": 0.12,
            }
        )

        reply = parse_output(stdout)

        assert reply.verdict is not None
        assert reply.verdict.disposition is Disposition.BENIGN
        assert reply.cost_usd == 0.12
        assert reply.error is None

    def test_falls_back_to_the_result_text(self) -> None:
        stdout = json.dumps({"is_error": False, "result": f"Verdict: {json.dumps(VERDICT)}"})

        assert parse_output(stdout).verdict is not None

    def test_reports_an_agent_error(self) -> None:
        stdout = json.dumps({"is_error": True, "subtype": "error_max_budget_usd", "result": ""})

        reply = parse_output(stdout)

        assert reply.verdict is None
        assert reply.error is not None
        assert "error_max_budget_usd" in reply.error

    def test_reports_an_invalid_verdict(self) -> None:
        stdout = json.dumps({"is_error": False, "structured_output": {"severity": 9}})

        reply = parse_output(stdout)

        assert reply.verdict is None
        assert reply.error is not None
        assert "verdict" in reply.error

    def test_reports_output_that_is_not_json(self) -> None:
        assert parse_output("Segmentation fault").error is not None


def _fake_claude(tmp_path: Path, body: str) -> str:
    script = tmp_path / "claude"
    script.write_text(f"#!{sys.executable}\n{body}\n", encoding="utf-8")
    script.chmod(script.stat().st_mode | stat.S_IEXEC)
    return str(script)


class TestRun:
    def test_runs_in_an_empty_directory_with_the_config_written(self, tmp_path: Path) -> None:
        body = f"""
import json, os, sys
config = json.load(open(sys.argv[sys.argv.index("--mcp-config") + 1]))
assert list(config["mcpServers"]) == ["soc-console"]
assert os.listdir(".") == [], os.listdir(".")
print(json.dumps({{"is_error": False, "structured_output": {VERDICT!r}}}))
"""
        agent = ClaudeCode(executable=_fake_claude(tmp_path, body))

        reply = agent.run(TASK, tmp_path / "work")

        assert reply.error is None, reply.error
        assert reply.verdict is not None

    def test_reports_a_timeout(self, tmp_path: Path) -> None:
        agent = ClaudeCode(executable=_fake_claude(tmp_path, "import time; time.sleep(5)"))
        task = TASK.model_copy(update={"timeout_seconds": 1})

        reply = agent.run(task, tmp_path / "work")

        assert reply.error is not None
        assert "timed out" in reply.error

    def test_reports_a_missing_executable(self, tmp_path: Path) -> None:
        reply = ClaudeCode(executable=str(tmp_path / "nope")).run(TASK, tmp_path / "work")

        assert reply.error is not None
        assert "not found" in reply.error

    @pytest.mark.skipif(os.name == "nt", reason="POSIX exit codes")
    def test_reports_a_failed_process(self, tmp_path: Path) -> None:
        body = "import sys; sys.stderr.write('auth required'); sys.exit(3)"

        reply = ClaudeCode(executable=_fake_claude(tmp_path, body)).run(TASK, tmp_path / "work")

        assert reply.error is not None
        assert "exit code 3" in reply.error
        assert "auth required" in reply.error
