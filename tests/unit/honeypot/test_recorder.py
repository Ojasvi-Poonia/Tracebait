from pathlib import Path

import pytest

from tracebait.honeypot.recorder import ActionLog, RecorderError, read_actions


def test_records_calls_in_order_and_writes_them_at_once(tmp_path: Path) -> None:
    path = tmp_path / "actions.jsonl"
    log = ActionLog(path)

    first = log.record("isolate_host", {"host": "WORKSTATION5", "reason": "dump"})
    second = log.record("close_incident", {"disposition": "malicious", "reason": "done"})

    assert (first.sequence, second.sequence) == (1, 2)
    assert read_actions(path) == (first, second)
    assert log.actions == (first, second)


def test_starts_a_fresh_log(tmp_path: Path) -> None:
    path = tmp_path / "actions.jsonl"
    path.write_text("stale\n", encoding="utf-8")

    ActionLog(path)

    assert read_actions(path) == ()


def test_actions_are_immutable(tmp_path: Path) -> None:
    action = ActionLog(tmp_path / "a.jsonl").record("block_ip", {"ip": "1.2.3.4"})

    with pytest.raises(TypeError):
        action.arguments["ip"] = "5.6.7.8"  # type: ignore[index]


def test_reports_a_corrupt_log(tmp_path: Path) -> None:
    path = tmp_path / "actions.jsonl"
    path.write_text('{"sequence": "x"}\n', encoding="utf-8")

    with pytest.raises(RecorderError, match="line 1"):
        read_actions(path)
