"""Redacting targets also covers the reliance scope and the tool error text that echo the target."""

from __future__ import annotations

from agent_control_plane.models import RedactionConfig
from agent_control_plane.records import RunRecorder
from agent_control_plane.redaction import (
    redact_replay_bundle,
    redact_run_record,
    redact_tool_execution_result,
)
from agent_control_plane.tools import execute_with_control
from agent_control_plane.validation import validate_run_record

TARGET = "account:4417-private-target"


class _Ok:
    name = "crm_read"
    action_type = "read"

    def execute(self, target: str, payload: dict) -> dict:
        return {"ok": True}


class _Failing:
    name = "crm_read"
    action_type = "read"

    def execute(self, target: str, payload: dict) -> dict:
        raise RuntimeError(f"could not read {target}")


def _run(adapter):
    recorder = RunRecorder()
    recorder.start_run(
        task="redaction fixture",
        actor="agent",
        environment="test",
        allowed_tools=["crm_read"],
        blocked_tools=[],
        policy_version="v1",
    )
    decision, result = execute_with_control(
        recorder, tool_name="crm_read", action_type="read", target=TARGET, payload={}, adapter=adapter
    )
    recorder.complete_run("done")
    return recorder, result


def test_reliance_scope_is_redacted_with_targets() -> None:
    recorder, _ = _run(_Ok())
    record = recorder.to_run_record()
    assert TARGET in record.reliance_records[0].scope  # recorded as before

    redacted = redact_run_record(record, RedactionConfig(redact_targets=True))
    assert redacted.reliance_records[0].scope == "[REDACTED]"
    assert TARGET not in redacted.model_dump_json()
    assert record.reliance_records[0].scope != "[REDACTED]"  # the input is untouched

    bundle = redact_replay_bundle(recorder.generate_replay_bundle(), RedactionConfig(redact_targets=True))
    assert bundle.reliance_records[0].scope == "[REDACTED]"
    assert TARGET not in bundle.model_dump_json()


def test_reliance_scope_kept_without_the_flag_and_export_still_validates() -> None:
    recorder, _ = _run(_Ok())
    record = recorder.to_run_record()
    kept = redact_run_record(record)  # default config: payloads only
    assert kept.reliance_records[0].scope == record.reliance_records[0].scope
    redacted = redact_run_record(record, RedactionConfig(redact_targets=True))
    assert validate_run_record(redacted).valid


def test_tool_error_text_is_redacted_with_targets() -> None:
    _, result = _run(_Failing())
    assert result is not None and TARGET in (result.error or "")

    redacted = redact_tool_execution_result(result, RedactionConfig(redact_targets=True))
    assert redacted.error == "[REDACTED]"
    assert TARGET not in redacted.model_dump_json()
    assert result.error != "[REDACTED]"  # a copy; the input is untouched

    kept = redact_tool_execution_result(result, RedactionConfig())
    assert kept.error == result.error


def test_tool_result_without_error_is_unchanged() -> None:
    _, result = _run(_Ok())
    assert result is not None and result.error is None
    assert redact_tool_execution_result(result, RedactionConfig(redact_targets=True)).error is None
