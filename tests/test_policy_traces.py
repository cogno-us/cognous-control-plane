"""Tests for policy evaluation traces."""

from __future__ import annotations

from agent_control_plane.models import ActionProposal, AuthorityRecord, Frame
from agent_control_plane.policy_gate import PolicyGate
from agent_control_plane.records import RunRecorder


def _make_frame(
    allowed_tools: list[str] | None = None,
    blocked_tools: list[str] | None = None,
) -> Frame:
    return Frame(
        frame_id="frame-1",
        task="trace test",
        actor="trace-agent",
        environment="test",
        allowed_tools=allowed_tools or [],
        blocked_tools=blocked_tools or [],
        policy_version="v1.0",
    )


def _make_action(tool_name: str, action_type: str) -> ActionProposal:
    return ActionProposal(
        action_id=f"{tool_name}-{action_type}",
        run_id="run-1",
        tool_name=tool_name,
        action_type=action_type,
        target="resource:1",
    )


def _make_authority(scope: list[str]) -> AuthorityRecord:
    return AuthorityRecord(
        authority_id="auth-1",
        run_id="run-1",
        actor="trace-agent",
        scope=scope,
        source="test",
    )


def test_evaluate_with_trace_returns_decision_and_trace() -> None:
    gate = PolicyGate()
    action = _make_action("crm_read", "read")
    decision, trace = gate.evaluate_with_trace(action, _make_frame(["crm_read"]), [])

    assert decision.result == "allow"
    assert decision.trace_id == trace.trace_id
    assert trace.final_result == decision.result
    assert trace.deterministic_fingerprint == decision.deterministic_fingerprint


def test_allowed_read_matches_read_allowed_tool_policy() -> None:
    gate = PolicyGate()
    _, trace = gate.evaluate_with_trace(_make_action("crm_read", "read"), _make_frame(["crm_read"]), [])

    assert trace.rules_evaluated[-1].rule_name == "read_allowed_tool_policy"
    assert trace.rules_evaluated[-1].matched is True


def test_blocked_tool_matches_blocked_tool_policy() -> None:
    gate = PolicyGate()
    _, trace = gate.evaluate_with_trace(
        _make_action("email_send", "external_send"),
        _make_frame(["email_send"], ["email_send"]),
        [],
    )

    assert trace.rules_evaluated[-1].rule_name == "blocked_tool_policy"
    assert trace.rules_evaluated[-1].matched is True


def test_unknown_tool_matches_unknown_tool_policy() -> None:
    gate = PolicyGate()
    _, trace = gate.evaluate_with_trace(_make_action("unknown_tool", "read"), _make_frame(["crm_read"]), [])

    assert trace.rules_evaluated[-1].rule_name == "unknown_tool_policy"
    assert trace.rules_evaluated[-1].matched is True


def test_external_send_without_authority_matches_external_send_authority_policy() -> None:
    gate = PolicyGate()
    _, trace = gate.evaluate_with_trace(
        _make_action("email_send", "external_send"),
        _make_frame(["email_send"]),
        [],
    )

    assert trace.rules_evaluated[-1].rule_name == "external_send_authority_policy"
    assert trace.rules_evaluated[-1].matched is True


def test_write_with_authority_matches_write_authority_policy() -> None:
    gate = PolicyGate()
    _, trace = gate.evaluate_with_trace(
        _make_action("notes_write", "write"),
        _make_frame(["notes_write"]),
        [_make_authority(["write"])],
    )

    assert trace.rules_evaluated[-1].rule_name == "write_authority_policy"
    assert trace.rules_evaluated[-1].matched is True


def test_run_recorder_stores_policy_traces_by_default() -> None:
    recorder = RunRecorder()
    recorder.start_run(
        task="trace recorder test",
        actor="trace-agent",
        environment="test",
        allowed_tools=["crm_read"],
        blocked_tools=["email_send"],
        policy_version="v1.0",
    )
    action = recorder.propose_action(
        tool_name="crm_read",
        action_type="read",
        target="customer:1",
    )

    decision, blocked = recorder.evaluate_action(action)
    recorder.complete_run()
    run_record = recorder.to_run_record()
    replay_bundle = recorder.generate_replay_bundle()

    assert decision.trace_id is not None
    assert blocked is None
    assert len(recorder.get_policy_traces()) == 1
    assert len(run_record.policy_traces) == 1
    assert len(replay_bundle.policy_traces) == 1
