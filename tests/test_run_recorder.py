"""Tests for RunRecorder action evaluation constraints."""

from __future__ import annotations

import pytest

from agent_control_plane.models import ActionProposal
from agent_control_plane.records import RunRecorder


def _make_started_recorder() -> RunRecorder:
    recorder = RunRecorder()
    recorder.start_run(
        task="RunRecorder test",
        actor="test-agent",
        environment="test",
        allowed_tools=["crm_read"],
        blocked_tools=["email_send"],
        policy_version="v1.0",
    )
    return recorder


def test_evaluate_action_rejects_foreign_run_action() -> None:
    recorder = _make_started_recorder()
    action = ActionProposal(
        action_id="foreign-action",
        run_id="other-run",
        tool_name="crm_read",
        action_type="read",
        target="customer:1",
    )

    with pytest.raises(ValueError, match="different run"):
        recorder.evaluate_action(action)


def test_evaluate_action_rejects_unrecorded_action() -> None:
    recorder = _make_started_recorder()
    run_id = recorder.to_run_record().run_id
    action = ActionProposal(
        action_id="unrecorded-action",
        run_id=run_id,
        tool_name="crm_read",
        action_type="read",
        target="customer:1",
    )

    with pytest.raises(ValueError, match="not proposed in this run"):
        recorder.evaluate_action(action)


def test_evaluate_action_allows_proposed_action() -> None:
    recorder = _make_started_recorder()
    action = recorder.propose_action(
        tool_name="crm_read",
        action_type="read",
        target="customer:1",
    )

    decision, blocked = recorder.evaluate_action(action)

    assert decision.result == "allow"
    assert blocked is None


def test_a_different_proposal_under_a_recorded_action_id_is_refused() -> None:
    recorder = _make_started_recorder()
    action = recorder.propose_action(tool_name="email_send", action_type="external_send", target="prod-db")
    other = action.model_copy(update={"tool_name": "crm_read", "action_type": "read", "target": "readme"})

    with pytest.raises(ValueError, match="differs from the proposal recorded"):
        recorder.evaluate_action(other)

    assert recorder.to_run_record().decisions == []  # nothing was recorded for the refused evaluation


def test_recorded_proposals_are_not_reachable_through_returned_objects() -> None:
    recorder = _make_started_recorder()
    action = recorder.propose_action(tool_name="crm_read", action_type="read", target="customer:1", payload={"k": "v"})
    object.__setattr__(action, "target", "elsewhere")
    action.payload["k"] = "changed"
    snapshot = recorder.to_run_record()
    assert snapshot.actions[0].target == "customer:1" and snapshot.actions[0].payload == {"k": "v"}
    snapshot.actions[0].payload["k"] = "changed-too"
    assert recorder.to_run_record().actions[0].payload == {"k": "v"}


def test_complete_run_is_terminal_and_bundles_need_a_completed_run() -> None:
    recorder = _make_started_recorder()
    action = recorder.propose_action(tool_name="crm_read", action_type="read", target="customer:1")
    with pytest.raises(RuntimeError, match="not completed"):
        recorder.generate_replay_bundle()
    assert recorder.generate_replay_bundle(allow_incomplete=True).run_id == recorder.to_run_record().run_id  # explicit opt-in
    recorder.complete_run("done")
    assert recorder.generate_replay_bundle().final_output == "done"
    for call in (
        lambda: recorder.propose_action(tool_name="crm_read", action_type="read", target="x"),
        lambda: recorder.evaluate_action(action),
        lambda: recorder.record_reliance(source_name="s", source_type="tool", scope="x"),
        lambda: recorder.add_authority_record(actor="a", scope=["read"], source="s"),
        lambda: recorder.complete_run("again"),
    ):
        with pytest.raises(RuntimeError, match="completed"):
            call()
