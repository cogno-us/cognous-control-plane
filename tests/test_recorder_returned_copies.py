"""Records handed back by the recorder are copies: changing one does not change what the run recorded."""

from __future__ import annotations

from agent_control_plane.records import RunRecorder


def _recorder() -> RunRecorder:
    recorder = RunRecorder()
    recorder.start_run(
        task="copy semantics",
        actor="agent-v1",
        environment="test",
        allowed_tools=["crm_read"],
        blocked_tools=["email_send"],
        policy_version="v1.0",
    )
    return recorder


def test_returned_decision_is_a_copy() -> None:
    recorder = _recorder()
    action = recorder.propose_action(tool_name="crm_read", action_type="read", target="t", payload={})
    decision, _ = recorder.evaluate_action(action)
    decision.result = "allow" if decision.result != "allow" else "block"
    decision.reason = "changed by the caller"
    stored = recorder.to_run_record().decisions[0]
    assert stored.result == "allow" and stored.reason != "changed by the caller"


def test_returned_blocked_action_is_a_copy() -> None:
    recorder = _recorder()
    action = recorder.propose_action(tool_name="email_send", action_type="write", target="t", payload={})
    _, blocked = recorder.evaluate_action(action)
    assert blocked is not None
    blocked.reason = "changed by the caller"
    assert recorder.to_run_record().blocked_actions[0].reason != "changed by the caller"


def test_blocked_decision_returned_is_a_copy() -> None:
    recorder = _recorder()
    action = recorder.propose_action(tool_name="email_send", action_type="write", target="t", payload={})
    decision, blocked = recorder.evaluate_action(action)
    decision.result = "allow"
    assert recorder.to_run_record().decisions[0].result == "block"
    assert blocked is not None


def test_returned_policy_traces_are_copies() -> None:
    recorder = _recorder()
    action = recorder.propose_action(tool_name="crm_read", action_type="read", target="t", payload={})
    recorder.evaluate_action(action)
    traces = recorder.get_policy_traces()
    traces[0].final_result = "block"
    traces[0].rules_evaluated.clear()
    again = recorder.get_policy_traces()
    assert again[0].final_result == "allow" and again[0].rules_evaluated


def test_returned_reliance_record_is_a_copy() -> None:
    recorder = _recorder()
    record = recorder.record_reliance(source_name="crm_read", source_type="tool", scope="customer fields")
    record.scope = "changed by the caller"
    assert recorder.to_run_record().reliance_records[0].scope == "customer fields"


def test_returned_authority_record_is_a_copy() -> None:
    recorder = _recorder()
    record = recorder.add_authority_record(actor="agent-v1", scope=["read"], source="test")
    record.scope.append("write")
    assert recorder.to_run_record().authority_records[0].scope == ["read"]


def test_valid_flow_still_records_and_exports() -> None:
    recorder = _recorder()
    action = recorder.propose_action(tool_name="crm_read", action_type="read", target="t", payload={"a": 1})
    decision, blocked = recorder.evaluate_action(action)
    assert decision.result == "allow" and blocked is None
    recorder.record_reliance(source_name="crm_read", source_type="tool", scope="s", referenced_action_id=action.action_id)
    recorder.complete_run("done")
    record = recorder.to_run_record()
    assert [d.decision_id for d in record.decisions] == [decision.decision_id]
    assert len(record.policy_traces) == 1 and len(record.reliance_records) == 1
