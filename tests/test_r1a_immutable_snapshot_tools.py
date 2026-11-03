"""R1-A (csf_157f0532e46704d37e3f35e9): execute_with_control executes the recorded, evaluated payload, not the caller's live dict."""
from __future__ import annotations

from tests.test_tool_adapter import RecordingAdapter, _make_recorder
from agent_control_plane.tools import execute_with_control


def _run(mutate_when):
    recorder = _make_recorder()
    adapter = RecordingAdapter()
    payload = {"fields": ["name"], "filter": {"ids": [1, 2]}}
    original = {"fields": ["name"], "filter": {"ids": [1, 2]}}
    if mutate_when == "evaluation":
        orig_eval = recorder.evaluate_action

        def evaluate(action, *a, **k):
            out = orig_eval(action, *a, **k)
            payload["fields"].append("ssn")          # nested mutation after the decision, before execution
            payload["filter"]["ids"].append(999)
            payload["extra"] = 1
            return out

        recorder.evaluate_action = evaluate
    decision, result = execute_with_control(recorder, tool_name="crm_read", action_type="read", target="customer:1",
                                            payload=payload, adapter=adapter)
    return recorder, adapter, decision, result, payload, original


def test_nested_caller_mutation_between_evaluation_and_execution_does_not_reach_the_adapter():  # test 8
    recorder, adapter, decision, result, payload, original = _run("evaluation")
    assert decision.result == "allow" and result.executed is True
    assert payload != original  # the mutation really happened
    assert adapter.calls == [("customer:1", original)]


def test_executed_payload_equals_the_recorded_evaluated_payload():  # test 9
    recorder, adapter, decision, result, payload, original = _run("evaluation")
    recorded = [a for a in recorder._actions if a.action_id == result.action_id]
    assert len(recorded) == 1
    assert adapter.calls[0][1] == recorded[0].payload == original


def test_nested_mutation_after_proposal_before_evaluation_is_also_detached():
    recorder = _make_recorder()
    adapter = RecordingAdapter()
    payload = {"fields": ["name"]}
    orig_propose = recorder.propose_action

    def propose(**kw):
        out = orig_propose(**kw)
        payload["fields"].append("ssn")  # mutated right after the proposal is recorded
        return out

    recorder.propose_action = propose
    execute_with_control(recorder, tool_name="crm_read", action_type="read", target="customer:1", payload=payload, adapter=adapter)
    assert adapter.calls == [("customer:1", {"fields": ["name"]})]


def test_adapter_mutating_its_payload_cannot_alter_the_recorded_action():
    recorder = _make_recorder()

    class Scribbler(RecordingAdapter):
        def execute(self, target, payload):
            payload["fields"].append("scribble")
            return {}

    execute_with_control(recorder, tool_name="crm_read", action_type="read", target="customer:1",
                         payload={"fields": ["name"]}, adapter=Scribbler())
    assert recorder._actions[0].payload == {"fields": ["name"]}
