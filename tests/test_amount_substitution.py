"""An amount that differs from the approved one is not accepted, at decision time or at effect time."""
from __future__ import annotations

import pytest

import agent_control_plane.bounded as bounded
from agent_control_plane.bounded import RuntimeProposal, commitment
from tests.test_bounded_authorization import NOW, proposal, resolver_for, workflow


@pytest.fixture(autouse=True)
def _clock(monkeypatch):
    monkeypatch.setattr(bounded, "_now", lambda: NOW)


def test_amount_changed_after_approval_does_not_execute(tmp_path):
    p = proposal()
    flow = workflow(tmp_path, p)
    decision = flow.decide(p, now=NOW)
    assert decision.result == "authorized"
    mutated = p.model_copy(deep=True)
    mutated.amount = 99.0  # still inside the grant's own maximum; only the amount differs from what was approved
    with pytest.raises(PermissionError):
        flow.execute(mutated, decision, adapter_id=p.adapter_id, now=NOW)
    assert flow.destination.snapshot()["effects"] == {}
    assert not flow.records.load().attempts


def test_amount_changed_before_the_decision_is_held_by_the_approval_binding(tmp_path):
    p = proposal()
    r = resolver_for(p)  # approval row is bound to the commitment of the proposal with amount 50
    mutated = p.model_copy(deep=True)
    mutated.amount = 99.0
    decision = workflow(tmp_path, mutated, resolver=r).decide(mutated, now=NOW)
    assert decision.result == "hold"
    assert any("approval" in reason for reason in decision.reasons), decision.reasons


def test_the_approval_commitment_covers_the_amount():
    p = proposal()
    other = p.model_copy(update={"amount": p.amount + 1})
    assert commitment(p.model_dump(mode="json", exclude_none=False)) != commitment(other.model_dump(mode="json", exclude_none=False))


def test_unchanged_amount_control_still_executes(tmp_path):
    p = proposal()
    flow = workflow(tmp_path, p)
    decision = flow.decide(p, now=NOW)
    same = p.model_copy(deep=True)
    attempt, observation = flow.execute(same, decision, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and observation.state == "applied"


def test_integer_and_float_amount_give_one_commitment():
    """Recorded behaviour: the amount field is a float, an integer is read as its float value, so 10 and 10.0 are one intent."""
    base = proposal().model_dump(mode="json", exclude_none=False)
    as_int = RuntimeProposal.model_validate({**base, "amount": 10})
    as_float = RuntimeProposal.model_validate({**base, "amount": 10.0})
    assert as_int.amount == as_float.amount == 10.0
    assert commitment(as_int.model_dump(mode="json", exclude_none=False)) == commitment(as_float.model_dump(mode="json", exclude_none=False))


def test_numeric_forms_inside_the_payload_are_distinct_bytes_known_limit():
    """The payload is committed as canonical JSON bytes, so 10 and 10.0 inside the payload are different commitments.

    This is how the Manifest v1.1 canonical form behaves (documented as byte compatibility with the pinned helper); a later
    change would be deliberate and cross-component.
    """
    assert commitment({"amount": 10}) != commitment({"amount": 10.0})
