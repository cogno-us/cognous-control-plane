"""Known limits, pinned as they behave today (characterisation only; no behaviour is changed here).

Every test name ends in ``_known_limit``. A later change to any of these behaviours must be deliberate: the test is then
rewritten together with the change, not loosened to make it pass.
"""
from __future__ import annotations

import json
from datetime import timedelta

import pytest

import agent_control_plane.bounded as bounded
from agent_control_plane.bounded import DefinitiveDestinationRejection, LocalRefundDestination
from tests.test_bounded_authorization import NOW, PROFILE, proposal, resolver_for, workflow

DESTINATION_ARGS = dict(target="t", amount=1.0, unit="USD", payload={})


@pytest.fixture(autouse=True)
def _clock(monkeypatch):
    monkeypatch.setattr(bounded, "_now", lambda: NOW)


# ---------------------------------------------------------------- (a) child grants under one parent

def test_cumulative_counters_are_per_grant_id_so_three_children_reach_their_own_cap_known_limit(tmp_path):
    """The destination counts effects per grant_id only. Three grants of 40 each reach 40, 120 in all, and no parent total
    (for example 100) is consulted anywhere on the effect path. A later change (a root-keyed budget) must be deliberate."""
    destination = LocalRefundDestination(tmp_path / "d.json")
    for child in ("child-1", "child-2", "child-3"):
        for n in range(40):
            result = destination.apply(effect_id=f"{child}-effect-{n}", grant_id=child, max_effects=40, **DESTINATION_ARGS)
            assert result["duplicate"] is False
    assert len(destination.snapshot()["effects"]) == 120
    assert destination.snapshot()["grant_effect_counts"] == {"child-1": 40, "child-2": 40, "child-3": 40}
    with pytest.raises(DefinitiveDestinationRejection, match="cumulative_grant_max_effects_exhausted"):
        destination.apply(effect_id="child-1-effect-40", grant_id="child-1", max_effects=40, **DESTINATION_ARGS)


def test_a_grant_that_names_a_parent_is_not_authorized_by_this_profile_known_limit(tmp_path):
    """At this head a grant with ``delegation.parent_grant_id`` is held (``delegation_profile_unsupported``): there is no
    ancestor walk or shared ancestor budget, so a child never reaches the destination through the workflow. The addendum's
    three-children case therefore arises only with independently issued grants (the test above)."""
    p = proposal()
    r = resolver_for(p, delegated=True)
    decision = workflow(tmp_path, p, resolver=r).decide(p, now=NOW)
    assert decision.result == "hold"
    assert "delegation_profile_unsupported" in decision.reasons


# ---------------------------------------------------------------- (b) decision age is not consulted

def _refresh_observations(r, at):
    """The authority sources answer again at ``at`` (every status carries a fresh observed_at)."""
    stamp = at.isoformat()
    for table in (r.statuses, r.identities, r.mandates, r.approvals, r.policies, r.conflicts, r.evidence):
        for item in table.values():
            item.observed_at = stamp
    for mapping in r.role_mappings.values():
        if hasattr(mapping, "observed_at"):
            mapping.observed_at = stamp


def test_week_old_authorized_decision_still_executes_when_inputs_match_known_limit(tmp_path, monkeypatch):
    """``decided_at`` is not consulted at effect time: a decision seven days old executes if the inputs read now still match."""
    p = proposal()
    r = resolver_for(p)
    r.contexts[PROFILE]["grant"]["expires_at"] = (NOW + timedelta(days=8)).isoformat()
    flow = workflow(tmp_path, p, resolver=r)
    decision = flow.decide(p, now=NOW)
    assert decision.result == "authorized", decision.reasons

    later = NOW + timedelta(days=7)
    monkeypatch.setattr(bounded, "_now", lambda: later)
    _refresh_observations(r, later)
    attempt, observation = flow.execute(p, decision, adapter_id=p.adapter_id, now=later)
    assert attempt.status == "acknowledged" and observation.state == "applied"
    assert decision.decided_at == NOW.isoformat()  # still the old decision
    assert (later - bounded._parse(decision.decided_at)) == timedelta(days=7)


# ---------------------------------------------------------------- (c) operation id replay vs different payload

def test_same_operation_id_with_a_different_payload_gets_the_replay_refusal_known_limit(tmp_path):
    """The destination keys operation dedupe on the operation id alone. A request with a new effect_id for the same operation
    gets ``operation_already_committed`` whether its payload is identical (a replay) or different (a different request)."""
    destination = LocalRefundDestination(tmp_path / "d.json")
    args = dict(grant_id="g", max_effects=5, **DESTINATION_ARGS)
    destination.apply(effect_id="e1", operation_id="op-1", **args)

    with pytest.raises(DefinitiveDestinationRejection) as replay:
        destination.apply(effect_id="e2", operation_id="op-1", **args)
    different = {**args, "payload": {"customer_id": "someone-else"}, "amount": 99.0, "target": "other"}
    with pytest.raises(DefinitiveDestinationRejection) as changed:
        destination.apply(effect_id="e3", operation_id="op-1", **different)

    assert str(replay.value) == str(changed.value) == "operation_already_committed"
    assert set(destination.snapshot()["effects"]) == {"e1"}


# ---------------------------------------------------------------- (d) a hold keeps no lifecycle and no link

def test_a_hold_has_no_binding_and_a_later_decision_carries_no_link_to_it_known_limit(tmp_path):
    """Default path (no opt-in profile). A held decision is a persisted row with its resolution inputs and reasons, but no
    binding; there is no hold lifecycle (no cause, lapse, lineage or recovery member), and the later decision for the same
    proposal is a separate row that names neither the hold's decision_id nor anything derived from it."""
    p = proposal()
    r = resolver_for(p)
    approvals = dict(r.approvals)
    r.approvals.clear()
    flow = workflow(tmp_path, p, resolver=r)
    held = flow.decide(p, now=NOW)
    assert held.result == "hold" and "required_approval_missing" in held.reasons
    assert held.binding is None
    assert held.resolution_inputs  # the read inputs are retained on the default path
    assert not any(member in held.model_dump(mode="json") for member in ("hold_id", "lapse", "lineage", "cause", "recovery"))

    r.approvals.update(approvals)
    later = flow.decide(p, now=NOW)
    assert later.result == "authorized" and later.decision_id != held.decision_id
    assert held.decision_id not in json.dumps(later.model_dump(mode="json"))

    document = json.loads(flow.records.path.read_text(encoding="utf-8"))
    assert [d["result"] for d in document["decisions"]] == ["hold", "authorized"]
    assert not any(key in document for key in ("holds", "hold_events", "lineage"))
