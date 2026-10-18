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


# ---------------------------------------------------------------- (e) manifest action without an authority_context

def test_action_without_authority_context_does_not_pin_the_context_ref_known_limit(tmp_path):
    """The ``authority_context_ref`` pin (``authority_profile_mismatch``) is compared only when the manifest action declares an
    ``authority_context``. For an action without one the proposal's ref is not compared to anything declared. The decision still
    holds, because the institution, domain and tier comparisons against an empty declaration refuse, and a ref the host does not
    hold is unresolvable. A later change (pin the ref unconditionally) must be deliberate; the freeze list tracks it."""
    import tempfile
    from pathlib import Path
    from agent_control_plane.bounded import (BoundedAuthorizationWorkflow, BoundedRecordStore, ObservationPolicy)
    from tests.test_bounded_authorization import manifest

    def decide(*, declared, ref):
        p = proposal()
        r = resolver_for(p)
        if ref != PROFILE:
            r.contexts[ref] = r.contexts[PROFILE]  # the host also holds a context under the other name
        m = manifest()
        if not declared:
            for action in m["actions"]:
                action.pop("authority_context", None)
        p = p.model_copy(update={"authority_context_ref": ref})
        root = Path(tempfile.mkdtemp(dir=tmp_path))
        flow = BoundedAuthorizationWorkflow(
            allow_test_time=True, manifest=m, resolver=r, destination=LocalRefundDestination(root / "d.json"),
            records=BoundedRecordStore(root / "r.json", "run-1"), observation_policy=ObservationPolicy(max_age_seconds=300, clock_tolerance_seconds=5))
        return flow.decide(p, now=NOW)

    # control: with the declaration the ref is pinned
    assert "authority_profile_mismatch" in decide(declared=True, ref="urn:other").reasons
    # without the declaration the pin is not applied, and the decision does not authorize
    undeclared = decide(declared=False, ref="urn:other")
    assert "authority_profile_mismatch" not in undeclared.reasons
    assert undeclared.result == "hold"
    assert {"institution_mismatch", "authority_domain_mismatch", "consequence_tier_mismatch"} <= set(undeclared.reasons)
    # valid producer control: the declared action with the matching ref authorizes
    assert decide(declared=True, ref=PROFILE).result == "authorized"


# ---------------------------------------------------------------- (f) operation-identity ledger has no retention rule

def test_removed_operation_rows_let_a_revision_2_decision_authorize_but_the_destination_refuses_known_limit(tmp_path, monkeypatch):
    """The operation-identity ledger has no retention rule. With its ``operations`` rows removed from the run record, a
    revision-2 decision whose renewal is unrecorded gives ``authorized`` (the id is admitted again as a first admission) where
    the intact ledger gives ``hold`` / ``operation_renewal_unrecorded``. The destination still refuses the second effect
    (``operation_already_committed``). A retention rule is a freeze item; the record-level check of the independent verifier
    rejects the pruned record."""
    from tests.test_operation_identity import OPERATION, enable, renew, two_effects, two_effects_manifest
    from tests.test_runtime_authority import setup_flow

    two_effects_manifest(monkeypatch)
    p, r, f, c = setup_flow(tmp_path)
    two_effects(r)
    cfg = enable(r, f, c)
    d1 = f.decide(p, now=NOW)
    assert d1.result == "authorized", d1.reasons
    attempt, observation = f.execute(p, d1, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and observation.state == "applied"

    renew(r, cfg, "2")
    intact = f.decide(p, now=NOW)  # control: the ledger is intact, the renewal is unrecorded
    assert intact.result == "hold" and "operation_renewal_unrecorded" in intact.reasons

    document = json.loads(f.records.path.read_text(encoding="utf-8"))
    assert document["operations"], "the ledger rows exist before removal"
    document["operations"] = []
    f.records.path.write_text(json.dumps(document), encoding="utf-8")

    pruned = f.decide(p, now=NOW)
    assert pruned.result == "authorized" and pruned.reasons == []
    attempt2, _ = f.execute(p, pruned, adapter_id=p.adapter_id, now=NOW)
    assert attempt2.status == "failed" and attempt2.error == "operation_already_committed"
    state = f.destination.snapshot()
    assert set(state["effects"]) == {d1.effect_id} and state["operations"] == {OPERATION: d1.effect_id}


# ---------------------------------------------------------------- (g) provisioned claim and identity / mandate status

class _ClaimOnlyStore:
    """Stands in for a participating local store that validates only the provisioned claim (as the profile document describes)
    and consumes it once. It re-reads no resolver input, so it sees exactly the state the claim carries."""

    def __init__(self):
        self.claims = {}
        self.consumed = []

    def provision(self, claim):
        self.claims[claim.claim_id] = claim

    def consume(self, claim_id, *, now):
        from agent_control_plane.local_authority_effect import verify_local_execution_claim
        claim = self.claims[claim_id]
        assert verify_local_execution_claim(claim)
        assert bounded._parse(claim.not_before) <= now < bounded._parse(claim.expires_at)
        assert claim_id not in self.consumed and len(self.consumed) < claim.max_effects
        self.consumed.append(claim_id)
        return claim.effect_id


@pytest.mark.parametrize(
    ("table", "key", "field"),
    [("identities", None, "authenticated"), ("mandates", "issuer:1|role:issuer", "mandate_valid")],
)
def test_claim_consumption_does_not_see_identity_or_mandate_status_change_known_limit(tmp_path, monkeypatch, table, key, field):
    """Profile ``local-authority-effect``: the claim projects grant, approval, policy and evidence state. Identity
    authentication and mandate validity are read at issuance only. With a valid provisioned claim and only that one status
    changed to false (grant, approval, policy and evidence unchanged), a store that validates the claim alone still consumes it.
    Controls: issuing a new claim and the default ``execute`` path both re-read the status and refuse. This matches the
    boundary stated in docs/local-authority-effect-profile.md. A later change (more dependencies in the claim, or refusing such
    provisioning) must be deliberate and rewrites this test."""
    from tests import test_local_authority_effect_profile as profile
    from agent_control_plane.local_authority_effect import (
        materialize_local_execution_claim, provision_local_execution_claim, verify_local_execution_claim)

    monkeypatch.setattr(bounded, "_now", lambda: profile.NOW)
    p, resolver, flow, decision = profile.setup(tmp_path)
    store = _ClaimOnlyStore()
    claim = provision_local_execution_claim(flow, p, decision, now=profile.NOW, provision=store.provision, claim_id="c1")
    assert verify_local_execution_claim(claim)

    registry = getattr(resolver, table)
    name = key or profile.ACTOR
    registry[name] = registry[name].model_copy(update={field: False})
    assert getattr(registry[name], field) is False

    # the claim has no member for either status
    assert not any(member in claim.model_dump(mode="json") for member in ("identity", "authenticated", "mandate", "mandate_valid"))
    assert verify_local_execution_claim(claim)
    # known limit: the claim-only store still consumes the claim
    assert store.consume("c1", now=profile.NOW) == decision.effect_id
    # controls: issuance and the default execute path both re-read the status and refuse
    with pytest.raises(PermissionError, match="authorization-critical inputs changed before claim issuance"):
        materialize_local_execution_claim(flow, p, decision, now=profile.NOW)
    with pytest.raises(PermissionError, match="authorization-critical inputs changed before effect"):
        flow.execute(p, decision, adapter_id=p.adapter_id, now=profile.NOW)


def test_claim_consumption_with_unchanged_status_is_the_valid_producer_control(tmp_path, monkeypatch):
    """Control for the test above: with nothing changed the same store consumes the claim and the default path executes."""
    from tests import test_local_authority_effect_profile as profile
    from agent_control_plane.local_authority_effect import provision_local_execution_claim

    monkeypatch.setattr(bounded, "_now", lambda: profile.NOW)
    p, resolver, flow, decision = profile.setup(tmp_path)
    store = _ClaimOnlyStore()
    provision_local_execution_claim(flow, p, decision, now=profile.NOW, provision=store.provision, claim_id="c1")
    assert store.consume("c1", now=profile.NOW) == decision.effect_id
    attempt, observation = flow.execute(p, decision, adapter_id=p.adapter_id, now=profile.NOW)
    assert attempt.status == "acknowledged" and observation.state == "applied"
