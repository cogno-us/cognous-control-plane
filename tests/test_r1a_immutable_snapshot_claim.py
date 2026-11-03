"""R1-A (csf_da0ba5306958df9dd957f0a4): the local-authority-effect claim derives entirely from a private snapshot of the proposal.

Before, only `_resolve` used the private copy; handoff ref, snapshot validation, validity interval, operation commitment and the claim
fields were read from the caller's live proposal, so a mutation during a host callback (resolver snapshot read, provisioning sink)
changed the claim without changing what was authorized.
"""
from __future__ import annotations

import pytest

from agent_control_plane.bounded import commitment
from agent_control_plane.local_authority_effect import (
    _operation_payload,
    materialize_local_execution_claim,
    provision_local_execution_claim,
    verify_local_execution_claim,
)
from tests.test_local_authority_effect_profile import NOW, PROFILE, setup


def _scribble(p):
    p.amount = 99.0
    p.target = "acct:EVIL"
    p.payload["reason"] = "tampered"
    p.payload_commitment = "sha256:" + "0" * 64
    p.effects = 7
    p.unit = "EUR"
    p.actor = "urn:attacker"
    p.not_before = "2000-01-01T00:00:00+00:00"
    p.expires_at = "2001-01-01T00:00:00+00:00"
    p.requested_permissions.append("admin.everything")


def _expected(snapshot, decision, claim):
    inst = claim.institution_id, claim.authority_domain
    return commitment(_operation_payload(snapshot, decision, institution_id=inst[0], authority_domain=inst[1]))


def _assert_claim_matches_snapshot(claim, snapshot, decision):
    assert claim.target == snapshot.target
    assert claim.amount == snapshot.amount
    assert claim.unit == snapshot.unit
    assert claim.effects == snapshot.effects
    assert claim.actor == snapshot.actor
    assert claim.payload_commitment == snapshot.payload_commitment
    assert claim.requested_permissions == snapshot.requested_permissions
    assert claim.operation_commitment == _expected(snapshot, decision, claim)
    assert claim.grant_id == decision.binding.grant_id
    assert claim.requirement_commitment == decision.binding.requirement_commitment
    assert claim.approval_state and claim.policy_state and claim.evidence_state
    assert claim.not_before and claim.expires_at and claim.not_before < claim.expires_at
    assert claim.expires_at.startswith("2026-10-07T16:00:00")  # grant expiry, not the attacker's 2001 value
    assert verify_local_execution_claim(claim) is True


def _hook_resolver(resolver, fn):
    orig = type(resolver).authority_effect_snapshot

    def snap(self, ref):
        fn()
        return orig(self, ref)

    resolver.authority_effect_snapshot = snap.__get__(resolver)


def test_materialize_claim_unaffected_by_mutation_during_handoff_callback(tmp_path):  # tests 10, 11
    proposal, resolver, flow, decision = setup(tmp_path)
    snapshot = proposal.model_copy(deep=True)
    _hook_resolver(resolver, lambda: _scribble(proposal))
    claim = materialize_local_execution_claim(flow, proposal, decision, now=NOW, claim_id="c")
    assert proposal.target == "acct:EVIL"  # the caller's object really was mutated
    _assert_claim_matches_snapshot(claim, snapshot, decision)


def test_provisioned_claim_unaffected_by_mutation_in_the_sink(tmp_path):  # tests 10, 11
    proposal, resolver, flow, decision = setup(tmp_path)
    snapshot = proposal.model_copy(deep=True)
    seen = {}

    def sink(claim):
        _scribble(proposal)  # mutation after the claim was built, inside the handoff
        seen["claim"] = claim

    claim = provision_local_execution_claim(flow, proposal, decision, now=NOW, provision=sink, claim_id="c")
    assert seen["claim"] == claim
    _assert_claim_matches_snapshot(claim, snapshot, decision)


def test_mutation_of_the_authority_context_ref_during_callback_cannot_redirect_the_snapshot_read(tmp_path):
    proposal, resolver, flow, decision = setup(tmp_path)
    snapshot = proposal.model_copy(deep=True)
    refs = []
    orig = type(resolver).authority_effect_snapshot

    def snap(self, ref):
        refs.append(ref)
        proposal.authority_context_ref = "urn:attacker:context"
        return orig(self, ref)

    resolver.authority_effect_snapshot = snap.__get__(resolver)
    claim = materialize_local_execution_claim(flow, proposal, decision, now=NOW)
    assert refs == [PROFILE]
    _assert_claim_matches_snapshot(claim, snapshot, decision)


def test_decision_mutation_during_callback_cannot_change_the_claim(tmp_path):
    proposal, resolver, flow, decision = setup(tmp_path)
    expected_effect = decision.effect_id
    _hook_resolver(resolver, lambda: setattr(decision, "effect_id", "effect:attacker"))
    claim = materialize_local_execution_claim(flow, proposal, decision, now=NOW)
    assert claim.effect_id == expected_effect
