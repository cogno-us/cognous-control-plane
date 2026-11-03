"""R1-A (csf_c7e3b3a6ffe782a80a860b30): the AGT adapter evaluates one private snapshot of the proposal.

Before, the caller's proposal (and its nested payload, by reference) was read again after the awaited AGT backend call, so mutation
during the await let AGT approve one state while Cognous authorized and returned another.
"""
from __future__ import annotations

import asyncio
import copy

import pytest

from agent_control_plane.bounded import AuthorizationBinding, RuntimeDecision, commitment
from agent_control_plane.microsoft_agt import AgtDecision, MicrosoftAgtPreToolCallAdapter
from tests.test_microsoft_agt import FakeAuthority, proposal


def _pc(p):
    return commitment(p.model_dump(mode="json", exclude_none=False))


class MutatingBackend:
    """Records what it was handed, then mutates the caller-owned proposal while the adapter is suspended in the await."""

    def __init__(self, caller, mutate, decision=None):
        self.caller, self.mutate = caller, mutate
        self.decision = decision or AgtDecision(decision="allow")
        self.seen_payload_commitment = None
        self.seen_arguments = None

    async def evaluate_pre_tool_call(self, *, tenant_id, tool_name, arguments, tool_call_id, snapshot):
        self.seen_arguments = copy.deepcopy(arguments)
        self.seen_payload_commitment = commitment(arguments)
        await asyncio.sleep(0)
        self.mutate(self.caller)
        return self.decision


class RecordingAuthority(FakeAuthority):
    def authorize(self, *, proposal, tenant_id, now=None):
        self.seen_commitment = _pc(proposal)
        return super().authorize(proposal=proposal, tenant_id=tenant_id, now=now)


def _mut_amount(p): p.amount = 99999
def _mut_target(p): p.target = "urn:attacker:target"
def _mut_nested(p): p.payload["customer_id"] = "c-ATTACKER"; p.payload["extra"] = {"x": 1}
def _mut_commit(p): p.payload_commitment = "sha256:" + "0" * 64


@pytest.mark.asyncio
@pytest.mark.parametrize("mutate", [_mut_amount, _mut_target, _mut_nested, _mut_commit],
                         ids=["amount", "target", "nested_payload", "payload_commitment"])
async def test_mutation_during_awaited_backend_call_cannot_change_what_is_evaluated(mutate):  # tests 1-4, 6, 7
    caller = proposal()
    original = caller.model_copy(deep=True)
    original_commitment = _pc(original)
    backend = MutatingBackend(caller, mutate)
    authority = RecordingAuthority("authorized")
    result = await MicrosoftAgtPreToolCallAdapter(backend=backend, authority=authority).evaluate(
        tenant_id="tenant-alpha", proposal=caller, tool_name="urn:cognous:adapter:synthetic-refund-v1")

    assert _pc(caller) != original_commitment  # the mutation really happened on the caller's object
    # AGT and Cognous evaluated the same original snapshot.
    assert backend.seen_arguments == original.payload
    assert backend.seen_payload_commitment == original.payload_commitment
    assert authority.seen_commitment == original_commitment
    assert result.evidence.original_proposal_commitment == original_commitment
    assert result.evidence.effective_proposal_commitment == original_commitment
    # The decision and the returned proposal are those of the snapshot, not of the mutated caller object.
    assert result.result == "authorized"
    assert result.proposal == original
    assert result.cognous_decision.binding.proposal_commitment == original_commitment


@pytest.mark.asyncio
async def test_caller_mutation_after_success_does_not_change_returned_proposal():  # tests 5, 7
    caller = proposal()
    original = caller.model_copy(deep=True)
    result = await MicrosoftAgtPreToolCallAdapter(
        backend=MutatingBackend(caller, lambda p: None), authority=FakeAuthority("authorized")
    ).evaluate(tenant_id="tenant-alpha", proposal=caller, tool_name="urn:cognous:adapter:synthetic-refund-v1")
    assert result.result == "authorized"
    caller.amount = 12345
    caller.target = "urn:attacker:target"
    caller.payload["customer_id"] = "c-ATTACKER"
    caller.payload_commitment = "sha256:" + "1" * 64
    assert result.proposal == original
    assert commitment(result.proposal.payload) == result.proposal.payload_commitment


@pytest.mark.asyncio
async def test_backend_and_authority_cannot_alias_the_snapshot_or_the_returned_proposal():
    caller = proposal()
    original = caller.model_copy(deep=True)

    class Scribbling(MutatingBackend):
        async def evaluate_pre_tool_call(self, *, arguments, **kw):
            arguments["customer_id"] = "scribbled-by-backend"
            return AgtDecision(decision="allow")

    class ScribblingAuthority(FakeAuthority):
        def authorize(self, *, proposal, tenant_id, now=None):
            decision = super().authorize(proposal=proposal, tenant_id=tenant_id, now=now)
            proposal.payload["customer_id"] = "scribbled-by-authority"
            return decision

    result = await MicrosoftAgtPreToolCallAdapter(
        backend=Scribbling(caller, lambda p: None), authority=ScribblingAuthority("authorized")
    ).evaluate(tenant_id="tenant-alpha", proposal=caller, tool_name="urn:cognous:adapter:synthetic-refund-v1")
    assert result.proposal == original
    assert caller == original  # the caller's own object is untouched by the backend


@pytest.mark.asyncio
async def test_an_authorization_whose_binding_does_not_fix_the_snapshot_is_held_on_the_allow_path():
    class UnboundAuthority(FakeAuthority):
        def authorize(self, *, proposal, tenant_id, now=None):
            return RuntimeDecision(decision_id="d", effect_id="e", result="authorized", reasons=[], decided_at="2026-10-08T17:00:00+00:00",
                                   binding=AuthorizationBinding.model_construct(proposal_commitment="sha256:" + "f" * 64,
                                                                                payload_commitment=proposal.payload_commitment))

    result = await MicrosoftAgtPreToolCallAdapter(backend=MutatingBackend(proposal(), lambda p: None), authority=UnboundAuthority()).evaluate(
        tenant_id="tenant-alpha", proposal=proposal(), tool_name="urn:cognous:adapter:synthetic-refund-v1")
    assert result.result == "hold" and result.reasons == ("authorization_unbound",)


@pytest.mark.asyncio
async def test_transform_is_still_applied_to_the_snapshot_not_the_mutated_caller():
    caller = proposal()
    original = caller.model_copy(deep=True)
    changed = {"customer_id": "customer-001", "refund_reason": "policy-normalized"}
    backend = MutatingBackend(caller, _mut_amount, AgtDecision(decision="transform", transformed_policy_target=changed,
                                                               transformed_policy_target_applied=True))
    result = await MicrosoftAgtPreToolCallAdapter(backend=backend, authority=FakeAuthority("authorized")).evaluate(
        tenant_id="tenant-alpha", proposal=caller, tool_name="urn:cognous:adapter:synthetic-refund-v1")
    assert result.result == "authorized" and result.evidence.transformed is True
    assert result.proposal.amount == original.amount and result.proposal.payload == changed
