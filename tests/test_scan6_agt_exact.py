"""Microsoft AGT adapter: exact tenant and decision strings, and a transform needs a bound authorization (scan 6, CP-3 and CP-4).

Before, the adapter trimmed the tenant and trimmed and lower-cased the AGT decision before comparing, and it authorized a transformed
proposal when the Cognous decision carried `binding: None`.
"""
from __future__ import annotations

from dataclasses import dataclass

import pytest

from agent_control_plane.bounded import AuthorizationBinding, RuntimeDecision, commitment
from agent_control_plane.microsoft_agt import AgtDecision, MicrosoftAgtPreToolCallAdapter
from tests.test_microsoft_agt import FakeAuthority, FakeBackend, proposal

CHANGED = {"customer_id": "customer-001", "refund_reason": "policy-normalized"}


def _transform():
    return AgtDecision(decision="transform", transformed_policy_target=CHANGED, transformed_policy_target_applied=True)


@dataclass
class BoundAuthority:
    binding: object = None
    bind_evaluated: bool = False  # bind the proposal the adapter passed in, as the real gate does

    def __post_init__(self):
        self.calls = []

    def authorize(self, *, proposal, tenant_id, now=None):
        self.calls.append((proposal, tenant_id))
        binding = _binding(proposal) if self.bind_evaluated else self.binding
        return RuntimeDecision(decision_id="d", effect_id="e", result="authorized", reasons=[],
                               decided_at="2026-10-08T17:00:00+00:00", binding=binding)


def _binding(proposal=None):
    """A binding for the proposal the authority evaluated; without one, the legacy presence-only stand-in (wave 7: no longer accepted)."""
    if proposal is None:
        return AuthorizationBinding.model_construct(proposal_commitment="sha256:x")
    return AuthorizationBinding.model_construct(
        proposal_commitment=commitment(proposal.model_dump(mode="json", exclude_none=False)),
        payload_commitment=proposal.payload_commitment)


@pytest.mark.asyncio
async def test_a_transform_without_a_binding_is_not_authorized():
    authority = BoundAuthority(binding=None)
    adapter = MicrosoftAgtPreToolCallAdapter(backend=FakeBackend(_transform()), authority=authority)
    result = await adapter.evaluate(tenant_id="tenant-alpha", proposal=proposal(), tool_name="refund_adapter")
    assert result.result == "hold" and result.reasons == ("transform_authorization_unbound",)
    assert result.evidence.transformed is True


@pytest.mark.asyncio
async def test_a_transform_with_a_binding_is_authorized():
    adapter = MicrosoftAgtPreToolCallAdapter(backend=FakeBackend(_transform()), authority=BoundAuthority(bind_evaluated=True))
    result = await adapter.evaluate(tenant_id="tenant-alpha", proposal=proposal(), tool_name="refund_adapter")
    assert result.result == "authorized"


@pytest.mark.asyncio
async def test_an_allow_is_unchanged_by_the_binding_rule():
    adapter = MicrosoftAgtPreToolCallAdapter(backend=FakeBackend(AgtDecision(decision="allow")), authority=FakeAuthority("authorized"))
    result = await adapter.evaluate(tenant_id="tenant-alpha", proposal=proposal(), tool_name="refund_adapter")
    assert result.result == "authorized"


@pytest.mark.asyncio
@pytest.mark.parametrize("decision", ["ALLOW", "Allow", " allow", "allow ", "TRANSFORM", "Deny"])
async def test_an_inexact_decision_string_is_unsupported_and_never_authorizes(decision):
    backend = FakeBackend(AgtDecision(decision=decision, transformed_policy_target=CHANGED, transformed_policy_target_applied=True))
    authority = FakeAuthority("authorized")
    adapter = MicrosoftAgtPreToolCallAdapter(backend=backend, authority=authority)
    result = await adapter.evaluate(tenant_id="tenant-alpha", proposal=proposal(), tool_name="refund_adapter")
    assert result.result == "hold" and result.reasons == ("unsupported_agt_decision",)
    assert authority.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("tenant_id", [" tenant-alpha", "tenant-alpha ", "\ttenant-alpha\n"])
async def test_a_padded_tenant_is_passed_exactly_and_never_trimmed(tenant_id):
    backend = FakeBackend(AgtDecision(decision="allow"))
    authority = FakeAuthority("authorized")
    adapter = MicrosoftAgtPreToolCallAdapter(backend=backend, authority=authority)
    result = await adapter.evaluate(tenant_id=tenant_id, proposal=proposal(), tool_name="refund_adapter")
    assert result.evidence.tenant_id == tenant_id
    assert backend.calls[0]["tenant_id"] == tenant_id and authority.calls[0][1] == tenant_id


@pytest.mark.asyncio
async def test_a_padded_tenant_does_not_match_a_tenant_bearing_proposal():
    from agent_control_plane.bounded import TenantRuntimeProposal
    tenant_proposal = TenantRuntimeProposal(**proposal().model_dump(), tenant_id="tenant-alpha")
    backend, authority = FakeBackend(AgtDecision(decision="allow")), FakeAuthority("authorized")
    adapter = MicrosoftAgtPreToolCallAdapter(backend=backend, authority=authority)
    result = await adapter.evaluate(tenant_id="tenant-alpha ", proposal=tenant_proposal, tool_name="refund_adapter")
    assert result.result == "hold" and result.reasons == ("tenant_mismatch",)
    assert backend.calls == [] and authority.calls == []


@pytest.mark.asyncio
@pytest.mark.parametrize("tenant_id", ["", "   ", None])
async def test_a_blank_tenant_is_still_missing(tenant_id):
    adapter = MicrosoftAgtPreToolCallAdapter(backend=FakeBackend(AgtDecision(decision="allow")), authority=FakeAuthority("authorized"))
    result = await adapter.evaluate(tenant_id=tenant_id, proposal=proposal(), tool_name="refund_adapter")
    assert result.result == "hold" and result.reasons == ("tenant_missing",)
