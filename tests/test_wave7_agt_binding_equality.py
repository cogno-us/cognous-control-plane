"""A transformed proposal is authorized only by a binding that fixes the transformed commitments (fix wave 7, T2-C).

Before, the adapter checked only that the binding was present, so a stale binding (for the pre-transform proposal) or a foreign one
authorized the transformed proposal. A mismatch holds with the existing reason `transform_authorization_unbound`; no code is added.
"""
from __future__ import annotations

import pytest

from agent_control_plane.bounded import AuthorizationBinding, commitment
from agent_control_plane.microsoft_agt import AgtDecision, MicrosoftAgtPreToolCallAdapter
from tests.test_microsoft_agt import FakeBackend, proposal
from tests.test_scan6_agt_exact import BoundAuthority, _transform, _binding



async def _run(authority):
    adapter = MicrosoftAgtPreToolCallAdapter(backend=FakeBackend(_transform()), authority=authority)
    return await adapter.evaluate(tenant_id="tenant-alpha", proposal=proposal(), tool_name="refund_adapter")


@pytest.mark.asyncio
async def test_a_binding_for_the_pre_transform_proposal_is_held():
    original = proposal()
    stale = _binding(original)
    result = await _run(BoundAuthority(binding=stale))
    assert result.result == "hold" and result.reasons == ("transform_authorization_unbound",)
    assert result.evidence.transformed is True


@pytest.mark.asyncio
@pytest.mark.parametrize("field", ["proposal_commitment", "payload_commitment"])
async def test_a_foreign_commitment_in_the_binding_is_held(field):
    class Foreign(BoundAuthority):
        def authorize(self, *, proposal, tenant_id, now=None):
            self.binding = _binding(proposal)
            setattr(self.binding, field, "sha256:" + "0" * 64)
            return super().authorize(proposal=proposal, tenant_id=tenant_id, now=now)
    result = await _run(Foreign())
    assert result.result == "hold" and result.reasons == ("transform_authorization_unbound",)


@pytest.mark.asyncio
async def test_a_binding_without_a_payload_commitment_is_held():
    class NoPayload(BoundAuthority):
        def authorize(self, *, proposal, tenant_id, now=None):
            self.binding = AuthorizationBinding.model_construct(
                proposal_commitment=commitment(proposal.model_dump(mode="json", exclude_none=False)))
            return super().authorize(proposal=proposal, tenant_id=tenant_id, now=now)
    result = await _run(NoPayload())
    assert result.result == "hold" and result.reasons == ("transform_authorization_unbound",)


@pytest.mark.asyncio
async def test_a_binding_for_the_transformed_proposal_is_authorized():
    authority = BoundAuthority(bind_evaluated=True)
    result = await _run(authority)
    assert result.result == "authorized"
    assert authority.calls[0][0].payload != proposal().payload


def test_the_reason_registry_did_not_grow():
    import json
    from pathlib import Path
    root = Path(__file__).resolve().parents[1] / "schemas"
    assert len(json.loads((root / "runtime_authority_reasons_0_2.json").read_text())["codes"]) == 164
