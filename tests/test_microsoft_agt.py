from __future__ import annotations

from dataclasses import dataclass

import pytest

from agent_control_plane.bounded import AuthorizationBinding, RuntimeDecision, RuntimeProposal, commitment
from agent_control_plane.microsoft_agt import (
    AgtDecision,
    MicrosoftAgtCompatibilityResult,
    MicrosoftAgtPreToolCallAdapter,
    MicrosoftAgtSdkBackend,
    MicrosoftAgtUnavailable,
)


def proposal(payload=None):
    payload = payload or {"customer_id": "customer-001", "refund_reason": "duplicate"}
    return RuntimeProposal(
        manifest_id="refund-integration-pilot-v1",
        manifest_version="1.1",
        manifest_digest="sha256:manifest",
        actor="urn:cognous:actor:test",
        principal="urn:cognous:principal:test",
        action_id="urn:cognous:action:refund-issue-routine-v1",
        adapter_id="urn:cognous:adapter:synthetic-refund-v1",
        target="urn:cognous:synthetic-account:customer-001",
        payload=payload,
        payload_commitment=commitment(payload),
        requested_permissions=["refund.issue.routine"],
        amount=50,
        unit="USD",
        effects=1,
        authority_context_ref="urn:cognous:alvorada:public-stack-profile:0.1.0",
        requirement_id="urn:cognous:authority-requirement:refund-routine-v1",
        run_id="run-w5",
    )


class FakeBackend:
    def __init__(self, decision):
        self.decision = decision
        self.calls = []

    async def evaluate_pre_tool_call(self, **kwargs):
        self.calls.append(kwargs)
        if isinstance(self.decision, Exception):
            raise self.decision
        return self.decision


@dataclass
class FakeAuthority:
    result: str = "authorized"

    def __post_init__(self):
        self.calls = []

    def authorize(self, *, proposal, tenant_id, now=None):
        self.calls.append((proposal.model_copy(deep=True), tenant_id))
        return RuntimeDecision(
            decision_id=f"decision-{len(self.calls)}",
            effect_id=f"effect-{len(self.calls)}",
            result=self.result,
            reasons=[] if self.result == "authorized" else ["authority_not_current"],
            decided_at="2026-10-08T17:00:00+00:00",
            # An authorized decision carries its binding (scan 6, CP-4: a transform without one is held); a refusal carries none.
            binding=AuthorizationBinding.model_construct(proposal_commitment="sha256:fake") if self.result == "authorized" else None,
        )


@pytest.mark.asyncio
async def test_allow_is_only_additional_restriction_and_requires_cognous_authority():
    backend = FakeBackend(AgtDecision(decision="allow", input_identity="agt-in", enforced_identity="agt-in"))
    authority = FakeAuthority("authorized")
    adapter = MicrosoftAgtPreToolCallAdapter(backend=backend, authority=authority)

    result = await adapter.evaluate(
        tenant_id="tenant-alpha",
        proposal=proposal(),
        tool_name="refund_adapter",
        tool_call_id="call-1",
    )

    assert result.result == "authorized"
    assert authority.calls[0][1] == "tenant-alpha"
    assert result.evidence.agt_decision == "allow"
    assert result.evidence.cognous_result == "authorized"
    assert "not Cognous authority" in result.evidence.limitation


@pytest.mark.asyncio
async def test_agt_allow_cannot_override_cognous_deny():
    backend = FakeBackend(AgtDecision(decision="allow"))
    authority = FakeAuthority("deny")
    adapter = MicrosoftAgtPreToolCallAdapter(backend=backend, authority=authority)

    result = await adapter.evaluate(
        tenant_id="tenant-alpha",
        proposal=proposal(),
        tool_name="refund_adapter",
    )

    assert result.result == "deny"
    assert result.reasons == ("authority_not_current",)


@pytest.mark.asyncio
async def test_transform_gets_fresh_authorization_for_new_commitment():
    changed = {"customer_id": "customer-001", "refund_reason": "policy-normalized"}
    backend = FakeBackend(
        AgtDecision(
            decision="transform",
            transformed_policy_target=changed,
            transformed_policy_target_applied=True,
            input_identity="agt-before",
            enforced_identity="agt-after",
        )
    )
    authority = FakeAuthority("authorized")
    adapter = MicrosoftAgtPreToolCallAdapter(backend=backend, authority=authority)
    original = proposal()

    result = await adapter.evaluate(
        tenant_id="tenant-alpha",
        proposal=original,
        tool_name="refund_adapter",
    )

    assert result.result == "authorized"
    assert len(authority.calls) == 1
    authorized_proposal, tenant = authority.calls[0]
    assert tenant == "tenant-alpha"
    assert authorized_proposal.payload == changed
    assert authorized_proposal.payload_commitment == commitment(changed)
    assert result.evidence.transformed is True
    assert result.evidence.original_proposal_commitment != result.evidence.effective_proposal_commitment


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("agt", "expected"),
    [
        (AgtDecision(decision="deny"), "deny"),
        (AgtDecision(decision="escalate"), "hold"),
        (AgtDecision(decision="warn"), "hold"),
        (AgtDecision(decision="allow", warnings=({"reason": "review"},)), "hold"),
        (AgtDecision(decision="unknown"), "hold"),
        (AgtDecision(decision="transform", transformed_policy_target="not-an-object", transformed_policy_target_applied=True), "hold"),
    ],
)
async def test_nonclean_or_unsupported_agt_results_never_authorize(agt, expected):
    authority = FakeAuthority("authorized")
    adapter = MicrosoftAgtPreToolCallAdapter(backend=FakeBackend(agt), authority=authority)
    result = await adapter.evaluate(
        tenant_id="tenant-alpha",
        proposal=proposal(),
        tool_name="refund_adapter",
    )
    assert result.result == expected
    assert authority.calls == []


@pytest.mark.asyncio
async def test_missing_tenant_and_backend_failure_fail_closed():
    authority = FakeAuthority("authorized")
    adapter = MicrosoftAgtPreToolCallAdapter(
        backend=FakeBackend(AgtDecision(decision="allow")),
        authority=authority,
    )
    missing = await adapter.evaluate(
        tenant_id=" ",
        proposal=proposal(),
        tool_name="refund_adapter",
    )
    assert missing.result == "hold"
    assert missing.reasons == ("tenant_missing",)

    failing = MicrosoftAgtPreToolCallAdapter(
        backend=FakeBackend(MicrosoftAgtUnavailable("offline")),
        authority=authority,
    )
    unavailable = await failing.evaluate(
        tenant_id="tenant-alpha",
        proposal=proposal(),
        tool_name="refund_adapter",
    )
    assert unavailable.result == "hold"
    assert unavailable.reasons == ("capability_unavailable",)
    assert authority.calls == []


@pytest.mark.asyncio
async def test_real_sdk_types_are_supported_when_installed():
    acs = pytest.importorskip("agent_control_specification")

    class Runtime:
        def __init__(self):
            self.request = None

        async def evaluate_intervention_point(self, request):
            self.request = request
            return acs.InterventionPointResult(
                verdict=acs.Verdict(decision=acs.Decision.ALLOW, reason="fixture_allow"),
                input_identity="sdk-input",
                enforced_identity="sdk-input",
            )

    runtime = Runtime()
    backend = MicrosoftAgtSdkBackend(runtime)
    result = await backend.evaluate_pre_tool_call(
        tenant_id="tenant-alpha",
        tool_name="refund_adapter",
        arguments={"customer_id": "customer-001"},
        tool_call_id="sdk-call-1",
        snapshot={"run_id": "run-w5"},
    )

    assert runtime.request.intervention_point == acs.InterventionPoint.PRE_TOOL_CALL
    assert runtime.request.snapshot["tenant_id"] == "tenant-alpha"
    assert runtime.request.snapshot["tool_call"]["name"] == "refund_adapter"
    assert runtime.request.snapshot["tool_call"]["id"] == "sdk-call-1"
    assert result.decision == "allow"
    assert result.input_identity == "sdk-input"


@pytest.mark.asyncio
async def test_tenant_mismatch_between_argument_and_proposal_holds_before_agt():
    from agent_control_plane.bounded import TenantRuntimeProposal

    backend = FakeBackend(AgtDecision(decision="allow"))
    authority = FakeAuthority("authorized")
    adapter = MicrosoftAgtPreToolCallAdapter(backend=backend, authority=authority)
    tenant_proposal = TenantRuntimeProposal(**proposal().model_dump(), tenant_id="tenant-beta")

    result = await adapter.evaluate(
        tenant_id="tenant-alpha", proposal=tenant_proposal, tool_name="refund_adapter", tool_call_id="call-t"
    )

    assert result.result == "hold"
    assert "tenant_mismatch" in result.reasons
    assert backend.calls == [] and authority.calls == []


@pytest.mark.asyncio
async def test_matching_tenant_proposal_is_evaluated_normally():
    from agent_control_plane.bounded import TenantRuntimeProposal

    backend = FakeBackend(AgtDecision(decision="allow"))
    authority = FakeAuthority("authorized")
    adapter = MicrosoftAgtPreToolCallAdapter(backend=backend, authority=authority)
    tenant_proposal = TenantRuntimeProposal(**proposal().model_dump(), tenant_id="tenant-alpha")

    result = await adapter.evaluate(
        tenant_id="tenant-alpha", proposal=tenant_proposal, tool_name="refund_adapter", tool_call_id="call-t2"
    )

    assert result.result == "authorized"


@pytest.mark.asyncio
async def test_tool_bindings_hold_on_mismatch_and_pass_on_match():
    backend = FakeBackend(AgtDecision(decision="allow"))
    authority = FakeAuthority("authorized")
    bindings = {"urn:cognous:adapter:synthetic-refund-v1": "refund_adapter"}
    adapter = MicrosoftAgtPreToolCallAdapter(backend=backend, authority=authority, tool_bindings=bindings)

    wrong = await adapter.evaluate(
        tenant_id="tenant-alpha", proposal=proposal(), tool_name="read_only_lookup", tool_call_id="call-b1"
    )
    assert wrong.result == "hold" and "tool_binding_mismatch" in wrong.reasons
    assert backend.calls == [] and authority.calls == []

    ok = await adapter.evaluate(
        tenant_id="tenant-alpha", proposal=proposal(), tool_name="refund_adapter", tool_call_id="call-b2"
    )
    assert ok.result == "authorized"

    unlisted = MicrosoftAgtPreToolCallAdapter(backend=backend, authority=authority, tool_bindings={})
    held = await unlisted.evaluate(
        tenant_id="tenant-alpha", proposal=proposal(), tool_name="refund_adapter", tool_call_id="call-b3"
    )
    assert held.result == "hold" and "tool_binding_mismatch" in held.reasons
