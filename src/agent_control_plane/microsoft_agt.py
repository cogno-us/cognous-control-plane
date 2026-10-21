"""Optional Microsoft Agent Governance Toolkit pre_tool_call compatibility profile.

This module is intentionally not part of the core component lock. Microsoft AGT
is an additional restriction surface; it never grants Cognous authority.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Literal, Mapping, Protocol

from agent_control_plane.bounded import RuntimeDecision, RuntimeProposal, commitment

MICROSOFT_AGT_UPSTREAM_REVISION = "84ae67348705996a3d65e31936afb7d02853f2a0"
MICROSOFT_AGT_PROFILE = "microsoft-agt-pre-tool-call/0.1"


class MicrosoftAgtUnavailable(RuntimeError):
    """Raised when the optional Microsoft AGT SDK/backend cannot be used."""


@dataclass(frozen=True)
class AgtDecision:
    decision: str
    reason: str | None = None
    message: str | None = None
    transformed_policy_target: Any = None
    transformed_policy_target_applied: bool = False
    warnings: tuple[Mapping[str, Any], ...] = ()
    evidence_artefact: str | None = None
    evidence_verification_pointers: Mapping[str, str] = field(default_factory=dict)
    input_identity: str | None = None
    enforced_identity: str | None = None


class MicrosoftAgtBackend(Protocol):
    async def evaluate_pre_tool_call(
        self,
        *,
        tenant_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        tool_call_id: str | None,
        snapshot: Mapping[str, Any],
    ) -> AgtDecision: ...


class CognousAuthorityEvaluator(Protocol):
    def authorize(
        self,
        *,
        proposal: RuntimeProposal,
        tenant_id: str,
        now: datetime | None = None,
    ) -> RuntimeDecision: ...


@dataclass(frozen=True)
class MicrosoftAgtCompatibilityEvidence:
    profile: str
    upstream_revision: str
    source: str
    tenant_id: str
    tool_name: str
    tool_call_id: str | None
    agt_decision: str
    agt_reason: str | None
    agt_message: str | None
    agt_warnings: tuple[Mapping[str, Any], ...]
    agt_input_identity: str | None
    agt_enforced_identity: str | None
    agt_evidence_artefact: str | None
    agt_evidence_verification_pointers: Mapping[str, str]
    original_proposal_commitment: str
    effective_proposal_commitment: str | None
    transformed: bool
    cognous_decision_id: str | None
    cognous_result: str | None
    limitation: str


@dataclass(frozen=True)
class MicrosoftAgtCompatibilityResult:
    result: Literal["authorized", "deny", "hold", "error"]
    proposal: RuntimeProposal | None
    cognous_decision: RuntimeDecision | None
    evidence: MicrosoftAgtCompatibilityEvidence
    reasons: tuple[str, ...]


class MicrosoftAgtSdkBackend:
    """Adapter for the pinned AGT Python SDK RuntimeClient surface.

    The runtime client is injected. Construction/import is optional so this
    package does not acquire a hard dependency on agent-control-specification.
    """

    def __init__(self, runtime_client: Any):
        self._runtime_client = runtime_client

    async def evaluate_pre_tool_call(
        self,
        *,
        tenant_id: str,
        tool_name: str,
        arguments: Mapping[str, Any],
        tool_call_id: str | None,
        snapshot: Mapping[str, Any],
    ) -> AgtDecision:
        try:
            from agent_control_specification import (
                EnforcementMode,
                InterventionPoint,
                InterventionPointRequest,
            )
        except ImportError as exc:  # pragma: no cover - qualification job covers real SDK
            raise MicrosoftAgtUnavailable(
                "agent-control-specification is not installed"
            ) from exc

        tool_call: dict[str, Any] = {
            "name": tool_name,
            "args": dict(arguments),
        }
        if tool_call_id is not None:
            tool_call["id"] = tool_call_id

        raw_snapshot = dict(snapshot)
        raw_snapshot["tenant_id"] = tenant_id
        raw_snapshot["tool_call"] = tool_call

        request = InterventionPointRequest(
            intervention_point=InterventionPoint.PRE_TOOL_CALL,
            snapshot=raw_snapshot,
            mode=EnforcementMode.ENFORCE,
        )
        try:
            result = await self._runtime_client.evaluate_intervention_point(request)
        except Exception as exc:
            raise MicrosoftAgtUnavailable(
                f"AGT pre_tool_call evaluation failed: {type(exc).__name__}: {exc}"
            ) from exc

        verdict = getattr(result, "verdict", None)
        if verdict is None or not hasattr(verdict, "decision"):
            raise MicrosoftAgtUnavailable("unsupported AGT response: missing verdict.decision")

        raw_decision = verdict.decision
        decision = getattr(raw_decision, "value", raw_decision)
        if not isinstance(decision, str):
            raise MicrosoftAgtUnavailable("unsupported AGT response: non-string decision")

        raw_warnings = getattr(verdict, "warnings", ()) or ()
        warnings: list[Mapping[str, Any]] = []
        for warning in raw_warnings:
            if isinstance(warning, Mapping):
                warnings.append(dict(warning))
            else:
                warnings.append(
                    {
                        "reason": getattr(warning, "reason", None),
                        "message": getattr(warning, "message", None),
                    }
                )

        evidence = getattr(verdict, "evidence", None)
        artefact = getattr(evidence, "artefact", None) if evidence is not None else None
        pointers = (
            dict(getattr(evidence, "verification_pointers", {}) or {})
            if evidence is not None
            else {}
        )

        return AgtDecision(
            decision=decision,
            reason=getattr(verdict, "reason", None),
            message=getattr(verdict, "message", None),
            transformed_policy_target=getattr(result, "transformed_policy_target", None),
            transformed_policy_target_applied=bool(
                getattr(result, "transformed_policy_target_applied", False)
            ),
            warnings=tuple(warnings),
            evidence_artefact=artefact,
            evidence_verification_pointers=pointers,
            input_identity=getattr(result, "input_identity", None),
            enforced_identity=getattr(result, "enforced_identity", None),
        )


class MicrosoftAgtPreToolCallAdapter:
    """Conjunctive AGT + Cognous gate for one bounded pre_tool_call profile."""

    def __init__(
        self,
        *,
        backend: MicrosoftAgtBackend,
        authority: CognousAuthorityEvaluator,
        tool_bindings: Mapping[str, str] | None = None,
    ) -> None:
        self._backend = backend
        self._authority = authority
        # Opt-in: ``{adapter_id: tool_name}`` taken from the same trusted manifest entry as the proposals. When given, an
        # evaluation whose proposal adapter has no entry, or whose ``tool_name`` differs, is held before AGT is asked.
        self._tool_bindings = dict(tool_bindings) if tool_bindings is not None else None

    async def evaluate(
        self,
        *,
        tenant_id: str,
        proposal: RuntimeProposal,
        tool_name: str,
        tool_call_id: str | None = None,
        snapshot: Mapping[str, Any] | None = None,
        now: datetime | None = None,
    ) -> MicrosoftAgtCompatibilityResult:
        # The tenant is an opaque exact string: never trimmed or case-folded (a padded tenant is passed on, and compared, as given).
        tenant = tenant_id if isinstance(tenant_id, str) and tenant_id.strip() else ""
        original_commitment = commitment(
            proposal.model_dump(mode="json", exclude_none=False)
        )
        if not tenant:
            return self._finish(
                result="hold",
                tenant_id="",
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                agt=AgtDecision(decision="unavailable", reason="tenant_missing"),
                original_commitment=original_commitment,
                proposal=None,
                cognous=None,
                transformed=False,
                reasons=("tenant_missing",),
            )

        proposal_tenant = getattr(proposal, "tenant_id", None)
        if proposal_tenant is not None and proposal_tenant != tenant:
            return self._finish(
                result="hold",
                tenant_id=tenant,
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                agt=AgtDecision(decision="unavailable", reason="tenant_mismatch"),
                original_commitment=original_commitment,
                proposal=None,
                cognous=None,
                transformed=False,
                reasons=("tenant_mismatch",),
            )
        if self._tool_bindings is not None and self._tool_bindings.get(proposal.adapter_id) != tool_name:
            return self._finish(
                result="hold",
                tenant_id=tenant,
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                agt=AgtDecision(decision="unavailable", reason="tool_binding_mismatch"),
                original_commitment=original_commitment,
                proposal=None,
                cognous=None,
                transformed=False,
                reasons=("tool_binding_mismatch",),
            )

        try:
            agt = await self._backend.evaluate_pre_tool_call(
                tenant_id=tenant,
                tool_name=tool_name,
                arguments=proposal.payload,
                tool_call_id=tool_call_id,
                snapshot=snapshot or {},
            )
        except MicrosoftAgtUnavailable as exc:
            return self._finish(
                result="hold",
                tenant_id=tenant,
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                agt=AgtDecision(decision="unavailable", reason="backend_unavailable", message=str(exc)),
                original_commitment=original_commitment,
                proposal=None,
                cognous=None,
                transformed=False,
                reasons=("capability_unavailable",),
            )

        # The AGT decision is an exact lowercase token: "ALLOW", " allow" and "Transform" are unsupported, not normalised to authority.
        decision = agt.decision if isinstance(agt.decision, str) else ""

        # Warnings are restrictions in this bounded profile. They never become
        # implicit permission merely because the underlying AGT decision allows.
        if agt.warnings:
            return self._finish(
                result="hold",
                tenant_id=tenant,
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                agt=agt,
                original_commitment=original_commitment,
                proposal=None,
                cognous=None,
                transformed=False,
                reasons=("agt_warning_requires_review",),
            )

        if decision in {"deny", "escalate", "warn"}:
            return self._finish(
                result="deny" if decision == "deny" else "hold",
                tenant_id=tenant,
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                agt=agt,
                original_commitment=original_commitment,
                proposal=None,
                cognous=None,
                transformed=False,
                reasons=(f"agt_{decision}",),
            )

        transformed = False
        effective = proposal
        if decision == "transform":
            target = agt.transformed_policy_target
            if not agt.transformed_policy_target_applied or not isinstance(target, Mapping):
                return self._finish(
                    result="hold",
                    tenant_id=tenant,
                    tool_name=tool_name,
                    tool_call_id=tool_call_id,
                    agt=agt,
                    original_commitment=original_commitment,
                    proposal=None,
                    cognous=None,
                    transformed=False,
                    reasons=("unsupported_transform_response",),
                )
            effective = proposal.model_copy(
                deep=True,
                update={
                    "payload": dict(target),
                    "payload_commitment": commitment(dict(target)),
                },
            )
            transformed = True
        elif decision != "allow":
            return self._finish(
                result="hold",
                tenant_id=tenant,
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                agt=agt,
                original_commitment=original_commitment,
                proposal=None,
                cognous=None,
                transformed=False,
                reasons=("unsupported_agt_decision",),
            )

        # This call is deliberately after transform. A transformed proposal is
        # never allowed to reuse authorization for the pre-transform commitment.
        try:
            cognous = self._authority.authorize(
                proposal=effective,
                tenant_id=tenant,
                now=now,
            )
        except Exception as exc:
            return self._finish(
                result="error",
                tenant_id=tenant,
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                agt=agt,
                original_commitment=original_commitment,
                proposal=effective,
                cognous=None,
                transformed=transformed,
                reasons=(f"cognous_evaluation_error:{type(exc).__name__}",),
            )

        if transformed and cognous.result == "authorized" and cognous.binding is None:
            # An authorization of a transformed proposal must carry the decision binding that fixes the new commitment.
            return self._finish(
                result="hold",
                tenant_id=tenant,
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                agt=agt,
                original_commitment=original_commitment,
                proposal=effective,
                cognous=cognous,
                transformed=transformed,
                reasons=("transform_authorization_unbound",),
            )

        if cognous.result != "authorized":
            return self._finish(
                result="deny" if cognous.result == "deny" else "hold",
                tenant_id=tenant,
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                agt=agt,
                original_commitment=original_commitment,
                proposal=effective,
                cognous=cognous,
                transformed=transformed,
                reasons=tuple(cognous.reasons) or (f"cognous_{cognous.result}",),
            )

        return self._finish(
            result="authorized",
            tenant_id=tenant,
            tool_name=tool_name,
            tool_call_id=tool_call_id,
            agt=agt,
            original_commitment=original_commitment,
            proposal=effective,
            cognous=cognous,
            transformed=transformed,
            reasons=(),
        )

    def _finish(
        self,
        *,
        result: Literal["authorized", "deny", "hold", "error"],
        tenant_id: str,
        tool_name: str,
        tool_call_id: str | None,
        agt: AgtDecision,
        original_commitment: str,
        proposal: RuntimeProposal | None,
        cognous: RuntimeDecision | None,
        transformed: bool,
        reasons: tuple[str, ...],
    ) -> MicrosoftAgtCompatibilityResult:
        effective_commitment = (
            commitment(proposal.model_dump(mode="json", exclude_none=False))
            if proposal is not None
            else None
        )
        evidence = MicrosoftAgtCompatibilityEvidence(
            profile=MICROSOFT_AGT_PROFILE,
            upstream_revision=MICROSOFT_AGT_UPSTREAM_REVISION,
            source="microsoft/agent-governance-toolkit",
            tenant_id=tenant_id,
            tool_name=tool_name,
            tool_call_id=tool_call_id,
            agt_decision=agt.decision,
            agt_reason=agt.reason,
            agt_message=agt.message,
            agt_warnings=agt.warnings,
            agt_input_identity=agt.input_identity,
            agt_enforced_identity=agt.enforced_identity,
            agt_evidence_artefact=agt.evidence_artefact,
            agt_evidence_verification_pointers=dict(agt.evidence_verification_pointers),
            original_proposal_commitment=original_commitment,
            effective_proposal_commitment=effective_commitment,
            transformed=transformed,
            cognous_decision_id=cognous.decision_id if cognous else None,
            cognous_result=cognous.result if cognous else None,
            limitation=(
                "AGT is an additional restriction only. Cognous authorization is "
                "independent; AGT evidence/telemetry is not Cognous authority."
            ),
        )
        return MicrosoftAgtCompatibilityResult(
            result=result,
            proposal=proposal,
            cognous_decision=cognous,
            evidence=evidence,
            reasons=reasons,
        )
