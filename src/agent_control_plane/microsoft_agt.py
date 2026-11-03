"""Optional Microsoft Agent Governance Toolkit pre_tool_call compatibility profile.

This module is intentionally not part of the core component lock. Microsoft AGT
is an additional restriction surface; it never grants Cognous authority.
"""
from __future__ import annotations

import copy
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
    # R1-A2: the proposal adapter_id bound to ``tool_name`` at entry (the identity both AGT and Cognous were asked about).
    bound_adapter_id: str | None = None


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
        # Optional ``{adapter_id: tool_name}`` from the same trusted manifest entry as the proposals. When given, an evaluation
        # whose proposal adapter has no entry, or whose ``tool_name`` differs, is held before AGT is asked. When absent,
        # tool_name must equal proposal.adapter_id exactly (R1-A2).
        # R1-A2: a private copy whose keys and values are exact plain ``str`` (a str subclass can override ``__eq__``/``__hash__``);
        # anything else is refused at construction, and later mutation of the caller's mapping cannot change it.
        if tool_bindings is None:
            self._tool_bindings = None
        else:
            copied: dict[str, str] = {}
            for key, value in dict(tool_bindings).items():
                if type(key) is not str or type(value) is not str or not key or not value:
                    raise ValueError("tool_bindings keys and values must be non-empty exact str")
                copied[key] = value
            self._tool_bindings = copied

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
        # R1-A: one private deep snapshot, taken synchronously before the first await. The original commitment, the arguments given to
        # AGT, the Cognous authorization, the binding check and the returned proposal all derive from it; the caller's proposal
        # (nested payload included) is never read again, so mutation during the awaited backend call cannot change any of them.
        proposal = proposal.model_copy(deep=True)
        snapshot = copy.deepcopy(dict(snapshot)) if snapshot else None
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
        # R1-A2: one authoritative tool identity, established on the private snapshot before AGT is asked. ``bound_adapter_id`` is the
        # snapshot's adapter; ``tool_name`` is what AGT will evaluate. With ``tool_bindings`` the exact entry for the adapter must be
        # this tool_name (missing entry or any difference is a hold); without them tool_name must equal the adapter_id exactly. Nothing
        # is inferred, trimmed or case-folded.
        bound_adapter_id = proposal.adapter_id
        identity_hold = self._identity_hold_reason(bound_adapter_id, tool_name)
        if identity_hold is not None:
            return self._finish(
                result="hold",
                tenant_id=tenant,
                tool_name=tool_name,
                tool_call_id=tool_call_id,
                agt=AgtDecision(decision="unavailable", reason=identity_hold),
                original_commitment=original_commitment,
                proposal=None,
                cognous=None,
                transformed=False,
                reasons=(identity_hold,),
                bound_adapter_id=bound_adapter_id if isinstance(bound_adapter_id, str) else None,
            )

        try:
            agt = await self._backend.evaluate_pre_tool_call(
                tenant_id=tenant,
                tool_name=tool_name,
                arguments=copy.deepcopy(proposal.payload),
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
                bound_adapter_id=bound_adapter_id,
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
                bound_adapter_id=bound_adapter_id,
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
                bound_adapter_id=bound_adapter_id,
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
                    bound_adapter_id=bound_adapter_id,
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
            if effective.adapter_id != bound_adapter_id:
                # Defence in depth: a transform replaces only the payload. Should the effective proposal carry any other adapter
                # identity than the one bound at entry, AGT's decision no longer corresponds to what Cognous would authorize.
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
                    bound_adapter_id=bound_adapter_id,
                    reasons=("transform_identity_changed",),
                )
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
                bound_adapter_id=bound_adapter_id,
                reasons=("unsupported_agt_decision",),
            )

        # This call is deliberately after transform. A transformed proposal is
        # never allowed to reuse authorization for the pre-transform commitment.
        try:
            cognous = self._authority.authorize(
                proposal=effective.model_copy(deep=True),  # the authority gets its own copy: it cannot alter the snapshot
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
                bound_adapter_id=bound_adapter_id,
                reasons=(f"cognous_evaluation_error:{type(exc).__name__}",),
            )

        if cognous.result == "authorized" and not self._binding_fixes(cognous.binding, effective):
            # An authorization must carry a decision binding that fixes the snapshot's (or, after a transform, the transformed)
            # proposal and payload commitments; a missing, stale or foreign binding does not.
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
                bound_adapter_id=bound_adapter_id,
                reasons=("transform_authorization_unbound" if transformed else "authorization_unbound",),
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
                bound_adapter_id=bound_adapter_id,
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
            bound_adapter_id=bound_adapter_id,
            reasons=(),
        )

    def _identity_hold_reason(self, adapter_id: Any, tool_name: Any) -> str | None:
        """None when tool_name and adapter_id are one bound identity; else the typed hold reason."""
        if type(adapter_id) is not str or not adapter_id or type(tool_name) is not str or not tool_name:  # exact str only: no subclass equality
            return "tool_identity_unbound"
        if self._tool_bindings is None:
            return None if tool_name == adapter_id else "tool_identity_unbound"
        return None if self._tool_bindings.get(adapter_id) == tool_name else "tool_binding_mismatch"

    @staticmethod
    def _binding_fixes(binding: Any, effective: Any) -> bool:
        """True when the binding carries the proposal and payload commitments of the effective (transformed) proposal."""
        if binding is None:
            return False
        try:
            return (getattr(binding, "proposal_commitment", None) == commitment(effective.model_dump(mode="json", exclude_none=False))
                    and getattr(binding, "payload_commitment", None) == effective.payload_commitment)
        except Exception:  # noqa: BLE001 - an unreadable binding fixes nothing
            return False

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
        bound_adapter_id: str | None = None,
    ) -> MicrosoftAgtCompatibilityResult:
        if proposal is not None:
            proposal = proposal.model_copy(deep=True)  # the returned proposal never aliases the private snapshot or the caller
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
            bound_adapter_id=bound_adapter_id,
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
