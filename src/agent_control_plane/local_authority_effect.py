"""Opt-in local authority/effect execution-claim contract.

This module does not change the legacy BoundedAuthorizationWorkflow execution
path. It materializes a claim only from a persisted authorized decision plus a
fresh resolution of the same trusted workflow. The claim is not authority by
itself: a participating local authority/effect store must provision it and own
all later invalidating state changes for the profile.
"""
from __future__ import annotations

import copy
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Callable, Literal

from pydantic import BaseModel, Field

from agent_control_plane.bounded import (
    BoundedAuthorizationWorkflow,
    RuntimeDecision,
    RuntimeProposal,
    TenantAuthorizationBinding,
    TenantRuntimeProposal,
    _iso,
    _parse,
    commitment,
)

LOCAL_AUTHORITY_EFFECT_PROFILE = "urn:cognous:profiles:local-authority-effect:0.1.0-proposed"


class ApprovalProjection(BaseModel):
    approval_ref: str
    role_id: str
    approver: str
    status: Literal["active", "revoked", "unknown"]
    grant_id: str
    grant_revision: str
    proposal_commitment: str
    policy_versions: list[dict]
    observed_at: str


class TenantApprovalProjection(ApprovalProjection):
    tenant_id: str = Field(min_length=1, max_length=128)


class PolicyProjection(BaseModel):
    ref: str
    version: str
    status: Literal["active", "superseded", "unknown"]
    observed_at: str


class TenantPolicyProjection(PolicyProjection):
    tenant_id: str = Field(min_length=1, max_length=128)


class EvidenceProjection(BaseModel):
    obligation_id: str
    source_ref: str
    required: bool
    kind: str
    max_age_seconds: int
    unknown_behavior: str
    state: Literal["current", "stale", "unknown"]
    observed_at: str


class LocalExecutionClaim(BaseModel):
    """Exact execution claim for one participating local atomic profile.

    Possession of this object is not sufficient for execution. The executor must
    locate the same claim in the declared authoritative local store and consume
    it there in the same transaction that commits the protected effect.
    """

    profile: str = LOCAL_AUTHORITY_EFFECT_PROFILE
    claim_id: str
    decision_id: str
    effect_id: str
    institution_id: str
    authority_domain: str
    actor: str
    principal: str
    grant_id: str
    grant_revision: str
    grant_status: Literal["active"]
    manifest_id: str
    manifest_version: str
    manifest_digest: str
    action_id: str
    adapter_id: str
    target: str
    payload_commitment: str
    requested_permissions: list[str]
    amount: float = Field(allow_inf_nan=False)
    unit: str
    effects: int
    authority_context_id: str
    requirement_id: str
    requirement_commitment: str
    operation_commitment: str
    approval_state: list[ApprovalProjection]
    approval_state_commitment: str
    policy_state: list[PolicyProjection]
    policy_state_commitment: str
    evidence_state: list[EvidenceProjection]
    evidence_state_commitment: str
    authority_state_commitment: str
    budget_id: str
    max_effects: int
    not_before: str
    expires_at: str
    issued_at: str
    decision_input_commitment: str | None = None
    decision_input_profile_version: str | None = None
    source: Literal["trusted_control_plane_workflow"] = "trusted_control_plane_workflow"
    authorizing_by_possession: bool = False
    claim_commitment: str


class TenantLocalExecutionClaim(LocalExecutionClaim):
    """Tenant-aware local execution claim for bounded-authorization-effect/0.2."""

    authorization_generation: Literal["bounded-authorization-effect/0.2"] = "bounded-authorization-effect/0.2"
    tenant_id: str = Field(min_length=1, max_length=128)
    approval_state: list[TenantApprovalProjection]
    policy_state: list[TenantPolicyProjection]


def _utc(value: str) -> datetime:
    parsed = _parse(value)
    return parsed.astimezone(timezone.utc)


def _operation_payload(
    proposal: RuntimeProposal,
    decision: RuntimeDecision,
    *,
    institution_id: str,
    authority_domain: str,
) -> dict[str, Any]:
    binding = decision.binding
    if binding is None:
        raise PermissionError("authorized decision is missing an authorization binding")
    value = {
        "actor": proposal.actor,
        "principal": proposal.principal,
        "institution_id": institution_id,
        "authority_domain": authority_domain,
        "manifest_id": proposal.manifest_id,
        "manifest_version": proposal.manifest_version,
        "manifest_digest": proposal.manifest_digest,
        "action_id": proposal.action_id,
        "adapter_id": proposal.adapter_id,
        "target": proposal.target,
        "payload": copy.deepcopy(proposal.payload),
        "payload_commitment": proposal.payload_commitment,
        "requested_permissions": list(proposal.requested_permissions),
        "amount": proposal.amount,
        "unit": proposal.unit,
        "effects": proposal.effects,
        "authority_context_id": proposal.authority_context_ref,
        "requirement_id": proposal.requirement_id,
        "grant_id": binding.grant_id,
        "grant_revision": binding.grant_revision,
    }
    if isinstance(binding, TenantAuthorizationBinding):
        if not isinstance(proposal, TenantRuntimeProposal) or proposal.tenant_id != binding.tenant_id:
            raise PermissionError("tenant proposal/binding mismatch")
        value["tenant_id"] = binding.tenant_id
    return value


def _validate_issuance_snapshot(
    workflow: BoundedAuthorizationWorkflow,
    proposal: RuntimeProposal,
    decision: RuntimeDecision,
    snapshot: dict[str, Any],
    *,
    now: datetime,
) -> tuple[dict[str, Any], dict[str, Any], dict[str, Any], list[ApprovalProjection], list[PolicyProjection], list[EvidenceProjection]]:
    """Validate the coherent authority snapshot used for claim issuance."""
    current = decision.binding
    if current is None:
        raise PermissionError("authorized decision is missing an authorization binding")

    context = snapshot.get("context")
    if not isinstance(context, dict):
        raise PermissionError("authority snapshot context unavailable")
    institution = context.get("institution") or {}
    grant = context.get("grant") or {}
    requirement = context.get("requirement") or {}
    tenant_id = current.tenant_id if isinstance(current, TenantAuthorizationBinding) else None
    if tenant_id is not None:
        if context.get("tenant_id") != tenant_id or grant.get("tenant_id") != tenant_id:
            raise PermissionError("authority snapshot tenant binding mismatch")

    if institution.get("institution_id") is None or institution.get("authority_domain") is None:
        raise PermissionError("authority snapshot institution binding unavailable")
    if grant.get("grant_id") != current.grant_id or grant.get("revision") != current.grant_revision:
        raise PermissionError("authority snapshot grant binding mismatch")
    if requirement.get("requirement_id") != current.requirement_id:
        raise PermissionError("authority snapshot requirement binding mismatch")
    if commitment(requirement) != current.requirement_commitment:
        raise PermissionError("authority snapshot requirement commitment mismatch")

    grant_status = snapshot.get("grant_status")
    if grant_status is None:
        raise PermissionError("grant status unavailable at claim issuance")
    if (
        grant_status.grant_id != current.grant_id
        or grant_status.revision != current.grant_revision
        or grant_status.status != "active"
        or grant_status.institution_id != institution.get("institution_id")
        or grant_status.authority_domain != institution.get("authority_domain")
        or (tenant_id is not None and grant_status.tenant_id != tenant_id)
    ):
        raise PermissionError("grant projection is not active and binding-consistent")

    approvals_by_ref = snapshot.get("approvals")
    if not isinstance(approvals_by_ref, dict):
        raise PermissionError("approval snapshot unavailable at claim issuance")
    approvals: list[ApprovalProjection] = []
    for ref in grant.get("approval_refs", []):
        value = approvals_by_ref.get(ref)
        if value is None:
            raise PermissionError("approval state unavailable at claim issuance")
        if (
            value.approval_ref != ref
            or value.status != "active"
            or value.grant_id != current.grant_id
            or value.grant_revision != current.grant_revision
            or value.proposal_commitment != current.proposal_commitment
            or value.policy_versions != current.policy_versions
            or value.institution_id != institution.get("institution_id")
            or value.authority_domain != institution.get("authority_domain")
            or (tenant_id is not None and value.tenant_id != tenant_id)
        ):
            raise PermissionError("approval projection is not active and binding-consistent")
        approval_type = TenantApprovalProjection if tenant_id is not None else ApprovalProjection
        approval_kwargs = {"tenant_id": tenant_id} if tenant_id is not None else {}
        approvals.append(approval_type(
            **approval_kwargs,
            approval_ref=value.approval_ref,
            role_id=value.role_id,
            approver=value.approver,
            status=value.status,
            grant_id=value.grant_id,
            grant_revision=value.grant_revision,
            proposal_commitment=value.proposal_commitment,
            policy_versions=copy.deepcopy(value.policy_versions),
            observed_at=value.observed_at,
        ))

    policies_by_ref = snapshot.get("policies")
    if not isinstance(policies_by_ref, dict):
        raise PermissionError("policy snapshot unavailable at claim issuance")
    policies: list[PolicyProjection] = []
    for item in current.policy_versions:
        value = policies_by_ref.get(item["ref"])
        if value is None:
            raise PermissionError("policy state unavailable at claim issuance")
        if (
            value.ref != item["ref"]
            or value.version != item["version"]
            or value.status != "active"
            or value.institution_id != institution.get("institution_id")
            or value.authority_domain != institution.get("authority_domain")
            or (tenant_id is not None and value.tenant_id != tenant_id)
        ):
            raise PermissionError("policy projection is not active and binding-consistent")
        policy_type = TenantPolicyProjection if tenant_id is not None else PolicyProjection
        policy_kwargs = {"tenant_id": tenant_id} if tenant_id is not None else {}
        policies.append(policy_type(
            **policy_kwargs,
            ref=value.ref,
            version=value.version,
            status=value.status,
            observed_at=value.observed_at,
        ))

    evidence_by_id = snapshot.get("evidence")
    if not isinstance(evidence_by_id, dict):
        raise PermissionError("evidence snapshot unavailable at claim issuance")
    evidence: list[EvidenceProjection] = []
    for obligation in requirement.get("evidence", []):
        oid = obligation["obligation_id"]
        value = evidence_by_id.get(oid)
        decision_critical = bool(obligation.get("required")) or obligation.get("unknown_behavior") == "hold_effect"
        if value is None:
            if decision_critical:
                raise PermissionError("decision-relevant evidence state unavailable at claim issuance")
            continue
        if (
            value.obligation_id != oid
            or value.source_ref != obligation.get("source_ref")
            or value.institution_id != institution.get("institution_id")
            or value.authority_domain != institution.get("authority_domain")
        ):
            raise PermissionError("evidence projection binding mismatch")
        if decision_critical and value.state != "current":
            raise PermissionError("evidence projection is not current")
        observed = _utc(value.observed_at)
        max_age = int(obligation.get("max_age_seconds", 0))
        if observed > now + timedelta(seconds=workflow.clock_tolerance_seconds):
            # The regular resolver check below remains authoritative for configured
            # tolerance; this branch only rejects obviously future snapshot state.
            raise PermissionError("evidence projection time is in the future")
        if decision_critical and (now - observed).total_seconds() > max_age:
            raise PermissionError("evidence projection is stale at claim issuance")
        evidence.append(EvidenceProjection(
            obligation_id=value.obligation_id,
            source_ref=value.source_ref,
            required=bool(obligation.get("required")),
            kind=str(obligation.get("kind", "")),
            max_age_seconds=max_age,
            unknown_behavior=str(obligation.get("unknown_behavior", "")),
            state=value.state,
            observed_at=value.observed_at,
        ))

    return context, institution, grant, approvals, policies, evidence


def _materialize_under_handoff(
    workflow: BoundedAuthorizationWorkflow,
    proposal: RuntimeProposal,
    decision: RuntimeDecision,
    *,
    now: datetime,
    claim_id: str | None,
    budget_id: str | None,
    expires_at: str | None,
    decision_input_commitment: str | None,
    decision_input_profile_version: str | None,
    provision: Callable[[LocalExecutionClaim], None] | None,
) -> LocalExecutionClaim:
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("claim issuance time must be timezone-aware")
    now = workflow._evaluation_time(now)

    persisted = workflow.records.decision(decision.decision_id)
    if persisted is None or persisted != decision:
        raise PermissionError("decision is not the immutable persisted decision")
    if decision.result != "authorized" or decision.binding is None:
        raise PermissionError("decision is not authorized")

    resolver = workflow.resolver
    handoff = getattr(resolver, "authority_effect_handoff", None)
    snapshot_reader = getattr(resolver, "authority_effect_snapshot", None)
    if not callable(handoff) or not callable(snapshot_reader):
        raise PermissionError("resolver does not implement trusted authority-effect handoff")

    frozen = proposal.model_copy(deep=True)
    with handoff(proposal.authority_context_ref or ""):
        inputs = []
        reasons, current = workflow._resolve(frozen, now, inputs=inputs)
        reasons = workflow._record_check(inputs, now, reasons, "claim")
        if reasons or current is None or current != decision.binding:
            raise PermissionError("authorization-critical inputs changed before claim issuance")

        snapshot = snapshot_reader(proposal.authority_context_ref or "")
        if not isinstance(snapshot, dict):
            raise PermissionError("coherent authority snapshot unavailable at claim issuance")

        context, institution, grant, approvals, policies, evidence = _validate_issuance_snapshot(
            workflow, proposal, decision, snapshot, now=now
        )
        grant_status = snapshot["grant_status"]
        requirement = context.get("requirement") or {}

        start_candidates = [_utc(grant["not_before"])]
        if proposal.not_before:
            start_candidates.append(_utc(proposal.not_before))
        end_candidates = [_utc(grant["expires_at"])]
        if proposal.expires_at:
            end_candidates.append(_utc(proposal.expires_at))
        if expires_at:
            end_candidates.append(_utc(expires_at))
        not_before_dt = max(start_candidates)
        expires_at_dt = min(end_candidates)
        if expires_at_dt <= not_before_dt or expires_at_dt <= now:
            raise PermissionError("execution claim has no usable validity interval")

        approval_dump = [item.model_dump(mode="json") for item in approvals]
        policy_dump = [item.model_dump(mode="json") for item in policies]
        evidence_dump = [item.model_dump(mode="json") for item in evidence]
        operation_commitment = commitment(_operation_payload(
            proposal,
            decision,
            institution_id=institution.get("institution_id"),
            authority_domain=institution.get("authority_domain"),
        ))
        authority_state = {
            "grant_id": current.grant_id,
            "grant_revision": current.grant_revision,
            "grant_status": grant_status.status,
            "requirement_commitment": current.requirement_commitment,
            "approvals": approval_dump,
            "policies": policy_dump,
            "evidence": evidence_dump,
        }

        raw = {
            "profile": LOCAL_AUTHORITY_EFFECT_PROFILE,
            "claim_id": claim_id or str(uuid.uuid4()),
            "decision_id": decision.decision_id,
            "effect_id": decision.effect_id,
            "institution_id": institution.get("institution_id"),
            "authority_domain": institution.get("authority_domain"),
            "actor": proposal.actor,
            "principal": proposal.principal,
            "grant_id": current.grant_id,
            "grant_revision": current.grant_revision,
            "grant_status": grant_status.status,
            "manifest_id": proposal.manifest_id,
            "manifest_version": proposal.manifest_version,
            "manifest_digest": proposal.manifest_digest,
            "action_id": proposal.action_id,
            "adapter_id": proposal.adapter_id,
            "target": proposal.target,
            "payload_commitment": proposal.payload_commitment,
            "requested_permissions": list(proposal.requested_permissions),
            "amount": proposal.amount,
            "unit": proposal.unit,
            "effects": proposal.effects,
            "authority_context_id": current.authority_context_id,
            "requirement_id": current.requirement_id,
            "requirement_commitment": current.requirement_commitment,
            "operation_commitment": operation_commitment,
            "approval_state": approval_dump,
            "approval_state_commitment": commitment(approval_dump),
            "policy_state": policy_dump,
            "policy_state_commitment": commitment(policy_dump),
            "evidence_state": evidence_dump,
            "evidence_state_commitment": commitment(evidence_dump),
            "authority_state_commitment": commitment(authority_state),
            "budget_id": budget_id or f"grant:{current.grant_id}",
            "max_effects": current.effective_max_effects,
            "not_before": _iso(not_before_dt),
            "expires_at": _iso(expires_at_dt),
            "issued_at": _iso(now),
            "decision_input_commitment": decision_input_commitment,
            "decision_input_profile_version": decision_input_profile_version,
            "source": "trusted_control_plane_workflow",
            "authorizing_by_possession": False,
        }
        claim_type = LocalExecutionClaim
        if isinstance(current, TenantAuthorizationBinding):
            raw["authorization_generation"] = "bounded-authorization-effect/0.2"
            raw["tenant_id"] = current.tenant_id
            claim_type = TenantLocalExecutionClaim
        raw["claim_commitment"] = commitment(raw)
        claim = claim_type.model_validate(raw)

        # This call occurs while the authority source handoff lock remains held.
        # Once it returns, the participating sink is authoritative for subsequent
        # profile mutations. A sink that does not become authoritative cannot
        # claim the Worker 21 atomic profile.
        if provision is not None:
            provision(claim)
        return claim


def materialize_local_execution_claim(
    workflow: BoundedAuthorizationWorkflow,
    proposal: RuntimeProposal,
    decision: RuntimeDecision,
    *,
    now: datetime,
    claim_id: str | None = None,
    budget_id: str | None = None,
    expires_at: str | None = None,
    decision_input_commitment: str | None = None,
    decision_input_profile_version: str | None = None,
) -> LocalExecutionClaim:
    """Return a validated non-executable claim snapshot.

    This function uses the trusted resolver handoff while reading the final
    authority snapshot, but it does not transfer authority to an executor store.
    Use provision_local_execution_claim() for the enforceable local profile.
    """
    return _materialize_under_handoff(
        workflow, proposal, decision, now=now, claim_id=claim_id,
        budget_id=budget_id, expires_at=expires_at,
        decision_input_commitment=decision_input_commitment,
        decision_input_profile_version=decision_input_profile_version,
        provision=None,
    )


def provision_local_execution_claim(
    workflow: BoundedAuthorizationWorkflow,
    proposal: RuntimeProposal,
    decision: RuntimeDecision,
    *,
    provision: Callable[[LocalExecutionClaim], None],
    now: datetime,
    claim_id: str | None = None,
    budget_id: str | None = None,
    expires_at: str | None = None,
    decision_input_commitment: str | None = None,
    decision_input_profile_version: str | None = None,
) -> LocalExecutionClaim:
    """Atomically hand current authority to a participating local claim store.

    The resolver's authority_effect_handoff boundary MUST exclude every trusted
    authority-invalidating writer while final resolution, snapshot validation,
    claim construction, and sink provisioning occur. After provision() returns,
    the participating local store becomes authoritative for all subsequent
    grant/approval/policy/evidence changes claimed by this profile.
    """
    if not callable(provision):
        raise TypeError("provision must be callable")
    return _materialize_under_handoff(
        workflow, proposal, decision, now=now, claim_id=claim_id,
        budget_id=budget_id, expires_at=expires_at,
        decision_input_commitment=decision_input_commitment,
        decision_input_profile_version=decision_input_profile_version,
        provision=provision,
    )


def verify_local_execution_claim(
    claim: LocalExecutionClaim | TenantLocalExecutionClaim | dict[str, Any]
) -> bool:
    if isinstance(claim, LocalExecutionClaim):
        value = claim.model_dump(mode="json", exclude_none=False)
    else:
        value = copy.deepcopy(claim)
        try:
            if "tenant_id" in value or "authorization_generation" in value:
                TenantLocalExecutionClaim.model_validate(value)
            else:
                LocalExecutionClaim.model_validate(value)
        except Exception:
            return False
    supplied = value.pop("claim_commitment", None)
    if value.get("profile") != LOCAL_AUTHORITY_EFFECT_PROFILE:
        return False
    if value.get("source") != "trusted_control_plane_workflow":
        return False
    if value.get("authorizing_by_possession") is not False:
        return False

    approvals = value.get("approval_state")
    policies = value.get("policy_state")
    evidence = value.get("evidence_state")
    if not isinstance(approvals, list) or not isinstance(policies, list) or not isinstance(evidence, list):
        return False
    if value.get("approval_state_commitment") != commitment(approvals):
        return False
    if value.get("policy_state_commitment") != commitment(policies):
        return False
    if value.get("evidence_state_commitment") != commitment(evidence):
        return False

    authority_state = {
        "grant_id": value.get("grant_id"),
        "grant_revision": value.get("grant_revision"),
        "grant_status": value.get("grant_status"),
        "requirement_commitment": value.get("requirement_commitment"),
        "approvals": approvals,
        "policies": policies,
        "evidence": evidence,
    }
    if value.get("authority_state_commitment") != commitment(authority_state):
        return False
    return supplied == commitment(value)
