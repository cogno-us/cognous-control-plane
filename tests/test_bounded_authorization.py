"""Acceptance tests for the bounded authorization-to-effect pilot."""
from __future__ import annotations

import copy
import json
from pathlib import Path
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest

from agent_control_plane.bounded import (
    ApprovalStatus,
    BoundedAuthorizationWorkflow,
    BoundedRecordStore,
    ConflictStatus,
    EffectAttempt,
    EffectObservation,
    EvidenceStatus,
    GrantStatus,
    IdentityStatus,
    LocalRefundDestination,
    MandateStatus,
    ObservationPolicy,
    PolicyStatus,
    ReconciliationResult,
    RoleMappingStatus,
    RuntimeProposal,
    TenantAuthorizationBinding,
    TenantRuntimeProposal,
    SyntheticResolver,
    commitment,
)

NOW = datetime(2026, 10, 5, 19, 0, tzinfo=timezone.utc)


@pytest.fixture(autouse=True)
def _fixed_synthetic_clock(monkeypatch):
    import agent_control_plane.bounded as bounded_module
    monkeypatch.setattr(bounded_module, "_now", lambda: NOW)

PROFILE = "urn:cognous:alvorada:public-stack-profile:0.1.0"
INSTITUTION = "urn:cognous:institution:synthetic-customer-service"
ACTOR = "urn:cognous:identity:refund-agent-1"
PRINCIPAL = "urn:cognous:principal:refund-service"
ISSUER = "urn:cognous:principal:synthetic-governor"
ISSUER_ROLE = "urn:cognous:role:refund-governor"
POLICY_REF = "urn:cognous:policy:refund-policy"
POLICY_VERSION = "1.0"


FIXTURE = Path(__file__).parent / "fixtures" / "refund_integration_v1_1.manifest.json"


def manifest():
    return json.loads(FIXTURE.read_text(encoding="utf-8"))

def proposal(tier="T1", *, correlation_id="case-1"):
    m = manifest()
    if tier == "T1":
        action_id = "urn:cognous:action:refund-issue-routine-v1"
        target = "urn:cognous:synthetic-account:customer-001"
        payload = {"customer_id": "customer-001", "refund_reason": "duplicate"}
        perm = "refund.issue.routine"
        amount = 50.0
        requirement = "urn:cognous:authority-requirement:refund-routine-v1"
    else:
        action_id = "urn:cognous:action:refund-issue-high-v1"
        target = "urn:cognous:synthetic-account:customer-002"
        payload = {
            "customer_id": "customer-002",
            "refund_reason": "service failure",
            "case_reference": "case-002",
        }
        perm = "refund.issue.high"
        amount = 500.0
        requirement = "urn:cognous:authority-requirement:refund-high-v1"
    return RuntimeProposal(
        manifest_id=m["manifest_id"],
        manifest_version=m["manifest_version"],
        manifest_digest=commitment(m),
        actor=ACTOR,
        principal=PRINCIPAL,
        action_id=action_id,
        adapter_id="urn:cognous:adapter:synthetic-refund-v1",
        target=target,
        payload=payload,
        payload_commitment=commitment(payload),
        requested_permissions=[perm],
        amount=amount,
        unit="USD",
        effects=1,
        authority_context_ref=PROFILE,
        requirement_id=requirement,
        correlation_id=correlation_id,
        run_id="run-1",
        evidence_refs=["urn:cognous:evidence:refund-entitlement"],
    )


def authority_context(p, *, tier="T1", with_grant=True, delegated=False):
    role = (
        "urn:cognous:role:customer-service-supervisor"
        if tier == "T1"
        else "urn:cognous:role:refund-authorizer"
    )
    action_name = "refund_issue_routine" if tier == "T1" else "refund_issue_high_consequence"
    grant_id = "urn:cognous:grant:routine-1" if tier == "T1" else "urn:cognous:grant:high-1"
    evidence = [{
        "obligation_id": "urn:cognous:evidence:refund-entitlement",
        "kind": "authorization",
        "source_ref": "urn:cognous:source:entitlement",
        "max_age_seconds": 300,
        "required": True,
        "unknown_behavior": "hold_effect",
    }]
    if tier == "T2":
        evidence.append({
            "obligation_id": "urn:cognous:evidence:refund-approval",
            "kind": "authorization",
            "source_ref": "urn:cognous:source:approval",
            "max_age_seconds": 300,
            "required": True,
            "unknown_behavior": "hold_effect",
        })
    evidence.append({
        "obligation_id": "urn:cognous:evidence:optional-context",
        "kind": "context",
        "source_ref": "urn:cognous:source:optional",
        "max_age_seconds": 300,
        "required": False,
        "unknown_behavior": "preserve_if_other_basis_suffices",
    })
    context = {
        "schema_version": "0.1.0",
        "interface_status": "proposed_pending_governor_review",
        "context_id": "urn:cognous:authority-context:pilot-1",
        "institution": {
            "institution_id": INSTITUTION,
            "authority_domain": "customer-refunds",
            "authority_basis_ref": "urn:cognous:authority-basis:synthetic",
            "authority_mode": "principle_inspired",
        },
        "principal": PRINCIPAL,
        "acting_identity": ACTOR,
        "accountable_human_role": {
            "role_id": "urn:cognous:role:accountable-human",
            "human_principal": "urn:cognous:principal:human-1",
            "mandate_ref": "urn:cognous:mandate:human-1",
        },
        "requirement": {
            "requirement_id": p.requirement_id,
            "governing_sources": [{
                "ref": "urn:cognous:policy:refund-policy",
                "version": POLICY_VERSION,
                "provision": "refund",
                "standing": "local_policy",
            }],
            "permissions": [{
                "action": action_name,
                "targets": [p.target],
                "data_scopes": list(p.requested_permissions),
                "max_amount": 100.0 if tier == "T1" else 1000.0,
                "unit": "USD",
                "max_effects": 1,
            }],
            "approvals": [{"role_id": role, "independent_of_actor": True}],
            "evidence": evidence,
            "consequence": {
                "tier": tier,
                "rationale": "Synthetic test tier.",
                "profile_ref": f"urn:cognous:consequence:{tier}",
            },
        },
        "conflicts": {
            "precedence_refs": ["urn:cognous:policy:refund-policy"],
            "incompatible_role_pairs": [],
            "escalation_ref": "urn:cognous:procedure:escalation",
            "appeal_ref": "urn:cognous:procedure:appeal",
            "continuity_ref": "urn:cognous:procedure:continuity",
            "remedy_ref": "urn:cognous:procedure:remedy",
        },
        "supporting_evidence_refs": [],
        "change": {"kind": "none", "proposal_ref": None, "adoption_record_ref": None},
    }
    if with_grant:
        context["grant"] = {
            "grant_id": grant_id,
            "revision": "1",
            "requirement_id": p.requirement_id,
            "issuer": ISSUER,
            "issuer_role": ISSUER_ROLE,
            "issuance_record_ref": "urn:cognous:issuance:1",
            "grantee": PRINCIPAL,
            "acting_identity": ACTOR,
            "issued_at": (NOW - timedelta(hours=1)).isoformat(),
            "not_before": (NOW - timedelta(minutes=30)).isoformat(),
            "expires_at": (NOW + timedelta(hours=1)).isoformat(),
            "status_ref": "urn:cognous:status:grant-1",
            "policy_versions": [{"ref": POLICY_REF, "version": POLICY_VERSION}],
            "permissions": [{
                "action": action_name,
                "targets": [p.target],
                "data_scopes": list(p.requested_permissions),
                "max_amount": 100.0 if tier == "T1" else 1000.0,
                "unit": "USD",
                "max_effects": 1,
            }],
            "delegation": {
                "parent_grant_id": "urn:cognous:grant:parent" if delegated else None,
                "may_delegate": False,
                "remaining_depth": 0,
            },
            "approval_refs": [f"urn:cognous:approval:{tier.lower()}-1"],
        }
    return context


def resolver_for(p, *, tier="T1", with_grant=True, delegated=False):
    ctx = authority_context(p, tier=tier, with_grant=with_grant, delegated=delegated)
    statuses = {}
    approvals = {}
    if with_grant:
        grant = ctx["grant"]
        statuses[grant["grant_id"]] = GrantStatus(
            grant_id=grant["grant_id"],
            revision=grant["revision"],
            status="active",
            observed_at=NOW.isoformat(),
            version="status-v1",
            status_ref=grant["status_ref"],
            authority_basis_ref="urn:cognous:authority-basis:synthetic",
            institution_id=INSTITUTION,
            authority_domain="customer-refunds",
        )
        role = ctx["requirement"]["approvals"][0]["role_id"]
        approval_ref = grant["approval_refs"][0]
        approvals[approval_ref] = ApprovalStatus(
            approval_ref=approval_ref,
            role_id=role,
            approver="urn:cognous:principal:reviewer-1",
            grant_id=grant["grant_id"],
            grant_revision=grant["revision"],
            proposal_commitment=commitment(p.model_dump(mode="json", exclude_none=False)),
            policy_versions=copy.deepcopy(grant["policy_versions"]),
            observed_at=NOW.isoformat(),
            institution_id=INSTITUTION,
            authority_domain="customer-refunds",
        )
    aliases = {
        "customer-service-supervisor": ["urn:cognous:role:customer-service-supervisor"],
        "refund-authorizer": ["urn:cognous:role:refund-authorizer"],
    }
    mapping = RoleMappingStatus(
        institution_id=INSTITUTION,
        version="roles-v1",
        digest=commitment({
            "institution_id": INSTITUTION,
            "version": "roles-v1",
            "aliases": aliases,
        }),
        aliases=aliases,
    )
    return SyntheticResolver(
        contexts={PROFILE: ctx},
        statuses=statuses,
        identities={
            ACTOR: IdentityStatus(
                identity=ACTOR,
                principal=PRINCIPAL,
                authenticated=True,
                delegation_valid=True,
                observed_at=NOW.isoformat(),
                institution_id=INSTITUTION,
                authority_domain="customer-refunds",
                chain=["urn:cognous:grant:parent"] if delegated else [],
            )
        },
        mandates={
            f"{ISSUER}|{ISSUER_ROLE}": MandateStatus(
                issuer=ISSUER,
                issuer_role=ISSUER_ROLE,
                issuance_record_ref=ctx["grant"]["issuance_record_ref"] if with_grant else "urn:cognous:issuance:none",
                mandate_valid=True,
                observed_at=NOW.isoformat(),
                institution_id=INSTITUTION,
                authority_domain="customer-refunds",
            )
        },
        approvals=approvals,
        policies={
            POLICY_REF: PolicyStatus(
                ref=POLICY_REF,
                version=POLICY_VERSION,
                status="active",
                observed_at=NOW.isoformat(),
                institution_id=INSTITUTION,
                authority_domain="customer-refunds",
            )
        },
        conflicts={
            p.requirement_id: ConflictStatus(
                requirement_id=p.requirement_id,
                state="clear",
                observed_at=NOW.isoformat(),
                conflict_refs=copy.deepcopy(ctx["conflicts"]["precedence_refs"]),
                institution_id=INSTITUTION,
                authority_domain="customer-refunds",
            )
        },
        role_mappings={INSTITUTION: mapping},
        evidence={
            "urn:cognous:evidence:refund-entitlement": EvidenceStatus(
                obligation_id="urn:cognous:evidence:refund-entitlement",
                state="current",
                observed_at=NOW.isoformat(),
                source_ref="urn:cognous:source:entitlement",
                institution_id=INSTITUTION,
                authority_domain="customer-refunds",
            ),
            "urn:cognous:evidence:refund-approval": EvidenceStatus(
                obligation_id="urn:cognous:evidence:refund-approval",
                state="current",
                observed_at=NOW.isoformat(),
                source_ref="urn:cognous:source:approval",
                institution_id=INSTITUTION,
                authority_domain="customer-refunds",
            ),
            "urn:cognous:evidence:optional-context": EvidenceStatus(
                obligation_id="urn:cognous:evidence:optional-context",
                state="unknown",
                observed_at=NOW.isoformat(),
                source_ref="urn:cognous:source:optional",
                institution_id=INSTITUTION,
                authority_domain="customer-refunds",
            ),
        },
    )


def workflow(tmp_path, p, *, tier="T1", resolver=None):
    resolver = resolver or resolver_for(p, tier=tier)
    return BoundedAuthorizationWorkflow(
        allow_test_time=True,
        manifest=manifest(),
        resolver=resolver,
        destination=LocalRefundDestination(tmp_path / "destination.json"),
        records=BoundedRecordStore(tmp_path / "run.json", "run-1"),
        observation_policy=ObservationPolicy(max_age_seconds=300, clock_tolerance_seconds=5),
    )


def test_valid_t1_succeeds_and_changes_destination(tmp_path):
    p = proposal()
    flow = workflow(tmp_path, p)
    decision = flow.decide(p, now=NOW)
    assert decision.result == "authorized"

    attempt, observed = flow.execute(
        p, decision, adapter_id=p.adapter_id, now=NOW
    )
    assert attempt.status == "acknowledged"
    assert observed.state == "applied"
    assert observed.destination_state["amount"] == 50.0
    assert len(flow.destination.snapshot()["effects"]) == 1


def test_t2_requires_additional_approval(tmp_path):
    p = proposal("T2")
    r = resolver_for(p, tier="T2")
    r.approvals.clear()
    decision = workflow(tmp_path, p, tier="T2", resolver=r).decide(p, now=NOW)
    assert decision.result == "hold"
    assert "required_approval_missing" in decision.reasons


def test_requirement_only_or_copied_verification_json_cannot_authorize(tmp_path):
    p = proposal()
    r = resolver_for(p, with_grant=False)
    r.contexts[PROFILE]["supporting_evidence_refs"] = [
        "urn:cognous:bitrep:verification-result:copied-json",
        "urn:cognous:index:block:included",
    ]
    decision = workflow(tmp_path, p, resolver=r).decide(p, now=NOW)
    assert decision.result == "hold"
    assert "issued_grant_missing" in decision.reasons


@pytest.mark.parametrize("field", ["payload", "target", "actor", "adapter", "manifest"])
def test_substitution_prevents_effect(tmp_path, field):
    p = proposal()
    flow = workflow(tmp_path, p)
    decision = flow.decide(p, now=NOW)
    assert decision.result == "authorized"
    mutated = p.model_copy(deep=True)
    adapter_id = p.adapter_id
    if field == "payload":
        mutated.payload["refund_reason"] = "changed"
    elif field == "target":
        mutated.target = "urn:cognous:synthetic-account:attacker"
    elif field == "actor":
        mutated.actor = "urn:cognous:identity:other"
    elif field == "adapter":
        adapter_id = "urn:cognous:adapter:other"
    else:
        mutated.manifest_digest = "sha256:" + "0" * 64
    with pytest.raises(PermissionError):
        flow.execute(mutated, decision, adapter_id=adapter_id, now=NOW)
    assert flow.destination.snapshot()["effects"] == {}


def test_revocation_expiry_stale_status_and_policy_change_hold(tmp_path):
    p = proposal()
    r = resolver_for(p)
    grant = r.contexts[PROFILE]["grant"]

    r.statuses[grant["grant_id"]].status = "revoked"
    assert "grant_not_active" in workflow(tmp_path / "a", p, resolver=r).decide(p, now=NOW).reasons

    r = resolver_for(p)
    r.contexts[PROFILE]["grant"]["expires_at"] = (NOW - timedelta(seconds=1)).isoformat()
    assert "grant_outside_validity" in workflow(tmp_path / "b", p, resolver=r).decide(p, now=NOW).reasons

    r = resolver_for(p)
    r.statuses[grant["grant_id"]].observed_at = (NOW - timedelta(minutes=5)).isoformat()
    assert "grant_status_stale_or_future" in workflow(tmp_path / "c", p, resolver=r).decide(p, now=NOW).reasons

    r = resolver_for(p)
    r.policies[POLICY_REF].version = "2.0"
    assert "policy_stale_or_changed" in workflow(tmp_path / "d", p, resolver=r).decide(p, now=NOW).reasons


def test_delegation_cannot_widen_or_survive_invalid_parent(tmp_path):
    p = proposal()
    r = resolver_for(p, delegated=True)
    r.identities[ACTOR].delegation_valid = False
    decision = workflow(tmp_path / "a", p, resolver=r).decide(p, now=NOW)
    assert "identity_or_delegation_invalid" in decision.reasons

    base = proposal()
    r2 = resolver_for(base, delegated=True)
    p2 = base.model_copy(deep=True)
    p2.requested_permissions.append("refund.issue.admin")
    approval_ref = r2.contexts[PROFILE]["grant"]["approval_refs"][0]
    r2.approvals[approval_ref].proposal_commitment = commitment(
        p2.model_dump(mode="json", exclude_none=False)
    )
    decision2 = workflow(tmp_path / "b", p2, resolver=r2).decide(p2, now=NOW)
    assert decision2.result == "hold"
    assert "grant_scope_mismatch" in decision2.reasons


def test_stale_required_evidence_holds_but_optional_unknown_does_not(tmp_path):
    p = proposal()
    r = resolver_for(p)
    r.evidence["urn:cognous:evidence:refund-entitlement"].observed_at = (
        NOW - timedelta(minutes=10)
    ).isoformat()
    decision = workflow(tmp_path / "a", p, resolver=r).decide(p, now=NOW)
    assert "required_evidence_stale_or_future" in decision.reasons

    r2 = resolver_for(p)
    decision2 = workflow(tmp_path / "b", p, resolver=r2).decide(p, now=NOW)
    assert decision2.result == "authorized"


def test_unresolved_conflict_holds_effect(tmp_path):
    p = proposal()
    r = resolver_for(p)
    r.conflicts[p.requirement_id].state = "conflict"
    decision = workflow(tmp_path, p, resolver=r).decide(p, now=NOW)
    assert decision.result == "hold"
    assert "authority_conflict_unresolved" in decision.reasons


def test_wrong_evidence_source_binding_holds_and_no_effect(tmp_path):
    p = proposal()
    r = resolver_for(p)
    r.evidence["urn:cognous:evidence:refund-entitlement"].source_ref = "urn:wrong:source"
    flow = workflow(tmp_path, p, resolver=r)
    decision = flow.decide(p, now=NOW)
    assert decision.result == "hold"
    assert "evidence_binding_mismatch" in decision.reasons
    assert flow.destination.snapshot()["effects"] == {}


def test_stale_approval_identity_and_mandate_hold(tmp_path):
    p = proposal()

    r = resolver_for(p)
    approval_ref = r.contexts[PROFILE]["grant"]["approval_refs"][0]
    r.approvals[approval_ref].observed_at = (NOW - timedelta(days=365)).isoformat()
    flow = workflow(tmp_path / "approval", p, resolver=r)
    d = flow.decide(p, now=NOW)
    assert "approval_status_stale_or_future" in d.reasons
    assert flow.destination.snapshot()["effects"] == {}

    r = resolver_for(p)
    r.identities[ACTOR].observed_at = (NOW - timedelta(days=365)).isoformat()
    flow = workflow(tmp_path / "identity", p, resolver=r)
    d = flow.decide(p, now=NOW)
    assert "identity_status_stale_or_future" in d.reasons
    assert flow.destination.snapshot()["effects"] == {}

    r = resolver_for(p)
    r.mandates[f"{ISSUER}|{ISSUER_ROLE}"].observed_at = (NOW - timedelta(days=365)).isoformat()
    flow = workflow(tmp_path / "mandate", p, resolver=r)
    d = flow.decide(p, now=NOW)
    assert "issuer_mandate_stale_or_future" in d.reasons
    assert flow.destination.snapshot()["effects"] == {}


def test_resolver_record_identifier_binding_is_enforced(tmp_path):
    p = proposal()
    r = resolver_for(p)
    grant_id = r.contexts[PROFILE]["grant"]["grant_id"]
    r.statuses[grant_id].grant_id = "urn:wrong:grant"
    flow = workflow(tmp_path / "grant", p, resolver=r)
    d = flow.decide(p, now=NOW)
    assert "grant_status_binding_mismatch" in d.reasons
    assert flow.destination.snapshot()["effects"] == {}

    r = resolver_for(p)
    grant_id = r.contexts[PROFILE]["grant"]["grant_id"]
    r.statuses[grant_id].status_ref = "urn:wrong:status"
    d = workflow(tmp_path / "status-ref", p, resolver=r).decide(p, now=NOW)
    assert "grant_status_binding_mismatch" in d.reasons

    r = resolver_for(p)
    r.mandates[f"{ISSUER}|{ISSUER_ROLE}"].issuance_record_ref = "urn:wrong:issuance"
    d = workflow(tmp_path / "mandate-ref", p, resolver=r).decide(p, now=NOW)
    assert "issuer_mandate_binding_mismatch" in d.reasons

    r = resolver_for(p)
    r.conflicts[p.requirement_id].conflict_refs = ["urn:wrong:precedence"]
    d = workflow(tmp_path / "conflict-ref", p, resolver=r).decide(p, now=NOW)
    assert "conflict_status_binding_mismatch" in d.reasons

    r = resolver_for(p)
    r.policies[POLICY_REF].ref = "urn:wrong:policy"
    d = workflow(tmp_path / "policy", p, resolver=r).decide(p, now=NOW)
    assert "policy_binding_mismatch" in d.reasons

    r = resolver_for(p)
    r.conflicts[p.requirement_id].requirement_id = "urn:wrong:requirement"
    d = workflow(tmp_path / "conflict", p, resolver=r).decide(p, now=NOW)
    assert "conflict_status_binding_mismatch" in d.reasons

    r = resolver_for(p)
    approval_ref = r.contexts[PROFILE]["grant"]["approval_refs"][0]
    r.approvals[approval_ref].approval_ref = "urn:wrong:approval"
    d = workflow(tmp_path / "approval", p, resolver=r).decide(p, now=NOW)
    assert "approval_binding_mismatch" in d.reasons

    r = resolver_for(p)
    r.mandates[f"{ISSUER}|{ISSUER_ROLE}"].issuer = "urn:wrong:issuer"
    d = workflow(tmp_path / "mandate", p, resolver=r).decide(p, now=NOW)
    assert "issuer_mandate_binding_mismatch" in d.reasons


def test_future_resolver_timestamp_beyond_clock_tolerance_holds(tmp_path):
    p = proposal()
    r = resolver_for(p)
    grant_id = r.contexts[PROFILE]["grant"]["grant_id"]
    r.statuses[grant_id].observed_at = (NOW + timedelta(seconds=6)).isoformat()
    flow = workflow(tmp_path, p, resolver=r)
    d = flow.decide(p, now=NOW)
    assert d.result == "hold"
    assert "grant_status_stale_or_future" in d.reasons
    assert flow.destination.snapshot()["effects"] == {}


def test_requirement_narrower_than_grant_holds(tmp_path):
    p = proposal()
    r = resolver_for(p)
    r.contexts[PROFILE]["requirement"]["permissions"][0]["max_amount"] = 1.0
    flow = workflow(tmp_path, p, resolver=r)
    d = flow.decide(p, now=NOW)
    assert d.result == "hold"
    assert "requirement_scope_mismatch" in d.reasons
    assert flow.destination.snapshot()["effects"] == {}


def test_mutated_effect_or_binding_cannot_execute(tmp_path):
    p = proposal()
    flow = workflow(tmp_path, p)
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized"

    mutated = d.model_copy(deep=True)
    mutated.effect_id = "caller-chosen-effect"
    with pytest.raises(PermissionError):
        flow.execute(p, mutated, adapter_id=p.adapter_id, now=NOW)
    assert flow.destination.snapshot()["effects"] == {}

    mutated2 = d.model_copy(deep=True)
    mutated2.binding.target = "urn:cognous:synthetic-account:attacker"
    with pytest.raises(PermissionError):
        flow.execute(p, mutated2, adapter_id=p.adapter_id, now=NOW)
    assert flow.destination.snapshot()["effects"] == {}


def test_role_mapping_is_versioned_scoped_and_revalidated(tmp_path):
    p = proposal()
    r = resolver_for(p)
    flow = workflow(tmp_path, p, resolver=r)
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized"

    mapping = r.role_mappings[INSTITUTION]
    mapping.version = "roles-v2"
    mapping.digest = commitment({
        "institution_id": INSTITUTION,
        "version": mapping.version,
        "aliases": mapping.aliases,
    })
    with pytest.raises(PermissionError):
        flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert flow.destination.snapshot()["effects"] == {}

    r2 = resolver_for(p)
    r2.role_mappings[INSTITUTION].aliases["customer-service-supervisor"] = [
        "urn:cognous:role:customer-service-supervisor",
        "urn:cognous:role:ambiguous",
    ]
    r2.role_mappings[INSTITUTION].digest = commitment({
        "institution_id": INSTITUTION,
        "version": r2.role_mappings[INSTITUTION].version,
        "aliases": r2.role_mappings[INSTITUTION].aliases,
    })
    d2 = workflow(tmp_path / "ambiguous", p, resolver=r2).decide(p, now=NOW)
    assert d2.result == "hold"
    assert "review_requirement_not_resolved" in d2.reasons


def test_changed_policy_after_decision_prevents_effect(tmp_path):
    p = proposal()
    r = resolver_for(p)
    flow = workflow(tmp_path, p, resolver=r)
    decision = flow.decide(p, now=NOW)
    r.policies[POLICY_REF].version = "2.0"
    with pytest.raises(PermissionError):
        flow.execute(p, decision, adapter_id=p.adapter_id, now=NOW)
    assert flow.destination.snapshot()["effects"] == {}


def test_lost_ack_restart_reconciles_without_duplicate(tmp_path):
    p = proposal()
    r = resolver_for(p)
    flow = workflow(tmp_path, p, resolver=r)
    decision = flow.decide(p, now=NOW)
    attempt, observed = flow.execute(
        p, decision, adapter_id=p.adapter_id, now=NOW, lose_ack=True
    )
    assert attempt.status == "unknown"
    assert observed.state == "applied"

    restarted = BoundedAuthorizationWorkflow(
        allow_test_time=True,
        manifest=manifest(),
        resolver=r,
        destination=LocalRefundDestination(tmp_path / "destination.json"),
        records=BoundedRecordStore(tmp_path / "run.json", "run-1"),
        observation_policy=ObservationPolicy(max_age_seconds=300, clock_tolerance_seconds=5),
    )
    assert restarted.reconcile(decision.effect_id, now=NOW).result == "applied"
    retry, observed2 = restarted.execute(
        p, decision, adapter_id=p.adapter_id, now=NOW
    )
    assert retry.status == "acknowledged"
    assert retry.acknowledgement["reconciled_existing"] is True
    assert observed2.state == "applied"
    assert len(restarted.destination.snapshot()["effects"]) == 1
    assert restarted.records.load().decisions[0].decision_id == decision.decision_id


def test_partial_delivery_holds_instead_of_blind_retry(tmp_path):
    p = proposal()
    flow = workflow(tmp_path, p)
    decision = flow.decide(p, now=NOW)
    attempt, observed = flow.execute(
        p, decision, adapter_id=p.adapter_id, now=NOW, partial=True
    )
    assert attempt.status == "partial"
    assert observed.state == "partial"
    assert flow.reconcile(decision.effect_id, now=NOW).result == "hold"
    retry, observed2 = flow.execute(p, decision, adapter_id=p.adapter_id, now=NOW)
    assert retry.status == "partial"
    assert observed2.state == "partial"
    assert len(flow.destination.snapshot()["effects"]) == 1


def test_duplicate_submission_does_not_duplicate_effect(tmp_path):
    p = proposal()
    flow = workflow(tmp_path, p)
    decision = flow.decide(p, now=NOW)
    first, _ = flow.execute(p, decision, adapter_id=p.adapter_id, now=NOW)
    second, _ = flow.execute(p, decision, adapter_id=p.adapter_id, now=NOW)
    assert first.status == "acknowledged"
    assert second.acknowledgement["reconciled_existing"] is True
    assert first.attempt_id != second.attempt_id
    assert len(flow.destination.snapshot()["effects"]) == 1


def test_concurrent_distinct_effects_respect_local_cumulative_cap(tmp_path):
    p1 = proposal(correlation_id="case-1")
    p2 = proposal(correlation_id="case-2")
    r = resolver_for(p1)
    approval_ref = r.contexts[PROFILE]["grant"]["approval_refs"][0]
    p2_commitment = commitment(p2.model_dump(mode="json", exclude_none=False))

    # One synthetic approval record can only bind one operation, so replace it
    # immediately before each decision, then execute both already-authorized
    # effects concurrently against the same local grant budget.
    flow = workflow(tmp_path, p1, resolver=r)
    d1 = flow.decide(p1, now=NOW)
    r.approvals[approval_ref].proposal_commitment = p2_commitment
    d2 = flow.decide(p2, now=NOW)
    assert d1.result == d2.result == "authorized"

    # Restore independent operation binding for revalidation by using two
    # resolver views that share the same destination but distinct approvals.
    r1 = resolver_for(p1)
    r2 = resolver_for(p2)
    f1 = BoundedAuthorizationWorkflow(
        allow_test_time=True,
        manifest=manifest(), resolver=r1, destination=flow.destination,
        records=BoundedRecordStore(tmp_path / "run1.json", "run-1"),
        observation_policy=ObservationPolicy(max_age_seconds=300, clock_tolerance_seconds=5),
    )
    f2 = BoundedAuthorizationWorkflow(
        allow_test_time=True,
        manifest=manifest(), resolver=r2, destination=flow.destination,
        records=BoundedRecordStore(tmp_path / "run2.json", "run-2"),
        observation_policy=ObservationPolicy(max_age_seconds=300, clock_tolerance_seconds=5),
    )
    d1 = f1.decide(p1, now=NOW)
    d2 = f2.decide(p2, now=NOW)

    def run(f, p, d):
        return f.execute(p, d, adapter_id=p.adapter_id, now=NOW)[0].status

    with ThreadPoolExecutor(max_workers=2) as pool:
        statuses = list(pool.map(lambda args: run(*args), [(f1, p1, d1), (f2, p2, d2)]))
    assert sorted(statuses) == ["acknowledged", "failed"]
    state = flow.destination.snapshot()
    assert len(state["effects"]) == 1
    grant_id = r.contexts[PROFILE]["grant"]["grant_id"]
    assert state["grant_effect_counts"][grant_id] == 1


class ObservationProxy:
    """Test adapter that injects one observation without implementing dispatch semantics."""

    def __init__(self, base, *, observation=None, error=None):
        self.base = base
        self.observation = observation
        self.error = error

    def observe(self, effect_id):
        if self.error is not None:
            raise self.error
        return self.observation.model_copy(deep=True)

    def apply(self, **kwargs):
        return self.base.apply(**kwargs)

    def snapshot(self):
        return self.base.snapshot()


def observation_workflow(tmp_path, observation, *, policy=True, error=None):
    p = proposal()
    resolver = resolver_for(p)
    base = LocalRefundDestination(tmp_path / "destination.json")
    records = BoundedRecordStore(tmp_path / "run.json", "observation-run")
    return (
        base,
        records,
        BoundedAuthorizationWorkflow(
        allow_test_time=True,
            manifest=manifest(),
            resolver=resolver,
            destination=ObservationProxy(base, observation=observation, error=error),
            records=records,
            observation_policy=(
                ObservationPolicy(max_age_seconds=300, clock_tolerance_seconds=5)
                if policy else None
            ),
        ),
    )


@pytest.mark.parametrize(
    ("observation", "reason"),
    [
        (
            EffectObservation(
                effect_id="effect-1",
                observed_at=(NOW - timedelta(seconds=301)).isoformat(),
                state="absent",
                destination_state={},
            ),
            "observation_stale",
        ),
        (
            EffectObservation(
                effect_id="effect-1",
                observed_at=None,
                state="absent",
                destination_state={},
            ),
            "observation_time_missing",
        ),
        (
            EffectObservation(
                effect_id="different-effect",
                observed_at=NOW.isoformat(),
                state="absent",
                destination_state={},
            ),
            "observation_effect_id_mismatch",
        ),
    ],
)
def test_invalid_absence_evidence_holds_and_is_retained(tmp_path, observation, reason):
    base, records, flow = observation_workflow(tmp_path, observation)
    before = base.snapshot()
    result = flow.reconcile("effect-1", now=NOW)
    assert result.result == "hold"
    assert result.retry_eligible is False
    assert result.observation_accepted is False
    assert reason in result.reasons
    assert result.observation is not None
    assert records.load().observations == []
    assert records.load().reconciliations[-1].reasons == result.reasons
    assert base.snapshot() == before


def test_missing_observation_age_policy_holds(tmp_path):
    observation = EffectObservation(
        effect_id="effect-1",
        observed_at=NOW.isoformat(),
        state="absent",
        destination_state={},
    )
    base, records, flow = observation_workflow(tmp_path, observation, policy=False)
    before = base.snapshot()
    result = flow.reconcile("effect-1", now=NOW)
    assert result.result == "hold"
    assert "observation_policy_missing" in result.reasons
    assert result.observation_accepted is False
    assert records.load().observations == []
    assert base.snapshot() == before


@pytest.mark.parametrize(
    ("observed_at", "reason"),
    [
        ("not-a-timestamp", "observation_time_malformed"),
        ("2026-10-05T19:00:00", "observation_time_timezone_missing"),
        ((NOW + timedelta(seconds=6)).isoformat(), "observation_time_future"),
    ],
)
def test_invalid_observation_time_holds(tmp_path, observed_at, reason):
    observation = EffectObservation(
        effect_id="effect-1",
        observed_at=observed_at,
        state="absent",
        destination_state={},
    )
    base, records, flow = observation_workflow(tmp_path, observation)
    result = flow.reconcile("effect-1", now=NOW)
    assert result.result == "hold"
    assert reason in result.reasons
    assert result.observation_accepted is False
    assert records.load().observations == []
    assert base.snapshot()["effects"] == {}


def test_missing_or_untrusted_evaluation_time_holds(tmp_path):
    observation = EffectObservation(
        effect_id="effect-1",
        observed_at=NOW.isoformat(),
        state="absent",
        destination_state={},
    )
    _, _, flow = observation_workflow(tmp_path / "missing", observation)
    missing = flow.reconcile("effect-1")
    assert missing.result == "hold"
    assert "evaluation_time_missing" in missing.reasons

    _, _, flow2 = observation_workflow(tmp_path / "naive", observation)
    naive = flow2.reconcile("effect-1", now=NOW.replace(tzinfo=None))
    assert naive.result == "hold"
    assert "evaluation_time_timezone_missing" in naive.reasons


def test_unknown_and_unavailable_observation_hold_without_mutation(tmp_path):
    unknown = EffectObservation(
        effect_id="effect-1",
        observed_at=NOW.isoformat(),
        state="unknown",
        destination_state={},
    )
    base, records, flow = observation_workflow(tmp_path / "unknown", unknown)
    before = base.snapshot()
    result = flow.reconcile("effect-1", now=NOW)
    assert result.result == "hold"
    assert "observation_state_unknown" in result.reasons
    assert result.observation_accepted is False
    assert records.load().observations == []
    assert base.snapshot() == before

    base2, records2, flow2 = observation_workflow(
        tmp_path / "unavailable",
        unknown,
        error=OSError("observation channel unavailable"),
    )
    before2 = base2.snapshot()
    unavailable = flow2.reconcile("effect-1", now=NOW)
    assert unavailable.result == "hold"
    assert unavailable.observation is None
    assert unavailable.retry_eligible is False
    assert "observation_unavailable:OSError" in unavailable.reasons
    assert records2.load().observations == []
    assert base2.snapshot() == before2


def test_fresh_matching_applied_and_absent_are_distinct_facts(tmp_path):
    applied = EffectObservation(
        effect_id="effect-1",
        observed_at=NOW.isoformat(),
        state="applied",
        destination_state={"effect_id": "effect-1", "state": "applied"},
    )
    base, records, flow = observation_workflow(tmp_path / "applied", applied)
    before = base.snapshot()
    result = flow.reconcile("effect-1", now=NOW)
    assert result.result == "applied"
    assert result.observation_accepted is True
    assert result.retry_eligible is False
    assert records.load().observations[-1].state == "applied"
    assert base.snapshot() == before

    absent = EffectObservation(
        effect_id="effect-2",
        observed_at=NOW.isoformat(),
        state="absent",
        destination_state={},
    )
    base2, records2, flow2 = observation_workflow(tmp_path / "absent", absent)
    before2 = base2.snapshot()
    result2 = flow2.reconcile("effect-2", now=NOW)
    assert result2.result == "observed_absent"
    assert result2.observation_accepted is True
    assert result2.retry_eligible is False
    assert "safe_to_retry" != result2.result
    assert records2.load().observations[-1].state == "absent"
    assert base2.snapshot() == before2


@pytest.mark.parametrize(
    "observation",
    [
        EffectObservation(
            effect_id="wrong-effect",
            observed_at=NOW.isoformat(),
            state="applied",
            destination_state={"effect_id": "effect-1", "state": "applied"},
        ),
        EffectObservation(
            effect_id="effect-1",
            observed_at=NOW.isoformat(),
            state="applied",
            destination_state={"effect_id": "wrong-effect", "state": "applied"},
        ),
        EffectObservation(
            effect_id="effect-1",
            observed_at=NOW.isoformat(),
            state="applied",
            destination_state={"effect_id": "effect-1", "state": "partial"},
        ),
    ],
)
def test_invalid_positive_observation_cannot_establish_applied(tmp_path, observation):
    base, records, flow = observation_workflow(tmp_path, observation)
    result = flow.reconcile("effect-1", now=NOW)
    assert result.result == "hold"
    assert result.observation_accepted is False
    assert records.load().observations == []
    assert base.snapshot()["effects"] == {}


def test_historical_safe_to_retry_record_is_parseable_but_not_retry_permission(tmp_path):
    historical = ReconciliationResult.model_validate({
        "effect_id": "effect-1",
        "reconciled_at": NOW.isoformat(),
        "result": "safe_to_retry",
        "observation": {
            "effect_id": "effect-1",
            "observed_at": NOW.isoformat(),
            "state": "absent",
            "destination_state": {},
        },
    })
    assert historical.result == "safe_to_retry"
    assert historical.retry_eligible is False
    base = LocalRefundDestination(tmp_path / "destination.json")
    before = base.snapshot()
    records = BoundedRecordStore(tmp_path / "run.json", "history")
    records.append_reconciliation(historical)
    assert records.load().reconciliations[-1].result == "safe_to_retry"
    assert records.load().reconciliations[-1].retry_eligible is False
    assert base.snapshot() == before


def test_observed_absent_after_prior_attempt_does_not_enable_dispatch(tmp_path):
    p = proposal()
    flow = workflow(tmp_path, p)
    decision = flow.decide(p, now=NOW)
    flow.records.append_attempt(EffectAttempt(
        attempt_id="attempt-prior",
        effect_id=decision.effect_id,
        decision_id=decision.decision_id,
        started_at=NOW.isoformat(),
        status="unknown",
    ))
    before = flow.destination.snapshot()
    with pytest.raises(PermissionError, match="observed absence does not establish retry eligibility"):
        flow.execute(p, decision, adapter_id=p.adapter_id, now=NOW)
    assert flow.destination.snapshot() == before
    latest = flow.records.load().reconciliations[-1]
    assert latest.result == "observed_absent"
    assert latest.retry_eligible is False


def test_missing_observation_policy_blocks_initial_dispatch(tmp_path):
    p = proposal()
    resolver = resolver_for(p)
    destination = LocalRefundDestination(tmp_path / "destination.json")
    flow = BoundedAuthorizationWorkflow(
        allow_test_time=True,
        manifest=manifest(),
        resolver=resolver,
        destination=destination,
        records=BoundedRecordStore(tmp_path / "run.json", "missing-policy"),
    )
    decision = flow.decide(p, now=NOW)
    assert decision.result == "authorized"
    before = destination.snapshot()
    with pytest.raises(PermissionError, match="destination observation is not valid"):
        flow.execute(p, decision, adapter_id=p.adapter_id, now=NOW)
    assert destination.snapshot() == before


class PostDispatchObservationFault:
    """Delegate real effects; inject exactly one post-dispatch observation fault."""

    def __init__(self, base, *, observation=None, error=None):
        self.base = base
        self.observation = observation
        self.error = error
        self.observe_calls = 0

    def observe(self, effect_id):
        self.observe_calls += 1
        if self.observe_calls == 1:
            return self.base.observe(effect_id)
        if self.observe_calls == 2:
            if self.error is not None:
                raise self.error
            return self.observation.model_copy(deep=True)
        return self.base.observe(effect_id)

    def apply(self, **kwargs):
        return self.base.apply(**kwargs)

    def snapshot(self):
        return self.base.snapshot()


def post_dispatch_fault_workflow(tmp_path, fault_observation=None, *, error=None):
    p = proposal()
    resolver = resolver_for(p)
    base = LocalRefundDestination(tmp_path / "destination.json")
    records = BoundedRecordStore(tmp_path / "run.json", "post-dispatch")
    destination = PostDispatchObservationFault(
        base,
        observation=fault_observation,
        error=error,
    )
    flow = BoundedAuthorizationWorkflow(
        allow_test_time=True,
        manifest=manifest(),
        resolver=resolver,
        destination=destination,
        records=records,
        observation_policy=ObservationPolicy(max_age_seconds=300, clock_tolerance_seconds=5),
    )
    return p, base, records, flow


@pytest.mark.parametrize(
    ("fault", "reason"),
    [
        (
            EffectObservation(
                effect_id="WRONG-EFFECT",
                observed_at=NOW.isoformat(),
                state="applied",
                destination_state={"effect_id": "WRONG-EFFECT", "state": "applied"},
            ),
            "observation_effect_id_mismatch",
        ),
        (
            EffectObservation(
                effect_id="placeholder",
                observed_at="2000-01-01T00:00:00+00:00",
                state="applied",
                destination_state={"effect_id": "placeholder", "state": "applied"},
            ),
            "observation_stale",
        ),
        (
            EffectObservation(
                effect_id="placeholder",
                observed_at="malformed",
                state="applied",
                destination_state={"effect_id": "placeholder", "state": "applied"},
            ),
            "observation_time_malformed",
        ),
        (
            EffectObservation(
                effect_id="placeholder",
                observed_at=NOW.isoformat(),
                state="applied",
                destination_state={"effect_id": "placeholder", "state": "partial"},
            ),
            "destination_state_contradiction",
        ),
    ],
)
def test_execute_rejects_invalid_post_dispatch_observation_without_replacing_effect(
    tmp_path, fault, reason
):
    p = proposal()
    # Bind placeholder fields to the actual effect only after authorization.
    resolver = resolver_for(p)
    base = LocalRefundDestination(tmp_path / "destination.json")
    records = BoundedRecordStore(tmp_path / "run.json", "post-dispatch")
    destination = PostDispatchObservationFault(base, observation=fault)
    flow = BoundedAuthorizationWorkflow(
        allow_test_time=True,
        manifest=manifest(),
        resolver=resolver,
        destination=destination,
        records=records,
        observation_policy=ObservationPolicy(max_age_seconds=300, clock_tolerance_seconds=5),
    )
    decision = flow.decide(p, now=NOW)
    assert decision.result == "authorized"
    if fault.effect_id == "placeholder":
        fault.effect_id = decision.effect_id
        fault.destination_state["effect_id"] = decision.effect_id

    attempt, observed = flow.execute(p, decision, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged"
    assert attempt.acknowledgement["effect"]["effect_id"] == decision.effect_id
    assert observed is None

    state_after_dispatch = base.snapshot()
    assert len(state_after_dispatch["effects"]) == 1
    assert decision.effect_id in state_after_dispatch["effects"]

    record = records.load()
    rejected = record.reconciliations[-1]
    assert rejected.result == "hold"
    assert rejected.observation_accepted is False
    assert reason in rejected.reasons
    assert rejected.observation is not None
    # Only the genuine pre-dispatch absence is accepted as destination evidence.
    assert len(record.observations) == 1
    assert record.observations[0].state == "absent"

    recovery_attempt, recovery_observation = flow.execute(
        p, decision, adapter_id=p.adapter_id, now=NOW
    )
    assert recovery_attempt.status == "acknowledged"
    assert recovery_attempt.acknowledgement["reconciled_existing"] is True
    assert recovery_observation is not None
    assert recovery_observation.effect_id == decision.effect_id
    assert recovery_observation.state == "applied"
    assert base.snapshot() == state_after_dispatch


def test_execute_retains_unavailable_post_dispatch_observation_without_repeating_effect(tmp_path):
    p = proposal()
    resolver = resolver_for(p)
    base = LocalRefundDestination(tmp_path / "destination.json")
    records = BoundedRecordStore(tmp_path / "run.json", "post-dispatch-unavailable")
    destination = PostDispatchObservationFault(
        base,
        error=OSError("post-dispatch observation unavailable"),
    )
    flow = BoundedAuthorizationWorkflow(
        allow_test_time=True,
        manifest=manifest(),
        resolver=resolver,
        destination=destination,
        records=records,
        observation_policy=ObservationPolicy(max_age_seconds=300, clock_tolerance_seconds=5),
    )
    decision = flow.decide(p, now=NOW)

    attempt, observed = flow.execute(p, decision, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged"
    assert observed is None
    state_after_dispatch = base.snapshot()
    assert len(state_after_dispatch["effects"]) == 1

    record = records.load()
    rejected = record.reconciliations[-1]
    assert rejected.result == "hold"
    assert rejected.observation is None
    assert rejected.observation_accepted is False
    assert "observation_unavailable:OSError" in rejected.reasons
    assert len(record.observations) == 1
    assert record.observations[0].state == "absent"

    recovery_attempt, recovery_observation = flow.execute(
        p, decision, adapter_id=p.adapter_id, now=NOW
    )
    assert recovery_attempt.status == "acknowledged"
    assert recovery_attempt.acknowledgement["reconciled_existing"] is True
    assert recovery_observation is not None
    assert recovery_observation.state == "applied"
    assert base.snapshot() == state_after_dispatch


# ---------------------------------------------------------------------------
# W1 tenant-aware bounded-authorization-effect/0.2 qualification
# ---------------------------------------------------------------------------

TENANT = "tenant-alpha"


def tenant_proposal(tenant_id=TENANT):
    base = proposal()
    return TenantRuntimeProposal(
        **base.model_dump(mode="json", exclude_none=False),
        tenant_id=tenant_id,
    )


def tenant_resolver_for(p, *, tenant_id=TENANT):
    r = resolver_for(p)
    ctx = r.contexts[PROFILE]
    ctx["tenant_id"] = tenant_id
    grant = ctx["grant"]
    grant["tenant_id"] = tenant_id
    r.statuses[grant["grant_id"]].tenant_id = tenant_id
    approval_ref = grant["approval_refs"][0]
    r.approvals[approval_ref].tenant_id = tenant_id
    r.policies[POLICY_REF].tenant_id = tenant_id
    return r


def tenant_workflow(tmp_path, p, *, resolver=None):
    return workflow(
        tmp_path,
        p,
        resolver=resolver or tenant_resolver_for(p),
    )


def test_tenant_v02_valid_refund_executes_and_persists_tenant_binding(tmp_path):
    p = tenant_proposal()
    flow = tenant_workflow(tmp_path, p)
    decision = flow.decide(p, now=NOW)
    assert decision.result == "authorized", decision.reasons
    assert isinstance(decision.binding, TenantAuthorizationBinding)
    assert decision.binding.generation == "bounded-authorization-effect/0.2"
    assert decision.binding.tenant_id == TENANT

    # Persist/reload must not collapse the v0.2 subtype into historical v0.1.
    persisted = flow.records.decision(decision.decision_id)
    assert isinstance(persisted.binding, TenantAuthorizationBinding)
    assert persisted.binding.tenant_id == TENANT

    attempt, observed = flow.execute(p, decision, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged"
    assert observed is not None and observed.state == "applied"
    assert len(flow.destination.snapshot()["effects"]) == 1


def test_tenant_only_substitution_cannot_reuse_authorization(tmp_path):
    p = tenant_proposal()
    flow = tenant_workflow(tmp_path, p)
    decision = flow.decide(p, now=NOW)
    assert decision.result == "authorized"

    substituted = p.model_copy(update={"tenant_id": "tenant-beta"})
    with pytest.raises(PermissionError, match="authorization-critical inputs changed"):
        flow.execute(substituted, decision, adapter_id=p.adapter_id, now=NOW)
    assert flow.destination.snapshot()["effects"] == {}


@pytest.mark.parametrize(
    ("mutation", "reason"),
    [
        ("context", "tenant_context_mismatch"),
        ("grant", "grant_tenant_mismatch"),
        ("grant_status", "grant_tenant_mismatch"),
        ("approval", "approval_tenant_mismatch"),
        ("policy", "policy_tenant_mismatch"),
    ],
)
def test_wrong_or_missing_authority_tenant_holds(tmp_path, mutation, reason):
    p = tenant_proposal()
    r = tenant_resolver_for(p)
    grant = r.contexts[PROFILE]["grant"]
    wrong = "tenant-beta"
    if mutation == "context":
        r.contexts[PROFILE]["tenant_id"] = wrong
    elif mutation == "grant":
        grant["tenant_id"] = wrong
    elif mutation == "grant_status":
        r.statuses[grant["grant_id"]].tenant_id = wrong
    elif mutation == "approval":
        r.approvals[grant["approval_refs"][0]].tenant_id = wrong
    else:
        r.policies[POLICY_REF].tenant_id = wrong

    decision = tenant_workflow(tmp_path, p, resolver=r).decide(p, now=NOW)
    assert decision.result == "hold"
    assert reason in decision.reasons


def test_missing_tenant_is_not_inferred_from_institution_target_or_payload(tmp_path):
    p = tenant_proposal()
    r = tenant_resolver_for(p)
    del r.contexts[PROFILE]["tenant_id"]
    r.contexts[PROFILE]["institution"]["institution_id"] = (
        "urn:cognous:institution:tenant-alpha"
    )
    decision = tenant_workflow(tmp_path, p, resolver=r).decide(p, now=NOW)
    assert decision.result == "hold"
    assert "tenant_context_mismatch" in decision.reasons


def test_effect_time_tenant_and_authority_revalidation_blocks_changed_state(tmp_path):
    p = tenant_proposal()
    r = tenant_resolver_for(p)
    flow = tenant_workflow(tmp_path, p, resolver=r)
    decision = flow.decide(p, now=NOW)
    assert decision.result == "authorized"

    grant = r.contexts[PROFILE]["grant"]
    r.statuses[grant["grant_id"]].tenant_id = "tenant-beta"
    with pytest.raises(PermissionError, match="authorization-critical inputs changed"):
        flow.execute(p, decision, adapter_id=p.adapter_id, now=NOW)
    assert flow.destination.snapshot()["effects"] == {}


@pytest.mark.parametrize("kind", ["revoked", "expired", "invalid_actor", "conflict"])
def test_tenant_path_rejects_invalid_current_authority(tmp_path, kind):
    p = tenant_proposal()
    r = tenant_resolver_for(p)
    grant = r.contexts[PROFILE]["grant"]
    flow = tenant_workflow(tmp_path, p, resolver=r)
    decision = flow.decide(p, now=NOW)
    assert decision.result == "authorized"

    if kind == "revoked":
        r.statuses[grant["grant_id"]].status = "revoked"
    elif kind == "expired":
        r.contexts[PROFILE]["grant"]["expires_at"] = (NOW - timedelta(seconds=1)).isoformat()
    elif kind == "invalid_actor":
        r.identities[ACTOR].authenticated = False
    else:
        r.conflicts[p.requirement_id].state = "conflict"

    with pytest.raises(PermissionError, match="authorization-critical inputs changed"):
        flow.execute(p, decision, adapter_id=p.adapter_id, now=NOW)
    assert flow.destination.snapshot()["effects"] == {}


@pytest.mark.parametrize("field", ["target", "payload", "action"])
def test_tenant_path_conflicting_operation_substitution_is_denied(tmp_path, field):
    p = tenant_proposal()
    flow = tenant_workflow(tmp_path, p)
    decision = flow.decide(p, now=NOW)
    assert decision.result == "authorized"

    changed = p.model_copy(deep=True)
    if field == "target":
        changed.target = "urn:cognous:synthetic-account:attacker"
    elif field == "payload":
        changed.payload["refund_reason"] = "substituted"
    else:
        changed.action_id = "urn:cognous:action:refund-issue-high-v1"

    with pytest.raises(PermissionError, match="authorization-critical inputs changed"):
        flow.execute(changed, decision, adapter_id=p.adapter_id, now=NOW)
    assert flow.destination.snapshot()["effects"] == {}
