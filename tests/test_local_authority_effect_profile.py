from __future__ import annotations

import copy
import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agent_control_plane.bounded import (
    ApprovalStatus,
    BoundedAuthorizationWorkflow,
    BoundedRecordStore,
    ConflictStatus,
    EvidenceStatus,
    GrantStatus,
    IdentityStatus,
    LocalRefundDestination,
    MandateStatus,
    ObservationPolicy,
    PolicyStatus,
    RoleMappingStatus,
    RuntimeProposal,
    SyntheticResolver,
    commitment,
)
from agent_control_plane.local_authority_effect import (
    LOCAL_AUTHORITY_EFFECT_PROFILE,
    materialize_local_execution_claim,
    provision_local_execution_claim,
    verify_local_execution_claim,
)

NOW = datetime(2026, 10, 7, 15, 0, tzinfo=timezone.utc)
INSTITUTION = "urn:cognous:institution:test"
DOMAIN = "refunds"
ACTOR = "urn:cognous:identity:agent"
PRINCIPAL = "urn:cognous:principal:service"
GRANT = "urn:cognous:grant:1"
POLICY = "urn:cognous:policy:refund"
APPROVAL = "urn:cognous:approval:1"
EVIDENCE = "urn:cognous:evidence:entitlement"
PROFILE = "urn:cognous:authority-context:test"
REQ = "urn:cognous:requirement:test"


def manifest():
    return {
        "manifest_id": "m1",
        "manifest_version": "1.1",
        "tools": [{"tool_name": "refund", "adapter_id": "urn:cognous:adapter:refund"}],
        "actions": [{
            "action_id": "urn:cognous:action:refund",
            "action_name": "refund_issue",
            "tool_name": "refund",
            "target_policy": {"allow_any_target": False, "allowed_targets": ["acct:1"]},
            "payload_policy": {"required_fields": ["reason"], "optional_fields": [], "forbidden_fields": []},
            "effect_limits": {"max_effects": 1, "max_amount": 100, "unit": "USD"},
            "authority_required": [{"scope": "refund.issue", "required": True}],
            "authority_context": {
                "profile_ref": PROFILE,
                "requirement_id": REQ,
                "institution_id": INSTITUTION,
                "authority_domain": DOMAIN,
                "consequence_tier": "T1",
            },
            "review_requirement": {"mode": "approval_required", "reviewer_role": "reviewer"},
        }],
    }


def setup(tmp_path):
    m = manifest()
    payload = {"reason": "duplicate"}
    p = RuntimeProposal(
        manifest_id="m1",
        manifest_version="1.1",
        manifest_digest=commitment(m),
        actor=ACTOR,
        principal=PRINCIPAL,
        action_id="urn:cognous:action:refund",
        adapter_id="urn:cognous:adapter:refund",
        target="acct:1",
        payload=payload,
        payload_commitment=commitment(payload),
        requested_permissions=["refund.issue"],
        amount=50,
        unit="USD",
        effects=1,
        authority_context_ref=PROFILE,
        requirement_id=REQ,
        run_id="run-1",
    )
    policy_versions = [{"ref": POLICY, "version": "1"}]
    context = {
        "schema_version": "0.1.0",
        "interface_status": "proposed_pending_governor_review",
        "context_id": PROFILE,
        "institution": {
            "institution_id": INSTITUTION,
            "authority_domain": DOMAIN,
            "authority_basis_ref": "basis:1",
        },
        "principal": PRINCIPAL,
        "acting_identity": ACTOR,
        "requirement": {
            "requirement_id": REQ,
            "permissions": [{
                "action": "refund_issue",
                "targets": ["acct:1"],
                "data_scopes": ["refund.issue"],
                "max_amount": 100,
                "unit": "USD",
                "max_effects": 1,
            }],
            "approvals": [{"role_id": "urn:cognous:role:reviewer", "independent_of_actor": True}],
            "evidence": [{
                "obligation_id": EVIDENCE,
                "kind": "authorization",
                "source_ref": "source:1",
                "max_age_seconds": 300,
                "required": True,
                "unknown_behavior": "hold_effect",
            }],
            "consequence": {"tier": "T1"},
        },
        "conflicts": {"precedence_refs": []},
        "grant": {
            "grant_id": GRANT,
            "revision": "1",
            "requirement_id": REQ,
            "issuer": "issuer:1",
            "issuer_role": "role:issuer",
            "issuance_record_ref": "issuance:1",
            "grantee": PRINCIPAL,
            "acting_identity": ACTOR,
            "issued_at": NOW.isoformat(),
            "not_before": (NOW - timedelta(minutes=1)).isoformat(),
            "expires_at": (NOW + timedelta(hours=1)).isoformat(),
            "status_ref": "status:1",
            "policy_versions": policy_versions,
            "permissions": [{
                "action": "refund_issue",
                "targets": ["acct:1"],
                "data_scopes": ["refund.issue"],
                "max_amount": 100,
                "unit": "USD",
                "max_effects": 1,
            }],
            "delegation": {"parent_grant_id": None, "may_delegate": False, "remaining_depth": 0},
            "approval_refs": [APPROVAL],
        },
    }
    aliases = {"reviewer": ["urn:cognous:role:reviewer"]}
    resolver = SyntheticResolver(
        contexts={PROFILE: context},
        statuses={GRANT: GrantStatus(
            grant_id=GRANT, revision="1", status="active", observed_at=NOW.isoformat(),
            version="1", status_ref="status:1", authority_basis_ref="basis:1",
            institution_id=INSTITUTION, authority_domain=DOMAIN,
        )},
        identities={ACTOR: IdentityStatus(
            identity=ACTOR, principal=PRINCIPAL, authenticated=True, delegation_valid=True,
            observed_at=NOW.isoformat(), institution_id=INSTITUTION, authority_domain=DOMAIN,
        )},
        mandates={"issuer:1|role:issuer": MandateStatus(
            issuer="issuer:1", issuer_role="role:issuer", issuance_record_ref="issuance:1",
            mandate_valid=True, observed_at=NOW.isoformat(),
            institution_id=INSTITUTION, authority_domain=DOMAIN,
        )},
        approvals={APPROVAL: ApprovalStatus(
            approval_ref=APPROVAL, role_id="urn:cognous:role:reviewer", approver="human:1",
            grant_id=GRANT, grant_revision="1",
            proposal_commitment=commitment(p.model_dump(mode="json", exclude_none=False)),
            policy_versions=policy_versions, status="active", observed_at=NOW.isoformat(),
            institution_id=INSTITUTION, authority_domain=DOMAIN,
        )},
        policies={POLICY: PolicyStatus(
            ref=POLICY, version="1", status="active", observed_at=NOW.isoformat(),
            institution_id=INSTITUTION, authority_domain=DOMAIN,
        )},
        conflicts={REQ: ConflictStatus(
            requirement_id=REQ, state="clear", observed_at=NOW.isoformat(),
            institution_id=INSTITUTION, authority_domain=DOMAIN, conflict_refs=[],
        )},
        evidence={EVIDENCE: EvidenceStatus(
            obligation_id=EVIDENCE, state="current", observed_at=NOW.isoformat(),
            source_ref="source:1", institution_id=INSTITUTION, authority_domain=DOMAIN,
        )},
        role_mappings={INSTITUTION: RoleMappingStatus(
            institution_id=INSTITUTION, version="1",
            digest=commitment({"institution_id": INSTITUTION, "version": "1", "aliases": aliases}),
            aliases=aliases,
        )},
    )
    flow = BoundedAuthorizationWorkflow(
        allow_test_time=True,
        manifest=m,
        resolver=resolver,
        destination=LocalRefundDestination(tmp_path / "destination.json"),
        records=BoundedRecordStore(tmp_path / "run.json", "run-1"),
        observation_policy=ObservationPolicy(max_age_seconds=60),
    )
    decision = flow.decide(p, now=NOW)
    assert decision.result == "authorized", decision.reasons
    return p, resolver, flow, decision


def test_materialized_claim_binds_current_authority_and_operation(tmp_path):
    proposal, resolver, flow, decision = setup(tmp_path)
    claim = materialize_local_execution_claim(
        flow,
        proposal,
        decision,
        now=NOW,
        claim_id="claim-1",
        decision_input_commitment="sha256:" + "a" * 64,
        decision_input_profile_version="0.1.0-proposed",
    )
    assert claim.profile == LOCAL_AUTHORITY_EFFECT_PROFILE
    assert claim.claim_id == "claim-1"
    assert claim.institution_id == INSTITUTION
    assert claim.authority_domain == DOMAIN
    assert claim.grant_id == GRANT
    assert claim.approval_state[0].approval_ref == APPROVAL
    assert claim.policy_state[0].version == "1"
    assert claim.evidence_state[0].state == "current"
    assert claim.max_effects == 1
    assert claim.authorizing_by_possession is False
    assert verify_local_execution_claim(claim) is True


def test_tampered_claim_fails_commitment_verification(tmp_path):
    proposal, _, flow, decision = setup(tmp_path)
    claim = materialize_local_execution_claim(flow, proposal, decision, now=NOW)
    raw = claim.model_dump(mode="json", exclude_none=False)
    raw["target"] = "acct:other"
    assert verify_local_execution_claim(raw) is False


def test_changed_authority_blocks_claim_issuance(tmp_path):
    proposal, resolver, flow, decision = setup(tmp_path)
    resolver.statuses[GRANT] = resolver.statuses[GRANT].model_copy(update={"status": "revoked"})
    try:
        materialize_local_execution_claim(flow, proposal, decision, now=NOW)
    except PermissionError as exc:
        assert "authorization-critical inputs changed" in str(exc)
    else:
        raise AssertionError("revoked authority unexpectedly issued a claim")


def test_requested_expiry_cannot_extend_grant(tmp_path):
    proposal, _, flow, decision = setup(tmp_path)
    requested = (NOW + timedelta(days=5)).isoformat()
    claim = materialize_local_execution_claim(
        flow, proposal, decision, now=NOW, expires_at=requested
    )
    assert datetime.fromisoformat(claim.expires_at) == NOW + timedelta(hours=1)


class InterleavingSnapshotResolver(SyntheticResolver):
    """Inject one invalidating change after _resolve but before snapshot return."""

    def __init__(self, *args, mutate_kind: str, **kwargs):
        super().__init__(*args, **kwargs)
        self.mutate_kind = mutate_kind
        self.injected = False

    def authority_effect_snapshot(self, ref: str):
        if not self.injected:
            self.injected = True
            if self.mutate_kind == "approval":
                self.approvals[APPROVAL] = self.approvals[APPROVAL].model_copy(
                    update={"status": "revoked"}
                )
            elif self.mutate_kind == "policy":
                self.policies[POLICY] = self.policies[POLICY].model_copy(
                    update={"status": "superseded"}
                )
            else:
                raise AssertionError(self.mutate_kind)
        return super().authority_effect_snapshot(ref)


def _replace_resolver(flow, resolver):
    flow.resolver = resolver
    return flow


@pytest.mark.parametrize(
    ("kind", "message"),
    [
        ("approval", "approval projection is not active"),
        ("policy", "policy projection is not active"),
    ],
)
def test_invalidation_between_resolve_and_snapshot_cannot_enter_claim(tmp_path, kind, message):
    proposal, base, flow, decision = setup(tmp_path)
    resolver = InterleavingSnapshotResolver(
        contexts=copy.deepcopy(base.contexts),
        statuses=copy.deepcopy(base.statuses),
        identities=copy.deepcopy(base.identities),
        mandates=copy.deepcopy(base.mandates),
        approvals=copy.deepcopy(base.approvals),
        policies=copy.deepcopy(base.policies),
        conflicts=copy.deepcopy(base.conflicts),
        evidence=copy.deepcopy(base.evidence),
        role_mappings=copy.deepcopy(base.role_mappings),
        mutate_kind=kind,
    )
    _replace_resolver(flow, resolver)
    with pytest.raises(PermissionError, match=message):
        provision_local_execution_claim(
            flow,
            proposal,
            decision,
            now=NOW,
            provision=lambda claim: (_ for _ in ()).throw(
                AssertionError("invalid claim reached provisioning sink")
            ),
        )


def test_provisioning_occurs_inside_trusted_authority_handoff(tmp_path):
    proposal, resolver, flow, decision = setup(tmp_path)
    observed = {}

    def sink(claim):
        # RLock is held by this thread throughout final resolve/snapshot/provision.
        owned = getattr(resolver._authority_effect_lock, "_is_owned", lambda: False)()
        observed["lock_owned"] = owned
        observed["claim"] = claim

    claim = provision_local_execution_claim(
        flow, proposal, decision, now=NOW, provision=sink, claim_id="handoff-claim"
    )
    assert observed["lock_owned"] is True
    assert observed["claim"] == claim
    assert claim.claim_id == "handoff-claim"
