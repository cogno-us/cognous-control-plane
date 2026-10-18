"""Opt-in runtime-authority/0.1 contracts. No production trust is implied."""
from __future__ import annotations

import copy
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt

from .freshness import FreshnessProfile
from .operation_identity import OperationIdentityProfile, valid_operation_id

PROFILE_VERSION = "runtime-authority/0.1"
VOCABULARY_VERSION = "runtime-authority-reasons/0.1"


class ActionClass(BaseModel):
    """Host-governed action classification, outside the grant write path."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    class_id: str = Field(min_length=1)
    irreversible: bool = True
    max_status_age_seconds: int = Field(default=60, ge=0)
    on_unreadable: Literal["refuse", "bounded_tolerance"] = "refuse"


class EvidenceCriterion(BaseModel):
    """Bounded typed predicates; never evaluates source-supplied code."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["evidence-criterion/0.1"] = "evidence-criterion/0.1"
    kind: Literal["minimum_count", "exact_members"]
    producer_id: str
    subject_digest: str
    minimum_count: StrictInt = Field(default=0, ge=0)
    members: list[str] = Field(default_factory=list, max_length=10000)


class PurposeStatus(BaseModel):
    """An attributable lifecycle observation supplied by the trusted adapter."""
    model_config = ConfigDict(extra="forbid")
    system: str
    record_id: str
    epoch: str
    institution_id: str
    authority_domain: str
    tenant_id: str | None = None
    state: Literal["open", "closed"]
    observed_at: str
    epoch_capability: Literal["authoritative", "lossless_closure_log", "status_only"]


class RuntimeAuthorityProfile(BaseModel):
    """Trusted host configuration. Public keys are never selected by evidence."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["runtime-authority/0.1"] = PROFILE_VERSION
    catalogue_version: str
    actions: dict[str, ActionClass]
    producer_keys: dict[str, str] = Field(default_factory=dict)  # Ed25519 hex
    allow_synthetic_resolver: bool = False
    # Opt-in operation-identity/0.1. Omitted from dumps (and so from every commitment
    # that hashes the profile) while unset, which keeps the default path byte-identical.
    operation_identity: OperationIdentityProfile | None = Field(default=None, exclude_if=lambda v: v is None)
    # Opt-in freshness/0.1 (three clocks, deadline at opening, overdue state, reaper, age basis). Same omission rule.
    freshness: FreshnessProfile | None = Field(default=None, exclude_if=lambda v: v is None)

    def snapshot(self) -> RuntimeAuthorityProfile:
        """Detach trusted configuration from caller-owned mutable dictionaries."""
        return self.model_copy(deep=True)


def approval_commitment(profile: RuntimeAuthorityProfile, context: dict) -> str:
    """Bind governed inputs, criteria, catalogue and purpose to actual approval."""
    from .bounded import commitment
    return commitment({
        "profile": profile.model_dump(mode="json"),
        "runtime_authority": context.get("runtime_authority"),
        "purpose_ref": (context.get("grant") or {}).get("purpose_ref"),
        "grant_expires_at": (context.get("grant") or {}).get("expires_at"),
    })


def validate_evidence(status, criterion: EvidenceCriterion, profile: RuntimeAuthorityProfile,
                      context: dict) -> list[str]:
    """Authenticate producer bytes and evaluate only the declared criterion."""
    from .bounded import _canonical_bytes
    envelope = getattr(status, "validation_record", None)
    if not isinstance(envelope, dict) or not envelope.get("signature"):
        return ["evidence_unsigned"]
    if set(envelope) != {"statement", "signature"}:
        return ["evidence_record_invalid"]
    statement = envelope["statement"]
    if not isinstance(statement, dict) or set(statement) != {
        "version", "producer_id", "obligation_id", "subject_digest", "observed_at",
        "institution_id", "authority_domain", "tenant_id", "values",
    }:
        return ["evidence_record_invalid"]
    key = profile.producer_keys.get(criterion.producer_id)
    if not key or statement["producer_id"] != criterion.producer_id:
        return ["evidence_producer_untrusted"]
    try:
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
        Ed25519PublicKey.from_public_bytes(bytes.fromhex(key)).verify(
            bytes.fromhex(envelope["signature"]), _canonical_bytes(statement))
    except ImportError:
        return ["evidence_verifier_unavailable"]
    except Exception:
        return ["evidence_signature_invalid"]
    if statement["version"] != "validation-record/0.1":
        return ["evidence_record_version_unsupported"]
    expected = {
        "obligation_id": status.obligation_id, "subject_digest": criterion.subject_digest,
        "observed_at": status.observed_at,
        "institution_id": context["institution"]["institution_id"],
        "authority_domain": context["institution"]["authority_domain"],
        "tenant_id": context.get("tenant_id"),
    }
    if any(statement[k] != v for k, v in expected.items()):
        return ["evidence_subject_mismatch"]
    values = statement["values"]
    if not isinstance(values, dict):
        return ["evidence_record_invalid"]
    if criterion.kind == "minimum_count":
        count = values.get("validated_count")
        if type(count) is not int or count < criterion.minimum_count:
            return ["evidence_criterion_unmet"]
    else:
        members = values.get("validated_members")
        if (not isinstance(members, list) or any(not isinstance(x, str) for x in members)
                or len(members) != len(set(members)) or len(criterion.members) != len(set(criterion.members))
                or set(members) != set(criterion.members)):
            return ["evidence_criterion_unmet"]
    return []


def validate_extensions(profile: RuntimeAuthorityProfile, proposal, context: dict,
                        inputs: list, resolver, now: datetime, capture) -> tuple[list[str], dict]:
    """Validate approval-owned prerequisites using the reads used by the gate."""
    from .bounded import _parse, commitment
    reasons = []
    spec = context.get("runtime_authority")
    if not isinstance(spec, dict) or spec.get("profile") != PROFILE_VERSION:
        return ["runtime_authority_profile_missing"], {}
    allowed = {"profile", "required_inputs", "required_inputs_digest", "evidence_criteria",
               "expected_effective_grant_digest", "effective_grant_derivation_version"}
    if profile.operation_identity is not None:
        allowed.add("operation_id")
    if set(spec) - allowed:
        reasons.append("runtime_authority_field_unsupported")
    expected_approval = approval_commitment(profile, context)
    approvals = [x for x in inputs if x.input_type == "approval" and not x.missing]
    if not approvals or any(x.observed.get("runtime_authority_commitment") != expected_approval for x in approvals):
        reasons.append("runtime_authority_approval_mismatch")
    required = spec.get("required_inputs")
    if (not isinstance(required, list) or not required
            or any(not isinstance(x, dict) or set(x) != {"input_type", "input_id"}
                       or not all(isinstance(v, str) and v for v in x.values()) for x in required)):
        reasons.append("required_input_set_invalid")
    else:
        canonical = sorted(required, key=lambda x: (x["input_type"], x["input_id"]))
        if len({(x["input_type"], x["input_id"]) for x in required}) != len(required):
            reasons.append("required_input_set_invalid")
        if commitment(canonical) != spec.get("required_inputs_digest"):
            reasons.append("required_input_set_invalid")
    criteria = spec.get("evidence_criteria", {})
    if not isinstance(criteria, dict):
        reasons.append("evidence_criterion_unsupported")
        criteria = {}
    # The profile requires a criterion for each required authorization obligation.
    for obligation in context.get("requirement", {}).get("evidence", []):
        oid = obligation["obligation_id"]
        if not (obligation.get("required") and obligation.get("kind") == "authorization"):
            continue
        try:
            criterion = EvidenceCriterion.model_validate(criteria[oid])
        except (KeyError, ValueError, TypeError):
            reasons.append("evidence_criterion_unsupported")
            continue
        # Retrieve the exact record captured during this check, never reread.
        status = inputs.records.get(("evidence", oid))
        if status is not None:
            reasons.extend(validate_evidence(status, criterion, profile, context))
    grant = context.get("grant") or {}
    purpose = grant.get("purpose_ref")
    if purpose is not None:
        if not isinstance(purpose, dict) or set(purpose) != {"system", "record_id", "epoch"} or not all(isinstance(x,str) and x for x in purpose.values()):
            reasons.append("purpose_binding_invalid")
        else:
            ref = commitment(purpose)
            try:
                raw = resolver.purpose_status(copy.deepcopy(purpose))
            except Exception:
                raw = None
            try:
                observed = PurposeStatus.model_validate(raw)
            except (ValueError, TypeError):
                observed = None
            capture("purpose", ref, observed)
            if observed is None:
                reasons.append("purpose_unreadable")
            else:
                cl = profile.actions.get(proposal.action_id)
                if observed.epoch_capability == "status_only":
                    reasons.append("purpose_epoch_capability_unsupported")
                if (observed.system != purpose["system"] or observed.record_id != purpose["record_id"]
                    or observed.institution_id != context["institution"]["institution_id"]
                    or observed.authority_domain != context["institution"]["authority_domain"]
                    or observed.tenant_id != context.get("tenant_id")):
                    reasons.append("purpose_binding_invalid")
                if observed.epoch != purpose["epoch"]:
                    reasons.append("purpose_epoch_changed")
                if observed.state == "closed":
                    reasons.append("purpose_closed")
                age = (now - _parse(observed.observed_at)).total_seconds()
                if not cl or age < 0 or age > cl.max_status_age_seconds:
                    reasons.append("purpose_unreadable")
    elif not grant.get("expires_at"):
        reasons.append("grant_expiry_required")
    if isinstance(required, list) and all(isinstance(x, dict) and set(x)=={"input_type","input_id"} for x in required):
        read = {(x.input_type, x.input_id) for x in inputs if not x.missing}
        if any((x["input_type"],x["input_id"]) not in read for x in required):
            reasons.append("required_input_not_read")
    expected_digest = spec.get("expected_effective_grant_digest")
    if expected_digest is not None:
        import re
        if (not isinstance(expected_digest, str) or not re.fullmatch(r"sha256:[a-f0-9]{64}", expected_digest)
                or spec.get("effective_grant_derivation_version") != "effective-grant/0.1"):
            reasons.append("effective_grant_binding_invalid")
    operation_fields = {}
    if profile.operation_identity is not None:
        # The issuer supplies the operation id inside the approved extension; a planner or
        # worker cannot, because the approval commitment covers the whole extension.
        operation_id = spec.get("operation_id")
        if operation_id is None:
            reasons.append("operation_id_missing")
        elif not valid_operation_id(operation_id):
            reasons.append("operation_id_invalid")
        else:
            operation_fields = {"operation_id": operation_id, "operation_issuer": grant.get("issuer")}
    extension = {
        "profile": PROFILE_VERSION, "approval_commitment": expected_approval,
        "required_inputs_digest": spec.get("required_inputs_digest"),
        "catalogue_digest": commitment(profile.model_dump(mode="json")),
        "expected_effective_grant_digest": spec.get("expected_effective_grant_digest"),
        "effective_grant_derivation_version": spec.get("effective_grant_derivation_version"),
        **operation_fields,
    }
    return reasons, extension


def reopen_conditions(reasons: list[str], inputs: list) -> list[dict]:
    """Describe reconsideration prerequisites; never permission to dispatch."""
    out = []
    for item in inputs:
        if item.input_type == "grant" and item.observed.get("status") == "revoked":
            out.append({"kind":"successor_grant_revision", "input_id":item.input_id,
                        "previous_revision":item.observed.get("revision")})
    if "status_unreadable" in reasons:
        out.append({"kind":"readable_authority_status"})
    return out
