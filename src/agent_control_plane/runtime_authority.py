"""Opt-in runtime-authority/0.1 contracts. No production trust is implied."""
from __future__ import annotations

import copy
from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_serializer, model_validator

from .dedupe import DedupeProfile
from .freshness import FreshnessProfile
from .holder_inventory import HolderInventory
from .merge import MergeProfile
from .operation_identity import OperationIdentityProfile, valid_operation_id
from . import policy_binding as _pb
from .policy_binding import PolicyBinding
from .reversibility import ReversibilityProfile, check_class_members, flatten_x_reversibility, nest_x_reversibility

PROFILE_VERSION = "runtime-authority/0.1"
VOCABULARY_VERSION = "runtime-authority-reasons/0.1"
VOCABULARY_VERSION_0_2 = "runtime-authority-reasons/0.2"
VOCABULARY_VERSION_0_3 = "runtime-authority-reasons/0.3"
#: Codes registered by 0.2 and not by 0.1 (all but the last five, the scan-3 default-path manifest-gate codes, emitted only by opt-in profiles). ``schemas/runtime_authority_reasons_0_1.json`` is the
#: original 121 codes, byte-identical to its pinned form; ``..._0_2.json`` is the full set (0.1 plus these) because one row can mix
#: codes of both, and a row carries exactly one label that must resolve all of its codes. A test pins this set to the two files.
CODES_ADDED_IN_0_2 = frozenset({
    "operation_grant_mismatch",
    "operation_id_invalid",
    "operation_id_missing",
    "operation_not_admitted",
    "operation_renewal_unrecorded",
    "renewal_not_written_by_grant_issuer",
    "renewal_revision_not_new",
    "check_expired_before_dispatch",
    "check_overdue",
    "check_lease_unavailable",
    "status_nonce_mismatch",
    "age_extension_unsigned",
    "age_extension_self_signed",
    "age_extension_signer_not_configured",
    "age_extension_exceeds_limit",
    "age_extension_invalid",
    "age_extension_authority_unconfigured",
    "holder_inventory_missing",
    "merge_operation_ids_invalid",
    "merge_operation_not_admitted",
    "merge_operation_discriminator_mismatch",
    "merge_operation_already_folded",
    "merge_survivor_already_folded",
    "merge_authority_unfunded",
    "merge_rule_unknown",
    "operation_merged_effect_exists",
    "operation_merged_effect_unresolved",
    "purpose_cache_irreversible_class",
    "purpose_cache_after_reversal_window",
    "purpose_cache_stale",
    "purpose_closure_recorded",
    "age_extension_irreversible_class",
    "dedupe_unresolved_attempt_blocks_new_key",
    "attempt_unresolved_past_horizon",
    "escalation_after_key_ttl",
    "dedupe_operation_effect_applied",
    "grant_revocation_recorded",
    # Default-path manifest-gate and authority-limit refusals (scan 3): not opt-in-profile codes; registered here because 0.1 is pinned.
    "action_blocked",
    "missing_effect_limits",
    "missing_amount_limit",
    "effect_limit_malformed",
    "authority_limit_malformed",
    # Default-path manifest validation (scan 6): the gate runs the action-manifest validator's error rules.
    "invalid_manifest",
})

#: Codes registered ONLY by 0.3 (the policy-binding/0.1 opt-in profile). ``schemas/runtime_authority_reasons_0_2.json`` stays frozen at its
#: 164 codes (git blob a46ef35e7ece5c3a16e50d174000c49e3632eb12); ``schemas/runtime_authority_reasons_0_3.json`` is a NEW immutable file with
#: those 164 entries unchanged and in order plus these eight (172). The names are PROPOSED and NOT RATIFIED by the owning component.
CODES_ADDED_IN_0_3 = frozenset(_pb.NEW_CODES)

#: sha256 of the registry file bytes per label: the evidence identity of a label. A test pins each to the file in ``schemas/``.
REGISTRY_SHA256 = {
    VOCABULARY_VERSION: "fbc4df2e02457e294ca1f819d0e507c4452e46691e4f139a66be48967c2096c0",
    VOCABULARY_VERSION_0_2: "c7678fa766f4d67d71ad9533672afdc87b3765ac1d336acae26504fc74ce3be6",
    VOCABULARY_VERSION_0_3: "58b29ef74b9bd49d3eae7278d8cce73c7cbc6a1095a07f7b9fa44f48a7b8c07f",
}

#: terminal-revocation/0.1: a retained check already observed this (grant_id, revision) revoked.
CODE_REVOCATION_RECORDED = "grant_revocation_recorded"


def vocabulary_for(reasons) -> str:
    """The registry label a row's reasons need: 0.1 unless a code only 0.2 registers is present (then 0.2, a superset of 0.1), and 0.3
    (a superset of 0.2) only when one of the eight policy-binding codes is present.

    Rows that carry no opt-in-profile code keep the pinned 0.1 label and every existing 0.2 row keeps 0.2, so nothing is reinterpreted."""
    if any(code in CODES_ADDED_IN_0_3 for code in reasons):
        return VOCABULARY_VERSION_0_3
    return VOCABULARY_VERSION_0_2 if any(code in CODES_ADDED_IN_0_2 for code in reasons) else VOCABULARY_VERSION


def registry_identity(label) -> str:
    """The pinned sha256 of the registry file a label names. Fails closed (``ValueError``) on any unsupported or non-string label:
    there is no fallback meaning for an unknown label."""
    if type(label) is not str or label not in REGISTRY_SHA256:
        raise ValueError(f"unsupported reason registry label: {label!r}")
    return REGISTRY_SHA256[label]


def registry_admits(label, reasons, registry_codes=None) -> bool:
    """True only when ``label`` is supported and resolves every reason. A 0.3 code under 0.1 or 0.2 is refused, so is an unsupported
    label, and (when the consumer's loaded registry ``registry_codes`` is given) any code it does not list."""
    if type(label) is not str or label not in REGISTRY_SHA256:
        return False
    if type(reasons) not in (list, tuple) or any(type(code) is not str for code in reasons):
        return False
    for code in reasons:
        if code in CODES_ADDED_IN_0_3 and label != VOCABULARY_VERSION_0_3:
            return False
        if code in CODES_ADDED_IN_0_2 and label == VOCABULARY_VERSION:
            return False
        if registry_codes is not None and code not in registry_codes:
            return False
    return True


class ActionClass(BaseModel):
    """Host-governed action classification, outside the grant write path."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    class_id: str = Field(min_length=1)
    irreversible: bool = True
    max_status_age_seconds: int = Field(default=60, ge=0)
    on_unreadable: Literal["refuse", "bounded_tolerance"] = "refuse"
    # Opt-in holder-inventory/0.1: a flagged class holds until the profile carries a holder inventory. Omitted from dumps while
    # False, which keeps the default path (and every commitment that hashes the profile) byte-identical.
    requires_revocation_assurance: bool = Field(default=False, exclude_if=lambda v: not v)
    # Opt-in reversibility/0.1 members (see reversibility.py). All omitted from dumps while unset, so the default path is unchanged.
    # ``irreversible`` stays the derived legacy field: true if and only if ``reversibility`` is ``irreversible``.
    reversibility: Literal["irreversible", "reversible_until", "reversible_at_cost"] | None = Field(
        default=None, exclude_if=lambda v: v is None)
    reversible_until: str | None = Field(default=None, exclude_if=lambda v: v is None)
    reversal_cost: str | None = Field(default=None, exclude_if=lambda v: v is None)
    reads_protected_data: bool = Field(default=False, exclude_if=lambda v: not v)
    counterparty_observable: bool = Field(default=True, exclude_if=lambda v: v)

    @model_validator(mode="before")
    @classmethod
    def _reversibility_members(cls, data):
        return check_class_members(flatten_x_reversibility(data)) if isinstance(data, dict) else data

    @model_serializer(mode="wrap")
    def _x_reversibility(self, handler):
        # ODES effect-reversibility shape: the five members travel as ONE ``x-reversibility`` object on the action class. Absent
        # (and the dump byte-identical to before) unless a value is declared.
        return nest_x_reversibility(handler(self))


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


class TerminalRevocationProfile(BaseModel):
    """Opt-in terminal-revocation/0.1: revocation is terminal for a grant revision.

    With it, a grant whose retained resolution checks already observed ``revoked`` for the same ``(grant_id, revision)`` is
    refused (``grant_revocation_recorded``) at decision and at effect time, even when the status read now says ``active``. A
    new grant revision is the way back. ``suspended`` stays reversible. The memory is this control plane's own record store:
    a revocation it never observed cannot be remembered, and the store has no keyed integrity check.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["terminal-revocation/0.1"] = "terminal-revocation/0.1"


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
    # Opt-in holder-inventory/0.1 (enumerated authority holders). Same omission rule.
    holder_inventory: HolderInventory | None = Field(default=None, exclude_if=lambda v: v is None)
    # Opt-in merge-record/0.1, reversibility/0.1 and dedupe-ttl/0.1 (stream N4). Same omission rule.
    merge: MergeProfile | None = Field(default=None, exclude_if=lambda v: v is None)
    reversibility: ReversibilityProfile | None = Field(default=None, exclude_if=lambda v: v is None)
    dedupe: DedupeProfile | None = Field(default=None, exclude_if=lambda v: v is None)
    # Opt-in terminal-revocation/0.1. Same omission rule.
    terminal_revocation: TerminalRevocationProfile | None = Field(default=None, exclude_if=lambda v: v is None)
    # Opt-in policy-binding/0.1 (approval generation, registry freshness ceilings). Same omission rule: absent, every dump and every
    # commitment is byte-identical to before.
    policy_binding: PolicyBinding | None = Field(default=None, exclude_if=lambda v: v is None)

    @model_validator(mode="after")
    def _profiles_compose(self):
        if (self.merge is not None or self.dedupe is not None) and self.operation_identity is None:
            raise ValueError("merge-record/0.1 and dedupe-ttl/0.1 are defined over operation ids and need operation-identity/0.1")
        declared = [a for a in self.actions.values() if a.reversibility is not None]
        if declared and self.reversibility is None:
            raise ValueError("reversibility values need the reversibility/0.1 profile")
        defects = _pb.policy_binding_defects(self)
        if defects:
            raise ValueError("policy_binding: " + ",".join(defects))
        return self

    def snapshot(self) -> RuntimeAuthorityProfile:
        """Detach trusted configuration from caller-owned mutable dictionaries."""
        return self.model_copy(deep=True)


def approval_commitment(profile: RuntimeAuthorityProfile, context: dict) -> str:
    """Bind governed inputs, criteria, catalogue and purpose to actual approval."""
    from .bounded import commitment
    preimage = {
        "profile": profile.model_dump(mode="json"),
        "runtime_authority": context.get("runtime_authority"),
        "purpose_ref": (context.get("grant") or {}).get("purpose_ref"),
        "grant_expires_at": (context.get("grant") or {}).get("expires_at"),
    }
    binding = profile.policy_binding
    if binding is None:
        return commitment(preimage)  # legacy: byte-identical to before, no tag
    # approval-commitment/0.2: tagged; the effective policy identity and the authenticated generation are SEPARATE preimage members.
    return commitment({"commitment_version": _pb.APPROVAL_COMMITMENT_V2, **preimage,
                       "policy_identity": _pb.identity_members(binding),
                       "policy_generation": getattr(binding, "policy_generation", None)})


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
        if (not criterion.members  # an approved empty member set approves nothing: it is not a pass
                or not isinstance(members, list) or any(not isinstance(x, str) for x in members)
                or len(members) != len(set(members)) or len(criterion.members) != len(set(criterion.members))
                or set(members) != set(criterion.members)):
            return ["evidence_criterion_unmet"]
    return []


def validate_extensions(profile: RuntimeAuthorityProfile, proposal, context: dict,
                        inputs: list, resolver, now: datetime, capture, purpose_cache=None) -> tuple[list[str], dict]:
    """Validate approval-owned prerequisites using the reads used by the gate.

    ``purpose_cache`` (reversibility/0.1 only) is called when the purpose status is unreadable: ``(purpose, ref, action_class) ->
    (accepted PurposeStatus or None, reason codes, observed extras)``. Without it a purpose outage refuses for every class."""
    from .bounded import _parse, commitment
    reasons = []
    spec = context.get("runtime_authority")
    if not isinstance(spec, dict) or spec.get("profile") != PROFILE_VERSION:
        return ["runtime_authority_profile_missing"], {}
    allowed = {"profile", "required_inputs", "required_inputs_digest", "evidence_criteria",
               "expected_effective_grant_digest", "effective_grant_derivation_version"}
    if profile.operation_identity is not None:
        allowed.add("operation_id")
    binding = profile.policy_binding
    if binding is not None:  # ``activation_sequence`` is RESERVED: it is not here, so it is refused as an unsupported field
        allowed |= {"approval_commitment_version", "policy_generation", "policy_activation_ref"}
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
            extra = None
            if observed is None and raw is None and purpose_cache is not None:
                observed, cache_reasons, extra = purpose_cache(purpose, ref, profile.actions.get(proposal.action_id))
                reasons.extend(cache_reasons)
            if extra is not None:
                capture("purpose", ref, observed, None, extra)
            else:
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
                # An accepted cached snapshot was already held to its own bound (class bound, or an extension of it named by a configured signer: asserted, unauthenticated).
                if extra is None and (not cl or age < 0 or age > cl.max_status_age_seconds):
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
    class_ = profile.actions.get(proposal.action_id)
    if class_ is not None and class_.requires_revocation_assurance:
        # holder-inventory/0.1: revocation cannot be assured over holders nobody enumerated, so the class holds.
        if profile.holder_inventory is None or not profile.holder_inventory.exists():
            reasons.append("holder_inventory_missing")
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
    generation_fields = {}
    if binding is not None:
        # Re-run at EVERY evaluation: ``model_copy`` and ``snapshot`` skip validators. The trusted values come from the profile, never from the approval.
        defects = _pb.policy_binding_defects(profile)
        if "invalid" in defects:
            reasons.append("policy_binding_invalid")
        if "unanchored" in defects:
            reasons.append("freshness_ceiling_unanchored")
        if "exceeded" in defects:
            reasons.append("freshness_ceiling_exceeded")
        version, generation, activation = (spec.get("approval_commitment_version"), spec.get("policy_generation"),
                                           spec.get("policy_activation_ref"))
        if version is None or generation is None or activation is None:
            reasons.append("approval_policy_generation_missing")
        if version is not None and (type(version) is not str or version not in _pb.SUPPORTED_APPROVAL_COMMITMENT_VERSIONS):
            reasons.append("approval_commitment_version_unsupported")
        if (generation is not None and not _pb.valid_int(generation)) or (activation is not None and not _pb.valid_digest(activation)):
            reasons.append("approval_policy_generation_invalid")
        if "invalid" not in defects:
            if _pb.valid_int(generation) and generation != binding.policy_generation:
                reasons.append("approval_policy_generation_mismatch")
            if _pb.valid_digest(activation) and activation != binding.activation_ref:
                reasons.append("approval_policy_activation_mismatch")
            generation_fields = {"approval_commitment_version": _pb.APPROVAL_COMMITMENT_V2,
                                 "policy_generation": binding.policy_generation, "policy_activation_ref": binding.activation_ref}
    extension = {
        "profile": PROFILE_VERSION, "approval_commitment": expected_approval,
        "required_inputs_digest": spec.get("required_inputs_digest"),
        "catalogue_digest": commitment(profile.model_dump(mode="json")),
        "expected_effective_grant_digest": spec.get("expected_effective_grant_digest"),
        "effective_grant_derivation_version": spec.get("effective_grant_derivation_version"),
        **operation_fields,
        **generation_fields,
    }
    return reasons, extension


def reopen_conditions(reasons: list[str], inputs: list) -> list[dict]:
    """Describe reconsideration prerequisites; never permission to dispatch."""
    out = []
    for item in inputs:
        if item.input_type == "grant" and item.observed.get("status") == "revoked":
            out.append({"kind":"successor_grant_revision", "input_id":item.input_id,
                        "previous_revision":item.observed.get("revision")})
    if CODE_REVOCATION_RECORDED in reasons:  # terminal-revocation/0.1: only a new revision can reopen
        listed = {x["input_id"] for x in out}
        for item in inputs:
            if item.input_type == "grant" and item.input_id not in listed:
                out.append({"kind":"successor_grant_revision", "input_id":item.input_id,
                            "previous_revision":item.observed.get("revision")})
                listed.add(item.input_id)
    if "status_unreadable" in reasons:
        out.append({"kind":"readable_authority_status"})
    return out
