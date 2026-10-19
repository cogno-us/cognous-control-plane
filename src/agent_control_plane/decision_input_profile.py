"""Proposed decision-input commitment profile.

This module is intentionally non-authorizing. It validates a standalone record
and its locally recomputable commitments. It is not wired into the live
BoundedAuthorizationWorkflow and does not issue, renew, consume, or verify
execution authority.
"""
from __future__ import annotations

import hashlib
import json
from datetime import datetime
from typing import Any

try:
    from .time_instant import TIME_INSTANT_NAIVE, InstantError, parse_instant
except ImportError:  # loaded standalone by file path (tools/verify_decision_input_commitment.py): load the stdlib-only sibling
    import importlib.util as _importlib_util
    from pathlib import Path as _Path

    _spec = _importlib_util.spec_from_file_location("_acp_time_instant", _Path(__file__).with_name("time_instant.py"))
    _time_instant = _importlib_util.module_from_spec(_spec)
    _spec.loader.exec_module(_time_instant)
    TIME_INSTANT_NAIVE, InstantError, parse_instant = (
        _time_instant.TIME_INSTANT_NAIVE, _time_instant.InstantError, _time_instant.parse_instant)

PROFILE_VERSION = "0.1.0-proposed"
CANONICALIZATION_PROFILE = "json-sort-keys-compact-utf8-no-nan-python-semantics-v0.1-proposed"
COMMITMENT_ALGORITHM = "SHA-256"
SUPPORTED_RESOLUTION_SEMANTICS_ID = "urn:cognous:resolver:required-evidence-v1"
SUPPORTED_CLASSIFICATION_SEMANTICS = {
    "classifier": "exact-source-current-with-max-age",
    "version": "1",
    "admissible_source": "exact-match",
    "future_observation": "reject",
    "precedence": ["CONFLICT", "UNKNOWN", "STALE", "MISSING", "VALID"],
}

REASON_PRECEDENCE = (
    "INPUT_INVALID",
    "CANDIDATE_BINDING_FAILED",
    "INSTITUTIONAL_REQUIREMENT_FAILED",
    "POLICY_BINDING_FAILED",
    "EVIDENCE_UNSATISFIED",
    "CONTEXT_OR_TIME_FAILED",
    "RESOLVER_SEMANTICS_FAILED",
    "DECISION_INCONSISTENT",
)

ALLOWED_ASSURANCE_CLASSES = {
    "trusted_declaration",
    "locally_recomputable_commitment",
    "authenticated_source",
    "externally_verified_fact",
}
ALLOWED_EVIDENCE_STATES = {"current", "unknown", "conflict"}


class ProfileValidationError(ValueError):
    """Raised when a proposed-profile record fails validation."""

    def __init__(self, code: str, message: str):
        super().__init__(message)
        self.code = code


def canonical_bytes(value: object) -> bytes:
    """Return current-stack-compatible deterministic JSON bytes.

    This deliberately mirrors the current Python helper. It does not claim
    RFC 8785/JCS conformance or cross-language equivalence. JSON number type and
    Unicode code-point sequence remain significant; no Unicode normalization or
    numeric normalization is performed.
    """
    try:
        return json.dumps(
            value,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
            allow_nan=False,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise ProfileValidationError("CANONICALIZATION_REJECTED", str(exc)) from exc


def commitment(value: object) -> str:
    return "sha256:" + hashlib.sha256(canonical_bytes(value)).hexdigest()


def _parse_time(value: Any, *, code: str) -> datetime:
    if not isinstance(value, str) or not value.strip():
        raise ProfileValidationError(code, "timestamp must be a non-empty string")
    try:
        return parse_instant(value)
    except InstantError as exc:
        if exc.code == TIME_INSTANT_NAIVE:
            raise ProfileValidationError(code, "timestamp must include a timezone") from exc
        raise ProfileValidationError(code, "timestamp is malformed") from exc


def _require_dict(value: Any, path: str) -> dict[str, Any]:
    if not isinstance(value, dict):
        raise ProfileValidationError("INPUT_INVALID", f"{path} must be an object")
    return value


def _require_list(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        raise ProfileValidationError("INPUT_INVALID", f"{path} must be an array")
    return value


def _require_nonempty_string(value: Any, path: str) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ProfileValidationError("INPUT_INVALID", f"{path} must be a non-empty string")
    return value


def _verify_named_commitment(container: dict[str, Any], value_key: str, commitment_key: str, code: str) -> None:
    if value_key not in container:
        raise ProfileValidationError("INPUT_INVALID", f"missing {value_key}")
    expected = container.get(commitment_key)
    if not isinstance(expected, str) or not expected.startswith("sha256:"):
        raise ProfileValidationError("INPUT_INVALID", f"missing or malformed {commitment_key}")
    if commitment(container[value_key]) != expected:
        raise ProfileValidationError(code, f"{commitment_key} does not match {value_key}")


def _obligation_semantic_payload(obligation: dict[str, Any]) -> dict[str, Any]:
    return {
        "obligation_id": obligation.get("obligation_id"),
        "policy_origin_ref": obligation.get("policy_origin_ref"),
        "policy_origin_version": obligation.get("policy_origin_version"),
        "required": obligation.get("required"),
        "source_ref": obligation.get("source_ref"),
        "max_age_seconds": obligation.get("max_age_seconds"),
        "resolution_semantics_id": obligation.get("resolution_semantics_id"),
        "resolution_semantics_commitment": obligation.get("resolution_semantics_commitment"),
    }


def _validate_obligation_fields(obligation: dict[str, Any]) -> None:
    oid = _require_nonempty_string(obligation.get("obligation_id"), "evidence_obligations[].obligation_id")
    _require_nonempty_string(obligation.get("policy_origin_ref"), f"obligation {oid}.policy_origin_ref")
    _require_nonempty_string(obligation.get("policy_origin_version"), f"obligation {oid}.policy_origin_version")
    if type(obligation.get("required")) is not bool:
        raise ProfileValidationError("OBLIGATION_REQUIRED_INVALID", f"obligation {oid}.required must be boolean")
    _require_nonempty_string(obligation.get("source_ref"), f"obligation {oid}.source_ref")
    max_age = obligation.get("max_age_seconds")
    if type(max_age) is not int or max_age < 0:
        raise ProfileValidationError(
            "EVIDENCE_FRESHNESS_INVALID",
            f"obligation {oid}.max_age_seconds must be a non-negative integer",
        )
    _require_nonempty_string(obligation.get("resolution_semantics_id"), f"obligation {oid}.resolution_semantics_id")
    semantics_commitment = obligation.get("resolution_semantics_commitment")
    if not isinstance(semantics_commitment, str) or not semantics_commitment.startswith("sha256:"):
        raise ProfileValidationError("INPUT_INVALID", f"obligation {oid}.resolution_semantics_commitment must be sha256")


def _validate_evidence_item_fields(
    item: dict[str, Any],
    *,
    by_obligation: dict[str, dict[str, Any]],
    evaluation_time: datetime,
) -> None:
    evidence_id = _require_nonempty_string(item.get("evidence_id"), "evidence_items[].evidence_id")
    obligation_ids = _require_list(item.get("obligation_ids"), f"evidence {evidence_id}.obligation_ids")
    if not obligation_ids:
        raise ProfileValidationError("INPUT_INVALID", f"evidence {evidence_id}.obligation_ids must not be empty")
    if any(not isinstance(oid, str) or not oid for oid in obligation_ids):
        raise ProfileValidationError("INPUT_INVALID", f"evidence {evidence_id}.obligation_ids must contain strings")
    if len(set(obligation_ids)) != len(obligation_ids):
        raise ProfileValidationError("INPUT_INVALID", f"evidence {evidence_id}.obligation_ids contains duplicates")

    source_ref = _require_nonempty_string(item.get("source_ref"), f"evidence {evidence_id}.source_ref")
    for oid in obligation_ids:
        obligation = by_obligation.get(oid)
        if obligation is None:
            raise ProfileValidationError("EVIDENCE_OBLIGATION_UNKNOWN", f"evidence {evidence_id} references unknown obligation {oid}")
        if source_ref != obligation["source_ref"]:
            raise ProfileValidationError(
                "EVIDENCE_SOURCE_MISMATCH",
                f"evidence {evidence_id} source {source_ref} is not admissible for obligation {oid}",
            )

    observed_at = _parse_time(item.get("observed_at"), code="EVIDENCE_TIME_INVALID")
    if observed_at > evaluation_time:
        raise ProfileValidationError(
            "EVIDENCE_TIME_FUTURE",
            f"evidence {evidence_id}.observed_at is after evaluation_time",
        )

    state = item.get("declared_state")
    if not isinstance(state, str) or state not in ALLOWED_EVIDENCE_STATES:
        raise ProfileValidationError(
            "EVIDENCE_STATE_INVALID",
            f"evidence {evidence_id}.declared_state must be one of {sorted(ALLOWED_EVIDENCE_STATES)}",
        )

    provenance = _require_dict(item.get("provenance"), f"evidence {evidence_id}.provenance")
    provenance_source = _require_nonempty_string(
        provenance.get("source_ref"), f"evidence {evidence_id}.provenance.source_ref"
    )
    if provenance_source != source_ref:
        raise ProfileValidationError(
            "EVIDENCE_PROVENANCE_SOURCE_MISMATCH",
            f"evidence {evidence_id} provenance source does not match evidence source",
        )


def _validate_resolver_semantics(resolver: dict[str, Any]) -> str:
    _verify_named_commitment(
        resolver,
        "classification_semantics",
        "classification_semantics_commitment",
        "RESOLVER_SEMANTICS_COMMITMENT_MISMATCH",
    )
    declared = resolver["classification_semantics"]
    if declared != SUPPORTED_CLASSIFICATION_SEMANTICS:
        raise ProfileValidationError(
            "UNSUPPORTED_RESOLVER_SEMANTICS",
            "declared classification semantics are not implemented by this proposed verifier",
        )
    return resolver["classification_semantics_commitment"]


def _evidence_status(obligation: dict[str, Any], items: list[dict[str, Any]], evaluation_time: datetime) -> str:
    """Classify already validated evidence under the single supported classifier."""
    oid = obligation["obligation_id"]
    candidates = [item for item in items if oid in item["obligation_ids"]]
    if not candidates:
        return "MISSING"
    states = {item["declared_state"] for item in candidates}
    if "conflict" in states or len({item.get("content_commitment") for item in candidates}) > 1:
        return "CONFLICT"
    if "unknown" in states:
        return "UNKNOWN"
    max_age = obligation["max_age_seconds"]
    for item in candidates:
        observed_at = _parse_time(item["observed_at"], code="EVIDENCE_TIME_INVALID")
        if (evaluation_time - observed_at).total_seconds() > max_age:
            return "STALE"
    if states == {"current"}:
        return "VALID"
    return "UNKNOWN"


def verify_record(record: dict[str, Any]) -> dict[str, Any]:
    """Validate one proposed-profile record and return locally established facts.

    Verification is structural and commitment-relative. It does not authenticate
    declarations or sources and does not establish external truth.
    """
    record = _require_dict(record, "record")
    if record.get("profile_version") != PROFILE_VERSION:
        raise ProfileValidationError("INPUT_INVALID", "unsupported proposed profile version")
    if record.get("authorizing") is not False:
        raise ProfileValidationError("INPUT_INVALID", "profile record must be explicitly non-authorizing")
    if record.get("canonicalization_profile") != CANONICALIZATION_PROFILE:
        raise ProfileValidationError("INPUT_INVALID", "canonicalization profile mismatch")
    if record.get("commitment_algorithm") != COMMITMENT_ALGORITHM:
        raise ProfileValidationError("INPUT_INVALID", "commitment algorithm mismatch")

    candidate = _require_dict(record.get("candidate"), "candidate")
    _verify_named_commitment(candidate, "materialized", "commitment", "CANDIDATE_COMMITMENT_MISMATCH")

    assurance = _require_dict(record.get("assurance"), "assurance")
    for name, classification in assurance.items():
        if classification not in ALLOWED_ASSURANCE_CLASSES:
            raise ProfileValidationError("INPUT_INVALID", f"invalid assurance class for {name}")

    policies = [_require_dict(x, "policies[]") for x in _require_list(record.get("policies"), "policies")]
    by_policy: dict[tuple[str, str], dict[str, Any]] = {}
    for policy in policies:
        ref = _require_nonempty_string(policy.get("ref"), "policies[].ref")
        version = _require_nonempty_string(policy.get("version"), "policies[].version")
        key = (ref, version)
        if key in by_policy:
            raise ProfileValidationError("INPUT_INVALID", "duplicate policy ref/version")
        _verify_named_commitment(policy, "content", "content_commitment", "POLICY_CONTENT_COMMITMENT_MISMATCH")
        _verify_named_commitment(policy, "evaluation_semantics", "evaluation_semantics_commitment", "POLICY_SEMANTICS_COMMITMENT_MISMATCH")
        by_policy[key] = policy

    evaluation_time = _parse_time(record.get("evaluation_time"), code="EVALUATION_TIME_INVALID")
    resolver = _require_dict(record.get("resolver_semantics"), "resolver_semantics")
    supported_semantics_commitment = _validate_resolver_semantics(resolver)

    obligations = [_require_dict(x, "evidence_obligations[]") for x in _require_list(record.get("evidence_obligations"), "evidence_obligations")]
    by_obligation: dict[str, dict[str, Any]] = {}
    for obligation in obligations:
        _validate_obligation_fields(obligation)
        oid = obligation["obligation_id"]
        if oid in by_obligation:
            raise ProfileValidationError("INPUT_INVALID", "duplicate obligation_id")
        origin = (obligation["policy_origin_ref"], obligation["policy_origin_version"])
        if origin not in by_policy:
            raise ProfileValidationError("POLICY_BINDING_FAILED", f"obligation {oid} has unknown policy origin")
        expected = obligation.get("obligation_commitment")
        if expected != commitment(_obligation_semantic_payload(obligation)):
            raise ProfileValidationError("OBLIGATION_COMMITMENT_MISMATCH", f"obligation {oid} commitment mismatch")
        if (
            obligation["resolution_semantics_id"] != SUPPORTED_RESOLUTION_SEMANTICS_ID
            or obligation["resolution_semantics_commitment"] != supported_semantics_commitment
        ):
            raise ProfileValidationError(
                "OBLIGATION_RESOLVER_SEMANTICS_MISMATCH",
                f"obligation {oid} does not bind the supported declared resolver semantics",
            )
        by_obligation[oid] = obligation

    requirements = [_require_dict(x, "institutional_requirements[]") for x in _require_list(record.get("institutional_requirements"), "institutional_requirements")]
    for requirement in requirements:
        _verify_named_commitment(requirement, "content", "commitment", "INSTITUTIONAL_REQUIREMENT_COMMITMENT_MISMATCH")
        if requirement.get("non_overridable") is not True:
            raise ProfileValidationError("INSTITUTIONAL_REQUIREMENT_FAILED", "institutional requirement must be non-overridable")
        expected_obligations = _require_dict(requirement.get("obligation_commitments"), "institutional_requirements[].obligation_commitments")
        for oid, expected in expected_obligations.items():
            actual = by_obligation.get(oid)
            if actual is None:
                raise ProfileValidationError("INSTITUTIONAL_OBLIGATION_REMOVED", f"institutional obligation {oid} missing")
            if actual.get("obligation_commitment") != expected:
                raise ProfileValidationError("INSTITUTIONAL_OBLIGATION_REINTERPRETED", f"institutional obligation {oid} changed")
            if actual.get("policy_origin_ref") != requirement.get("policy_origin_ref"):
                raise ProfileValidationError("INSTITUTIONAL_OBLIGATION_REINTERPRETED", f"institutional obligation {oid} origin changed")

    evidence = [_require_dict(x, "evidence_items[]") for x in _require_list(record.get("evidence_items"), "evidence_items")]
    for item in evidence:
        _verify_named_commitment(item, "content", "content_commitment", "EVIDENCE_CONTENT_COMMITMENT_MISMATCH")
        _verify_named_commitment(item, "provenance", "provenance_commitment", "EVIDENCE_PROVENANCE_COMMITMENT_MISMATCH")
        if item.get("assurance_class") not in ALLOWED_ASSURANCE_CLASSES:
            raise ProfileValidationError("INPUT_INVALID", "invalid evidence assurance class")
        _validate_evidence_item_fields(item, by_obligation=by_obligation, evaluation_time=evaluation_time)

    context = _require_dict(record.get("context"), "context")
    _verify_named_commitment(context, "materialized", "commitment", "CONTEXT_COMMITMENT_MISMATCH")

    statuses: dict[str, str] = {}
    for oid, obligation in by_obligation.items():
        status = _evidence_status(obligation, evidence, evaluation_time)
        statuses[oid] = status
        if obligation["required"] and status != "VALID":
            raise ProfileValidationError(f"EVIDENCE_{status}", f"required obligation {oid} resolved {status}")

    decision = _require_dict(record.get("decision"), "decision")
    decision_input_payload = {
        "profile_version": record.get("profile_version"),
        "canonicalization_profile": record.get("canonicalization_profile"),
        "commitment_algorithm": record.get("commitment_algorithm"),
        "candidate": candidate,
        "institutional_requirements": requirements,
        "policies": policies,
        "evidence_obligations": obligations,
        "evidence_items": evidence,
        "context": context,
        "evaluation_time": record.get("evaluation_time"),
        "resolver_semantics": resolver,
        "assurance": assurance,
    }
    if decision.get("input_commitment") != commitment(decision_input_payload):
        raise ProfileValidationError("DECISION_INPUT_COMMITMENT_MISMATCH", "decision input commitment does not match closed inputs")
    if tuple(decision.get("reason_precedence", [])) != REASON_PRECEDENCE:
        raise ProfileValidationError("DECISION_REASON_PRECEDENCE_MISMATCH", "reason precedence differs from profile")
    if decision.get("result") not in {"authorized", "hold", "deny"}:
        raise ProfileValidationError("INPUT_INVALID", "unsupported decision result")
    if not isinstance(decision.get("primary_reason"), str):
        raise ProfileValidationError("INPUT_INVALID", "primary_reason required")

    protected = {k: v for k, v in record.items() if k != "record_commitment"}
    expected_record_commitment = record.get("record_commitment")
    actual_record_commitment = commitment(protected)
    if expected_record_commitment != actual_record_commitment:
        raise ProfileValidationError("RECORD_COMMITMENT_MISMATCH", "record commitment mismatch")

    return {
        "valid": True,
        "record_commitment": actual_record_commitment,
        "evidence_statuses": statuses,
        "assurance_scope": "classification labels are declarations unless separately authenticated or verified",
        "independent_external_truth_verified": False,
        "authorizing": False,
    }
