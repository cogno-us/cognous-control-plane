"""Opt-in operation identity profile (operation-identity/0.1).

One join record per attempt. The profile is selected only by the host-governed
``RuntimeAuthorityProfile.operation_identity`` field. With it unset nothing here
runs, ``effect_id`` keeps its legacy meaning and no stored or hashed byte changes.

Identity facts, in the vocabulary of the runtime sidecar ``OperationDiscriminator``
(principal, authority domain, operation id):

* ``operation_id`` is supplied by the grant issuer inside the issuer-approved
  ``runtime_authority`` extension (so the approval commitment covers it). It is
  stable across grant revisions. A planner or worker never supplies it.
* ``attempt_id`` is the existing ``EffectAttempt.attempt_id``; it stays subordinate.
* ``check_id`` is the journal check that licensed the attempt. The same id is now
  carried by ``CheckEvent``, ``ResolutionCheck`` and the attempt join row.
* A renewal names the operation it continues. Only the issuer recorded at admission
  writes one; any other writer is refused and the refusal is recorded. ``written_by`` is an asserted name (unauthenticated):
  the check compares strings, it does not authenticate the writer.
* A merge is defined over operation ids. ``merged_into`` is a field only here; merge
  logic is a later stream.
"""
from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

PROFILE_ID = "operation-identity/0.1"
#: Capability a destination must declare before the workflow dispatches an operation id.
DESTINATION_CAPABILITY = "operation-identity/0.1"

OPERATION_ID_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:/#-]{0,127}")

#: Reason/refusal codes emitted by this profile (all registered in the reason registry).
CODE_ID_MISSING = "operation_id_missing"
CODE_ID_INVALID = "operation_id_invalid"
CODE_GRANT_MISMATCH = "operation_grant_mismatch"
CODE_RENEWAL_UNRECORDED = "operation_renewal_unrecorded"
CODE_NOT_ADMITTED = "operation_not_admitted"
CODE_NOT_BY_ISSUER = "renewal_not_written_by_grant_issuer"
CODE_REVISION_NOT_NEW = "renewal_revision_not_new"


class OperationIdentityProfile(BaseModel):
    """Trusted host configuration: what the resolver is, recorded on every join row."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["operation-identity/0.1"] = PROFILE_ID
    resolver_id: str = Field(min_length=1, max_length=256)
    resolver_version: str = Field(min_length=1, max_length=256)


class OperationAdmissionRow(BaseModel):
    """First authorized decision for an operation id: who issued it and for which grant."""

    model_config = ConfigDict(extra="forbid")
    operation_id: str
    principal_id: str
    authority_domain: str
    issuer: str
    grant_id: str
    first_grant_revision: str
    admitted_at: str
    evaluated_at: str | None = Field(default=None, exclude_if=lambda v: v is None)  # freshness/0.1 only


class OperationRenewalRow(BaseModel):
    """A renewal (grant revision continuing an operation), accepted or refused."""

    model_config = ConfigDict(extra="forbid")
    renewal_id: str
    operation_id: str
    grant_id: str | None = None
    from_revision: str | None = None
    to_revision: str
    written_by: str
    outcome: Literal["accepted", "refused"]
    refusal_code: str | None = None
    recorded_at: str
    evaluated_at: str | None = Field(default=None, exclude_if=lambda v: v is None)  # freshness/0.1 only


class AttemptJoin(BaseModel):
    """One join row per attempt, so operation, attempt and check join by id."""

    model_config = ConfigDict(extra="forbid")
    join_id: str
    operation_id: str
    attempt_id: str
    check_id: str
    effect_id: str
    decision_id: str
    grant_id: str
    grant_revision: str
    resolver_id: str
    resolver_version: str
    class_max_age: int
    expected_effective_grant_digest: str | None = None
    #: Field only. When a later stream folds this operation into another, this holds
    #: the surviving ``operation_id``, never an attempt id.
    merged_into: str | None = None
    recorded_at: str
    evaluated_at: str | None = Field(default=None, exclude_if=lambda v: v is None)  # freshness/0.1 only
    time_source: Literal["control_plane", "test_override"]


def valid_operation_id(value: object) -> bool:
    return isinstance(value, str) and OPERATION_ID_PATTERN.fullmatch(value) is not None


def licensed_revisions(document: dict, operation_id: str) -> set[str]:
    """Grant revisions that may license this operation: first, plus accepted renewals."""
    admitted = next((x for x in document.get("operations", []) if x["operation_id"] == operation_id), None)
    if admitted is None:
        return set()
    return {admitted["first_grant_revision"]} | {
        x["to_revision"] for x in document.get("operation_renewals", [])
        if x["operation_id"] == operation_id and x["outcome"] == "accepted"
    }


def operation_status(document: dict, *, operation_id: str, principal_id: str, authority_domain: str,
                     issuer: str, grant_id: str, grant_revision: str) -> Literal[
                         "ok", "not_admitted", "collision", "renewal_unrecorded"]:
    """Read-only judgement of a binding against the operation ledger."""
    admitted = next((x for x in document.get("operations", []) if x["operation_id"] == operation_id), None)
    if admitted is None:
        return "not_admitted"
    if (admitted["principal_id"], admitted["authority_domain"], admitted["issuer"], admitted["grant_id"]) != (
            principal_id, authority_domain, issuer, grant_id):
        return "collision"
    if grant_revision not in licensed_revisions(document, operation_id):
        return "renewal_unrecorded"
    return "ok"
