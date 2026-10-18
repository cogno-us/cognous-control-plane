"""Opt-in merge-record/0.1: two operations later ruled to be one are folded by a record over ``operation_id`` values only.

Selected only by the host-governed ``RuntimeAuthorityProfile.merge`` field (it needs ``operation_identity`` too). With it unset nothing
here runs and no stored or hashed byte changes.

* A merge names a survivor operation and one or more folded operations. It never names an attempt id.
* The equivalence rule behind it is identified by content digest. The digest must be adopted by a ``rule_revision`` row of kind
  ``merge_equivalence_rule`` that is named by a configured signer (asserted, unauthenticated), a principal other than its reviser (N2). Otherwise the merge resolves
  ``unknown`` and has no effect.
* A merge by an authority that is not funded (``MergeProfile.funded_authorities``) is ``held`` and has no effect.
* A merge is ``refused`` when its operation ids are malformed, not admitted, bound to different principals or domains, or already folded.
* Only a ``merged`` record has effect. Every outcome is appended as a row; rows are never edited. A later rule change appends a
  ``rule_revision`` row and leaves earlier merge rows as they were written.
* Effect: the folded operations and the survivor share one effect budget of one. Before the second effect the second effect is
  suppressed (``operation_merged_effect_exists``). After both applied, a compensation obligation lists the effect id of every applied
  attempt. The obligation is a record only: nothing is compensated, reversed or sent here.

Limits (read before relying on it):
* This moves trust to the merge authority and to the rule signer; it makes that dependency explicit and does not remove it.
* All of it is a join over rows that anyone who can write the record file can rewrite (there is no record-store key): visibility for an honest reader, not tamper evidence.
* The destination key of a folded operation becomes the survivor's id, which a destination that stores our id enforces atomically; a
  destination without that capability is protected only by the control plane's own gate (check, then dispatch).
"""
from __future__ import annotations

import uuid
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

from .operation_identity import valid_operation_id
from .rule_revision import resolve_rule

PROFILE_ID = "merge-record/0.1"
RULE_KIND = "merge_equivalence_rule"

CODE_IDS_INVALID = "merge_operation_ids_invalid"
CODE_NOT_ADMITTED = "merge_operation_not_admitted"
CODE_DISCRIMINATOR_MISMATCH = "merge_operation_discriminator_mismatch"
CODE_ALREADY_FOLDED = "merge_operation_already_folded"
CODE_SURVIVOR_FOLDED = "merge_survivor_already_folded"
CODE_UNFUNDED = "merge_authority_unfunded"
CODE_RULE_UNKNOWN = "merge_rule_unknown"
CODE_EFFECT_EXISTS = "operation_merged_effect_exists"
CODE_EFFECT_UNRESOLVED = "operation_merged_effect_unresolved"

MergeOutcome = Literal["merged", "held", "unknown", "refused"]


class MergeProfile(BaseModel):
    """Trusted host configuration: who may merge. Never selected by a row."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["merge-record/0.1"] = PROFILE_ID
    #: Principals funded to fold operations. An authority outside this set holds.
    funded_authorities: list[str] = Field(min_length=1)


class MergeRecord(BaseModel):
    """One merge decision, over operation ids only. Appended, never edited."""

    model_config = ConfigDict(extra="forbid")
    merge_id: str = Field(min_length=1)
    survivor_operation_id: str
    folded_operation_ids: list[str]
    equivalence_rule_ref: str
    equivalence_rule_digest: str
    rule_state: Literal["adopted", "unknown"]
    rule_verified_through: str
    rule_findings: list[str] = Field(default_factory=list)
    merged_by: str
    authority_ref: str | None = None
    reason: str = Field(min_length=1)
    outcome: MergeOutcome
    reasons: list[str] = Field(default_factory=list)
    compensation_obligation_id: str | None = Field(default=None, exclude_if=lambda v: v is None)
    recorded_at: str
    evaluated_at: str | None = Field(default=None, exclude_if=lambda v: v is None)  # freshness/0.1 only


class CompensationObligation(BaseModel):
    """What a merge after two applied effects leaves to do. Record only: nothing here compensates anything."""

    model_config = ConfigDict(extra="forbid")
    obligation_id: str
    merge_id: str
    survivor_operation_id: str
    operation_ids: list[str]
    effect_ids: list[str]                                   # every applied attempt's effect id, once each
    effect_ids_by_operation: dict[str, list[str]]
    unresolved_effect_ids: list[str] = Field(default_factory=list)  # attempts with no outcome yet (may have applied)
    status: Literal["recorded"] = "recorded"
    execution: Literal["not_executed"] = "not_executed"
    recorded_at: str
    evaluated_at: str | None = Field(default=None, exclude_if=lambda v: v is None)


# ------------------------------------------------------------------------------------------------ reading the ledger
def _merged_rows(document: dict) -> list[dict]:
    return [x for x in document.get("merge_records", []) if x["outcome"] == "merged"]


def merged_into(document: dict, operation_id: str) -> str | None:
    """The operation a folded operation was merged into (the survivor, followed through later merges), else None."""
    folded_to = {f: m["survivor_operation_id"] for m in _merged_rows(document) for f in m["folded_operation_ids"]}
    current, seen = operation_id, set()
    while current in folded_to and current not in seen:
        seen.add(current)
        current = folded_to[current]
    return current if current != operation_id else None


def merge_root(document: dict, operation_id: str) -> str:
    return merged_into(document, operation_id) or operation_id


def merge_members(document: dict, operation_id: str) -> list[str]:
    """Every operation sharing the effect budget of ``operation_id`` (itself alone when it was never merged)."""
    root = merge_root(document, operation_id)
    return [root] + sorted({f for m in _merged_rows(document) for f in m["folded_operation_ids"]
                            if merge_root(document, f) == root})


def dispatch_operation_id(document: dict, operation_id: str) -> str:
    """The id a destination that stores our id dedupes on: the survivor's for a folded operation."""
    return merge_root(document, operation_id)


def attempt_outcomes(document: dict, operation_ids: list[str]) -> tuple[dict[str, list[str]], list[str]]:
    """Per operation, the effect ids of applied attempts; and the effect ids of attempts with no outcome yet.

    Applied: acknowledged or partial, or any status with a closeout that observed the effect applied or partial. Unresolved:
    ``attempted`` or ``unknown`` with no closeout. A ``failed`` attempt without a closeout did not apply.
    """
    wanted = set(operation_ids)
    joins = {j["attempt_id"]: j for j in document.get("attempt_joins", []) if j["operation_id"] in wanted}
    latest: dict[str, dict] = {}
    for row in document.get("attempts", []):
        if row["attempt_id"] in joins:
            latest[row["attempt_id"]] = row
    closed = {c["attempt_id"] for c in document.get("closeouts", []) if c["observed_state"] in ("applied", "partial")}
    applied: dict[str, list[str]] = {op: [] for op in operation_ids}
    unresolved: list[str] = []
    for attempt_id, row in latest.items():
        op, effect = joins[attempt_id]["operation_id"], row["effect_id"]
        if row["status"] in ("acknowledged", "partial") or attempt_id in closed:
            if effect not in applied[op]:
                applied[op].append(effect)
        elif row["status"] in ("attempted", "unknown") and effect not in unresolved:
            unresolved.append(effect)
    return applied, [e for e in unresolved if not any(e in v for v in applied.values())]


def merge_gate(document: dict, operation_id: str, effect_id: str) -> str | None:
    """Effect-time check for an operation that belongs to a merged set: a second effect is suppressed.

    Returns a reason code, or None. An operation that was never merged is untouched by this gate.
    """
    members = merge_members(document, operation_id)
    if len(members) == 1:
        return None
    applied, unresolved = attempt_outcomes(document, members)
    if any(e != effect_id for effects in applied.values() for e in effects):
        return CODE_EFFECT_EXISTS
    if any(e != effect_id for e in unresolved):
        return CODE_EFFECT_UNRESOLVED
    return None


# ------------------------------------------------------------------------------------------------ resolving a merge
def resolve_merge(document: dict, *, profile: MergeProfile, rule_profile, survivor: str, folded: list[str],
                  equivalence_rule_ref: str, equivalence_rule_digest: str, merged_by: str, authority_ref: str | None,
                  reason: str, recorded_at: str, evaluated_at: str | None = None
                  ) -> tuple[MergeRecord, CompensationObligation | None]:
    """Judge one merge request against the ledger. Pure: returns the rows to append, writes nothing.

    Precedence of outcomes: ``refused`` (structural), then ``held`` (unfunded authority), then ``unknown`` (rule not adopted).
    Every failing check is listed in ``reasons``.
    """
    refused: list[str] = []
    ids = [survivor, *folded]
    if not folded or len(set(ids)) != len(ids) or not all(valid_operation_id(x) for x in ids):
        refused.append(CODE_IDS_INVALID)
    admitted = {x["operation_id"]: x for x in document.get("operations", [])}
    if not refused:
        if any(x not in admitted for x in ids):
            refused.append(CODE_NOT_ADMITTED)
        else:
            if len({(admitted[x]["principal_id"], admitted[x]["authority_domain"]) for x in ids}) != 1:
                refused.append(CODE_DISCRIMINATOR_MISMATCH)
            if merged_into(document, survivor) is not None:
                refused.append(CODE_SURVIVOR_FOLDED)
            if any(merged_into(document, f) is not None for f in folded):
                refused.append(CODE_ALREADY_FOLDED)
    held = [] if merged_by in profile.funded_authorities else [CODE_UNFUNDED]
    revisions = document.get("rule_revisions", [])
    if rule_profile is None:
        res = {"state": "unknown", "verified_through": "none", "findings": ["rule_revision_profile_unconfigured"]}
    else:
        res = resolve_rule(rule_profile, revisions, equivalence_rule_ref, equivalence_rule_digest)
        if any(x["rule_ref"] == equivalence_rule_ref and x["rule_kind"] != RULE_KIND for x in revisions):
            res = {**res, "state": "unknown", "findings": [*res["findings"], "rule_kind_not_merge_equivalence_rule"]}
    unknown = [CODE_RULE_UNKNOWN] if res["state"] != "adopted" else []
    outcome: MergeOutcome = "refused" if refused else "held" if held else "unknown" if unknown else "merged"
    merge_id = str(uuid.uuid4())
    obligation = None
    if outcome == "merged":
        members = [survivor, *folded]
        applied, unresolved = attempt_outcomes(document, members)
        effect_ids = [e for op in members for e in applied[op]]
        if len(effect_ids) >= 2:  # two effects landed for what is now one operation
            obligation = CompensationObligation(
                obligation_id=str(uuid.uuid4()), merge_id=merge_id, survivor_operation_id=survivor,
                operation_ids=sorted(members), effect_ids=effect_ids,
                effect_ids_by_operation={op: applied[op] for op in members if applied[op]},
                unresolved_effect_ids=unresolved, recorded_at=recorded_at,
                **({"evaluated_at": evaluated_at} if evaluated_at else {}))
    record = MergeRecord(
        merge_id=merge_id, survivor_operation_id=survivor, folded_operation_ids=list(folded),
        equivalence_rule_ref=equivalence_rule_ref, equivalence_rule_digest=equivalence_rule_digest,
        rule_state=res["state"], rule_verified_through=res["verified_through"], rule_findings=list(res["findings"]),
        merged_by=merged_by, authority_ref=authority_ref, reason=reason, outcome=outcome,
        reasons=sorted({*refused, *held, *unknown}),
        compensation_obligation_id=obligation.obligation_id if obligation else None, recorded_at=recorded_at,
        **({"evaluated_at": evaluated_at} if evaluated_at else {}))
    return record, obligation
