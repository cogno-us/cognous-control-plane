"""Opt-in rule-revision/0.1: digest-pinned rules with append-only, independently signed revision rows.

One record shape (`RuleRevision`, modelled on `VocabularyChange`) serves four rule kinds: the reason registry, a policy, a gate
implementation and a merge equivalence rule. A rule version is a name; the digest pins the content. A digest only counts as adopted
when a revision row for it was signed by a configured principal other than the reviser.

Limits (read before relying on it):
* Trust moves to the revision signer. It is made explicit here; it is not removed.
* Everything is a join over rows in the record store. A holder of the store key can rewrite rows, so this gives visibility to an
  honest reader, not tamper evidence. An outside-held digest is a separate control.
* Nothing here is active unless a `RuleRevisionProfile` is configured; the pinned default path is unchanged.
"""
from __future__ import annotations

from datetime import datetime
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

PROFILE_VERSION = "rule-revision/0.1"
RULE_KINDS = ("reason_registry", "policy", "gate_implementation", "merge_equivalence_rule")
RuleKind = Literal["reason_registry", "policy", "gate_implementation", "merge_equivalence_rule"]

# Ordered verification levels. A receipt names the highest level reached before verification stopped.
LEVELS = ("none", "revision_row_present", "signer_independent_and_configured", "digest_matches_signed_revision")


class RuleRevision(BaseModel):
    """An append-only transition of one rule's content digest. Never edits a prior row."""
    model_config = ConfigDict(extra="forbid")
    revision_id: str = Field(min_length=1)
    rule_kind: RuleKind
    rule_ref: str = Field(min_length=1)
    from_digest: str | None = None        # None marks the adoption row of a rule
    to_digest: str = Field(min_length=1)
    reviser: str = Field(min_length=1)
    signer: str | None = None             # None = unsigned; never counts toward adoption
    authority_ref: str | None = None
    reason: str = Field(min_length=1)
    supersedes: str | None = None         # revision_id of an earlier row of the same rule_ref
    recorded_at: str
    # Arity declared at signing (reason_registry rows): {code: operand-shape count}. Compared with measured arity.
    declared_arity: dict[str, int] | None = Field(default=None, exclude_if=lambda v: v is None)


class RuleRevisionRefusal(BaseModel):
    """A refused revision attempt, retained so the refusal is visible."""
    model_config = ConfigDict(extra="forbid")
    refusal_id: str
    revision: dict
    reasons: list[str]
    recorded_at: str


class RuleRevisionRefused(ValueError):
    def __init__(self, reasons: list[str]):
        super().__init__(",".join(reasons))
        self.reasons = reasons


class RuleRevisionProfile(BaseModel):
    """Trusted host configuration. The signer set is configured, never hard-coded and never selected by a row.

    `host_digests` carries the digests of rules the host itself runs (reason registry, gate implementation, merge equivalence rule),
    keyed by rule_ref. Policy digests come from the policy status read at decision time.
    """
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["rule-revision/0.1"] = PROFILE_VERSION
    signers: list[str] = Field(min_length=1)
    host_digests: dict[str, str] = Field(default_factory=dict)
    host_rule_kinds: dict[str, RuleKind] = Field(default_factory=dict)


def _t(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt


def _row(x) -> dict:
    return x.model_dump(mode="json") if isinstance(x, BaseModel) else dict(x)


def revision_defects(profile: RuleRevisionProfile, row) -> list[str]:
    """Why a row does not count toward adoption. Empty means it counts."""
    r = _row(row)
    out = []
    if not r.get("signer"):
        out.append("unsigned_revision_row")
    elif r["signer"] == r["reviser"]:
        out.append("self_signed_revision_row")
    elif r["signer"] not in profile.signers:
        out.append("signer_not_configured")
    return out


def counting_rows(profile: RuleRevisionProfile, revisions, rule_ref: str) -> list[dict]:
    """Valid rows of one rule in append order, minus rows superseded by a later valid row."""
    rows = [_row(x) for x in revisions if _row(x)["rule_ref"] == rule_ref]
    valid = [x for x in rows if not revision_defects(profile, x)]
    superseded = {x["supersedes"] for x in valid if x.get("supersedes")}
    return [x for x in valid if x["revision_id"] not in superseded]


def adopted_digest(profile: RuleRevisionProfile, revisions, rule_ref: str) -> str | None:
    live = counting_rows(profile, revisions, rule_ref)
    return live[-1]["to_digest"] if live else None


def resolve_rule(profile: RuleRevisionProfile, revisions, rule_ref: str, observed_digest: str | None) -> dict:
    """Resolve one rule to `adopted` or `unknown`; `unknown` is never silently `adopted`."""
    rows = [_row(x) for x in revisions if _row(x)["rule_ref"] == rule_ref]
    findings: list[str] = []
    level = 0
    if rows:
        level = 1
    for r in rows:
        findings.extend(d for d in revision_defects(profile, r) if d not in findings)
    live = counting_rows(profile, revisions, rule_ref)
    if live:
        level = 2
    adopted = live[-1]["to_digest"] if live else None
    if not live:
        findings.append("no_signed_revision")
    if observed_digest is None:
        findings.append("observed_digest_absent")
    elif live and observed_digest != adopted:
        findings.append("digest_mismatch_with_adopted")
    state = "unknown"
    if live and observed_digest is not None and observed_digest == adopted:
        state, level = "adopted", 3
    return {"rule_ref": rule_ref, "state": state, "observed_digest": observed_digest, "adopted_digest": adopted,
            "verified_through": LEVELS[level], "findings": findings}


def append_rule_revision(records, profile: RuleRevisionProfile, revision: RuleRevision, *, now: str | None = None) -> RuleRevision:
    """Append a revision row, or persist a refusal row and raise `RuleRevisionRefused`.

    Self-signed and unauthorised-signer rows are refused. Unsigned rows are retained (visibility) but never count.
    Chain rule: `from_digest` must equal the currently adopted digest of the rule (or, when superseding, that of the superseded
    row); an adoption row has `from_digest=None` and requires that nothing is adopted yet or that it supersedes.
    """
    import uuid
    _t(revision.recorded_at)
    reasons: list[str] = []
    defects = revision_defects(profile, revision)
    reasons.extend(d for d in defects if d != "unsigned_revision_row")
    with records._transaction():
        document = records._read_document()
        rows = document.setdefault("rule_revisions", [])
        if any(x["revision_id"] == revision.revision_id for x in rows):
            reasons.append("rule_revision_duplicate")
        expected_from = adopted_digest(profile, rows, revision.rule_ref)
        if revision.supersedes:
            target = next((x for x in rows if x["revision_id"] == revision.supersedes), None)
            if target is None or target["rule_ref"] != revision.rule_ref:
                reasons.append("rule_revision_supersedes_unknown")
            else:
                expected_from = target["from_digest"]
        if "unsigned_revision_row" not in defects and revision.from_digest != expected_from:
            reasons.append("rule_revision_from_digest_mismatch")
        if not reasons:
            rows.append(revision.model_dump(mode="json"))
            from .bounded import BoundedRunRecord
            BoundedRunRecord.model_validate(document)
            records._write(document)
            return revision
        refusal = RuleRevisionRefusal(refusal_id=str(uuid.uuid4()), revision=revision.model_dump(mode="json"),
                                      reasons=sorted(set(reasons)), recorded_at=now or revision.recorded_at)
        document.setdefault("rule_revision_refusals", []).append(refusal.model_dump(mode="json"))
        from .bounded import BoundedRunRecord
        BoundedRunRecord.model_validate(document)
        records._write(document)
    raise RuleRevisionRefused(refusal.reasons)


def rule_identity(profile: RuleRevisionProfile, revisions, policy_digests: dict[str, str | None]) -> dict:
    """Digests (not only versions) and resolution state for the rules a decision or refusal relied on."""
    out: dict = {"rules": {}}
    for ref, digest in {**profile.host_digests, **policy_digests}.items():
        res = resolve_rule(profile, revisions, ref, digest)
        out["rules"][ref] = {"digest": digest, "state": res["state"], "verified_through": res["verified_through"],
                             "findings": res["findings"]}
    out["unknown"] = sorted(r for r, v in out["rules"].items() if v["state"] != "adopted")
    return out
