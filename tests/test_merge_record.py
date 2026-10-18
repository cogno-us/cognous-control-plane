"""merge-record/0.1: opt-in merge of two operations over operation ids only (component-local tests).

Synthetic fixtures only. The composed cross-component scenarios live in the qualification suite (suites/operation-identity,
test_merge_profile.py); these tests cover the control plane's own rules.

Provenance of "expected today" values (default path, profile unset): the `*_default_*` rows were RUN on main 3f6a766 before this
change and are re-run on every test run. Nothing here is taken from code reading alone.
"""
import ast
import json
import pathlib

import pytest

import agent_control_plane.bounded as bounded
from agent_control_plane import merge as merge_module
from agent_control_plane.bounded import commitment
from agent_control_plane.merge import MergeProfile, merge_gate, merge_members, merged_into
from agent_control_plane.rule_revision import RuleRevision, RuleRevisionProfile, append_rule_revision
from tests import test_bounded_authorization as tba
from tests.test_bounded_authorization import ISSUER, NOW, POLICY_REF, PROFILE
from tests.test_operation_identity import IDENTITY, run_document, two_effects, two_effects_manifest
from tests.test_runtime_authority import bind_approval, setup_flow

REGISTRY = json.loads((pathlib.Path(__file__).resolve().parents[1] / "schemas" / "runtime_authority_reasons_0_2.json").read_text())
MERGER, OTHER, SIGNER, POLICY_SIGNER = ("urn:cognous:principal:merger", "urn:cognous:principal:requester",
                                        "urn:cognous:principal:rule-signer", "urn:cognous:principal:policy-signer")
RULE = "urn:cognous:merge-rule:same-refund-case"
D1, D2 = commitment({"merge_rule": "v1"}), commitment({"merge_rule": "v2"})
POLICY_DIGEST = commitment({"policy": "v1"})
A, B, C = "op-order-100/refund-1", "op-order-100/refund-2", "op-order-100/refund-3"


@pytest.fixture(autouse=True)
def _clock(monkeypatch):
    monkeypatch.setattr(bounded, "_now", lambda: NOW)


class Ops:
    """One workflow serving several operations. The synthetic approval binds one proposal and one operation id at a time,
    so ``use`` swaps both (and rebinds the approval) before a decision or an execution."""

    def __init__(self, tmp_path, monkeypatch, *, funded=(MERGER,), rule_signers=(SIGNER, POLICY_SIGNER), merge=True):
        two_effects_manifest(monkeypatch)
        self.p1, self.r, self.f, cfg = setup_flow(tmp_path)
        two_effects(self.r)
        update = {"operation_identity": IDENTITY}
        if merge:
            update["merge"] = MergeProfile(funded_authorities=list(funded))
        cfg = cfg.model_copy(update=update)
        self.f.runtime_authority_profile = cfg.snapshot()
        self.cfg = cfg
        self.f.rule_revision_profile = RuleRevisionProfile(signers=list(rule_signers))
        self.r.policies[POLICY_REF].digest = POLICY_DIGEST
        self.sign(RuleRevision(revision_id="adopt-policy", rule_kind="policy", rule_ref=POLICY_REF, from_digest=None,
                               to_digest=POLICY_DIGEST, reviser=OTHER, signer=POLICY_SIGNER, authority_ref="synthetic-authority:1",
                               reason="synthetic", recorded_at=NOW.isoformat()))
        self.proposals = {A: self.p1, B: tba.proposal(correlation_id="case-2"), C: tba.proposal(correlation_id="case-3")}
        self.ref = self.r.contexts[PROFILE]["grant"]["approval_refs"][0]
        self.decisions = {}

    def sign(self, row):
        append_rule_revision(self.f.records, self.f.rule_revision_profile, row)

    def adopt_rule(self, digest=D1, *, rid="adopt-merge-rule", frm=None, signer=SIGNER, reviser=OTHER, kind="merge_equivalence_rule"):
        self.sign(RuleRevision(revision_id=rid, rule_kind=kind, rule_ref=RULE, from_digest=frm, to_digest=digest, reviser=reviser,
                               signer=signer, authority_ref="synthetic-authority:2", reason="synthetic",
                               recorded_at=NOW.isoformat()))

    def use(self, operation):
        self.r.contexts[PROFILE]["runtime_authority"]["operation_id"] = operation
        self.r.approvals[self.ref].proposal_commitment = commitment(
            self.proposals[operation].model_dump(mode="json", exclude_none=False))
        bind_approval(self.r, self.f.runtime_authority_profile)
        return self.proposals[operation]

    def decide(self, operation):
        p = self.use(operation)
        d = self.f.decide(p, now=NOW)
        assert d.result == "authorized", d.reasons
        self.decisions[operation] = d
        return d

    def execute(self, operation):
        p = self.use(operation)
        return self.f.execute(p, self.decisions[operation], adapter_id=p.adapter_id, now=NOW)

    def merge(self, folded=(B,), survivor=A, *, by=MERGER, digest=D1, ref=RULE):
        return self.f.record_merge(survivor_operation_id=survivor, folded_operation_ids=list(folded), equivalence_rule_ref=ref,
                                   equivalence_rule_digest=digest, merged_by=by, authority_ref="urn:cognous:authority:merge-1",
                                   reason="same refund, filed twice", now=NOW)

    def doc(self):
        return run_document(self.f)

    def effects(self):
        return sorted(self.f.destination.snapshot()["effects"])


@pytest.fixture
def ops(tmp_path, monkeypatch):
    o = Ops(tmp_path, monkeypatch)
    o.adopt_rule()
    return o


# ---------------------------------------------------------------- default path unchanged
def test_default_path_has_no_merge_keys_and_class_dump_is_unchanged(tmp_path):
    p, r, f, c = setup_flow(tmp_path)
    dumped = c.model_dump(mode="json")
    assert not {"merge", "reversibility", "dedupe"} & set(dumped)
    assert set(dumped["actions"][p.action_id]) == {"class_id", "irreversible", "max_status_age_seconds", "on_unreadable"}
    d = f.decide(p, now=NOW)
    f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    document = run_document(f)
    assert not {"merge_records", "compensation_obligations", "snapshot_uses", "dedupe_escalations"} & set(document)


def test_merge_without_the_profile_is_refused(tmp_path, monkeypatch):
    o = Ops(tmp_path, monkeypatch, merge=False)
    with pytest.raises(PermissionError):
        o.merge()
    assert "merge_records" not in o.doc()


def test_merge_profile_needs_operation_identity():
    from agent_control_plane.runtime_authority import ActionClass, RuntimeAuthorityProfile
    with pytest.raises(ValueError, match="operation-identity"):
        RuntimeAuthorityProfile(catalogue_version="x", actions={"a": ActionClass(class_id="c")},
                                merge=MergeProfile(funded_authorities=[MERGER]))


# ---------------------------------------------------------------- merge before the second effect suppresses it
def test_merge_before_effect_suppresses_second(ops):
    ops.decide(A), ops.decide(B)
    attempt, _ = ops.execute(A)
    assert attempt.status == "acknowledged"
    record = ops.merge()
    assert record.outcome == "merged" and record.reasons == []
    with pytest.raises(PermissionError):
        ops.execute(B)
    refusal = ops.f.records.load().refusals[-1]
    assert refusal.reasons == ["operation_merged_effect_exists"] and refusal.effect_id == ops.decisions[B].effect_id
    assert ops.effects() == [ops.decisions[A].effect_id], "the destination never saw the second effect"
    assert "compensation_obligations" not in ops.doc(), "only one effect landed: nothing to compensate"


def test_without_the_merge_the_second_effect_lands_today(ops):
    """Expected today (ran on the default-path code, merge not recorded): two operations, two effects."""
    ops.decide(A), ops.decide(B)
    ops.execute(A), ops.execute(B)
    assert len(ops.effects()) == 2


def test_first_effect_wins_whichever_operation_applies_first(ops):
    ops.decide(A), ops.decide(B)
    ops.merge()
    attempt, _ = ops.execute(B)  # the folded operation applies first: it is the one effect of the merged operation
    assert attempt.status == "acknowledged"
    with pytest.raises(PermissionError):
        ops.execute(A)
    assert ops.f.records.load().refusals[-1].reasons == ["operation_merged_effect_exists"]
    assert ops.effects() == [ops.decisions[B].effect_id]


def test_folded_operation_dispatches_under_the_survivors_id(ops):
    ops.decide(A), ops.decide(B)
    ops.merge()
    ops.execute(B)
    assert list(ops.f.destination.snapshot()["operations"]) == [A], "the destination key is the survivor's operation id"
    join = [x for x in ops.f.records.load().attempt_joins if x.operation_id == B][-1]
    assert join.merged_into == A and join.operation_id == B


def test_unresolved_attempt_in_the_merged_set_holds_the_second_effect(ops, monkeypatch):
    ops.decide(A), ops.decide(B)
    monkeypatch.setattr(ops.f.destination, "apply", lambda **kw: (_ for _ in ()).throw(TimeoutError("lost")))
    attempt, _ = ops.execute(A)
    assert attempt.status == "unknown"
    ops.merge()
    with pytest.raises(PermissionError):
        ops.execute(B)
    assert ops.f.records.load().refusals[-1].reasons == ["operation_merged_effect_unresolved"]


def test_resubmitting_the_one_applied_effect_is_not_suppressed_by_its_own_row(ops):
    """The gate looks for effects OTHER than the one being dispatched: the same effect id is the destination's own dedupe case."""
    ops.decide(A), ops.decide(B)
    ops.merge()
    ops.execute(A)
    again, _ = ops.execute(A)
    assert again.status == "acknowledged" and ops.effects() == [ops.decisions[A].effect_id]
    assert not [x for x in ops.f.records.load().refusals if x.reasons == ["operation_merged_effect_exists"]]


def test_an_effect_settled_by_a_closeout_counts_as_applied_not_unresolved(ops, monkeypatch):
    ops.decide(A), ops.decide(B)
    real = ops.f.destination.apply
    monkeypatch.setattr(ops.f.destination, "apply", lambda **kw: (_ for _ in ()).throw(TimeoutError("lost")))
    attempt, _ = ops.execute(A)
    assert attempt.status == "unknown"
    monkeypatch.setattr(ops.f.destination, "apply", real)
    real(effect_id=ops.decisions[A].effect_id, grant_id=ops.decisions[A].binding.grant_id, max_effects=2, target="t", amount=1,
         unit="USD", payload={})  # the provider did land it after the lost acknowledgement
    assert ops.f.reconcile(ops.decisions[A].effect_id, now=NOW).result == "applied"
    ops.merge()
    with pytest.raises(PermissionError):
        ops.execute(B)
    assert ops.f.records.load().refusals[-1].reasons == ["operation_merged_effect_exists"], "applied by closeout, not merely unresolved"


# ---------------------------------------------------------------- merge after both applied: obligation, record only
def test_merge_after_both_applied_emits_compensation_obligation(ops):
    ops.decide(A), ops.decide(B)
    ops.execute(A), ops.execute(B)
    before = ops.effects()
    record = ops.merge()
    assert record.outcome == "merged" and record.compensation_obligation_id
    (obligation,) = ops.f.records.load().compensation_obligations
    assert obligation.obligation_id == record.compensation_obligation_id and obligation.merge_id == record.merge_id
    assert sorted(obligation.effect_ids) == before == sorted([ops.decisions[A].effect_id, ops.decisions[B].effect_id])
    assert obligation.effect_ids_by_operation == {A: [ops.decisions[A].effect_id], B: [ops.decisions[B].effect_id]}
    assert obligation.status == "recorded" and obligation.execution == "not_executed"
    assert ops.effects() == before, "record only: nothing was compensated, reversed or sent"
    assert len(ops.f.records.load().attempts) == 4  # two attempts per operation (attempted, acknowledged); none added by the merge


def test_merge_record_references_operation_ids_not_attempt_ids(ops):
    ops.decide(A), ops.decide(B)
    ops.execute(A), ops.execute(B)
    record = ops.merge()
    text = json.dumps(record.model_dump(mode="json"))
    attempt_ids = {x.attempt_id for x in ops.f.records.load().attempts}
    assert attempt_ids and not any(x in text for x in attempt_ids)
    assert set(record.model_dump(mode="json")) >= {"survivor_operation_id", "folded_operation_ids", "equivalence_rule_digest"}
    assert [record.survivor_operation_id, *record.folded_operation_ids] == [A, B]


def test_obligation_lists_every_applied_attempt_including_a_renewed_operation(ops):
    """Composed: A was renewed (revision 2) and its r2 applied; B applied too. The merge names operations, the obligation the
    effect id of every applied attempt, not one per operation id."""
    from tests.test_operation_identity import renew
    ops.decide(A)
    renew(ops.r, ops.f.runtime_authority_profile, "2")
    ops.f.record_renewal(A, to_revision="2", written_by=ISSUER, now=NOW)
    ops.decide(B)
    d2 = ops.f.decide(ops.use(A), now=NOW)
    assert d2.result == "authorized", d2.reasons
    ops.decisions[A] = d2
    ops.execute(A), ops.execute(B)
    ops.merge()
    (obligation,) = ops.f.records.load().compensation_obligations
    assert sorted(obligation.effect_ids) == ops.effects() == sorted([d2.effect_id, ops.decisions[B].effect_id])
    assert ops.decisions[A].effect_id != ops.decisions[B].effect_id and d2.effect_id != "" and len(obligation.operation_ids) == 2


# ---------------------------------------------------------------- authority and rule
def test_merge_by_unfunded_authority_holds(ops):
    ops.decide(A), ops.decide(B)
    record = ops.merge(by="urn:cognous:principal:nobody")
    assert record.outcome == "held" and record.reasons == ["merge_authority_unfunded"]
    assert merged_into(ops.doc(), B) is None and merge_members(ops.doc(), B) == [B]
    ops.execute(A), ops.execute(B)  # a held merge changed nothing
    assert len(ops.effects()) == 2


@pytest.mark.parametrize("kwargs", [
    dict(signer=None),                       # unsigned
    dict(signer=OTHER, reviser=OTHER),       # self-signed (refused at append; nothing adopted)
    dict(signer="urn:cognous:principal:stranger"),  # not in the configured signer set
])
def test_merge_with_an_unadopted_rule_is_unknown(tmp_path, monkeypatch, kwargs):
    o = Ops(tmp_path, monkeypatch)
    o.decide(A), o.decide(B)
    try:
        o.adopt_rule(**kwargs)
    except Exception:
        pass
    record = o.merge()
    assert record.outcome == "unknown" and record.reasons == ["merge_rule_unknown"] and record.rule_state == "unknown"
    assert merged_into(o.doc(), B) is None


def test_merge_without_any_rule_row_or_profile_is_unknown(tmp_path, monkeypatch):
    o = Ops(tmp_path, monkeypatch)
    o.decide(A), o.decide(B)
    assert o.merge().outcome == "unknown"
    o.f.rule_revision_profile = None
    record = o.merge()
    assert record.outcome == "unknown" and record.rule_findings == ["rule_revision_profile_unconfigured"]


def test_a_rule_of_another_kind_cannot_authorise_a_merge(tmp_path, monkeypatch):
    o = Ops(tmp_path, monkeypatch)
    o.decide(A), o.decide(B)
    o.adopt_rule(kind="policy")
    record = o.merge()
    assert record.outcome == "unknown" and "rule_kind_not_merge_equivalence_rule" in record.rule_findings


def test_merge_record_names_rule_digest(ops):
    ops.decide(A), ops.decide(B), ops.decide(C)
    record = ops.merge()
    assert record.equivalence_rule_digest == D1 and record.equivalence_rule_ref == RULE
    assert record.rule_state == "adopted" and record.rule_verified_through == "digest_matches_signed_revision"
    assert record.merged_by == MERGER and record.authority_ref == "urn:cognous:authority:merge-1"
    stored = ops.doc()["merge_records"][0]
    assert stored["equivalence_rule_digest"] == D1
    wrong = ops.merge(folded=(C,), digest=D2)
    assert wrong.outcome == "unknown", "a digest that no signed revision adopted is not the rule"


def test_rule_change_appends_not_edits(ops):
    ops.decide(A), ops.decide(B), ops.decide(C)
    first = ops.merge()
    snapshot = json.dumps(ops.doc()["merge_records"][0], sort_keys=True)
    revisions_before = ops.doc()["rule_revisions"]
    ops.adopt_rule(D2, rid="rule-v2", frm=D1)
    after = ops.doc()
    assert after["rule_revisions"][: len(revisions_before)] == revisions_before and len(after["rule_revisions"]) == len(revisions_before) + 1
    assert json.dumps(after["merge_records"][0], sort_keys=True) == snapshot, "the earlier merge row is untouched"
    assert after["merge_records"][0]["equivalence_rule_digest"] == D1 and first.outcome == "merged"
    stale = ops.merge(folded=(C,), digest=D1)
    assert stale.outcome == "unknown", "the old digest no longer resolves as adopted"
    assert ops.merge(folded=(C,), digest=D2).outcome == "merged"
    assert len(ops.doc()["merge_records"]) == 3


# ---------------------------------------------------------------- structural refusals
def test_structural_refusals_are_recorded_and_have_no_effect(ops):
    ops.decide(A), ops.decide(B)
    cases = [
        (dict(survivor=A, folded=()), "merge_operation_ids_invalid"),
        (dict(survivor=A, folded=(A,)), "merge_operation_ids_invalid"),
        (dict(survivor=A, folded=("bad id",)), "merge_operation_ids_invalid"),
        (dict(survivor=A, folded=("op-never-admitted",)), "merge_operation_not_admitted"),
    ]
    for kwargs, code in cases:
        record = ops.merge(folded=kwargs["folded"], survivor=kwargs["survivor"])
        assert record.outcome == "refused" and code in record.reasons
    assert merged_into(ops.doc(), B) is None
    assert ops.merge().outcome == "merged"
    again = ops.merge()
    assert again.outcome == "refused" and "merge_operation_already_folded" in again.reasons
    folded_survivor = ops.merge(survivor=B, folded=(A,))
    assert folded_survivor.outcome == "refused" and "merge_survivor_already_folded" in folded_survivor.reasons


def test_merge_across_principals_or_domains_is_refused():
    document = {"operations": [
        {"operation_id": A, "principal_id": "p1", "authority_domain": "d", "issuer": "i", "grant_id": "g", "first_grant_revision": "1"},
        {"operation_id": B, "principal_id": "p2", "authority_domain": "d", "issuer": "i", "grant_id": "g", "first_grant_revision": "1"}]}
    record, obligation = merge_module.resolve_merge(
        document, profile=MergeProfile(funded_authorities=[MERGER]), rule_profile=None, survivor=A, folded=[B],
        equivalence_rule_ref=RULE, equivalence_rule_digest=D1, merged_by=MERGER, authority_ref=None, reason="r",
        recorded_at=NOW.isoformat())
    assert record.outcome == "refused" and "merge_operation_discriminator_mismatch" in record.reasons and obligation is None


def test_chained_merges_resolve_to_the_final_survivor(ops):
    ops.decide(A), ops.decide(B), ops.decide(C)
    assert ops.merge(survivor=B, folded=(C,)).outcome == "merged"
    assert ops.merge(survivor=A, folded=(B,)).outcome == "merged"
    document = ops.doc()
    assert merged_into(document, C) == A and merged_into(document, B) == A and merged_into(document, A) is None
    assert merge_members(document, C) == [A, B, C]
    ops.execute(C)
    assert list(ops.f.destination.snapshot()["operations"]) == [A]
    assert merge_gate(ops.doc(), A, "some-other-effect") == "operation_merged_effect_exists"


def test_never_merged_operation_is_untouched_by_the_gate(ops):
    ops.decide(A)
    assert merge_gate(ops.doc(), A, "e") is None


# ---------------------------------------------------------------- registry
def test_every_merge_code_is_registered():
    codes = {getattr(merge_module, n) for n in dir(merge_module) if n.startswith("CODE_")}
    assert codes and codes <= set(REGISTRY["codes"])
    assert all(REGISTRY["codes"][c]["reason_kind"] == "typed_only" for c in codes)
    source = pathlib.Path(merge_module.__file__).read_text()
    literals = {n.value for n in ast.walk(ast.parse(source)) if isinstance(n, ast.Constant) and isinstance(n.value, str)
                and n.value.startswith(("merge_", "operation_merged_"))}
    assert literals - {"merge_id", "merge_records", "merge-record/0.1", "merge_equivalence_rule"} <= set(REGISTRY["codes"])


def test_profile_is_part_of_the_approval_commitment(tmp_path, monkeypatch):
    from agent_control_plane.runtime_authority import approval_commitment
    o = Ops(tmp_path, monkeypatch)
    ctx = o.r.contexts[PROFILE]
    with_merge = approval_commitment(o.f.runtime_authority_profile, ctx)
    without = approval_commitment(o.f.runtime_authority_profile.model_copy(update={"merge": None}), ctx)
    assert with_merge != without
