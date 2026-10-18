"""rule-revision/0.1 (opt-in): digest-pinned rules, append-only independently signed revision rows. Synthetic fixtures only."""
import json
from datetime import timedelta
from pathlib import Path

import pytest

from agent_control_plane.bounded import commitment
from agent_control_plane.reason_vocabulary import (VocabularyChange, arity_flags, measured_arity, recomputability_flags,
                                                   refusal_trends)
from agent_control_plane.rule_revision import (RuleRevision, RuleRevisionProfile, RuleRevisionRefused, append_rule_revision,
                                               resolve_rule)
from tests.test_bounded_authorization import NOW, POLICY_REF
from tests.test_runtime_authority import held, setup_flow

REVISER, SIGNER = "synthetic-principal:reviser", "synthetic-principal:signer"
D1, D2 = commitment({"policy": "v1"}), commitment({"policy": "v1-edited"})
REGISTRY = json.loads((Path(__file__).resolve().parents[1] / "schemas" / "runtime_authority_reasons_0_1.json").read_text())


def rev(rid, to, frm=None, *, signer=SIGNER, reviser=REVISER, ref=POLICY_REF, kind="policy", supersedes=None, **kw):
    return RuleRevision(revision_id=rid, rule_kind=kind, rule_ref=ref, from_digest=frm, to_digest=to, reviser=reviser,
                        signer=signer, authority_ref="synthetic-authority:1", reason="synthetic", supersedes=supersedes,
                        recorded_at=NOW.isoformat(), **kw)


def flow(tmp_path, digest=D1):
    p, r, f, c = setup_flow(tmp_path)
    f.rule_revision_profile = RuleRevisionProfile(signers=[SIGNER])
    r.policies[POLICY_REF].digest = digest
    return p, r, f


def test_registry_counts_as_checked():
    kinds = [v["reason_kind"] for v in REGISTRY["codes"].values()]
    assert (len(kinds), kinds.count("typed_only"), kinds.count("recomputable")) == (138, 137, 1)  # 121 + 7 operation-identity/0.1 codes (N1) + 10 freshness/0.1 codes (N3)
    assert REGISTRY["codes"]["grant_revoked"]["reason_kind"] == "recomputable"


def test_default_path_unchanged_without_profile(tmp_path):
    p, r, f, c = setup_flow(tmp_path)
    d = f.decide(p, now=NOW)
    assert d.result == "authorized" and d.rule_identity is None and "rule_identity" not in d.model_dump(mode="json")


def test_unsigned_revision_row_resolves_unknown(tmp_path):
    p, r, f = flow(tmp_path)
    append_rule_revision(f.records, f.rule_revision_profile, rev("r1", D1, signer=None))
    d = held(f, p, "policy_status_unknown")
    assert d.rule_identity["rules"][POLICY_REF]["findings"][:1] == ["unsigned_revision_row"]
    assert d.rule_identity["rules"][POLICY_REF]["verified_through"] == "revision_row_present"


def test_self_signed_revision_refused_with_refusal_row(tmp_path):
    p, r, f = flow(tmp_path)
    with pytest.raises(RuleRevisionRefused) as e:
        append_rule_revision(f.records, f.rule_revision_profile, rev("r1", D1, signer=REVISER))
    assert "self_signed_revision_row" in e.value.reasons
    doc = f.records.load()
    assert doc.rule_revisions == [] and doc.rule_revision_refusals[0].reasons == ["self_signed_revision_row"]
    with pytest.raises(RuleRevisionRefused) as e:
        append_rule_revision(f.records, f.rule_revision_profile, rev("r2", D1, signer="synthetic-principal:stranger"))
    assert "signer_not_configured" in e.value.reasons


def test_signed_revision_reissued_grant_passes_and_rows_carry_digests(tmp_path):
    p, r, f = flow(tmp_path)
    append_rule_revision(f.records, f.rule_revision_profile, rev("r1", D1))
    d = f.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    ident = d.rule_identity["rules"][POLICY_REF]
    assert ident["digest"] == D1 and ident["verified_through"] == "digest_matches_signed_revision"
    assert d.resolution_inputs and any(x.observed.get("digest") == D1 for x in d.resolution_inputs if x.input_type == "policy")


def test_policy_edit_without_revision_row_resolves_unknown_and_flags_digest_mismatch(tmp_path):
    p, r, f = flow(tmp_path)
    append_rule_revision(f.records, f.rule_revision_profile, rev("r1", D1))
    assert f.decide(p, now=NOW).result == "authorized"
    r.policies[POLICY_REF].digest = D2  # same version label, content edited in place
    d = held(f, p, "policy_status_unknown")
    ident = d.rule_identity["rules"][POLICY_REF]
    assert ident["digest"] == D2 and "digest_mismatch_with_adopted" in ident["findings"]
    assert d.rule_identity["unknown"] == [POLICY_REF]
    append_rule_revision(f.records, f.rule_revision_profile, rev("r2", D2, D1))  # appended, signed: adopted again
    assert f.decide(p, now=NOW).result == "authorized"


def test_chain_is_append_only_and_checked(tmp_path):
    p, r, f = flow(tmp_path)
    prof = f.rule_revision_profile
    append_rule_revision(f.records, prof, rev("r1", D1))
    with pytest.raises(RuleRevisionRefused) as e:
        append_rule_revision(f.records, prof, rev("r1", D2, D1))
    assert "rule_revision_duplicate" in e.value.reasons
    with pytest.raises(RuleRevisionRefused) as e:
        append_rule_revision(f.records, prof, rev("r3", D2, "sha256:" + "0" * 64))
    assert "rule_revision_from_digest_mismatch" in e.value.reasons
    assert [x.revision_id for x in f.records.load().rule_revisions] == ["r1"]


def test_unsigned_then_resigned_by_supersession(tmp_path):
    p, r, f = flow(tmp_path)
    prof = f.rule_revision_profile
    append_rule_revision(f.records, prof, rev("r1", D1, signer=None))
    append_rule_revision(f.records, prof, rev("r1b", D1, signer=SIGNER, supersedes="r1"))
    assert resolve_rule(prof, f.records.load().rule_revisions, POLICY_REF, D1)["state"] == "adopted"


def test_row_version_predates_adoption_flagged_and_pre_split_tainted():
    adoption = VocabularyChange(change_id="c1", previous_version="v1", version="v2", registry_digest=D1, kind="split",
                                previous_codes=["old"], codes=["new_a", "new_b"], acknowledged_by=SIGNER,
                                acknowledged_at=NOW.isoformat())
    early = (NOW - timedelta(days=1)).isoformat()
    prior = [{"reason_vocabulary_version": "v1", "reasons": ["old"], "recorded_at": early}] * 5
    cur = [{"reason_vocabulary_version": "v2", "reasons": ["new_a"], "recorded_at": early},
           {"reason_vocabulary_version": "v2", "reasons": ["new_b"], "recorded_at": NOW.isoformat()}]
    plain = refusal_trends(prior, cur, previous_exposure=10, current_exposure=10)
    assert "rows_predating_adoption" not in plain and all("tainted_for_trend" not in s for s in plain["series"])
    rep = refusal_trends(prior, cur, previous_exposure=10, current_exposure=10, vocabulary_changes=[adoption])
    assert [(x["version"], x["index"]) for x in rep["rows_predating_adoption"]] == [("v2", 0)]
    by = {(s["version"], s["code"]): s for s in rep["series"]}
    assert by[("v1", "old")]["tainted_for_trend"] and by[("v1", "old")]["taint_reasons"] == ["pre_split_count"]
    assert by[("v2", "new_a")]["tainted_for_trend"] and not by[("v2", "new_b")]["tainted_for_trend"]
    assert by[("v2", "new_a")]["taint_reasons"] == ["row_predates_adoption"]


def test_adoption_row_may_be_a_reason_registry_revision():
    row = rev("r1", D1, ref="v2", kind="reason_registry")
    early = (NOW - timedelta(seconds=5)).isoformat()
    rep = refusal_trends([], [{"reason_vocabulary_version": "v2", "reasons": ["x"], "recorded_at": early}],
                         previous_exposure=0, current_exposure=1, rule_revisions=[row])
    assert rep["flagged_row_count"] == 1


def _row(code, types, t=NOW):
    return {"reasons": [code], "recorded_at": t.isoformat(),
            "resolution_inputs": [{"input_type": x, "input_id": x, "missing": True} for x in types]}


def test_reused_code_raises_measured_arity_declared_and_measured_both_kept():
    rows = [_row("policy_stale_or_changed", ["policy"]), _row("policy_stale_or_changed", ["policy"]),
            _row("policy_stale_or_changed", ["grant", "policy"])]
    m = measured_arity(rows, as_of=NOW.isoformat(), period_seconds=60)
    assert m["as_of"] == NOW.isoformat() and m["codes"]["policy_stale_or_changed"]["measured"] == 2
    flags = arity_flags({"policy_stale_or_changed": 1}, m)
    assert flags == [{"code": "policy_stale_or_changed", "flag": "measured_exceeds_declared", "declared": 1, "measured": 2,
                      "as_of": NOW.isoformat()}]
    assert arity_flags({"policy_stale_or_changed": 2}, m) == []
    old = measured_arity(rows, as_of=(NOW + timedelta(days=1)).isoformat(), period_seconds=60)
    assert old["codes"] == {}  # an observation as of T, outside the period it is empty
    assert arity_flags({}, m)[0]["flag"] == "arity_undeclared"
    revision = rev("r1", D1, ref="runtime-authority-reasons/0.1", kind="reason_registry", declared_arity={"policy_stale_or_changed": 1})
    assert revision.model_dump(mode="json")["declared_arity"] == {"policy_stale_or_changed": 1}


def test_declared_recomputable_without_operands_flagged():
    bare = {"reasons": ["grant_revoked"], "resolution_inputs": []}
    full = {"reasons": ["grant_revoked"], "resolution_inputs": [
        {"input_type": "grant", "input_id": "g", "observed": {"status": "revoked"}, "record_commitment": D1}]}
    flags = recomputability_flags([bare, full], REGISTRY["codes"])
    assert flags[0] == {"row": 0, "code": "grant_revoked", "declared": "recomputable", "derived": "typed_only",
                        "flag": "declared_overclaim"}
    assert not any(x["flag"] == "declared_overclaim" and x["row"] == 1 for x in flags)
    typed = {"reasons": ["status_unreadable"], "resolution_inputs": []}
    assert recomputability_flags([typed], REGISTRY["codes"]) == []  # declared typed_only, derived typed_only: agree


def test_existing_registry_version_unchanged():
    assert REGISTRY["version"] == "runtime-authority-reasons/0.1"
