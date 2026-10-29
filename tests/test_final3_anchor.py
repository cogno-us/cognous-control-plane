"""FINAL3 consumer 1/3: Registry-governed `FreshnessProfile.anchor_deadline_to_inputs` (family `f5-anchor-deadline-to-inputs-policy`, Registry `r08-v8`) on the composed
`GovernedPolicyWorkflow`, with the end-to-end D-07 residual fixture.

BUILDER_TESTED developer evidence. NOT independently qualified. NOT an authorization mechanism. Needs the Registry r08-v8 pin (a40fe75) and PyNaCl; real synthetic Ed25519.
"""
from __future__ import annotations

import copy
from datetime import timedelta

import pytest

from tests.final3_support import *  # noqa: F401,F403  (enforces the r08-v8 pin)
import tests.final3_support as S
import agent_control_plane.bounded as bounded
from agent_control_plane import effective_configuration_binding as ecb
from agent_control_plane.registry_governed_policy import RegistryGovernedPolicyRefused, final_composition_defect
from agent_control_plane.runtime_authority import approval_commitment
from tests import d06_support as D
from tests.freshness_d07_grid import stall_once
from tests.test_freshness import Clock

PREFIX = "anchor_deadline:"


@pytest.fixture(autouse=True)
def _fixed_synthetic_clock(monkeypatch):
    monkeypatch.setattr(bounded, "_now", lambda: NOW)
    for m in (pol, base.gov, base.agegov, base.f4gov):
        monkeypatch.setattr(m, "_now", lambda: NOW)


def ready(tmp_path, *, host_flag=False, value=None, freshness=True, **kw):
    p, res, cfg = base.prepared(tmp_path, t1=R_, **({"freshness": FreshnessProfile(anchor_deadline_to_inputs=host_flag)} if freshness else {}))
    src = Source(mat(ANC, value))
    flow = build(tmp_path, res, cfg, fams(anc=src), **kw)
    bind_approval(res, flow.runtime_authority_profile)
    return p, res, cfg, src, flow


def dump(profile, drop_flag=False):
    doc = profile.model_dump(mode="json")
    if drop_flag:
        doc["freshness"].pop("anchor_deadline_to_inputs", None)
    return doc


# ------------------------------------------------------------------------------------------------------------------------------ the strengthening
def test_a01_registry_anchor_sets_the_flag_false_to_true_and_nothing_else(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path)
    assert cfg.freshness.anchor_deadline_to_inputs is False and flow.runtime_authority_profile.freshness.anchor_deadline_to_inputs is True
    assert dump(flow.runtime_authority_profile, True) == dump(cfg, True)  # byte for byte but the flag
    ctx = res.contexts[PROFILE]
    assert approval_commitment(flow.runtime_authority_profile, ctx) != approval_commitment(cfg, ctx)  # approvals are issued against the FINAL profile
    ident = flow.registry_governed_policy_identity
    assert ident["families"] == ["anchor_deadline"] and ident["anchor_deadline"]["effective"] == {FIELDS[ANC]: "anchor"} and ident["host"]["anchor_deadline"] == "no_change"
    assert ident["anchor_deadline"]["effective_policy_digest"] == v8id.effective_policy_digest(ANC, {FIELDS[ANC]: "anchor"}, "r08-v8")
    assert ident["effective_profile_digest"] == base.agegov.profile_digest(flow.runtime_authority_profile) != base.agegov.profile_digest(cfg)


@pytest.mark.parametrize("host_flag,value", [(False, "no_change"), (True, "anchor"), (True, "no_change")])
def test_a02_a_no_op_leaves_the_profile_byte_identical_and_never_lowers_a_host_true(tmp_path, host_flag, value):
    p, res, cfg, src, flow = ready(tmp_path, host_flag=host_flag, value=value)
    assert flow.runtime_authority_profile.freshness.anchor_deadline_to_inputs is host_flag
    assert dump(flow.runtime_authority_profile) == dump(cfg)
    ident = flow.registry_governed_policy_identity
    assert ident["anchor_deadline"]["effective"][FIELDS[ANC]] == ("anchor" if host_flag else "no_change")
    assert ident["host"]["anchor_deadline"] == ("anchor" if host_flag else "no_change")


def test_a03_the_effective_digest_is_the_registry_identity_of_the_effective_value_and_every_state_is_distinct(tmp_path):
    ds = {v: v8id.effective_policy_digest(ANC, {FIELDS[ANC]: v}, "r08-v8") for v in ("anchor", "no_change")}
    assert ds["anchor"] != ds["no_change"] and v8id.registered_family_version(ANC, "r08-v8") == 1
    from agent_control_plane import registry_effective_policy as eff
    assert eff.FAMILY_TABLE["anchor_deadline"] == (f3.FAMILY_ANCHOR, f3.CONTRACT_V8) and eff.SCHEMA_REVISIONS["anchor_deadline"] == 1


def test_a04_authorizes_and_executes_with_an_approval_for_the_final_profile_and_not_for_the_host_one(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path)
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    attempt, observed = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and observed.state == "applied"
    p2, res2, cfg2 = base.prepared(tmp_path / "x", t1=R_, freshness=FreshnessProfile())
    flow2 = build(tmp_path / "x", res2, cfg2, fams(anc=Source(mat(ANC))))
    bind_approval(res2, cfg2)  # approval issued for the HOST profile
    d2 = flow2.decide(p2, now=NOW)
    assert d2.result == "hold" and "runtime_authority_approval_mismatch" in d2.reasons and effects(flow2) == {}


# ------------------------------------------------------------------------------------------------------------------------------ host preconditions
def test_b01_a_host_profile_without_a_freshness_profile_is_refused_before_any_source_read_and_none_is_invented(tmp_path):
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    assert cfg.freshness is None
    src = Source(mat(ANC))
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, fams(anc=src))
    refused(e, "host_freshness_profile_missing", "construction")
    assert src.calls == 0  # refused before the selection source was read or Registry was called


def test_b02_no_runtime_authority_profile_at_all_is_refused(tmp_path):
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, None, fams(anc=Source(mat(ANC))))
    refused(e, "runtime_authority_profile_required", "construction")


def test_b03_policy_binding_is_still_refused_for_the_profile_bearing_family(tmp_path):
    p, res, cfg, binding = D.pin_prepared(tmp_path)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, fams(anc=Source(mat(ANC))))
    refused(e, "policy_binding_unsupported", "construction")


def test_b04_the_direct_derivation_refuses_a_missing_freshness_profile_and_a_non_profile_host(tmp_path):
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    kw = dict(scope=SCOPES[ANC], institution_id=base.INSTITUTION, authority_domain=base.DOMAIN, material=mat(ANC), verifier=ev.Ed25519Verifier(), now=REG_NOW)
    got, ref = f3.derive_anchor(host=cfg, **kw)
    assert got is None and ref.code == "host_freshness_profile_missing"
    got, ref = f3.derive_anchor(host=None, **kw)
    assert got is None and ref.code == "runtime_authority_profile_required"
    assert f3.host_anchor_value(copy.deepcopy(cfg)) == (None, "host_freshness_profile_missing")


def test_b05_compose_anchor_never_invents_a_freshness_profile_and_only_ever_sets_true(tmp_path):
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    with pytest.raises(ValueError):
        f3.compose_anchor(cfg, {FIELDS[ANC]: "anchor"})
    assert f3.compose_anchor(cfg, {FIELDS[ANC]: "no_change"}).model_dump() == cfg.model_dump()
    host = base.host_profile(p, t1=R_, freshness=FreshnessProfile(anchor_deadline_to_inputs=True))
    assert f3.compose_anchor(host, {FIELDS[ANC]: "no_change"}).freshness.anchor_deadline_to_inputs is True  # a host True is never cleared


# ------------------------------------------------------------------------------------------------------------------------------ final composition check
def _pair(p, **over):
    host = base.host_profile(p, t1=R_, freshness=FreshnessProfile(**over.pop("host", {})))
    return host


def test_c01_final_composition_allows_only_the_flag_false_to_true_and_only_when_declared(tmp_path):
    p, res, cfg = base.prepared(tmp_path, t1=R_, freshness=FreshnessProfile())
    on = f3.compose_anchor(cfg, {FIELDS[ANC]: "anchor"})
    sc = {"status_max_age_seconds": 60, "approval_max_age_seconds": 60}
    assert final_composition_defect(cfg, on, sc, None, anchor_declared=True) is None
    assert final_composition_defect(cfg, on, sc, None) == "composed_profile_invalid"  # not declared: any difference is a foreign change
    assert final_composition_defect(on, cfg, sc, None, anchor_declared=True) == "composed_widens_host"  # True -> False is a widening
    assert final_composition_defect(cfg, cfg, sc, None, anchor_declared=True) is None


@pytest.mark.parametrize("field,value", [("max_age_extension_seconds", 5), ("reaper_interval_seconds", 31), ("nonce", False), ("lease_acquire_timeout_seconds", 6.0)])
def test_c02_any_other_freshness_change_next_to_the_flag_is_a_foreign_change(tmp_path, field, value):
    p, res, cfg = base.prepared(tmp_path, t1=R_, freshness=FreshnessProfile(max_age_extension_seconds=10))
    doc = f3.compose_anchor(cfg, {FIELDS[ANC]: "anchor"}).model_dump(mode="json")
    doc["freshness"][field] = value if field != "max_age_extension_seconds" else 5  # a LOWER extension is a legal narrowing; every other field is foreign
    forged = type(cfg).model_validate(doc)
    sc = {"status_max_age_seconds": 60, "approval_max_age_seconds": 60}
    got = final_composition_defect(cfg, forged, sc, None, anchor_declared=True)
    assert (got is None) if field == "max_age_extension_seconds" else (got == "composed_profile_invalid")


def test_c03_an_action_class_change_next_to_the_flag_is_refused(tmp_path):
    p, res, cfg = base.prepared(tmp_path, t1=R_, freshness=FreshnessProfile())
    doc = f3.compose_anchor(cfg, {FIELDS[ANC]: "anchor"}).model_dump(mode="json")
    doc["actions"][ACTION_ID]["irreversible"] = True
    sc = {"status_max_age_seconds": 60, "approval_max_age_seconds": 60}
    assert final_composition_defect(cfg, type(cfg).model_validate(doc), sc, None, anchor_declared=True) == "composed_profile_invalid"
    assert final_composition_defect(copy.deepcopy(cfg).model_copy(update={"freshness": None}), f3.compose_anchor(cfg, {FIELDS[ANC]: "anchor"}), sc, None,
                                    anchor_declared=True) == "host_freshness_profile_missing"


def test_c04_a_forged_composer_that_lowers_or_changes_something_else_is_refused_at_construction(tmp_path, monkeypatch):
    p, res, cfg = base.prepared(tmp_path, t1=R_, freshness=FreshnessProfile(anchor_deadline_to_inputs=True))
    real = f3.compose_anchor

    def lowers(base_, eff):
        doc = base_.model_dump(mode="json")
        doc["freshness"].pop("anchor_deadline_to_inputs", None)
        return type(base_).model_validate(doc)
    monkeypatch.setattr(f3, "compose_anchor", lowers)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, fams(anc=Source(mat(ANC))))
    refused(e, "composed_widens_host", "construction")

    def foreign(base_, eff):
        doc = real(base_, eff).model_dump(mode="json")
        doc["actions"][ACTION_ID]["max_status_age_seconds"] = 59
        doc["freshness"]["reaper_interval_seconds"] = 31
        return type(base_).model_validate(doc)
    monkeypatch.setattr(f3, "compose_anchor", foreign)
    cfg2 = base.prepared(tmp_path / "b", t1=R_, freshness=FreshnessProfile())[2]
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path / "b", base.prepared(tmp_path / "b2", t1=R_, freshness=FreshnessProfile())[1], cfg2, fams(anc=Source(mat(ANC))))
    refused(e, "composed_profile_invalid", "construction")


# ------------------------------------------------------------------------------------------------------------------------------ record / selection refusals
@pytest.mark.parametrize("payload", [{FIELDS[ANC]: True}, {FIELDS[ANC]: False}, {FIELDS[ANC]: "false"}, {FIELDS[ANC]: "ANCHOR"}, {FIELDS[ANC]: ""}, {},
                                      {FIELDS[ANC]: "anchor", "extra": 1}, {"anchor": "anchor"}])
def test_d01_malformed_anchor_records_are_refused_and_the_registry_can_never_assert_false(tmp_path, payload):
    p, res, cfg = base.prepared(tmp_path, t1=R_, freshness=FreshnessProfile(anchor_deadline_to_inputs=True))
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, fams(anc=Source(mat(ANC, record=t8.record(payload, family=ANC)))))
    assert e.value.refusal.code.startswith(PREFIX) and e.value.boundary == "construction"


@pytest.mark.parametrize("other", [AGE, TOL])
def test_d02_a_selection_of_another_v8_family_in_the_anchor_slot_is_refused(tmp_path, other):
    p, res, cfg = base.prepared(tmp_path, t1=R_, freshness=FreshnessProfile())
    wrong = base._material(rec(other), op=OPS[ANC], contract="r08-v8", domain=t8.V8_DOMAIN, family=other)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, fams(anc=Source(wrong)))
    assert e.value.refusal.code.startswith(PREFIX)


@pytest.mark.parametrize("what", ["v7_contract", "v7_domain", "wrong_consumer", "wrong_tenant", "wrong_operation"])
def test_d03_wrong_contract_scope_or_operation_is_refused(tmp_path, what):
    p, res, cfg = base.prepared(tmp_path, t1=R_, freshness=FreshnessProfile())
    kw = {"v7_contract": dict(contract="r08-v7"), "v7_domain": dict(domain=b"ocs-reg/r08-v7/selection\n"), "wrong_consumer": dict(stmt_over={"consumer_id": "other-consumer"}),
          "wrong_tenant": dict(stmt_over={"scope": dict(base.STMT_SCOPE, tenant="other-tenant")}), "wrong_operation": dict(stmt_over={"operation": "refund-issue-elsewhere"})}[what]
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, fams(anc=Source(mat(ANC, **kw))))
    assert e.value.refusal.code.startswith(PREFIX) and e.value.boundary == "construction"


def test_d04_the_contract_is_exactly_r08_v8_a_v7_style_record_of_the_family_is_refused(tmp_path):
    p, res, cfg = base.prepared(tmp_path, t1=R_, freshness=FreshnessProfile())
    with pytest.raises(RegistryGovernedPolicyRefused):
        build(tmp_path, res, cfg, fams(anc=Source(mat(ANC, record=t8.record(None, family=ANC, contract="r08-v7")))))


# ------------------------------------------------------------------------------------------------------------------------------ lifecycle boundaries
def _auth(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path)
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    return p, res, cfg, src, flow, d


@pytest.mark.parametrize("kind", ["revoked", "withdrawn", "expired", "source_fail", "replaced"])
@pytest.mark.parametrize("boundary", ["decision", "effect", "commit"])
def test_e01_a_bad_selection_is_refused_at_decision_execute_entry_and_the_pre_apply_gate(tmp_path, kind, boundary, monkeypatch):
    p, res, cfg, src, flow, d = _auth(tmp_path)
    bad = {"revoked": lambda: revoked(ANC), "withdrawn": lambda: withdrawn(ANC), "expired": None, "source_fail": None, "replaced": lambda: mat(ANC, "no_change", stmt_over=CHANGED)}[kind]
    now = NOW.replace(year=NOW.year + 1) if kind == "expired" else NOW
    if kind == "source_fail":
        def put(n=None):
            src.fail = True
    elif bad is not None:
        def put(n=None):
            src.mat = bad()
    else:
        def put(n=None):
            pass
    before = file_state(tmp_path, flow)
    if boundary == "decision":
        put()
        with pytest.raises(RegistryGovernedPolicyRefused) as e:
            flow.decide(p, now=now)
        assert e.value.boundary == "decision"
    elif boundary == "effect":
        put()
        with pytest.raises(RegistryGovernedPolicyRefused) as e:
            flow.execute(p, d, adapter_id=p.adapter_id, now=now)
        assert e.value.boundary == "effect"
    else:
        if kind == "expired":  # the fixed test clock is shared by entry and gate: the Registry is shown a clock one year later exactly at the gate (2nd derivation after this point)
            real, seen = f3.derive_anchor, []

            def late(**kw):
                seen.append(1)
                return real(**dict(kw, now=kw["now"].replace(year=kw["now"].year + 1) if len(seen) == 2 else kw["now"]))
            monkeypatch.setattr(f3, "derive_anchor", late)
        elif kind == "source_fail":
            class Dies(Source):
                def __call__(self):
                    self.calls += 1
                    if self.calls >= 4:
                        raise RuntimeError("down")
                    return self.mat
            src.__class__ = Dies
        else:
            src.after = (4, bad())
        attempt, _ = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
        assert attempt.status == "failed" and effects(flow) == {} and flow.governed_last_commit_refusal is not None
        return
    assert file_state(tmp_path, flow) == before and effects(flow) == {}


def test_e02_an_equal_replacement_selection_is_accepted_as_the_same_effective_policy(tmp_path):
    p, res, cfg, src, flow, d = _auth(tmp_path)
    src.mat = mat(ANC, "anchor", stmt_over=CHANGED)
    assert flow.decide(p, now=NOW).result == "authorized"


def test_e03_post_construction_edit_of_the_held_flag_is_refused_at_every_boundary(tmp_path):
    p, res, cfg, src, flow = ready(tmp_path)
    flow.runtime_authority_profile = cfg  # the host profile (flag False) put back over the anchored one
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "profile_modified", "decision")


def test_e04_a_declared_family_is_mandatory_no_partial_activation(tmp_path):
    p, res, cfg = base.prepared(tmp_path, t1=R_, freshness=FreshnessProfile())
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, GovernedFamilies(anchor_deadline=GovernedFamily(SCOPES[ANC], None)))
    assert e.value.refusal.code in ("families_invalid", "selection_source_invalid")
    src = Source(mat(ANC))
    src.fail = True
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, fams(anc=src))
    refused(e, "selection_source_failed", "construction")


# ------------------------------------------------------------------------------------------------------------------------------ END TO END with D-07
def _e2e(tmp_path, *, declared, host_flag, stall=29, age=30, ceiling=30):
    """Purpose-observation residual fixture of tests/test_freshness_purpose_anchor_successor.py (class ceiling 30 s, purpose observation 30 s old at NOW, stall 29 s
    between the effect check and dispatch, NO policy binding) through the COMPOSED workflow. `declared` selects the anchor family; otherwise a no-op observation family keeps
    the host flag as it is."""
    clock = Clock()
    previous = bounded._now
    bounded._now = clock
    try:
        p, res, cfg = base.prepared(tmp_path, purpose=True, t1=R_, t1_irrev=True, age1=ceiling, freshness=FreshnessProfile(anchor_deadline_to_inputs=host_flag))
        res.purpose.observed_at = (NOW - timedelta(seconds=age)).isoformat()
        families = fams(anc=Source(mat(ANC))) if declared else fams(age=Source(mat(AGE, 300)))
        flow = build(tmp_path, res, cfg, families)
        assert flow.runtime_authority_profile.policy_binding is None
        bind_approval(res, flow.runtime_authority_profile)
        d = flow.decide(p, now=NOW)
        assert d.result == "authorized", d.reasons
        calls = []
        inner = object.__getattribute__(flow.destination, "_inner")  # count the destination's own apply (behind the commit gate), not the gated wrapper
        real_apply = inner.apply
        inner.apply = lambda *a, **k: (calls.append(1), real_apply(*a, **k))[1]
        stall_once(flow, clock, stall)
        try:
            attempt, _ = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
            out = "dispatched" if attempt.status == "acknowledged" else attempt.status
        except PermissionError as exc:
            out = "refused"
        return out, len(calls), len(effects(flow)), flow
    finally:
        bounded._now = previous


def test_f01_the_anchor_family_delivers_the_guarantee_the_30s_29s_purpose_residual_is_refused(tmp_path):
    out, applies, n_effects, flow = _e2e(tmp_path / "with", declared=True, host_flag=False)
    assert flow.runtime_authority_profile.freshness.anchor_deadline_to_inputs is True
    assert (out, applies, n_effects) == ("refused", 0, 0)


def test_f02_without_the_family_the_host_False_flag_dispatches_the_documented_residual(tmp_path):
    out, applies, n_effects, flow = _e2e(tmp_path / "without", declared=False, host_flag=False)
    assert flow.runtime_authority_profile.freshness.anchor_deadline_to_inputs is False
    assert (out, applies, n_effects) == ("dispatched", 1, 1)


def test_f03_control_a_host_flag_already_true_is_refused_exactly_like_the_family_result(tmp_path):
    out, applies, n_effects, flow = _e2e(tmp_path / "host", declared=False, host_flag=True)
    assert (out, applies, n_effects) == ("refused", 0, 0)


@pytest.mark.parametrize("stall,expect", [(0, "dispatched"), (28, "dispatched"), (29, "refused"), (31, "refused")])
def test_f04_with_the_family_the_window_is_the_anchored_remaining_window_age_20_s(tmp_path, stall, expect):
    # age 20 s, ceiling 30 s: remaining anchored window 10 s. A stall of 0 s is inside it; 29 s and beyond is not. (28 s is also beyond 10 s: only 0 dispatches.)
    out = _e2e(tmp_path, declared=True, host_flag=False, age=20, stall=stall)[0]
    assert out == ("dispatched" if stall == 0 else "refused")


# ------------------------------------------------------------------------------------------------------------------------------ forged Registry decisions (the consumer re-checks the verdict)
def _stub_decision(effective, **over):
    import registry_successor.decision as rd
    return rd.PolicyDecision(**dict(dict(kind="applied", effective=effective, deny_all=False, deny_all_fields=(), code=None, detail="", caller_unchanged=False,
                                         operationally_authorized=False), **over))


@pytest.mark.parametrize("host_flag,record_value,forged,code", [
    (False, "no_change", "anchor", "effective_policy_invalid"),      # not the stricter of host and record (an unrequested strengthening is also refused)
    (True, "anchor", "no_change", "effective_policy_widens_host"),   # lowers a host True
    (True, "no_change", "no_change", "effective_policy_widens_host"),
    (False, "anchor", "no_change", "effective_policy_invalid"),      # ignores the record
    (False, "no_change", "bogus", "effective_policy_invalid"),
    (False, "no_change", True, "effective_policy_invalid"),          # a JSON boolean is never a value of this family
])
def test_g01_the_derivation_re_checks_a_forged_registry_verdict(tmp_path, monkeypatch, host_flag, record_value, forged, code):
    import registry_successor.v8_decision as v8d
    p = base.tenant_proposal()
    host = host_with_freshness(p, flag=host_flag)
    stub = _stub_decision({FIELDS[ANC]: forged})
    monkeypatch.setattr(v8d, "verify_and_decide_v8", lambda *a, **k: stub)
    got, ref = f3.derive_anchor(scope=SCOPES[ANC], institution_id=base.INSTITUTION, authority_domain=base.DOMAIN, host=host, material=mat(ANC, record_value),
                                verifier=ev.Ed25519Verifier(), now=REG_NOW)
    assert got is None and ref.code == code


@pytest.mark.parametrize("over,code", [(dict(operationally_authorized=True), "registry_decision_invalid"), (dict(deny_all=True), "registry_decision_invalid"),
                                       (dict(kind="overlay_not_applied", code="selection_revoked"), "registry_not_applied")])
def test_g02_a_registry_verdict_of_the_wrong_shape_is_refused(tmp_path, monkeypatch, over, code):
    import registry_successor.v8_decision as v8d
    p = base.tenant_proposal()
    stub = _stub_decision({FIELDS[ANC]: "anchor"}, **over)
    monkeypatch.setattr(v8d, "verify_and_decide_v8", lambda *a, **k: stub)
    got, ref = f3.derive_anchor(scope=SCOPES[ANC], institution_id=base.INSTITUTION, authority_domain=base.DOMAIN, host=host_with_freshness(p), material=mat(ANC),
                                verifier=ev.Ed25519Verifier(), now=REG_NOW)
    assert got is None and ref.code == code


def test_g03_a_family_schema_revision_other_than_1_from_the_registry_table_is_refused(tmp_path, monkeypatch):
    monkeypatch.setattr(v8id, "registered_family_version", lambda family, contract: 2)
    p = base.tenant_proposal()
    got, ref = f3.derive_anchor(scope=SCOPES[ANC], institution_id=base.INSTITUTION, authority_domain=base.DOMAIN, host=host_with_freshness(p), material=mat(ANC),
                                verifier=ev.Ed25519Verifier(), now=REG_NOW)
    assert got is None and ref.code == "effective_policy_digest_unavailable"
