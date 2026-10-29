"""Composed Registry-governed workflow oracles (F4 ages + F5 class status age + F5 per-class unreadable policy governing ONE scope) and the shared lifecycle they stand on.

BUILDER_TESTED developer evidence. NOT independently qualified. NOT an authorization mechanism. Real synthetic Ed25519 (no test doubles for the Registry verdict) through the real
`BoundedAuthorizationWorkflow`. Reuses the fixtures of `tests/test_f5_class_unreadable_governance.py` (same Registry pin, same builders).

Needs a Registry checkout at the exact `PIN` in `OCS_REGISTRY_PIN_DIR` (the r08-v5 pin) and PyNaCl. With `OCS_REQUIRE_REGISTRY_PIN=1` (CI) a missing pin or PyNaCl is a FAILURE; otherwise
the module is reported NOT RUN.
"""
from __future__ import annotations

import copy
import hashlib
from datetime import datetime, timedelta
from pathlib import Path

import pytest

import tests.test_f5_class_unreadable_governance as base  # noqa: E402  (also enforces the Registry pin and PyNaCl requirement)

from agent_control_plane import registry_f4_age_governance as f4gov  # noqa: E402
from agent_control_plane import registry_f5_class_age_governance as agegov  # noqa: E402
from agent_control_plane import registry_f5_class_unreadable_governance as ugov  # noqa: E402
from agent_control_plane import registry_governed_lifecycle as life  # noqa: E402
from agent_control_plane import registry_governed_policy as pol  # noqa: E402
from agent_control_plane.bounded import BoundedAuthorizationWorkflow, LocalRefundDestination  # noqa: E402
from agent_control_plane.registry_governed_policy import (  # noqa: E402
    GovernedActivationLedger, GovernedFamilies, GovernedFamily, GovernedPolicyWorkflow, RegistryGovernedPolicyRefused,
)
from agent_control_plane.freshness import FreshnessProfile  # noqa: E402
from agent_control_plane.runtime_authority import approval_commitment  # noqa: E402

R_, B_ = base.R_, base.B_
CLASS_T1, CLASS_T2 = base.CLASS_T1, base.CLASS_T2
NOW, REG_NOW, PROFILE, TENANT, ACTION_ID = base.NOW, base.REG_NOW, base.PROFILE, base.TENANT, base.ACTION_ID
mat, amat, Source, umap, uvals, ages, kwargs, prepared = base.mat, base.amat, base.Source, base.umap, base.uvals, base.ages, base.kwargs, base.prepared
revoked, trust_for, file_state, bind_approval, ev, ab = base.revoked, base.trust_for, base.file_state, base.bind_approval, base.ev, base.ab
GovernedScope, SelectionMaterial = base.GovernedScope, base.SelectionMaterial
OP_A, SCOPE_A = base.OP_A, base.SCOPE_A
SRC = Path(pol.__file__).resolve().parent
OP_F = "refund-issue-ages"
SCOPE_F = GovernedScope("consumer-test", TENANT.lower(), ACTION_ID, OP_F)
AGE_M = {CLASS_T1: 20}


@pytest.fixture(autouse=True)
def _fixed_synthetic_clock(monkeypatch):
    import agent_control_plane.bounded as bounded_module
    monkeypatch.setattr(bounded_module, "_now", lambda: NOW)
    for m in (pol, ugov, agegov, f4gov):
        monkeypatch.setattr(m, "_now", lambda: NOW)


# --------------------------------------------------------------------------------------------------------------- builders
def frec(status=30, approval=30):
    return base.r.seal_record(dict(base.r.make_record(), contract_version="r08-v2", family=ab.FAMILY_F4, record_id="f4-age-record",
                                   payload={"status_max_age_seconds": status, "approval_max_age_seconds": approval}))


def fmat(status=30, approval=30, *, trust=None, stmt_over=None, rec=None):
    return base._material(rec or frec(status, approval), op=OP_F, contract="r08-v2", domain=base.s.V2_DOMAIN, family=ab.FAMILY_F4, trust=trust, stmt_over=stmt_over)


def fsrc():
    return Source(fmat())


def asrc():
    return Source(amat(AGE_M))


def usrc():
    return Source(mat(umap(t1=R_)))


def families(f=None, a=None, u=None):
    return GovernedFamilies(f4_ages=GovernedFamily(SCOPE_F, f) if f is not None else None, class_age=GovernedFamily(SCOPE_A, a) if a is not None else None,
                            class_unreadable=GovernedFamily(base.SCOPE, u) if u is not None else None)


def build(tmp_path, res, cfg, fams, **kw):
    return GovernedPolicyWorkflow(families=fams, verifier=ev.Ed25519Verifier(), runtime_authority_profile=kw.pop("profile", cfg), construction_time=REG_NOW,
                                  **kw.pop("pol", {}), **kwargs(tmp_path, res, **kw))


def ready(tmp_path, *, f=True, a=True, u=True, bind=True, **profile_kw):
    """(proposal, resolver, host profile, {sources}, flow) with approvals issued against the FINAL effective profile."""
    p, res, cfg = prepared(tmp_path, **profile_kw)
    srcs = {"f": fsrc() if f else None, "a": asrc() if a else None, "u": usrc() if u else None}
    flow = build(tmp_path, res, cfg, families(srcs["f"], srcs["a"], srcs["u"]))
    if bind:
        bind_approval(res, flow.runtime_authority_profile)
    return p, res, cfg, srcs, flow


def refused(exc, code=None, boundary=None, registry_code=None):
    e = exc.value
    assert isinstance(e, PermissionError) and isinstance(e, RegistryGovernedPolicyRefused) and e.refusal.non_authorizing is True
    if code:
        assert e.refusal.code == code, e.refusal
    if boundary:
        assert e.boundary == boundary, e.boundary
    if registry_code:
        assert e.refusal.registry_code == registry_code, e.refusal
    return e


def authorized(tmp_path, **kw):
    p, res, cfg, srcs, flow = ready(tmp_path, **kw)
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    return p, res, cfg, srcs, flow, d


# =============================================================================================================== each family alone
def test_a01_unreadable_alone_equals_the_dedicated_workflow(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, f=False, a=False)
    dedicated = base.gbuild(tmp_path / "ded", base.Source(mat(umap(t1=R_))), res, cfg)
    assert flow.runtime_authority_profile.model_dump() == dedicated.runtime_authority_profile.model_dump()
    ident = flow.registry_governed_policy_identity
    assert ident["families"] == ["class_unreadable"] and ident["class_unreadable"]["effective_policy_digest"] == dedicated.registry_f5_unreadable_policy_identity["effective_policy_digest"]
    assert ident["effective_profile_digest"] == dedicated.registry_f5_unreadable_policy_identity["effective_profile_digest"] and ident["f4_ages"] is None
    assert (flow.status_max_age_seconds, flow.approval_max_age_seconds) == (60, 60)


def test_a02_class_age_alone_equals_the_dedicated_workflow(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, f=False, u=False)
    dedicated = agegov.GovernedClassAgeWorkflow(scope=SCOPE_A, selection_source=Source(amat(AGE_M)), verifier=ev.Ed25519Verifier(), runtime_authority_profile=cfg,
                                                construction_time=REG_NOW, **kwargs(tmp_path / "ded", res))
    assert flow.runtime_authority_profile.model_dump() == dedicated.runtime_authority_profile.model_dump()
    assert flow.registry_governed_policy_identity["effective_profile_digest"] == dedicated.registry_f5_policy_identity["effective_profile_digest"]
    assert uvals(flow.runtime_authority_profile) == uvals(cfg)  # the unreadable value is untouched


def test_a03_f4_alone_with_a_profile_narrows_only_the_two_scalars(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, a=False, u=False)
    assert (flow.status_max_age_seconds, flow.approval_max_age_seconds) == (30, 30)
    assert flow.runtime_authority_profile.model_dump() == cfg.model_dump()  # profile-bearing fields are the host's, byte for byte
    ident = flow.registry_governed_policy_identity
    assert ident["f4_ages"]["effective"] == {"status_max_age_seconds": 30, "approval_max_age_seconds": 30} and ident["effective_profile_digest"] is None
    assert ident["f4_scalars_in_approval_commitment"] is False
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons


def test_a04_f4_alone_without_a_profile_is_the_f4_behaviour(tmp_path):
    p = base.tenant_proposal()
    res = base.tenant_resolver_for(p)
    flow = GovernedPolicyWorkflow(families=families(f=fsrc()), verifier=ev.Ed25519Verifier(), construction_time=REG_NOW, **kwargs(tmp_path, res))
    assert flow.runtime_authority_profile is None and (flow.status_max_age_seconds, flow.approval_max_age_seconds) == (30, 30)
    dedicated = f4gov.GovernedAgeWorkflow(scope=SCOPE_F, selection_source=fsrc(), verifier=ev.Ed25519Verifier(), construction_time=REG_NOW, **kwargs(tmp_path / "ded", res))
    assert flow.registry_governed_policy_identity["f4_ages"]["effective_policy_digest"] == dedicated.registry_f4_policy_identity["effective_policy_digest"]


# =============================================================================================================== supported combinations
def test_b01_all_three_compose_one_profile_plus_explicit_scalars(tmp_path):
    p, res, cfg, srcs, flow, d = authorized(tmp_path)
    eff = flow.runtime_authority_profile
    assert uvals(eff) == {CLASS_T1: R_, CLASS_T2: R_} and ages(eff) == {CLASS_T1: 20, CLASS_T2: 120}
    assert (flow.status_max_age_seconds, flow.approval_max_age_seconds) == (30, 30)
    ident = flow.registry_governed_policy_identity
    assert ident["families"] == ["f4_ages", "class_age", "class_unreadable"] and ident["effective_profile_digest"] == agegov.profile_digest(eff)
    assert d.binding.runtime_authority["catalogue_digest"] == ident["effective_profile_digest"]
    assert d.binding.runtime_authority["approval_commitment"] == approval_commitment(eff, res.contexts[PROFILE])


def test_b02_the_profile_equals_the_existing_joint_workflow_profile(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, f=False)
    joint = base.gbuild(tmp_path / "joint", Source(mat(umap(t1=R_))), res, cfg, age=Source(amat(AGE_M)))
    assert flow.runtime_authority_profile.model_dump() == joint.runtime_authority_profile.model_dump()
    assert flow.registry_governed_policy_identity["effective_profile_digest"] == joint.registry_f5_unreadable_policy_identity["effective_profile_digest"]


@pytest.mark.parametrize("use", [dict(a=False), dict(u=False), dict(f=False)])
def test_b03_each_pair_authorizes_and_executes(tmp_path, use):
    p, res, cfg, srcs, flow, d = authorized(tmp_path, **use)
    attempt, observed = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and observed.state == "applied"


def test_b04_composition_is_deterministic_and_order_of_construction_does_not_matter(tmp_path):
    a = ready(tmp_path / "a")[4].registry_governed_policy_identity
    b = ready(tmp_path / "b")[4].registry_governed_policy_identity
    assert a == b


def test_b05_all_three_execute_end_to_end(tmp_path):
    p, res, cfg, srcs, flow, d = authorized(tmp_path)
    attempt, observed = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and observed.state == "applied" and all(x.calls == 4 for x in srcs.values())  # construction, decision, entry, commit gate


# =============================================================================================================== declared applicability / missing mandatory family
def test_c01_nothing_declared_or_wrong_shapes_are_refused(tmp_path):
    p, res, cfg = prepared(tmp_path)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, GovernedFamilies())
    refused(e, "no_family_declared", "construction")
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        GovernedPolicyWorkflow(families=object(), verifier=ev.Ed25519Verifier(), runtime_authority_profile=cfg, construction_time=REG_NOW, **kwargs(tmp_path / "x", res))
    refused(e, "families_invalid", "construction")
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path / "y", res, cfg, GovernedFamilies(f4_ages="not-a-family"))
    refused(e, "families_invalid", "construction")


@pytest.mark.parametrize("which", ["a", "u"])
def test_c02_a_profile_bearing_family_requires_the_host_profile(tmp_path, which):
    p, res, cfg = prepared(tmp_path)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, families(a=asrc() if which == "a" else None, u=usrc() if which == "u" else None), profile=None)
    refused(e, "runtime_authority_profile_required", "construction")


@pytest.mark.parametrize("which", ["f", "a", "u"])
def test_c03_a_declared_family_is_mandatory_a_failing_source_refuses_the_whole_construction(tmp_path, which):
    p, res, cfg = prepared(tmp_path)
    srcs = {"f": fsrc(), "a": asrc(), "u": usrc()}
    srcs[which].fail = True
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, families(srcs["f"], srcs["a"], srcs["u"]))
    refused(e, "selection_source_failed", "construction")


@pytest.mark.parametrize("which,prefix", [("f", "f4_ages"), ("a", "class_age"), ("u", "class_unreadable")])
def test_c04_an_unusable_selection_in_any_declared_family_refuses_and_names_the_family(tmp_path, which, prefix):
    p, res, cfg = prepared(tmp_path)
    srcs = {"f": fsrc(), "a": asrc(), "u": usrc()}
    srcs[which].mat = None  # no material
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, families(srcs["f"], srcs["a"], srcs["u"]))
    refused(e, prefix + ":material_invalid", "construction")


def test_c05_scopes_must_share_consumer_tenant_and_action(tmp_path):
    p, res, cfg = prepared(tmp_path)
    other = GovernedScope("consumer-test", "tenant-other", ACTION_ID, OP_A)
    fams = GovernedFamilies(class_age=GovernedFamily(other, asrc()), class_unreadable=GovernedFamily(base.SCOPE, usrc()))
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, fams)
    refused(e, "family_scope_mismatch", "construction")
    bad = GovernedFamilies(f4_ages=GovernedFamily(GovernedScope("consumer-test", TENANT.lower(), "", OP_F), fsrc()))
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path / "z", res, cfg, bad)
    refused(e, "scope_invalid", "construction")


def test_c06_a_profile_with_policy_binding_is_refused_for_the_profile_bearing_families(tmp_path):
    p, res, cfg = prepared(tmp_path)
    from agent_control_plane.policy_binding import PolicyBinding
    pb = PolicyBinding(binding_digest="sha256:" + "1" * 64, selection_epoch=1, activation_ref="sha256:" + "2" * 64, policy_generation=1, disposition="selected")
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, families(a=asrc()), profile=cfg.model_copy(update={"policy_binding": pb}))
    refused(e, "policy_binding_unsupported", "construction")


# =============================================================================================================== original host invalidity
@pytest.mark.parametrize("reg", [R_, B_])
def test_h01_an_invalid_original_host_is_refused_before_any_registry_call_and_is_not_repaired(tmp_path, reg):
    p, res, bad = prepared(tmp_path, t1=B_, t1_irrev=True)  # the SCOPED class is irreversible AND bounded_tolerance: invalid under bounded.py's own invariant
    bind_approval(res, bad)
    d = BoundedAuthorizationWorkflow(runtime_authority_profile=bad, **kwargs(tmp_path / "plain", res)).decide(p, now=NOW)
    assert d.result == "hold" and "action_class_invalid" in d.reasons  # the unmodified workflow still holds the defect
    s_u, s_a, s_f = Source(mat(umap(t1=reg))), asrc(), fsrc()
    for fams in (families(s_f, s_a, s_u), families(None, None, s_u), families(None, s_a, s_u)):
        with pytest.raises(RegistryGovernedPolicyRefused) as e:
            build(tmp_path / "g", res, bad, fams)
        refused(e, "host_class_invalid", "construction")
    assert s_u.calls == 0 and s_a.calls == 0 and s_f.calls == 0  # nothing was read and no Registry call was made


# =============================================================================================================== final composed profile invalidity / no widening
def test_f01_the_final_composition_validator_rejects_every_widening_and_foreign_change(tmp_path):
    p, res, cfg = prepared(tmp_path)
    host = cfg
    good = ugov.compose_unreadable(agegov.compose_profile(host, {CLASS_T1: 20, CLASS_T2: 120}, {CLASS_T1: 20}), {CLASS_T1: R_, CLASS_T2: R_})
    scal = {"status_max_age_seconds": 60, "approval_max_age_seconds": 60}
    assert pol.final_composition_defect(host, good, scal, {"status_max_age_seconds": 30, "approval_max_age_seconds": 30}) is None
    assert pol.final_composition_defect(host, good, scal, {"status_max_age_seconds": 61, "approval_max_age_seconds": 30}) == "composed_widens_host"
    wider_age = agegov.compose_profile(host, {CLASS_T1: 61, CLASS_T2: 120}, {CLASS_T1: 61})
    assert pol.final_composition_defect(host, wider_age, scal, None) == "composed_widens_host"
    looser = host.model_copy(deep=True)
    looser.actions[p.action_id] = looser.actions[p.action_id].model_copy(update={"on_unreadable": B_})
    host_strict = ugov.compose_unreadable(host, {CLASS_T1: R_, CLASS_T2: R_})
    assert pol.final_composition_defect(host_strict, looser, scal, None) == "composed_widens_host"
    foreign = host.model_copy(update={"catalogue_version": "synthetic-catalogue/2"})
    assert pol.final_composition_defect(host, foreign, scal, None) == "composed_profile_invalid"
    bad_host = base.host_profile(p, t1=B_, t1_irrev=True)
    healed = ugov.compose_unreadable(bad_host, {CLASS_T1: R_, CLASS_T2: R_})
    assert pol.final_composition_defect(bad_host, healed, scal, None) == "host_class_invalid"  # a "narrowing" never repairs an invalid host
    assert pol.final_composition_defect(host, None, scal, None) == "composed_profile_invalid"


@pytest.mark.parametrize("reg_u,reg_a,reg_f", [(B_, 999, (999, 999)), (R_, 20, (30, 30)), (B_, 60, (60, 60))])
def test_f02_no_selection_value_ever_widens_any_host_value(tmp_path, reg_u, reg_a, reg_f):
    p, res, cfg = prepared(tmp_path)
    flow = build(tmp_path, res, cfg, families(Source(fmat(*reg_f)), Source(amat({CLASS_T1: reg_a})), Source(mat(umap(t1=reg_u)))))
    eff = flow.runtime_authority_profile
    assert all(ages(eff)[k] <= ages(cfg)[k] for k in ages(cfg)) and all(base.v5f._RANK[uvals(eff)[k]] <= base.v5f._RANK[uvals(cfg)[k]] for k in uvals(cfg))
    assert flow.status_max_age_seconds <= 60 and flow.approval_max_age_seconds <= 60


def test_f03_the_final_validator_blocks_a_derived_result_that_widens(tmp_path, monkeypatch):
    p, res, cfg = prepared(tmp_path)
    real = agegov.compose_profile
    monkeypatch.setattr(pol.agemod, "compose_profile", real)  # unchanged
    monkeypatch.setattr(pol.agemod, "derive_effective", lambda **k: ((cfg.model_copy(deep=True), {CLASS_T1: 20, CLASS_T2: 120}, "d", agegov.profile_digest(cfg)), None))
    monkeypatch.setattr(pol.unrmod, "compose_unreadable", lambda b, e: b.model_copy(update={"catalogue_version": "x"}))
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, families(None, asrc(), usrc()))
    refused(e, "composed_profile_invalid", "construction")


# =============================================================================================================== revocation / withdrawal at each boundary, each family
def revoked_for(k):
    rv = frozenset({("sel-test-1", 1)})
    return {"f": lambda: fmat(trust=trust_for(OP_F, revoked_selections=rv)), "a": lambda: amat(AGE_M, trust=trust_for(OP_A, revoked_selections=rv)),
            "u": lambda: mat(umap(t1=R_), trust=trust_for(base.OP_U, revoked_selections=rv))}[k]()


@pytest.mark.parametrize("k", ["f", "a", "u"])
def test_r01_a_family_revoked_after_construction_blocks_the_decision_without_state_change(tmp_path, k):
    p, res, cfg, srcs, flow = ready(tmp_path)
    before = file_state(tmp_path, flow)
    srcs[k].mat = revoked_for(k)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, dict(f="f4_ages", a="class_age", u="class_unreadable")[k] + ":registry_not_applied", "decision", "selection_revoked")
    assert file_state(tmp_path, flow) == before and flow.records.load().decisions == []


@pytest.mark.parametrize("k", ["f", "a", "u"])
def test_r02_a_family_revoked_between_decision_and_effect_blocks_the_effect(tmp_path, k):
    p, res, cfg, srcs, flow, d = authorized(tmp_path)
    before = file_state(tmp_path, flow)
    srcs[k].mat = revoked_for(k)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    refused(e, boundary="effect", registry_code="selection_revoked")
    assert file_state(tmp_path, flow) == before and flow.destination.snapshot()["effects"] == {}


@pytest.mark.parametrize("k", ["f", "a", "u"])
def test_r03_a_family_revoked_after_execute_entry_is_refused_at_the_commit_gate(tmp_path, k):
    p, res, cfg, srcs, flow, d = authorized(tmp_path)
    srcs[k].after = (4, revoked_for(k))
    attempt, _ = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "failed" and attempt.error == pol.REJECTION_CODE and flow.destination.snapshot()["effects"] == {}
    assert flow.governed_last_commit_refusal.registry_code == "selection_revoked"
    persisted = [x for x in flow.records.load().attempts if x.effect_id == d.effect_id]
    assert persisted[-1].status == "failed" and not any(x.status == "acknowledged" for x in persisted)


@pytest.mark.parametrize("k", ["f", "a", "u"])
def test_r04_a_changed_selection_between_execute_entry_and_dispatch_is_refused(tmp_path, k):
    p, res, cfg, srcs, flow, d = authorized(tmp_path)
    changed = {"f": fmat(20, 20, stmt_over={"selection_id": "sel-test-2", "epoch": 2}),
               "a": amat({CLASS_T1: 10}, stmt_over={"selection_id": "sel-test-2", "epoch": 2}),
               "u": mat(umap(t1=B_), stmt_over={"selection_id": "sel-test-2", "epoch": 2})}[k]
    srcs[k].after = (4, changed)
    attempt, _ = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "failed" and attempt.error == pol.REJECTION_CODE and flow.destination.snapshot()["effects"] == {}
    assert flow.governed_last_commit_refusal.code == "selection_changed"


@pytest.mark.parametrize("k", ["f", "a", "u"])
def test_r05_partial_source_outage_at_decision_or_effect_entry_refuses_the_whole_workflow(tmp_path, k):
    p, res, cfg, srcs, flow, d = authorized(tmp_path)
    srcs[k].fail = True
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    refused(e, "selection_source_failed", "effect")
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "selection_source_failed", "decision")
    assert flow.destination.snapshot()["effects"] == {}


@pytest.mark.parametrize("k", ["f", "a", "u"])
def test_r05b_the_source_dying_exactly_at_the_commit_gate_blocks_the_effect(tmp_path, k):
    p, res, cfg, srcs, flow, d = authorized(tmp_path)
    good = srcs[k].mat

    class Dies(Source):
        def __call__(self):
            self.calls += 1
            if self.calls >= 4:
                raise RuntimeError("down")
            return self.mat
    srcs[k].__class__ = Dies
    assert srcs[k].mat is good
    attempt, _ = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "failed" and attempt.error == pol.REJECTION_CODE and flow.destination.snapshot()["effects"] == {}
    assert flow.governed_last_commit_refusal.code == "selection_source_failed"


def test_r07_every_boundary_including_the_commit_gate_is_judged_at_the_execute_entry_time(tmp_path, monkeypatch):
    import agent_control_plane.bounded as bounded_module
    p, res, cfg, srcs, flow, d = authorized(tmp_path)
    seen = []
    real = pol.derive_policy

    def spy(**kw):
        seen.append(kw["now"])
        return real(**kw)
    monkeypatch.setattr(pol, "derive_policy", spy)
    monkeypatch.setattr(bounded_module, "_now", lambda: NOW + timedelta(seconds=1))  # the wall clock differs from the supplied test time
    attempt, _ = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and len(seen) == 2 and set(seen) == {NOW}  # effect entry and commit gate, both at the execute-entry time


@pytest.mark.parametrize("k", ["f", "a", "u"])
def test_r06_withdrawn_or_expired_trust_after_construction_blocks_each_family(tmp_path, k):
    p, res, cfg, srcs, flow = ready(tmp_path)
    expired = {"f": fmat(trust=trust_for(OP_F, valid_until="2026-10-04T00:00:00Z")), "a": amat(AGE_M, trust=trust_for(OP_A, valid_until="2026-10-04T00:00:00Z")),
               "u": mat(umap(t1=R_), trust=trust_for(base.OP_U, valid_until="2026-10-04T00:00:00Z"))}[k]
    srcs[k].mat = expired
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, boundary="decision", registry_code="trust_snapshot_expired")


# =============================================================================================================== scope, approval and decision identity
def test_s01_a_proposal_for_another_action_or_tenant_is_out_of_scope(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path)
    other = p.model_copy(update={"action_id": base.T2_ACTION})
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.decide(other, now=NOW)
    refused(e, "proposal_out_of_scope", "decision")
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.decide(p.model_copy(update={"tenant_id": "tenant-other"}), now=NOW)
    refused(e, "proposal_out_of_scope", "decision")


def test_s02_a_wrong_registry_scope_in_any_family_is_refused(tmp_path):
    p, res, cfg = prepared(tmp_path)
    wrong = dict(base.STMT_SCOPE, tenant="tenant-other")
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, families(Source(fmat(stmt_over={"scope": wrong})), asrc(), usrc()))
    refused(e, "f4_ages:registry_not_applied", "construction", "selection_scope_mismatch")


def test_i01_an_approval_issued_for_the_host_profile_does_not_authorize_the_narrowed_one(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, bind=False)
    bind_approval(res, cfg)  # approval over the HOST profile
    d = flow.decide(p, now=NOW)
    assert d.result == "hold" and "runtime_authority_approval_mismatch" in d.reasons
    bind_approval(res, flow.runtime_authority_profile)
    assert flow.decide(p, now=NOW).result == "authorized"


def test_i02_a_rebuilt_workflow_with_a_different_effective_profile_cannot_execute_the_persisted_decision(tmp_path):
    p, res, cfg, srcs, flow, d = authorized(tmp_path)
    alone = build(tmp_path, res, cfg, families(None, srcs["a"], None))  # same store, the unreadable family dropped: a different effective profile
    bind_approval(res, alone.runtime_authority_profile)
    with pytest.raises(PermissionError, match="authorization-critical inputs changed"):
        alone.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert alone.destination.snapshot()["effects"] == {}


def test_i03_restart_with_the_same_families_resumes_a_persisted_decision(tmp_path):
    p, res, cfg, srcs, flow, d = authorized(tmp_path)
    restarted = build(tmp_path, res, cfg, families(srcs["f"], srcs["a"], srcs["u"]))
    assert restarted.records.decision(d.decision_id) == d
    attempt, observed = restarted.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and observed.state == "applied"


def test_i04_the_f4_scalars_are_NOT_in_the_persisted_decision_binding_documented_unresolved_decision(tmp_path):
    """SUCCESSOR FORM, converted in place (D-06 Option B, Architect authorization 2026-10-29; docs/effective-configuration-binding.md).

    SUPERSESSION RECORD. At Control Plane b7eb11aaeed9c766ecaae7d22955093f7f7cd1aa this test characterized a design gap: dropping ONLY the F4 family leaves the profile (hence
    `catalogue_digest` and the approval commitment) identical, so a decision persisted under narrowed scalars was executable by a workflow whose scalars are the host's.
    The ORIGINAL assertions, quoted verbatim as text (they passed at b7eb11a; the original passing output is docs/evidence/d06/baseline-b7eb11a-v7pin.log):

        p, res, cfg, srcs, flow, d = authorized(tmp_path)
        no_f4 = build(tmp_path, res, cfg, families(None, srcs["a"], srcs["u"]))
        assert no_f4.runtime_authority_profile.model_dump() == flow.runtime_authority_profile.model_dump() and no_f4.status_max_age_seconds == 60
        attempt, observed = no_f4.execute(p, d, adapter_id=p.adapter_id, now=NOW)
        assert attempt.status == "acknowledged" and observed.state == "applied"

    Since the persisted effective-configuration binding that outcome is REFUSED. This function keeps the same fixtures and the same first assertion; the final execution
    assertion is inverted to the new refusal outcome. It runs in the gated suites as an ordinary passing test (no xfail/skip). Further successor: tests/test_effective_configuration_binding.py::
    test_c03_the_documented_i04_scenario_now_refuses (adds the status classification and the durable refusal row)."""
    p, res, cfg, srcs, flow, d = authorized(tmp_path)
    no_f4 = build(tmp_path, res, cfg, families(None, srcs["a"], srcs["u"]))
    assert no_f4.runtime_authority_profile.model_dump() == flow.runtime_authority_profile.model_dump() and no_f4.status_max_age_seconds == 60
    with pytest.raises(PermissionError, match="authorization-critical inputs changed before effect"):  # was: executed and applied (see the record above)
        no_f4.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert no_f4.destination.snapshot()["effects"] == {}


@pytest.mark.parametrize("edit", ["scalars", "profile_drop", "profile_swap"])
def test_i05_post_construction_edits_of_the_held_state_are_refused_at_every_boundary(tmp_path, edit):
    p, res, cfg, srcs, flow = ready(tmp_path)
    if edit == "scalars":
        flow.approval_max_age_seconds = 60
    elif edit == "profile_drop":
        flow.runtime_authority_profile = cfg
    else:
        flow.runtime_authority_profile = flow.runtime_authority_profile.model_copy(update={"catalogue_version": "x"})
    calls = {k: x.calls for k, x in srcs.items()}
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "scalars_modified" if edit == "scalars" else "profile_modified", "decision")
    assert {k: x.calls for k, x in srcs.items()} == calls  # the held state is judged FIRST: no selection source was even invoked


def test_i06_the_held_state_is_checked_again_after_the_sources_ran(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path)
    hostile = flow.runtime_authority_profile.model_copy(update={"catalogue_version": "x"})
    real = srcs["u"].__call__

    class Tamper(Source):
        def __call__(self_inner):
            flow.runtime_authority_profile = hostile
            return real()
    srcs["u"].__class__ = Tamper
    flow._gp_families.class_unreadable.selection_source.__class__ = Tamper
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "profile_modified", "decision")


# =============================================================================================================== construction inputs, clock, manifest, destination, bound components
def test_k01_the_construction_clock_is_the_real_clock_unless_the_host_allows_test_time(tmp_path):
    p = base.tenant_proposal()
    res = base.tenant_resolver_for(p)
    future = NOW + timedelta(days=30)  # outside every trust validity window if it were honoured
    flow = GovernedPolicyWorkflow(families=families(f=fsrc()), verifier=ev.Ed25519Verifier(), construction_time=future,
                                  **{**kwargs(tmp_path, res), "allow_test_time": False})
    assert (flow.status_max_age_seconds, flow.approval_max_age_seconds) == (30, 30)  # built at the (patched) real clock: the supplied time was ignored
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        GovernedPolicyWorkflow(families=families(f=fsrc()), verifier=ev.Ed25519Verifier(), construction_time=future, **kwargs(tmp_path / "t", res))  # honoured: expired then
    assert e.value.boundary == "construction"


def test_k02_a_naive_construction_time_is_refused(tmp_path):
    p, res, cfg = prepared(tmp_path)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        GovernedPolicyWorkflow(families=families(fsrc(), asrc(), usrc()), verifier=ev.Ed25519Verifier(), runtime_authority_profile=cfg,
                               construction_time=datetime(2026, 10, 3, 12, 0, 0), **kwargs(tmp_path, res))
    refused(e, "time_invalid", "construction")


def test_k03_an_already_gated_destination_is_refused(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path / "again", res, cfg, families(fsrc(), asrc(), usrc()), destination=flow.destination)
    refused(e, "destination_invalid", "construction")


def test_k04_a_changed_manifest_authority_after_construction_is_refused_at_every_boundary(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path)
    m = copy.deepcopy(flow.manifest)
    for a in m["actions"]:
        a["authority_context"]["institution_id"] = "institution-other"
    flow.manifest = m
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "manifest_authority_changed", "decision")


@pytest.mark.parametrize("bad", [-1, True, "60", 2147483648])
def test_k05_host_scalars_must_be_exact_integers_when_f4_is_declared(tmp_path, bad):
    p, res, cfg = prepared(tmp_path)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, families(f=fsrc()), pol={"status_max_age_seconds": bad})
    refused(e, "host_scalar_invalid", "construction")


@pytest.mark.parametrize("part", ["f4_ages", "class_age", "class_unreadable", "effective_profile_digest"])
def test_k06_each_component_of_the_bound_identity_is_compared_on_its_own(tmp_path, monkeypatch, part):
    p, res, cfg, srcs, flow = ready(tmp_path)
    real = pol.derive_policy

    def tampered(**kw):
        out, refusal = real(**kw)
        profile, scalars, bound = out
        bound = dict(bound)
        v = bound[part]
        bound[part] = "sha256:" + "0" * 64 if part == "effective_profile_digest" else (v[0], "sha256:" + "0" * 64, *v[2:])
        return (profile, scalars, bound), refusal
    monkeypatch.setattr(pol, "derive_policy", tampered)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "selection_changed", "decision")


def test_k07_the_extension_limit_can_never_grow_in_the_final_composition(tmp_path):
    p, res, cfg = prepared(tmp_path, freshness=FreshnessProfile(max_age_extension_seconds=300))
    scal = {"status_max_age_seconds": 60, "approval_max_age_seconds": 60}
    grown = cfg.model_copy(update={"freshness": cfg.freshness.model_copy(update={"max_age_extension_seconds": 301})})
    assert pol.final_composition_defect(cfg, grown, scal, None) == "composed_widens_host"
    same = cfg.model_copy(deep=True)
    assert pol.final_composition_defect(cfg, same, scal, None) is None


# =============================================================================================================== cached purpose exclusion, existing refusal semantics
def test_x01_the_cached_purpose_snapshot_path_is_still_not_governed_by_the_unreadable_value(tmp_path):
    import inspect
    import agent_control_plane.bounded as bounded
    assert "on_unreadable" not in inspect.getsource(bounded.BoundedAuthorizationWorkflow._cached_purpose)
    assert "on_unreadable" not in "".join(inspect.getsource(m) for m in (life,))  # the shared lifecycle never touches the field


def test_x02_an_outage_is_refused_under_the_composed_unreadable_value_exactly_as_the_dedicated_workflow(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path)
    base.unreadable(res)
    d = flow.decide(p, now=NOW)
    assert d.result == "hold" and "status_unreadable" in d.reasons and not any(x.read_state == "cached_positive" for x in d.resolution_inputs)


class Spy(LocalRefundDestination):
    applies = 0

    def apply(self, *a, **k):
        type(self).applies += 1
        return super().apply(*a, **k)


def test_x03_a_gate_refusal_never_reaches_the_destination_and_blocks_automatic_retry(tmp_path):
    Spy.applies = 0
    p, res, cfg = prepared(tmp_path)
    srcs = {"f": fsrc(), "a": asrc(), "u": usrc()}
    flow = build(tmp_path, res, cfg, families(srcs["f"], srcs["a"], srcs["u"]), destination=Spy(tmp_path / "spy.json"))
    bind_approval(res, flow.runtime_authority_profile)
    d = flow.decide(p, now=NOW)
    srcs["u"].after = (4, revoked_for("u"))
    attempt, _ = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "failed" and Spy.applies == 0
    srcs["u"].after = None
    with pytest.raises(PermissionError, match="retry eligibility"):
        flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)  # the failed attempt blocks the automatic retry
    assert Spy.applies == 0


# =============================================================================================================== activation ledger (local, advisory)
def test_l01_a_second_differently_configured_workflow_for_the_same_action_is_refused_by_a_shared_ledger(tmp_path):
    ledger = GovernedActivationLedger()
    p, res, cfg = prepared(tmp_path)
    first = build(tmp_path, res, cfg, families(None, asrc(), usrc()), pol={"activation_ledger": ledger})
    same = build(tmp_path / "same", res, cfg, families(None, asrc(), usrc()), pol={"activation_ledger": ledger})  # same configuration: idempotent
    assert same.registry_governed_policy_identity["configuration_digest"] == first.registry_governed_policy_identity["configuration_digest"]
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path / "other", res, cfg, families(fsrc(), asrc(), usrc()), pol={"activation_ledger": ledger})
    refused(e, "conflicting_governed_configuration", "construction")


def test_l02_supersede_retires_the_old_workflow_at_every_boundary(tmp_path):
    ledger = GovernedActivationLedger()
    p, res, cfg = prepared(tmp_path)
    old = build(tmp_path, res, cfg, families(None, asrc(), usrc()), pol={"activation_ledger": ledger})
    bind_approval(res, old.runtime_authority_profile)
    key = old._gp_key
    assert ledger.supersede(key, old.registry_governed_policy_identity["configuration_digest"], "sha256:" + "9" * 64)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        old.decide(p, now=NOW)
    refused(e, "activation_superseded", "decision")
    assert not ledger.supersede(key, "stale", "x")


def _claims_digest(flow):
    return flow.registry_governed_policy_identity["configuration_digest"]


@pytest.mark.parametrize("other", ["registry_age_value", "registry_unreadable_value", "registry_f4_value", "host_age", "host_scalar"])
def test_l04_two_differently_governed_configurations_never_share_an_identity(tmp_path, other):
    """Same declared families, same scope, same operation ids: only the effective policy values (Registry or host) differ. The identities must differ and a shared ledger must refuse."""
    ledger = GovernedActivationLedger()
    p, res, cfg = prepared(tmp_path)
    first = build(tmp_path, res, cfg, families(fsrc(), asrc(), usrc()), pol={"activation_ledger": ledger})
    kw, fams, pol_kw = {}, {"f": fsrc(), "a": asrc(), "u": usrc()}, {"activation_ledger": ledger}
    p2, res2, cfg2 = prepared(tmp_path / "second", **({"age1": 50} if other == "host_age" else {}))
    if other == "registry_age_value":
        fams["a"] = Source(amat({CLASS_T1: 10}))
    elif other == "registry_unreadable_value":
        fams["u"] = Source(mat(umap(t1=B_)))
    elif other == "registry_f4_value":
        fams["f"] = Source(fmat(20, 20))
    elif other == "host_scalar":
        pol_kw["status_max_age_seconds"] = 90
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path / "second", res2, cfg2, families(fams["f"], fams["a"], fams["u"]), pol=pol_kw)
    refused(e, "conflicting_governed_configuration", "construction")
    assert ledger.holder(first._gp_key) == _claims_digest(first)  # the first claim is untouched


def test_l05_the_identity_is_deterministic_for_the_same_governance(tmp_path):
    a = ready(tmp_path / "a")[4]
    b = ready(tmp_path / "b")[4]
    assert _claims_digest(a) == _claims_digest(b)


def test_l06_a_failed_construction_leaves_no_claim(tmp_path):
    ledger = GovernedActivationLedger()
    p, res, cfg = prepared(tmp_path)
    with pytest.raises(TypeError):  # fails inside the base constructor, AFTER derivation and identity computation
        GovernedPolicyWorkflow(families=families(fsrc(), asrc(), usrc()), verifier=ev.Ed25519Verifier(), runtime_authority_profile=cfg, construction_time=REG_NOW,
                               activation_ledger=ledger, bogus_workflow_argument=1, **kwargs(tmp_path / "a", res))
    assert ledger._claims == {}
    with pytest.raises(ValueError, match="explicit test clock"):  # a second base-constructor failure: synthetic profile without allow_test_time
        GovernedPolicyWorkflow(families=families(fsrc(), asrc(), usrc()), verifier=ev.Ed25519Verifier(), runtime_authority_profile=cfg, activation_ledger=ledger,
                               **{**kwargs(tmp_path / "b", res), "allow_test_time": False})
    assert ledger._claims == {}
    ok = build(tmp_path / "ok", res, cfg, families(None, asrc(), usrc()), pol={"activation_ledger": ledger})  # another configuration can still claim afterwards
    assert ledger.holder(ok._gp_key) == _claims_digest(ok)


def test_l07_a_refused_claim_leaves_the_first_claim_and_a_failed_registry_check_never_claims(tmp_path):
    ledger = GovernedActivationLedger()
    p, res, cfg = prepared(tmp_path)
    bad = usrc()
    bad.fail = True
    with pytest.raises(RegistryGovernedPolicyRefused):
        build(tmp_path, res, cfg, families(fsrc(), asrc(), bad), pol={"activation_ledger": ledger})
    assert ledger._claims == {}


def test_l08_concurrent_claims_have_exactly_one_winner_and_the_claim_is_atomic():
    import threading

    class SlowGet(dict):
        """A claim table whose plain `get` yields to the other thread: a check-then-set implementation would let both threads win."""
        gate = threading.Barrier(2, timeout=1)

        def get(self, *a, **k):
            value = super().get(*a, **k)
            try:
                self.gate.wait()
            except threading.BrokenBarrierError:
                pass
            return value

    ledger = GovernedActivationLedger()
    ledger._claims = SlowGet()
    key, results = ("t", "a", "i", "d"), []
    start = threading.Barrier(2)

    def go(cid):
        start.wait()
        results.append(ledger.claim(key, cid))
    threads = [threading.Thread(target=go, args=(c,)) for c in ("sha256:" + "a" * 64, "sha256:" + "b" * 64)]
    [th.start() for th in threads]
    [th.join() for th in threads]
    assert sorted(results) == [False, True] and ledger.holder(key) in ("sha256:" + "a" * 64, "sha256:" + "b" * 64)


def test_l09_many_concurrent_claims_agree_on_one_holder_and_only_its_identity_succeeds():
    import threading
    ledger, key, out = GovernedActivationLedger(), ("t", "a", "i", "d"), []
    ids = ["sha256:" + c * 64 for c in "abcd"]
    barrier = threading.Barrier(16)

    def go(cid):
        barrier.wait()
        out.append((cid, ledger.claim(key, cid)))
    threads = [threading.Thread(target=go, args=(ids[i % 4],)) for i in range(16)]
    [th.start() for th in threads]
    [th.join() for th in threads]
    held = ledger.holder(key)
    assert held in ids and len(out) == 16
    assert all(ok == (cid == held) for cid, ok in out)  # every thread with the winning identity succeeded, every other one was refused


def test_l03_the_ledger_is_local_and_documented_as_not_exclusive(tmp_path):
    """A workflow built WITHOUT the ledger, or the plain workflow, is invisible to it: no deployment-wide exclusivity is claimed."""
    ledger = GovernedActivationLedger()
    p, res, cfg = prepared(tmp_path)
    build(tmp_path, res, cfg, families(None, asrc(), usrc()), pol={"activation_ledger": ledger})
    build(tmp_path / "noledger", res, cfg, families(fsrc(), asrc(), usrc()))  # accepted: not registered
    BoundedAuthorizationWorkflow(runtime_authority_profile=cfg, **kwargs(tmp_path / "plain", res))
    assert "NOT deployment-wide exclusivity" in pol.__doc__


# =============================================================================================================== frozen Registry compatibility, existing consumers, protected files
def test_z01_the_composed_workflow_uses_the_registry_r08_v2_and_v5_contracts_unchanged(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path)
    for k, ctr in (("f", "r08-v2"), ("a", "r08-v2"), ("u", "r08-v5")):
        assert f'"contract_version":"{ctr}"' in srcs[k].mat.selection_text.replace(" ", "") or ctr in srcs[k].mat.selection_text


def test_z02_the_three_existing_workflows_keep_their_public_surface(tmp_path):
    for cls, attrs in ((f4gov.GovernedAgeWorkflow, ("registry_f4_policy_identity", "f4_last_commit_refusal", "_f4_commit_gate")),
                       (agegov.GovernedClassAgeWorkflow, ("registry_f5_policy_identity", "f5_last_commit_refusal", "_f5_commit_gate")),
                       (ugov.GovernedClassUnreadableWorkflow, ("registry_f5_unreadable_policy_identity", "fu_last_commit_refusal", "_fu_commit_gate"))):
        assert issubclass(cls, life.GovernedLifecycle) and all(hasattr(cls, a) for a in attrs)
    assert f4gov.GovernedScope is life.GovernedScope and f4gov.Refusal is life.Refusal and f4gov._GatedDestination is life._GatedDestination
    assert issubclass(agegov.RegistryClassAgeRefused, f4gov.RegistrySelectionRefused) and issubclass(ugov.RegistryClassUnreadableRefused, f4gov.RegistrySelectionRefused)
    assert (f4gov.REJECTION_CODE, agegov.REJECTION_CODE, ugov.REJECTION_CODE) == ("registry_f4_selection_invalid", "registry_f5_selection_invalid",
                                                                                   "registry_f5_unreadable_selection_invalid")


PROTECTED = {  # byte pins of the protected evaluators (identical to Control Plane ae47a04) and of the consolidated governance modules
    "bounded.py": "c219f8825a8ddf9da1fe6771ae575af0a9069ac8a04eadd40f093a9adb13655b",
    # D-07 Option A (Architect-authorized 2026-10-29): the ONLY protected-file change. Previous pin (CP main b7eb11a, CP #94 061a986):
    # a4b4ac36cca6e75d8fc3408b8738163acfb609a7265633aec2f799700ff9ea66. The other five pins below are unchanged
    # (tests/test_freshness_purpose_anchor_successor.py::test_d07_only_runtime_authority_changed_among_the_protected_evaluators).
    # Chain: b7eb11a a4b4ac36... -> D-07 head fb24ed0 ad7b95e5d3bc3ddcba110a6758cf63e7f22b537766d3d072cbc7af17385bce01 -> this pin (comment-only prose correction; code tokens identical).
    "runtime_authority.py": "45a27db8695ff9d23516e1937f3bafa2391bbc1587ed0fb09f56ea8f3e01d23f",
    "freshness.py": "3f146ee11a3424d816c6f35ba07259833612a985901b4a96c0275395f05d51c0",
    "policy_binding.py": "defdfac5fd60cf5be707a76204a12513f2f289b0620ec56d063b56dac4081a35",
    "rule_revision.py": "a3833f49e96db52e0665b9816daee2654f74f7784faad5101252b4c8722415a5",
    "reversibility.py": "5edbadebb3aa777fba7f652c10c8da3c5e9ee1766b71866ed55dc25b319477d1",
}


@pytest.mark.parametrize("name", sorted(PROTECTED))
def test_z03_protected_evaluators_are_unmodified_by_the_consolidation(name):
    assert hashlib.sha256((SRC / name).read_bytes()).hexdigest() == PROTECTED[name], name


def test_z04_the_shared_lifecycle_holds_no_policy_no_registry_import_and_never_touches_a_governed_field():
    import ast
    tree = ast.parse((SRC / "registry_governed_lifecycle.py").read_text())
    for node in ast.walk(tree):  # strip docstrings, then inspect code only
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef)) and node.body and isinstance(node.body[0], ast.Expr) and isinstance(getattr(node.body[0], "value", None), ast.Constant):
            node.body = node.body[1:] or [ast.Pass()]
    code = ast.unparse(tree)
    imported = {a.name for n in ast.walk(tree) if isinstance(n, (ast.Import, ast.ImportFrom)) for a in n.names} | {n.module or "" for n in ast.walk(tree) if isinstance(n, ast.ImportFrom)}
    assert not any("importlib" in i or "registry_successor" in i or "runtime_authority" in i for i in imported), imported
    assert "approval_commitment" not in code and "on_unreadable" not in code and "max_status_age_seconds" not in code and "model_dump" not in code
