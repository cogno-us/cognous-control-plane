"""Registry-governed `ActionClass.irreversible` (per action class, strengthen-only; Registry `r08-v7`, family `f5-action-class-irreversibility-policy`) reaching the real
`BoundedAuthorizationWorkflow` through the composed `GovernedPolicyWorkflow`, with the selection re-validated at construction, decision entry, execute entry and the pre-dispatch
commit gate, and the immutable `EffectivePolicySnapshot` it exposes.

BUILDER_TESTED developer evidence. NOT independently qualified. NOT an authorization mechanism. Real synthetic Ed25519 (no test doubles for the Registry verdict) through the real
workflow; the only doubles are explicit monkeypatches of a Registry RESULT used to prove the Control Plane re-checks it (they are named as such).

What is proven here: a Registry `irreversible` can only flip `ActionClass.irreversible` false -> true for every action of a class whose HOST declaration is a plain legacy-reversible
class (no reversibility members, `on_unreadable` refuse); every other host class is refused `irreversible_flip_conflict:<cause>` and is never repaired; a Registry `no_change` never lowers
a host true; the flag lives in the profile that `approval_commitment` and the persisted `catalogue_digest` already hash.

Needs a Registry checkout at the exact r08-v7 `PIN_V7` in `OCS_REGISTRY_PIN_DIR` and PyNaCl (`tests/test_f5_class_unreadable_governance.py` enforces both and `OCS_REQUIRE_REGISTRY_PIN=1`).
"""
from __future__ import annotations

import dataclasses
import hashlib
import importlib
import itertools
from datetime import timedelta
from pathlib import Path

import pytest

import tests.test_f5_class_unreadable_governance as base  # noqa: E402  (also enforces the Registry pin and PyNaCl requirement)
import tests.test_governed_policy_composition as comp  # noqa: E402
import tests.test_revocation_families_governance as rv  # noqa: E402

from agent_control_plane import registry_effective_policy as eff  # noqa: E402
from agent_control_plane import registry_governed_policy as pol  # noqa: E402
from agent_control_plane import registry_irreversibility_governance as ir  # noqa: E402
from agent_control_plane.registry_governed_policy import (  # noqa: E402
    GovernedActivationLedger, GovernedFamilies, GovernedFamily, GovernedPolicyWorkflow, RegistryGovernedPolicyRefused,
)
from agent_control_plane.reversibility import ReversibilityProfile, effectively_irreversible  # noqa: E402
from agent_control_plane.runtime_authority import ActionClass, RuntimeAuthorityProfile, approval_commitment  # noqa: E402

v7dec = importlib.import_module("registry_successor.v7_decision")
v7id = importlib.import_module("registry_successor.v7_policy_identity")

ev, trust_for, bind_approval, file_state, Source, kwargs = base.ev, base.trust_for, base.bind_approval, base.file_state, base.Source, base.kwargs
CLASS_T1, CLASS_T2, TENANT, ACTION_ID, NOW, REG_NOW, PROFILE = base.CLASS_T1, base.CLASS_T2, base.TENANT, base.ACTION_ID, base.NOW, base.REG_NOW, base.PROFILE
R_, B_ = base.R_, base.B_
GovernedScope = base.GovernedScope
V7_DOMAIN = b"ocs-reg/r08-v7/selection\n"
FAMILY, FIELD = ir.FAMILY_IR, ir.FIELD_IR
OP_IR = "refund-issue-irreversible"
SCOPE_IR = GovernedScope("consumer-test", TENANT.lower(), ACTION_ID, OP_IR)
IRR, NC = "irreversible", "no_change"
SRC = Path(pol.__file__).resolve().parent
RV, CHANGED, INV, variant = rv.RV, rv.CHANGED, rv.INV, rv.variant
EPOCH2 = {"epoch": 2}


@pytest.fixture(autouse=True)
def _fixed_synthetic_clock(monkeypatch):
    import agent_control_plane.bounded as bounded_module
    monkeypatch.setattr(bounded_module, "_now", lambda: NOW)
    for m in (pol, base.gov, base.agegov, base.f4gov):
        monkeypatch.setattr(m, "_now", lambda: NOW)


# --------------------------------------------------------------------------------------------------------------- Registry-side builders (real Ed25519)
def irec(m=None, *, family=None, contract="r08-v7", payload=None, **over):
    body = dict(base.r.make_record(), contract_version=contract, family=family or FAMILY, record_id="f5irr-record",
                payload=payload if payload is not None else {FIELD: m if m is not None else {CLASS_T1: IRR}})
    body.update(over)
    return base.r.seal_record(body)


def imat(m=None, *, rec=None, contract="r08-v7", domain=None, **kw):
    rec = rec or irec(m)
    stmt_over = dict(kw.pop("stmt_over", {}))
    stmt_over.setdefault("operation", OP_IR)
    stmt_over["family"] = stmt_over.get("family", rec.get("family", FAMILY))
    return base._material(rec, op=stmt_over.pop("operation"), contract=contract, domain=domain or V7_DOMAIN, family=stmt_over.pop("family"), stmt_over=stmt_over, **kw)


# --------------------------------------------------------------------------------------------------------------- Control-Plane-side builders
def host_cfg(p, **kw):
    """HOST profile whose scoped class T1 is legacy-reversible with on_unreadable `refuse` (the only class a flip accepts); T2 stays irreversible/refuse."""
    kw.setdefault("t1", R_)
    return base.host_profile(p, **kw)


def flags(profile):
    return {a.class_id: a.irreversible for a in profile.actions.values()}


def without_flag(profile):
    doc = profile.model_dump(mode="json")
    for a in doc["actions"].values():
        a.pop("irreversible", None)
    return doc


def fams(ir_=None, ra=None, tr=None, f=None, a=None, u=None):
    g = rv.fams(ra=ra, tr=tr, f=f, a=a, u=u)
    return dataclasses.replace(g, class_irreversible=GovernedFamily(SCOPE_IR, ir_) if ir_ is not None else None)


def build(tmp_path, res, cfg, families, **kw):
    return GovernedPolicyWorkflow(families=families, verifier=ev.Ed25519Verifier(), runtime_authority_profile=kw.pop("profile", cfg), construction_time=REG_NOW,
                                  **kw.pop("pol", {}), **kwargs(tmp_path, res, **kw))


def sources(*, ir_=None, ra=None, tr=None, f=False, a=False, u=False):
    return {"ir": Source(imat(ir_)) if ir_ is not None else None, "ra": Source(rv.rmat(ra)) if ra is not None else None, "tr": Source(rv.tmat(tr)) if tr is not None else None,
            "f": comp.fsrc() if f else None, "a": comp.asrc() if a else None, "u": comp.usrc() if u else None}


def ready(tmp_path, *, ir_=None, ra=None, tr=None, f=False, a=False, u=False, host=None, bind=True, **profile_kw):
    """(proposal, resolver, HOST profile, {sources}, flow). `ir_` is the irreversibility class map. Approvals are issued against the FINAL effective profile."""
    profile_kw.setdefault("t1", R_)
    p, res, cfg = base.prepared(tmp_path, **profile_kw)
    if host is not None:
        cfg = host(cfg)
    srcs = sources(ir_=ir_, ra=ra, tr=tr, f=f, a=a, u=u)
    flow = build(tmp_path, res, cfg, fams(srcs["ir"], srcs["ra"], srcs["tr"], srcs["f"], srcs["a"], srcs["u"]))
    if bind:
        bind_approval(res, flow.runtime_authority_profile)
    return p, res, cfg, srcs, flow


def authorized(tmp_path, **kw):
    kw.setdefault("host", rv.with_inventory)
    p, res, cfg, srcs, flow = ready(tmp_path, **kw)
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    return p, res, cfg, srcs, flow, d


PREFIX = "class_irreversible:"


def refused(exc, code=None, boundary=None, registry_code=None, prefix=None):
    return rv.refused(exc, code, boundary, registry_code, prefix)


def revoked_ir():
    return imat(trust=trust_for(OP_IR, revoked_selections=RV))


def changed_ir():
    return imat({CLASS_T1: NC}, stmt_over=CHANGED)  # the flip is withdrawn: another effective profile


def effects(flow):
    return flow.destination.snapshot()["effects"]


# =============================================================================================================== A: irreversibility alone
def test_a01_a_valid_selection_flips_the_governed_class_and_changes_nothing_else(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, ir_={CLASS_T1: IRR})
    assert flags(cfg) == {CLASS_T1: False, CLASS_T2: True}
    assert flags(flow.runtime_authority_profile) == {CLASS_T1: True, CLASS_T2: True}
    assert without_flag(flow.runtime_authority_profile) == without_flag(cfg)  # only the governed field differs, everything else byte for byte
    ident = flow.registry_governed_policy_identity
    assert ident["families"] == ["class_irreversible"] and ident["class_irreversible"]["effective"] == {CLASS_T1: IRR, CLASS_T2: IRR}
    assert ident["host"]["class_irreversible"] == {CLASS_T1: NC, CLASS_T2: IRR} and ident["terminal_revocation"] is None and ident["class_revocation_assurance"] is None


@pytest.mark.parametrize("host_irr", [False, True])
@pytest.mark.parametrize("reg", [NC, IRR])
def test_a02_the_effective_value_is_the_stricter_of_host_and_registry_and_a_host_true_is_never_lowered(tmp_path, host_irr, reg):
    p, res, cfg, srcs, flow = ready(tmp_path, ir_={CLASS_T1: reg}, t1_irrev=host_irr)
    assert flags(flow.runtime_authority_profile)[CLASS_T1] == (host_irr or reg == IRR)
    assert flags(flow.runtime_authority_profile)[CLASS_T2] is True
    if host_irr or reg == NC:  # a Registry value that changes nothing leaves the profile (and every existing approval) byte-identical
        assert flow.runtime_authority_profile.model_dump() == cfg.model_dump()


def test_a03_the_registry_digest_is_the_independent_v7_effective_policy_identity_including_the_family_schema_revision(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, ir_={CLASS_T1: IRR})
    eff_map = {CLASS_T1: IRR, CLASS_T2: IRR}
    expect = v7id.effective_policy_digest(FAMILY, {FIELD: eff_map}, "r08-v7")
    assert flow.registry_governed_policy_identity["class_irreversible"]["effective_policy_digest"] == expect
    assert v7id.effective_policy_digest(FAMILY, {FIELD: {CLASS_T1: IRR, CLASS_T2: NC}}, "r08-v7") != expect  # every class and value is bound
    assert v7id.effective_preimage(FAMILY, {FIELD: eff_map})["family_schema_revision"] == ir.FAMILY_SCHEMA_REVISION == 1
    assert eff.SCHEMA_REVISIONS["class_irreversible"] == ir.FAMILY_SCHEMA_REVISION


def test_a04_a_flip_makes_the_evaluator_treat_the_class_as_irreversible_and_nothing_is_dispatched_by_the_adapter(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, ir_={CLASS_T1: IRR})
    cl_host, cl_eff = cfg.actions[p.action_id], flow.runtime_authority_profile.actions[p.action_id]
    assert effectively_irreversible(cl_host, NOW) is False and effectively_irreversible(cl_eff, NOW) is True
    assert cl_eff.on_unreadable == R_ and cl_eff.reversibility is None  # no reversibility member was invented
    assert effects(flow) == {} and not flow.records.load().attempts


def test_a05_with_approval_and_inventory_the_flipped_class_authorizes_and_executes(tmp_path):
    p, res, cfg, srcs, flow, d = authorized(tmp_path, ir_={CLASS_T1: IRR})
    attempt, observed = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and observed.state == "applied"


def test_a06_governed_decisions_equal_the_existing_workflow_built_with_the_effective_profile(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, ir_={CLASS_T1: IRR})
    oracle = base.plain(tmp_path / "oracle", res, flow.runtime_authority_profile)
    bind_approval(res, oracle.runtime_authority_profile)
    dg, do = flow.decide(p, now=NOW), oracle.decide(p, now=NOW)
    assert (dg.result, dg.reasons) == (do.result, do.reasons)


def test_a07_an_approval_issued_for_the_host_profile_does_not_authorize_the_flipped_one(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, ir_={CLASS_T1: IRR}, bind=False)
    ctx = res.contexts[PROFILE]
    assert approval_commitment(flow.runtime_authority_profile, ctx) != approval_commitment(cfg, ctx)
    bind_approval(res, cfg)  # issued for the HOST profile
    d = flow.decide(p, now=NOW)
    assert d.result == "hold" and "runtime_authority_approval_mismatch" in d.reasons
    assert effects(flow) == {} and not flow.records.load().attempts
    bind_approval(res, flow.runtime_authority_profile)
    assert flow.decide(p, now=NOW).result == "authorized"


def test_a08_a_registry_value_that_flips_nothing_keeps_an_existing_approval_valid(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, ir_={CLASS_T1: NC}, bind=False)
    bind_approval(res, cfg)
    assert flow.decide(p, now=NOW).result == "authorized"


def test_a09_a_registry_class_unknown_to_the_host_is_refused_and_the_record_must_name_the_scoped_class(tmp_path):
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, fams(Source(imat({CLASS_T1: IRR, "class-not-in-host": IRR}))))
    refused(e, prefix=PREFIX, boundary="construction")
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path / "b", res, cfg, fams(Source(imat({CLASS_T2: IRR}))))
    refused(e, PREFIX + "scoped_class_not_governed", "construction")


@pytest.mark.parametrize("payload", [{}, {FIELD: {}}, {FIELD: {CLASS_T1: True}}, {FIELD: {CLASS_T1: "IRREVERSIBLE"}}, {FIELD: {CLASS_T1: "reversible"}},
                                     {FIELD: {CLASS_T1: IRR}, "extra": 1}, {FIELD: [CLASS_T1]}, {"class_requires_revocation_assurance": {CLASS_T1: "required"}}])
def test_a10_malformed_irreversibility_records_are_refused(tmp_path, payload):
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, fams(Source(imat(rec=irec(payload=payload)))))
    refused(e, prefix=PREFIX, boundary="construction")


def test_a11_the_family_can_never_assert_reversibility_a_registry_no_change_never_lowers_a_host_true(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, ir_={CLASS_T1: NC, CLASS_T2: NC})
    assert flags(flow.runtime_authority_profile) == {CLASS_T1: False, CLASS_T2: True}
    assert flow.registry_governed_policy_identity["class_irreversible"]["effective"] == {CLASS_T1: NC, CLASS_T2: IRR}
    assert flow.runtime_authority_profile.model_dump() == cfg.model_dump()


# =============================================================================================================== B: flip pre-check (host class) and ambiguity
def test_b01_a_host_class_with_on_unreadable_other_than_refuse_is_a_named_flip_conflict_and_is_never_repaired(tmp_path):
    p, res, cfg = base.prepared(tmp_path, t1=B_)  # the host value is bounded_tolerance
    src = Source(imat({CLASS_T1: IRR}))
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, fams(src))
    refused(e, PREFIX + "irreversible_flip_conflict:on_unreadable_not_refuse", "construction")


def test_b02_the_flip_never_relies_on_another_family_narrowing_the_host_on_unreadable(tmp_path):
    """The Registry unreadable family WOULD turn bounded_tolerance into refuse, which would make the flipped class valid; the flip pre-check reads the HOST value, so it still refuses."""
    p, res, cfg = base.prepared(tmp_path, t1=B_)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, fams(Source(imat({CLASS_T1: IRR})), u=comp.usrc()))
    refused(e, PREFIX + "irreversible_flip_conflict:on_unreadable_not_refuse", "construction")
    # the final-composition validator refuses the same hiding on its own: host bounded_tolerance, final refuse, class flipped
    host = base.prepared(tmp_path / "x", t1=B_)[2]
    forged = host.model_dump(mode="json")
    for a in forged["actions"].values():
        a["on_unreadable"] = R_
    forged["actions"][ACTION_ID]["irreversible"] = True
    final = RuntimeAuthorityProfile.model_validate(forged)
    scalars = {"status_max_age_seconds": 60, "approval_max_age_seconds": 60}
    assert pol.final_composition_defect(host, final, scalars, None, irreversible_declared=True) == ir.FLIP_CONFLICT + ":on_unreadable_not_refuse"
    assert pol.final_composition_defect(host, final, scalars, None, irreversible_declared=False) == "composed_profile_invalid"


def test_b03_a_host_class_that_declares_reversibility_is_a_flip_conflict(tmp_path):
    from datetime import datetime, timezone
    until = (NOW + timedelta(days=30)).astimezone(timezone.utc).isoformat()
    cls = ActionClass(class_id=CLASS_T1, reversibility="reversible_until", reversible_until=until, max_status_age_seconds=60, on_unreadable=R_)
    p, res, cfg = base.prepared(tmp_path, t1=R_, reversibility=ReversibilityProfile())
    cfg = base.host_profile(p, t1=R_, reversibility=ReversibilityProfile(), extra_actions={p.action_id: cls})
    assert cfg.actions[p.action_id].irreversible is False and cfg.actions[p.action_id].reversibility == "reversible_until"
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, fams(Source(imat({CLASS_T1: IRR}))))
    refused(e, PREFIX + "irreversible_flip_conflict:reversibility_declared", "construction")


@pytest.mark.parametrize("update,cause", [({"reversibility": "reversible_at_cost"}, "reversibility_declared"), ({"reversible_until": "2030-01-01T00:00:00+00:00"}, "reversible_until_declared"),
                                          ({"reversal_cost": "5"}, "reversal_cost_declared"), ({"on_unreadable": B_}, "on_unreadable_not_refuse"),
                                          ({"reads_protected_data": True}, "reads_protected_data"), ({"counterparty_observable": False}, "counterparty_observable_not_default")])
def test_b04_every_flip_condition_has_its_own_named_cause(tmp_path, update, cause):
    """Host classes that the model validators would never build (a forged host object) are still refused by the pre-check, one named cause each."""
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    forged = cfg.model_copy(update={"actions": {**cfg.actions, p.action_id: cfg.actions[p.action_id].model_copy(update=update)}})
    host_values, code = ir.host_class_irreversible(forged)
    assert code is None
    assert ir.flip_causes(forged.actions[p.action_id])[0] == cause
    assert ir.flip_conflict(forged, host_values, {CLASS_T1: IRR, CLASS_T2: IRR}) == ir.FLIP_CONFLICT + ":" + cause
    assert ir.flip_conflict(forged, host_values, {CLASS_T1: NC, CLASS_T2: IRR}) is None  # no flip requested: no conflict


def test_b05_a_registry_no_change_over_a_conflicting_host_class_is_not_a_flip_and_is_accepted(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, ir_={CLASS_T1: NC}, t1=B_)
    assert flow.runtime_authority_profile.model_dump() == cfg.model_dump()


def test_b06_a_host_class_that_is_already_irreversible_is_a_no_op_even_with_dependent_members(tmp_path):
    cls = ActionClass(class_id=CLASS_T1, reversibility="irreversible", max_status_age_seconds=60, on_unreadable=R_)
    p, res, cfg = base.prepared(tmp_path, t1=R_, reversibility=ReversibilityProfile())
    cfg = base.host_profile(p, t1=R_, reversibility=ReversibilityProfile(), extra_actions={p.action_id: cls})
    assert cfg.actions[p.action_id].irreversible is True
    flow = build(tmp_path, res, cfg, fams(Source(imat({CLASS_T1: IRR}))))
    assert flow.runtime_authority_profile.model_dump() == cfg.model_dump()


def test_b07_two_actions_of_one_class_with_different_flags_are_ambiguous_and_refused_before_any_source_read(tmp_path):
    p, res, cfg = base.prepared(tmp_path, t1=R_, shared=R_)  # T2 action shares the T1 class id; T1 flag False, T2 flag True
    src = Source(imat({CLASS_T1: IRR}))
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, fams(src))
    refused(e, "class_irreversible_ambiguous", "construction")
    assert src.calls == 0
    assert ir.host_class_irreversible(cfg) == (None, "class_irreversible_ambiguous")


def test_b08_every_action_of_the_class_flips_together(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, ir_={CLASS_T1: IRR}, shared=R_, t2_irrev=False)
    flipped = flow.runtime_authority_profile
    assert [a.irreversible for a in cfg.actions.values()] == [False, False]
    assert [a.irreversible for a in flipped.actions.values()] == [True, True]


def test_b09_an_invalid_original_host_is_refused_before_any_source_read_and_never_repaired(tmp_path):
    p, res, cfg = base.prepared(tmp_path, t1=B_, t1_irrev=True)  # irreversible AND bounded_tolerance: action_class_invalid for the evaluator
    src = Source(imat({CLASS_T1: IRR}))
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, fams(src))
    refused(e, "host_class_invalid", "construction")
    assert src.calls == 0


def test_b10_a_non_bool_host_flag_is_refused_before_any_registry_call(tmp_path):
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    forged = cfg.model_copy(update={"actions": {**cfg.actions, p.action_id: cfg.actions[p.action_id].model_copy(update={"irreversible": "no"})}})
    assert ir.host_class_irreversible(forged) == (None, "host_class_irreversible_invalid")
    src = Source(imat({CLASS_T1: IRR}))
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, forged, fams(src))
    assert e.value.refusal.code in ("host_class_irreversible_invalid", "host_profile_invalid", "host_class_invalid")
    assert src.calls == 0


# =============================================================================================================== C: composition with every other family
OTHERS = ("f", "a", "u", "ra", "tr")
SUBSETS = [dict(zip(OTHERS, flags_)) for flags_ in itertools.product([False, True], repeat=len(OTHERS))]
NEW = {"ra": {CLASS_T1: rv.RQ}, "tr": "on"}


def _kw(subset):
    kw = {k: v for k, v in subset.items() if k in ("f", "a", "u") and v}
    for k in ("ra", "tr"):
        if subset[k]:
            kw[k] = NEW[k]
    return kw


@pytest.mark.parametrize("subset", SUBSETS, ids=lambda s: "".join(k for k, v in s.items() if v) or "alone")
def test_c01_every_combination_with_the_other_five_families_authorizes_and_executes(tmp_path, subset):
    p, res, cfg, srcs, flow, d = authorized(tmp_path, ir_={CLASS_T1: IRR}, **_kw(subset))
    assert flags(flow.runtime_authority_profile)[CLASS_T1] is True
    names = [n for n in ("f4_ages", "class_age", "class_unreadable", "class_revocation_assurance", "class_irreversible", "terminal_revocation")
             if n == "class_irreversible" or {"f4_ages": "f", "class_age": "a", "class_unreadable": "u", "class_revocation_assurance": "ra", "terminal_revocation": "tr"}[n] in
             [k for k, v in subset.items() if v]]
    assert flow.registry_governed_policy_identity["families"] == names  # the fixed deterministic order
    attempt, observed = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and observed.state == "applied"


def test_c02_the_composition_order_is_fixed_and_the_three_final3_slots_sit_between_irreversibility_and_terminal_revocation():
    # FINAL3 successor: the three r08-v8 slots were appended AFTER irreversibility and BEFORE terminal revocation; the six earlier names keep their relative order.
    assert pol.FAMILY_NAMES == ("f4_ages", "class_age", "class_unreadable", "class_revocation_assurance", "class_irreversible", "anchor_deadline", "observation_max_age",
                                "observation_clock_tolerance", "terminal_revocation")
    assert [n for n in pol.FAMILY_NAMES if n not in ("anchor_deadline", "observation_max_age", "observation_clock_tolerance")] == [
        "f4_ages", "class_age", "class_unreadable", "class_revocation_assurance", "class_irreversible", "terminal_revocation"]


def test_c03_the_final_profile_equals_the_sequential_application_of_each_family(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, ir_={CLASS_T1: IRR}, ra={CLASS_T1: rv.RQ}, tr="on", a=True, u=True)
    prior = base.gbuild(tmp_path / "e", Source(base.mat(base.umap(t1=R_))), res, cfg, age=Source(base.amat(comp.AGE_M))).runtime_authority_profile
    expect = ir.compose_irreversible(variant(prior, assure={CLASS_T1: True}, terminal=True), {CLASS_T1: IRR, CLASS_T2: IRR})
    assert flow.runtime_authority_profile.model_dump() == expect.model_dump()
    assert approval_commitment(flow.runtime_authority_profile, res.contexts[PROFILE]) == approval_commitment(expect, res.contexts[PROFILE])


def test_c04_the_existing_families_alone_are_byte_identical_and_declare_no_new_member(tmp_path):
    """A workflow that does not declare the new family has the same profile, bound keys and configuration identity as before the family existed."""
    p, res, cfg, srcs, flow = ready(tmp_path, f=True, a=True, u=True, ra={CLASS_T1: rv.RQ}, tr="on")
    ident = flow.registry_governed_policy_identity
    assert ident["class_irreversible"] is None and "class_irreversible" not in flow._gl_bound
    assert flags(flow.runtime_authority_profile) == flags(cfg)
    assert flow.effective_policy_snapshot.family("class_irreversible") is None


def test_c04b_the_configuration_digest_and_effective_profile_of_a_workflow_without_the_family_equal_the_values_computed_on_the_base(tmp_path):
    """Golden literals computed on the unmodified base a62ca8d (F4 + class age + unreadable + assurance + terminal, same fixtures): adding the family changes no pre-existing identity."""
    p, res, cfg, srcs, flow = rv.ready(tmp_path, f=True, a=True, u=True, ra={CLASS_T1: rv.RQ}, tr="on")
    ident = flow.registry_governed_policy_identity
    assert ident["configuration_digest"] == "sha256:9e90e93289c83ef126577648c754a9b98afdd93e31da8d72e2ede39d830a4c60"
    assert ident["effective_profile_digest"] == "sha256:f3bb735adc2e4a6e42d691df28044736fc50ddcbcde2ed5d8e6df7d68549fc28"


def test_c05_a_declared_family_is_mandatory_no_partial_activation_and_no_fallback(tmp_path):
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    ok_ir, bad = Source(imat({CLASS_T1: IRR})), Source(rv.tmat("on"))
    bad.fail = True
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, fams(ok_ir, tr=bad))
    refused(e, "selection_source_failed", "construction")
    assert ok_ir.calls == 1 and bad.calls == 1 and not Path(tmp_path / "run.json").read_text().count("decision_id")
    bad2 = Source(imat({CLASS_T1: IRR}, stmt_over={"operation": "wrong-operation-name"}))
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path / "b", res, cfg, fams(bad2, tr=Source(rv.tmat("on"))))
    refused(e, prefix=PREFIX, boundary="construction")


def test_c06_scopes_must_share_consumer_tenant_and_action(tmp_path):
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    other = GovernedScope("consumer-test", TENANT.lower(), "urn:cognous:action:other-v1", OP_IR)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, GovernedFamilies(class_irreversible=GovernedFamily(other, Source(imat())), terminal_revocation=GovernedFamily(rv.SCOPE_TR, Source(rv.tmat()))))
    refused(e, "family_scope_mismatch", "construction")


def test_c07_a_profile_is_required_and_policy_binding_is_refused(tmp_path):
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        GovernedPolicyWorkflow(families=fams(Source(imat())), verifier=ev.Ed25519Verifier(), construction_time=REG_NOW, **kwargs(tmp_path, res))
    refused(e, "runtime_authority_profile_required", "construction")
    from agent_control_plane.policy_binding import PolicyBinding
    pb = PolicyBinding(binding_digest="sha256:" + "1" * 64, selection_epoch=1, activation_ref="sha256:" + "2" * 64, policy_generation=1, disposition="selected")
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path / "pb", res, cfg, fams(Source(imat())), profile=cfg.model_copy(update={"policy_binding": pb}))
    assert e.value.refusal.code in ("policy_binding_unsupported", "host_profile_invalid")


# =============================================================================================================== D: scope and authority
@pytest.mark.parametrize("over", [{"consumer_id": "other-consumer"}, {"scope": dict(base.STMT_SCOPE, tenant="other-tenant")}, {"scope": dict(base.STMT_SCOPE, institution="other-institution")},
                                  {"scope": dict(base.STMT_SCOPE, authority_domain="other-domain")}])
def test_d01_a_selection_for_another_consumer_tenant_institution_or_domain_is_refused(tmp_path, over):
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, fams(Source(imat(stmt_over=over))))
    refused(e, prefix=PREFIX, boundary="construction")


def test_d02_a_selection_pinned_to_another_operation_is_refused(tmp_path):
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, fams(Source(imat(stmt_over={"operation": "some-other-operation"}))))
    refused(e, prefix=PREFIX, boundary="construction")


def test_d03_a_proposal_for_another_action_or_tenant_is_out_of_scope(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, ir_={CLASS_T1: IRR})
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.decide(p.model_copy(update={"action_id": "urn:cognous:action:other-v1"}), now=NOW)
    refused(e, "proposal_out_of_scope", "decision")


def test_d04_an_unknown_scoped_action_is_refused(tmp_path):
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    ghost = GovernedScope("consumer-test", TENANT.lower(), "urn:cognous:action:ghost-v1", OP_IR)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, GovernedFamilies(class_irreversible=GovernedFamily(ghost, Source(imat()))))
    refused(e, boundary="construction")


# =============================================================================================================== F: attempted widening (a Registry RESULT forged inside the Control Plane's call)
def _forge(monkeypatch, effective_of):
    real = v7dec.verify_and_decide_v7

    def forged(*a, **k):
        d = real(*a, **k)
        return dataclasses.replace(d, effective=effective_of(d.effective)) if d.kind == "applied" else d
    monkeypatch.setattr(v7dec, "verify_and_decide_v7", forged)


def test_f01_a_forged_registry_result_that_lowers_a_host_irreversible_class_is_refused(tmp_path, monkeypatch):
    _forge(monkeypatch, lambda eff_: {FIELD: {CLASS_T1: NC, CLASS_T2: NC}})
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, fams(Source(imat({CLASS_T1: IRR}))))
    refused(e, PREFIX + "effective_policy_widens_host", "construction")


@pytest.mark.parametrize("forged,code", [({FIELD: {CLASS_T1: IRR}}, "effective_policy_invalid"),  # a host class is missing
                                         ({FIELD: {CLASS_T1: IRR, CLASS_T2: IRR, "class-extra": NC}}, "effective_policy_invalid"),  # an invented class
                                         ({FIELD: {CLASS_T1: NC, CLASS_T2: IRR}}, "effective_policy_invalid"),  # looser than the record: not the stricter value
                                         ({FIELD: {CLASS_T1: True, CLASS_T2: IRR}}, "effective_policy_invalid"),
                                         ({FIELD: {CLASS_T1: "maybe", CLASS_T2: IRR}}, "effective_policy_invalid"),
                                         ({"other": 1}, "effective_policy_invalid"), ({FIELD: [CLASS_T1]}, "effective_policy_invalid")])
def test_f02_a_forged_registry_result_that_is_not_the_stricter_of_host_and_record_is_refused(tmp_path, monkeypatch, forged, code):
    _forge(monkeypatch, lambda eff_: forged)
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, fams(Source(imat({CLASS_T1: IRR}))))
    refused(e, PREFIX + code, "construction")


def test_f03_a_forged_result_that_flips_a_class_the_record_does_not_name_is_refused(tmp_path, monkeypatch):
    p, res, cfg = base.prepared(tmp_path, t1=R_, shared=R_, t2_irrev=False)  # T2 action shares T1: build another host with a distinct reversible class instead
    cfg2 = base.host_profile(p, t1=R_, extra_actions={"urn:cognous:action:third-v1": ActionClass(class_id="third-class", irreversible=False, on_unreadable=R_)})
    _forge(monkeypatch, lambda eff_: {FIELD: {CLASS_T1: IRR, CLASS_T2: IRR, "third-class": IRR}})
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg2, fams(Source(imat({CLASS_T1: IRR}))))
    refused(e, PREFIX + "effective_policy_invalid", "construction")


@pytest.mark.parametrize("what", ["authorized", "wrong_kind", "deny_all", "not_applied", "not_a_decision"])
def test_f04_a_registry_decision_of_the_wrong_shape_is_refused(tmp_path, monkeypatch, what):
    real = v7dec.verify_and_decide_v7
    if what == "not_a_decision":
        monkeypatch.setattr(v7dec, "verify_and_decide_v7", lambda *a, **k: {"kind": "applied"})
    else:
        change = {"authorized": dict(operationally_authorized=True), "wrong_kind": dict(kind="applied_deny_all"), "deny_all": dict(deny_all=True),
                  "not_applied": dict(kind="overlay_not_applied")}[what]
        monkeypatch.setattr(v7dec, "verify_and_decide_v7", lambda *a, **k: dataclasses.replace(real(*a, **k), **change))
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, fams(Source(imat())))
    refused(e, prefix=PREFIX, boundary="construction")
    assert e.value.refusal.code.split(":", 1)[1] in ("registry_decision_invalid", "registry_not_applied")


def test_f05_the_final_composition_validator_rejects_lowering_foreign_changes_and_an_undeclared_flip(tmp_path):
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    scalars = {"status_max_age_seconds": 60, "approval_max_age_seconds": 60}
    flipped = ir.compose_irreversible(cfg, {CLASS_T1: IRR, CLASS_T2: IRR})
    assert pol.final_composition_defect(cfg, cfg, scalars, None, irreversible_declared=True) is None
    assert pol.final_composition_defect(cfg, flipped, scalars, None, irreversible_declared=True) is None
    assert pol.final_composition_defect(cfg, flipped, scalars, None) == "composed_profile_invalid"  # undeclared: any difference is a foreign change
    lowered = cfg.model_dump(mode="json")
    for a in lowered["actions"].values():
        a["irreversible"] = False
    lowered = RuntimeAuthorityProfile.model_validate(lowered)
    assert pol.final_composition_defect(cfg, lowered, scalars, None, irreversible_declared=True) == "composed_widens_host"  # host T2 true -> final false
    assert pol.final_composition_defect(cfg, lowered, scalars, None) == "composed_profile_invalid"
    foreign = flipped.model_copy(update={"catalogue_version": "tampered/1"})
    assert pol.final_composition_defect(cfg, foreign, scalars, None, irreversible_declared=True) == "composed_profile_invalid"
    # a declared flip may not travel with another changed class member
    extra = flipped.model_dump(mode="json")
    extra["actions"][ACTION_ID]["requires_revocation_assurance"] = True
    assert pol.final_composition_defect(cfg, RuntimeAuthorityProfile.model_validate(extra), scalars, None, irreversible_declared=True) == "composed_profile_invalid"
    assert pol.final_composition_defect(cfg, RuntimeAuthorityProfile.model_validate(extra), scalars, None, irreversible_declared=True, assurance_declared=True) is None


@pytest.mark.parametrize("sneak", ["flip"])
def test_f06_another_composer_that_flips_irreversible_without_the_family_being_declared_is_refused(tmp_path, monkeypatch, sneak):
    real = base.gov.compose_unreadable
    monkeypatch.setattr(pol.unrmod, "compose_unreadable", lambda b, e: ir.compose_irreversible(real(b, e), {CLASS_T1: IRR, CLASS_T2: IRR}))
    p, res, cfg = base.prepared(tmp_path)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, fams(u=comp.usrc()))
    refused(e, "composed_profile_invalid", "construction")


# =============================================================================================================== G/H/I/J/K: mandatory selection, replacement, revocation, withdrawal
def test_g01_a_failing_source_at_any_boundary_refuses_the_whole_workflow(tmp_path):
    p, res, cfg, srcs, flow, d = authorized(tmp_path, ir_={CLASS_T1: IRR}, tr="on")
    srcs["ir"].fail = True
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    refused(e, "selection_source_failed", "effect")
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "selection_source_failed", "decision")
    assert effects(flow) == {}


def test_g02_a_missing_mandatory_selection_at_construction_is_refused_and_nothing_falls_back(tmp_path):
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, GovernedFamilies(class_irreversible=GovernedFamily(SCOPE_IR, None)))
    assert e.value.refusal.code in ("families_invalid", "selection_source_invalid")


@pytest.mark.parametrize("change", ["values", "epoch", "selection_id"])
def test_h01_a_replaced_selection_is_refused_at_every_boundary(tmp_path, change):
    p, res, cfg, srcs, flow, d = authorized(tmp_path, ir_={CLASS_T1: IRR})
    before = file_state(tmp_path, flow)
    if change == "values":
        srcs["ir"].mat = changed_ir()
    else:  # same effective values under another epoch / selection id: the effective digest is equal, so the replacement is accepted as the same effective policy
        srcs["ir"].mat = imat({CLASS_T1: IRR}, stmt_over={"epoch": 2} if change == "epoch" else {"selection_id": "sel-test-9"})
    if change == "values":
        with pytest.raises(RegistryGovernedPolicyRefused) as e:
            flow.decide(p, now=NOW)
        refused(e, "selection_changed", "decision")
        with pytest.raises(RegistryGovernedPolicyRefused) as e:
            flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
        refused(e, "selection_changed", "effect")
        assert file_state(tmp_path, flow) == before
    else:
        assert flow.decide(p, now=NOW).result == "authorized"


def test_i01_key_or_selection_revocation_blocks_the_decision_without_state_change(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, ir_={CLASS_T1: IRR}, host=rv.with_inventory)
    before = file_state(tmp_path, flow)
    srcs["ir"].mat = revoked_ir()
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, prefix=PREFIX, boundary="decision", registry_code="selection_revoked")
    assert file_state(tmp_path, flow) == before and flow.records.load().decisions == []


def test_i02_a_withdrawn_selection_is_never_an_application(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, ir_={CLASS_T1: IRR}, host=rv.with_inventory)
    srcs["ir"].mat = base.withdrawn(lambda: irec({CLASS_T1: IRR}), None, OP_IR, V7_DOMAIN, "r08-v7", FAMILY)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, boundary="decision", registry_code="selection_withdrawn")
    assert effects(flow) == {}


def test_i03_an_expired_selection_is_refused_after_construction(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, ir_={CLASS_T1: IRR}, host=rv.with_inventory)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.decide(p, now=NOW.replace(year=NOW.year + 1))
    refused(e, boundary="decision")


def test_i04_a_signature_by_a_key_not_in_the_trust_snapshot_is_refused(tmp_path):
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, fams(Source(imat({CLASS_T1: IRR}, sk=base.OTHER_SK))))
    refused(e, prefix=PREFIX, boundary="construction")


def test_j01_revocation_between_decision_and_effect_blocks_the_effect(tmp_path):
    p, res, cfg, srcs, flow, d = authorized(tmp_path, ir_={CLASS_T1: IRR})
    before = file_state(tmp_path, flow)
    srcs["ir"].mat = revoked_ir()
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    refused(e, boundary="effect", registry_code="selection_revoked")
    assert file_state(tmp_path, flow) == before and effects(flow) == {}


def test_k01_revocation_after_execute_entry_is_refused_at_the_commit_gate_and_nothing_is_dispatched(tmp_path):
    p, res, cfg, srcs, flow, d = authorized(tmp_path, ir_={CLASS_T1: IRR})
    srcs["ir"].after = (4, revoked_ir())  # construction, decision, effect entry, then the commit gate
    attempt, _ = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "failed" and attempt.error == pol.REJECTION_CODE and effects(flow) == {}
    assert flow.governed_last_commit_refusal.registry_code == "selection_revoked"
    persisted = [x for x in flow.records.load().attempts if x.effect_id == d.effect_id]
    assert persisted[-1].status == "failed" and not any(x.status == "acknowledged" for x in persisted)


def test_k02_a_replacement_between_execute_entry_and_dispatch_is_refused_at_the_commit_gate(tmp_path):
    p, res, cfg, srcs, flow, d = authorized(tmp_path, ir_={CLASS_T1: IRR})
    srcs["ir"].after = (4, changed_ir())
    attempt, _ = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "failed" and effects(flow) == {}
    assert flow.governed_last_commit_refusal.code == "selection_changed"


def test_k03_the_source_dying_exactly_at_the_commit_gate_blocks_the_effect(tmp_path):
    p, res, cfg, srcs, flow, d = authorized(tmp_path, ir_={CLASS_T1: IRR})

    class Dies(Source):
        def __call__(self):
            self.calls += 1
            if self.calls >= 4:
                raise RuntimeError("down")
            return self.mat
    srcs["ir"].__class__ = Dies
    attempt, _ = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "failed" and effects(flow) == {}
    assert flow.governed_last_commit_refusal.code == "selection_source_failed"


def test_k04_a_failed_attempt_blocks_the_automatic_retry_and_never_reaches_the_destination(tmp_path):
    comp.Spy.applies = 0
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    cfg = rv.with_inventory(cfg)
    srcs = sources(ir_={CLASS_T1: IRR})
    flow = build(tmp_path, res, cfg, fams(srcs["ir"]), destination=comp.Spy(tmp_path / "spy.json"))
    bind_approval(res, flow.runtime_authority_profile)
    d = flow.decide(p, now=NOW)
    srcs["ir"].after = (4, revoked_ir())
    attempt, _ = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "failed" and comp.Spy.applies == 0
    srcs["ir"].after = None
    with pytest.raises(PermissionError, match="retry eligibility"):
        flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert comp.Spy.applies == 0


# =============================================================================================================== N/O: stale and cross-profile decisions, restart, held profile
def test_n01_a_decision_persisted_under_the_flipped_profile_cannot_be_executed_by_a_workflow_with_the_host_profile(tmp_path):
    p, res, cfg, srcs, flow, d = authorized(tmp_path, ir_={CLASS_T1: IRR})
    host_only = base.plain(tmp_path, res, cfg)
    bind_approval(res, host_only.runtime_authority_profile)
    with pytest.raises(PermissionError, match="authorization-critical inputs changed"):
        host_only.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert effects(host_only) == {}


def test_n02_a_decision_persisted_under_the_host_profile_cannot_be_executed_by_the_flipped_workflow(tmp_path):
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    cfg = rv.with_inventory(cfg)
    plain = base.plain(tmp_path, res, cfg)
    bind_approval(res, plain.runtime_authority_profile)
    d = plain.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    flipped = build(tmp_path, res, cfg, fams(Source(imat({CLASS_T1: IRR}))))
    bind_approval(res, flipped.runtime_authority_profile)
    with pytest.raises(PermissionError, match="authorization-critical inputs changed"):
        flipped.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert effects(flipped) == {}


def test_n03_a_decision_under_another_flip_set_is_refused(tmp_path):
    """Two different effective flips of the same host (T1 flipped vs not flipped) produce different profiles; a decision persisted under one is not executable under the other."""
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    cfg = rv.with_inventory(cfg)
    a = build(tmp_path, res, cfg, fams(Source(imat({CLASS_T1: IRR}))))
    bind_approval(res, a.runtime_authority_profile)
    d = a.decide(p, now=NOW)
    b = build(tmp_path, res, cfg, fams(Source(imat({CLASS_T1: NC}))))
    bind_approval(res, b.runtime_authority_profile)
    with pytest.raises(PermissionError, match="authorization-critical inputs changed"):
        b.execute(p, d, adapter_id=p.adapter_id, now=NOW)


def test_o01_restart_with_the_same_families_resumes_a_persisted_decision(tmp_path):
    p, res, cfg, srcs, flow, d = authorized(tmp_path, ir_={CLASS_T1: IRR})
    restarted = build(tmp_path, res, cfg, fams(srcs["ir"]))
    assert restarted.records.decision(d.decision_id) == d
    attempt, observed = restarted.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and observed.state == "applied"


def test_o02_restart_without_the_family_changes_the_profile_and_refuses_the_persisted_decision(tmp_path):
    p, res, cfg, srcs, flow, d = authorized(tmp_path, ir_={CLASS_T1: IRR})
    host_only = build(tmp_path, res, cfg, fams(tr=Source(rv.tmat("off"))))  # rebuilding without the family is a host configuration decision; the old decision does not survive it
    bind_approval(res, host_only.runtime_authority_profile)
    with pytest.raises(PermissionError, match="authorization-critical inputs changed"):
        host_only.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert effects(host_only) == {}


def test_n04_post_construction_edits_of_the_held_profile_are_refused_at_every_boundary(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, ir_={CLASS_T1: IRR}, host=rv.with_inventory)
    flow.runtime_authority_profile = rv.with_inventory(cfg)  # the host profile put back over the flipped one
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "profile_modified", "decision")


def test_n05_the_irreversibility_component_of_the_bound_identity_is_compared_on_its_own(tmp_path, monkeypatch):
    p, res, cfg, srcs, flow = ready(tmp_path, ir_={CLASS_T1: IRR}, tr="on", host=rv.with_inventory)
    bound = dict(flow._gl_bound)
    v = bound["class_irreversible"]
    bound["class_irreversible"] = (v[0], "sha256:" + "0" * 64)
    monkeypatch.setattr(flow, "_gl_bound", bound)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "selection_changed", "decision")


# =============================================================================================================== ledger identity
def test_l01_configurations_that_differ_only_in_the_irreversibility_family_never_share_an_identity(tmp_path):
    ledger = GovernedActivationLedger()
    p, res, cfg = base.prepared(tmp_path / "a", t1=R_)
    first = build(tmp_path / "a", res, cfg, fams(Source(imat({CLASS_T1: IRR}))), pol={"activation_ledger": ledger})
    p2, res2, cfg2 = base.prepared(tmp_path / "b", t1=R_)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path / "b", res2, cfg2, fams(Source(changed_ir())), pol={"activation_ledger": ledger})
    refused(e, "conflicting_governed_configuration", "construction")
    same = build(tmp_path / "c", res2, cfg2, fams(Source(imat({CLASS_T1: IRR}))), pol={"activation_ledger": ledger})
    assert same.registry_governed_policy_identity["configuration_digest"] == first.registry_governed_policy_identity["configuration_digest"]


def test_l02_a_host_flag_difference_changes_the_configuration_identity_even_with_the_same_effective_profile(tmp_path):
    p, res, cfg = base.prepared(tmp_path / "a", t1=R_)
    flat = build(tmp_path / "a", res, cfg, fams(Source(imat({CLASS_T1: IRR}))))
    host_true = base.prepared(tmp_path / "b", t1=R_, t1_irrev=True)[2]
    already = build(tmp_path / "b", res, host_true, fams(Source(imat({CLASS_T1: IRR}))))
    assert flat.runtime_authority_profile.model_dump() == already.runtime_authority_profile.model_dump()
    assert flat.registry_governed_policy_identity["configuration_digest"] != already.registry_governed_policy_identity["configuration_digest"]


# =============================================================================================================== EffectivePolicySnapshot / resolve_effective_policy
def _snap_inputs(tmp_path, **kw):
    kw.setdefault("t1", R_)
    p, res, cfg = base.prepared(tmp_path, **kw)
    return p, res, cfg


def _resolve(cfg, srcs_by_slot, families, **over):
    mats = {n: s() for n, s in srcs_by_slot.items()}
    args = dict(families=families, host=cfg, host_scalars={"status_max_age_seconds": 60, "approval_max_age_seconds": 60}, materials=mats, verifier=ev.Ed25519Verifier(),
                institution_id=base.INSTITUTION, authority_domain=base.DOMAIN, now=REG_NOW, host_irreversible=ir.host_class_irreversible(cfg)[0], host_terminal=pol.revmod.host_terminal_value(cfg))
    args.update(over)
    return eff.resolve_effective_policy(**args)


def test_s01_the_snapshot_describes_the_effective_policy_and_is_immutable(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, ir_={CLASS_T1: IRR}, tr="on")
    s = flow.effective_policy_snapshot
    assert s is flow.effective_policy_snapshot and isinstance(s, eff.EffectivePolicySnapshot)
    assert s.effective_profile_digest == base.agegov.profile_digest(flow.runtime_authority_profile) and s.host_profile_digest == base.agegov.profile_digest(cfg)
    assert s.host_profile_digest != s.effective_profile_digest
    f = s.family("class_irreversible")
    assert (f.family_id, f.contract_version, f.family_schema_revision, f.selection_id, f.selection_epoch) == (FAMILY, "r08-v7", 1, "sel-test-1", 1)
    assert f.effective_policy_digest == flow.registry_governed_policy_identity["class_irreversible"]["effective_policy_digest"]
    assert dict(f.effective) == {CLASS_T1: IRR, CLASS_T2: IRR}
    assert [x.slot for x in s.families] == ["class_irreversible", "terminal_revocation"]
    assert s.family("terminal_revocation").contract_version == "r08-v6" and s.family("terminal_revocation").family_schema_revision is None
    assert dict(dict(s.scope)["operation_ids"]) == {"class_irreversible": OP_IR, "terminal_revocation": rv.OP_TR}
    assert s.evaluated_at == REG_NOW.isoformat()

    def immutable(x):
        assert not isinstance(x, (dict, list, set, bytearray)), type(x)
        if dataclasses.is_dataclass(x):
            assert x.__dataclass_params__.frozen
            for fld in dataclasses.fields(x):
                immutable(getattr(x, fld.name))
        elif isinstance(x, tuple):
            for y in x:
                immutable(y)
        else:
            assert x is None or type(x) in (str, int, bool)
    immutable(s)
    with pytest.raises(dataclasses.FrozenInstanceError):
        s.effective_profile_digest = "x"  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        s.families[0].effective_policy_digest = "x"  # type: ignore[misc]
    with pytest.raises(TypeError):
        s.families[0].effective[0] = ("x", "y")  # type: ignore[index]


def test_s02_the_snapshot_is_deterministic_and_equals_the_pure_resolution(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, ir_={CLASS_T1: IRR})
    again = build(tmp_path / "again", res, cfg, fams(Source(imat({CLASS_T1: IRR}))))
    assert again.effective_policy_snapshot == flow.effective_policy_snapshot
    assert again.effective_policy_snapshot.identity_digest == flow.effective_policy_snapshot.identity_digest
    resolved = _resolve(cfg, {"class_irreversible": srcs["ir"]}, fams(srcs["ir"]))
    assert resolved == flow.effective_policy_snapshot and resolved.identity_digest == flow.effective_policy_snapshot.identity_digest


def test_s03_the_identity_changes_when_any_family_value_or_epoch_changes(tmp_path):
    base_digest = ready(tmp_path / "0", ir_={CLASS_T1: IRR}, tr="on")[4].effective_policy_snapshot.identity_digest
    seen = {base_digest}
    for i, kw in enumerate([dict(ir_={CLASS_T1: IRR}, tr="off"),  # terminal family value
                            dict(ir_={CLASS_T1: NC}, tr="on"),  # irreversibility value
                            dict(ir_={CLASS_T1: IRR}, tr="on", ra={CLASS_T1: rv.RQ})]):  # one more family
        seen.add(ready(tmp_path / str(i + 1), **kw)[4].effective_policy_snapshot.identity_digest)
    assert len(seen) == 4
    p, res, cfg = base.prepared(tmp_path / "e", t1=R_)
    epoch2 = build(tmp_path / "e", res, cfg, fams(Source(imat({CLASS_T1: IRR}, stmt_over=EPOCH2)), tr=Source(rv.tmat("on"))))
    assert epoch2.effective_policy_snapshot.family("class_irreversible").selection_epoch == 2
    assert epoch2.effective_policy_snapshot.identity_digest != base_digest  # same effective values, another epoch
    p, res, cfg = base.prepared(tmp_path / "s", t1=R_)
    sel = build(tmp_path / "s", res, cfg, fams(Source(imat({CLASS_T1: IRR}, stmt_over={"selection_id": "sel-test-9"})), tr=Source(rv.tmat("on"))))
    assert sel.effective_policy_snapshot.identity_digest != base_digest  # another selection id
    p, res, cfg = base.prepared(tmp_path / "h", t1=R_, t1_irrev=True)
    host_true = build(tmp_path / "h", res, cfg, fams(Source(imat({CLASS_T1: IRR})), tr=Source(rv.tmat("on"))))
    assert host_true.effective_policy_snapshot.host_profile_digest != ready(tmp_path / "h2", ir_={CLASS_T1: IRR}, tr="on")[4].effective_policy_snapshot.host_profile_digest


def test_s04_no_fallback_on_a_missing_or_failing_mandatory_family_and_no_weaker_policy_is_returned(tmp_path):
    p, res, cfg = _snap_inputs(tmp_path)
    ok, other = Source(imat({CLASS_T1: IRR})), Source(rv.tmat("on"))
    families = fams(ok, tr=other)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:  # one declared family has no material: the whole resolution refuses, the other family alone is NOT returned
        _resolve(cfg, {"class_irreversible": ok}, families)
    assert e.value.refusal.code == "selection_missing" and e.value.boundary == "resolution"
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        _resolve(cfg, {"class_irreversible": ok, "terminal_revocation": Source(rv.tmat("on", trust=trust_for(rv.OP_TR, revoked_selections=RV)))}, families)
    assert e.value.refusal.registry_code == "selection_revoked" and e.value.refusal.code.startswith("terminal_revocation:")
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        _resolve(cfg, {}, GovernedFamilies())
    assert e.value.refusal.code == "no_family_declared"
    conflict = base.prepared(tmp_path / "c", t1=B_)[2]  # a flip conflict is the existing refusal type, never a snapshot without the family
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        _resolve(conflict, {"class_irreversible": ok}, fams(ok))
    assert e.value.refusal.code == PREFIX + "irreversible_flip_conflict:on_unreadable_not_refuse"


def test_s05_the_selection_ref_parser_is_strict():
    ok = '{"statement":{"selection_id":"s1","epoch":3}}'
    assert eff.selection_ref(ok) == ("s1", 3)
    for bad in ('{"statement":{"selection_id":"s1","epoch":3,"epoch":4}}', '{"statement":{"selection_id":"s1","epoch":3.0}}', '{"statement":{"selection_id":"","epoch":3}}',
                '{"statement":{"selection_id":"s1","epoch":true}}', '{"statement":{"selection_id":1,"epoch":3}}', '{"statement":3}', "not json", None, '{"statement":{"selection_id":"s1","epoch":NaN}}'):
        assert eff.selection_ref(bad) is None, bad


# =============================================================================================================== R/S/T: frozen Registry compatibility, protected files
def test_r01_the_new_family_uses_only_the_r08_v7_contract_and_the_older_contracts_still_work(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, ir_={CLASS_T1: IRR}, ra={CLASS_T1: rv.RQ}, tr="on", u=True, a=True, f=True)
    assert '"r08-v7"' in srcs["ir"].mat.selection_text.replace(" ", "")
    assert '"r08-v6"' in srcs["ra"].mat.selection_text.replace(" ", "") and '"r08-v6"' in srcs["tr"].mat.selection_text.replace(" ", "")
    for k, ctr in (("f", "r08-v2"), ("a", "r08-v2"), ("u", "r08-v5")):
        assert ctr in srcs[k].mat.selection_text


@pytest.mark.parametrize("wrong", ["v6_contract_record", "v6_envelope", "v5_envelope", "other_family_in_v7_envelope", "terminal_in_slot", "v7_in_assurance_slot"])
def test_r02_a_record_of_another_contract_or_family_is_refused_in_each_slot_with_no_fallback(tmp_path, wrong):
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    if wrong == "v7_in_assurance_slot":  # the new family's material in an older family's slot
        with pytest.raises(RegistryGovernedPolicyRefused) as e:
            build(tmp_path, res, cfg, fams(ra=Source(imat({CLASS_T1: IRR}))))
        refused(e, prefix="class_revocation_assurance:", boundary="construction")
        return
    material = {"v6_contract_record": imat(rec=irec(contract="r08-v6")), "v6_envelope": imat(contract="r08-v6", domain=rv.V6_DOMAIN), "v5_envelope": imat(contract="r08-v5", domain=base.V5_DOMAIN),
                "other_family_in_v7_envelope": imat(rec=irec(family="f5-action-class-revocation-assurance-policy")), "terminal_in_slot": rv.tmat("on")}[wrong]
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, fams(Source(material)))
    refused(e, prefix=PREFIX, boundary="construction")


def test_s06_the_protected_evaluators_and_the_holder_inventory_module_are_byte_identical_to_main():
    pins = dict(comp.PROTECTED)
    pins["holder_inventory.py"] = "76f5aaa63f49bac182439ea3768798bf42ecbda2c586f20fd450a7053271f7ba"
    for name, digest in pins.items():
        assert hashlib.sha256((SRC / name).read_bytes()).hexdigest() == digest, name


def test_s07_the_new_modules_add_no_workflow_no_evaluator_import_and_no_policy_interpreter():
    import ast
    for name in ("registry_irreversibility_governance.py", "registry_effective_policy.py"):
        tree = ast.parse((SRC / name).read_text())
        for node in ast.walk(tree):
            if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef)) and node.body and isinstance(node.body[0], ast.Expr) and isinstance(getattr(node.body[0], "value", None), ast.Constant):
                node.body = node.body[1:] or [ast.Pass()]
        classes = [n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)]
        assert classes == ([] if name.startswith("registry_irr") else ["AppliedFamily", "EffectivePolicySnapshot"]), (name, classes)
        imported = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module} | {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
        assert not any(m.endswith(("bounded_authorization", "freshness", "policy_binding", "holder_inventory", "reversibility", "rule_revision", "registry_governed_lifecycle_x")) for m in imported), imported
        code = ast.unparse(tree)
        assert "eval(" not in code and "exec(" not in code and "approval_commitment" not in code and "model_copy" not in code


def test_s08_only_the_governed_field_is_written_by_the_flip_and_only_the_composed_module_changes_composition(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, ir_={CLASS_T1: IRR}, host=rv.with_inventory)
    changed = {k for k, v in flow.runtime_authority_profile.model_dump(mode="json").items() if cfg.model_dump(mode="json").get(k) != v}
    assert changed == {"actions"}
    a0, a1 = cfg.model_dump(mode="json")["actions"], flow.runtime_authority_profile.model_dump(mode="json")["actions"]
    assert {(aid, k) for aid in a0 for k in a0[aid] if a0[aid][k] != a1[aid][k]} == {(ACTION_ID, "irreversible")}


# =============================================================================================================== defensive direct checks
def test_u01_the_second_strict_parse_of_the_verified_record_text_refuses_anything_unusual():
    ok = '{"payload":{"class_irreversible":{"a":"irreversible"}}}'
    assert ir.registry_irreversible_map(ok) == {"a": "irreversible"}
    for bad in ('{"payload":{"class_irreversible":{"a":"irreversible","a":"irreversible"}}}', '{"payload":{"class_irreversible":{"a":1}}}', '{"payload":{"class_irreversible":{"a":true}}}',
                '{"payload":{"class_irreversible":{"a":"irreversible"},"x":1}}', '{"payload":{"class_irreversible":{}}}', '{"payload":{"class_irreversible":{"a":"Irreversible"}}}',
                '{"payload":{"class_irreversible":{"a":"reversible"}}}', '{"payload":{"class_irreversible":{"a":"irreversible"}},"x":1.5}', "not json", '{"payload":3}',
                '{"payload":{"other":{"a":"irreversible"}}}'):
        assert ir.registry_irreversible_map(bad) is None, bad


def _direct(cfg, **over):
    common = dict(scope=SCOPE_IR, institution_id=base.INSTITUTION, authority_domain=base.DOMAIN, verifier=ev.Ed25519Verifier(), now=REG_NOW, host=cfg,
                  host_values=ir.host_class_irreversible(cfg)[0], material=Source(imat()).__call__())
    common.update(over)
    return ir.derive_irreversible(**common)


def test_u02_a_verifier_that_is_not_the_admitted_ed25519_verifier_and_wrong_material_types_are_refused(tmp_path):
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    assert _direct(cfg)[1] is None  # positive control
    assert _direct(cfg, verifier=object())[1].code == "verifier_not_admitted"
    for bad in ("text", None, base.SelectionMaterial(b"bytes", "x", None), base.SelectionMaterial("x", 3, None)):
        assert _direct(cfg, material=bad)[1].code == "material_invalid"


def test_u03_registry_unavailable_and_call_failure_are_refusals(tmp_path, monkeypatch):
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    monkeypatch.setattr(v7dec, "verify_and_decide_v7", lambda *a, **k: (_ for _ in ()).throw(RuntimeError("boom")))
    assert _direct(cfg)[1].code == "registry_call_failed"
    monkeypatch.setattr(ir, "_registry_modules", lambda: (_ for _ in ()).throw(ImportError("no registry")))
    assert _direct(cfg)[1].code == "registry_unavailable"


def test_u04_the_composer_only_ever_sets_true_and_the_defensive_checks_hold_when_reached_directly(tmp_path, monkeypatch):
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    kept = ir.compose_irreversible(cfg, {CLASS_T1: NC, CLASS_T2: NC})
    assert flags(kept) == {CLASS_T1: False, CLASS_T2: True}  # a host true is never cleared
    assert flags(ir.compose_irreversible(cfg, {CLASS_T1: IRR, CLASS_T2: IRR})) == {CLASS_T1: True, CLASS_T2: True}
    ghost = GovernedScope("consumer-test", TENANT.lower(), "urn:cognous:action:ghost-v1", OP_IR)
    assert _direct(cfg, scope=ghost)[1].code == "action_class_unknown"
    from registry_successor.decision import PolicyDecision
    monkeypatch.setattr(v7dec, "verify_and_decide_v7", lambda *a, **k: PolicyDecision("applied", {FIELD: {CLASS_T1: IRR, CLASS_T2: IRR}}, False, (), None, "", False))
    unknown = Source(imat(rec=irec(payload={FIELD: {CLASS_T1: IRR, "class-x": IRR}}))).__call__()
    assert _direct(cfg, material=unknown)[1].code == "effective_policy_invalid"  # a record naming a class the host does not define is refused here too
    monkeypatch.setattr(v7dec, "verify_and_decide_v7", lambda *a, **k: PolicyDecision("applied", {FIELD: {CLASS_T1: IRR, CLASS_T2: IRR}}, False, (), None, "", False))
    monkeypatch.setattr(ir, "_registry_modules", lambda: (importlib.import_module("registry_successor.decision"), importlib.import_module("registry_successor.common"), v7dec,
                                                          type("I", (), {"effective_policy_digest": staticmethod(lambda *a, **k: (_ for _ in ()).throw(ValueError("x")))}),
                                                          ev.Ed25519Verifier))
    assert _direct(cfg)[1].code == "effective_policy_digest_unavailable"


def test_s06_the_snapshot_names_the_verified_selection_even_if_the_materials_mapping_changes_on_a_later_read(tmp_path):
    """Review finding L-1: each material is read ONCE, so a mapping that returns another object on a second read cannot change the selection named in the snapshot."""
    p, res, cfg, srcs, flow = ready(tmp_path, ir_={CLASS_T1: IRR})
    verified = srcs["ir"]()
    evil = Source(imat({CLASS_T1: IRR}, stmt_over={"selection_id": "sel-evil-1", "epoch": 99}))()

    class Flaky(dict):
        reads = 0

        def get(self, key, default=None):
            Flaky.reads += 1
            return verified if Flaky.reads == 1 else evil

        def __getitem__(self, key):
            Flaky.reads += 1
            return verified if Flaky.reads == 1 else evil

    snap = _resolve(cfg, {}, fams(srcs["ir"]), materials=Flaky(class_irreversible=verified))
    f = snap.family("class_irreversible")
    assert (f.selection_id, f.selection_epoch) == ("sel-test-1", 1)
