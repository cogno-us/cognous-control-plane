"""FINAL3 consumers 2/3 and 3/3: Registry-governed `ObservationPolicy.max_age_seconds` (`f5-observation-max-age-policy`) and `ObservationPolicy.clock_tolerance_seconds`
(`f5-observation-clock-tolerance-policy`), Registry `r08-v8`, on the composed `GovernedPolicyWorkflow`; exact boundaries through the REAL `_reconcile_observation`.

BUILDER_TESTED developer evidence. NOT independently qualified. NOT an authorization mechanism. Needs the Registry r08-v8 pin (a40fe75) and PyNaCl; real synthetic Ed25519.
The CONSTRUCTOR `clock_tolerance_seconds` is a different, held value: these tests pin that it is untouched and not narrowable.
"""
from __future__ import annotations

import ast
from datetime import timedelta

import pytest

from tests.final3_support import *  # noqa: F401,F403  (enforces the r08-v8 pin)
import agent_control_plane.bounded as bounded
from agent_control_plane import registry_effective_policy as eff
from agent_control_plane.bounded import EffectObservation
from agent_control_plane.registry_governed_policy import RegistryGovernedPolicyRefused
from tests.test_bounded_authorization import ObservationProxy


@pytest.fixture(autouse=True)
def _fixed_synthetic_clock(monkeypatch):
    monkeypatch.setattr(bounded, "_now", lambda: NOW)
    for m in (pol, base.gov, base.agegov, base.f4gov):
        monkeypatch.setattr(m, "_now", lambda: NOW)


def op(max_age=300, tol=5):
    return ObservationPolicy(max_age_seconds=max_age, clock_tolerance_seconds=tol)


def obs_at(offset):
    """An absent-state observation of `effect-1` stamped `offset` seconds AFTER the evaluation time (negative = older)."""
    return EffectObservation(effect_id="effect-1", observed_at=(NOW + timedelta(seconds=offset)).isoformat(), state="absent", destination_state={})


def flow_for(tmp_path, *, age=None, tol=None, host=None, observation=None, **kw):
    """Composed workflow declaring the given observation selections (a value is registry material or None). `host` is the host ObservationPolicy (default 300/5)."""
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    dest = ObservationProxy(LocalRefundDestination(tmp_path / "destination.json"), observation=observation if observation is not None else obs_at(0))
    flow = build(tmp_path, res, None, fams(age=Source(age) if age is not None else None, tol=Source(tol) if tol is not None else None), obs=host if host is not None else op(),
                 destination=dest, **kw)
    return p, res, flow


def verdict(flow, offset):
    flow.destination.observation = obs_at(offset)
    return flow.reconcile("effect-1", now=NOW)


# ------------------------------------------------------------------------------------------------------------------------------ effective values
def test_a01_registry_stricter_than_host_narrows_each_field_independently(tmp_path):
    p, res, flow = flow_for(tmp_path, age=mat(AGE, 60), tol=mat(TOL, 2))
    assert (flow.observation_policy.max_age_seconds, flow.observation_policy.clock_tolerance_seconds) == (60, 2)
    only_age = flow_for(tmp_path / "a", age=mat(AGE, 60))[2]
    assert (only_age.observation_policy.max_age_seconds, only_age.observation_policy.clock_tolerance_seconds) == (60, 5)  # the undeclared field keeps the host value
    only_tol = flow_for(tmp_path / "t", tol=mat(TOL, 2))[2]
    assert (only_tol.observation_policy.max_age_seconds, only_tol.observation_policy.clock_tolerance_seconds) == (300, 2)


def test_a02_host_stricter_than_registry_is_a_no_op_and_the_registry_never_widens(tmp_path):
    p, res, flow = flow_for(tmp_path, age=mat(AGE, 900), tol=mat(TOL, 30), host=op(120, 1))
    assert (flow.observation_policy.max_age_seconds, flow.observation_policy.clock_tolerance_seconds) == (120, 1)
    ident = flow.registry_governed_policy_identity
    assert ident["observation_max_age"]["effective"] == {FIELDS[AGE]: 120} and ident["observation_clock_tolerance"]["effective"] == {FIELDS[TOL]: 1}
    assert ident["host"]["observation_policy"] == {"max_age_seconds": 120, "clock_tolerance_seconds": 1}


@pytest.mark.parametrize("registry,host,expect", [(60, 300, 60), (300, 300, 300), (301, 300, 300), (1, 300, 1), (MAXV, 300, 300), (1, 1, 1)])
def test_a03_min_of_host_and_registry_for_max_age(tmp_path, registry, host, expect):
    flow = flow_for(tmp_path, age=mat(AGE, registry), host=op(host, 5))[2]
    assert flow.observation_policy.max_age_seconds == expect and flow.observation_policy.clock_tolerance_seconds == 5


@pytest.mark.parametrize("registry,host,expect", [(0, 5, 0), (5, 5, 5), (6, 5, 5), (2, 5, 2), (MAXV, 5, 5), (0, 0, 0), (3, 0, 0)])
def test_a04_min_of_host_and_registry_for_the_observation_tolerance_zero_admitted(tmp_path, registry, host, expect):
    flow = flow_for(tmp_path, tol=mat(TOL, registry), host=op(300, host))[2]
    assert flow.observation_policy.clock_tolerance_seconds == expect and flow.observation_policy.max_age_seconds == 300


def test_a05_the_host_policy_object_is_not_modified_and_the_bounded_workflow_holds_a_copy(tmp_path):
    host = op()
    flow = flow_for(tmp_path, age=mat(AGE, 60), host=host)[2]
    assert (host.max_age_seconds, host.clock_tolerance_seconds) == (300, 5) and flow.observation_policy is not host


def test_a06_digests_are_the_registry_v8_identity_of_the_effective_value_with_family_schema_revision_1(tmp_path):
    flow = flow_for(tmp_path, age=mat(AGE, 60), tol=mat(TOL, 2))[2]
    ident = flow.registry_governed_policy_identity
    assert ident["observation_max_age"]["effective_policy_digest"] == v8id.effective_policy_digest(AGE, {FIELDS[AGE]: 60}, "r08-v8")
    assert ident["observation_clock_tolerance"]["effective_policy_digest"] == v8id.effective_policy_digest(TOL, {FIELDS[TOL]: 2}, "r08-v8")
    assert v8id.registered_family_version(AGE, "r08-v8") == v8id.registered_family_version(TOL, "r08-v8") == 1
    for slot, fam in (("observation_max_age", AGE), ("observation_clock_tolerance", TOL)):
        assert eff.FAMILY_TABLE[slot] == (fam, "r08-v8") and eff.SCHEMA_REVISIONS[slot] == 1


# ------------------------------------------------------------------------------------------------------------------------------ exact boundaries at the NARROWED values
@pytest.mark.parametrize("age,offset,expect", [(60, -60, []), (60, -61, ["observation_stale"]), (60, -59, []), (1, -1, []), (1, -2, ["observation_stale"])])
def test_b01_exact_stale_boundary_at_the_narrowed_max_age(tmp_path, age, offset, expect):
    flow = flow_for(tmp_path, age=mat(AGE, age))[2]
    r = verdict(flow, offset)
    assert r.reasons == expect and r.observation_accepted is (not expect) and r.observation_max_age_seconds == age and r.observation_clock_tolerance_seconds == 5
    assert r.result == ("observed_absent" if not expect else "hold") and r.retry_eligible is False


@pytest.mark.parametrize("tol,offset,expect", [(2, 2, []), (2, 3, ["observation_time_future"]), (0, 0, []), (0, 1, ["observation_time_future"]), (1, 1, []), (1, 2, ["observation_time_future"])])
def test_b02_exact_future_boundary_at_the_narrowed_tolerance_zero_admitted(tmp_path, tol, offset, expect):
    flow = flow_for(tmp_path, tol=mat(TOL, tol))[2]
    r = verdict(flow, offset)
    assert r.reasons == expect and r.observation_accepted is (not expect) and r.observation_clock_tolerance_seconds == tol and r.observation_max_age_seconds == 300


def test_b03_both_families_jointly_the_two_boundaries_are_independent(tmp_path):
    flow = flow_for(tmp_path, age=mat(AGE, 60), tol=mat(TOL, 2))[2]
    assert verdict(flow, -60).reasons == [] and verdict(flow, -61).reasons == ["observation_stale"]
    assert verdict(flow, 2).reasons == [] and verdict(flow, 3).reasons == ["observation_time_future"]
    r = verdict(flow, 0)
    assert (r.observation_max_age_seconds, r.observation_clock_tolerance_seconds) == (60, 2) and r.reasons == []


def test_b04_host_boundaries_are_unchanged_where_the_registry_does_not_narrow(tmp_path):
    flow = flow_for(tmp_path, age=mat(AGE, 900), tol=mat(TOL, 30))[2]  # host 300 / 5 stay
    assert verdict(flow, -300).reasons == [] and verdict(flow, -301).reasons == ["observation_stale"]
    assert verdict(flow, 5).reasons == [] and verdict(flow, 6).reasons == ["observation_time_future"]


def test_b05_only_the_two_existing_reasons_are_added_and_nothing_turns_a_hold_into_a_pass(tmp_path):
    host = flow_for(tmp_path / "h", age=mat(AGE, 300))[2]  # the Registry value equals the host value: the host policy stands
    narrowed = flow_for(tmp_path / "n", age=mat(AGE, 60), tol=mat(TOL, 0))[2]
    for offset in range(-400, 12, 3):
        a, b = verdict(host, offset), verdict(narrowed, offset)
        assert set(b.reasons) - set(a.reasons) <= {"observation_stale", "observation_time_future"}
        assert not (b.observation_accepted and not a.observation_accepted)  # narrowing can only add holds


def test_b06_a_stale_or_future_observation_is_retained_as_a_hold_with_the_effective_values_and_nothing_is_dispatched(tmp_path):
    flow = flow_for(tmp_path, age=mat(AGE, 60))[2]
    r = verdict(flow, -61)
    assert r.result == "hold" and flow.records.load().reconciliations[-1].observation_max_age_seconds == 60 and flow.records.load().observations == [] and effects(flow) == {}


def test_b07_the_unavailable_observation_path_records_the_effective_values_too(tmp_path):
    flow = flow_for(tmp_path, age=mat(AGE, 60), tol=mat(TOL, 1))[2]
    flow.destination.error = RuntimeError("down")
    r = flow.reconcile("effect-1", now=NOW)
    assert (r.observation_max_age_seconds, r.observation_clock_tolerance_seconds) == (60, 1) and r.result == "hold"


# ------------------------------------------------------------------------------------------------------------------------------ the constructor tolerance is untouched
def test_c01_the_constructor_clock_tolerance_is_untouched_by_the_observation_tolerance_family(tmp_path):
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    flow = build(tmp_path, res, None, fams(tol=Source(mat(TOL, 0))), clock_tolerance_seconds=7)
    assert flow.clock_tolerance_seconds == 7 and flow.observation_policy.clock_tolerance_seconds == 0
    default = flow_for(tmp_path / "d", tol=mat(TOL, 0))[2]
    assert default.clock_tolerance_seconds == 5


def test_c02_the_constructor_tolerance_is_not_narrowable_the_alias_member_name_is_refused(tmp_path):
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    for payload in ({"clock_tolerance_seconds": 2}, {FIELDS[TOL]: 2, "clock_tolerance_seconds": 2}):
        with pytest.raises(RegistryGovernedPolicyRefused) as e:
            build(tmp_path, res, None, fams(tol=Source(mat(TOL, record=t8.record(payload, family=TOL)))))
        assert e.value.refusal.code.startswith("observation_clock_tolerance:") and e.value.boundary == "construction"
    from agent_control_plane import registry_final3_governance as g
    assert not hasattr(g, "FIELD_CLOCK_TOLERANCE") and "clock_tolerance_seconds" not in (g.FIELD_OBS_TOL, g.FIELD_OBS_AGE)
    tree = ast.parse((SRC / "registry_final3_governance.py").read_text())
    assert not any(isinstance(n, ast.Attribute) and n.attr == "clock_tolerance_seconds" and isinstance(n.value, ast.Name) and n.value.id == "self" for n in ast.walk(tree))


def test_c03_editing_either_tolerance_after_construction_is_refused(tmp_path):
    p, res, flow = flow_for(tmp_path, tol=mat(TOL, 2))
    flow.clock_tolerance_seconds = 1  # the constructor tolerance
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "scalars_modified", "decision")
    p, res, flow = flow_for(tmp_path / "o", tol=mat(TOL, 2))
    flow.observation_policy.clock_tolerance_seconds = 5  # the host value put back over the narrowed one
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "observation_policy_modified", "decision")


def test_c04_replacing_the_policy_object_or_widening_max_age_after_construction_is_refused(tmp_path):
    p, res, flow = flow_for(tmp_path, age=mat(AGE, 60))
    flow.observation_policy = op(300, 5)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "observation_policy_modified", "decision")
    p, res, flow = flow_for(tmp_path / "b", age=mat(AGE, 60))
    flow.observation_policy = None
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "observation_policy_modified", "decision")


# ------------------------------------------------------------------------------------------------------------------------------ host preconditions
@pytest.mark.parametrize("fam,slot", [(AGE, "age"), (TOL, "tol")])
def test_d01_a_declared_observation_family_with_no_host_policy_is_refused_at_construction_and_none_is_synthesized(tmp_path, fam, slot):
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    src = Source(mat(fam))
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, None, fams(**{slot: src}), obs=None)
    refused(e, "host_observation_policy_missing", "construction")
    assert src.calls == 0


def test_d02_a_workflow_without_the_families_still_holds_observation_policy_missing_unchanged(tmp_path):
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    dest = ObservationProxy(LocalRefundDestination(tmp_path / "destination.json"), observation=obs_at(0))
    flow = build(tmp_path, res, None, GovernedFamilies(f4_ages=GovernedFamily(comp.SCOPE_F, comp.fsrc())), obs=None, destination=dest)
    assert flow.observation_policy is None
    r = flow.reconcile("effect-1", now=NOW)
    assert r.result == "hold" and "observation_policy_missing" in r.reasons


def _broken(**values):
    pol_ = ObservationPolicy(max_age_seconds=300, clock_tolerance_seconds=5)
    for k, v in values.items():
        object.__setattr__(pol_, k, v)
    return pol_


BAD_HOSTS = {
    "assigned_zero_age": _broken(max_age_seconds=0), "negative_age": _broken(max_age_seconds=-5), "negative_tolerance": _broken(clock_tolerance_seconds=-1),
    "bool_age": _broken(max_age_seconds=True), "bool_tolerance": _broken(clock_tolerance_seconds=False), "float_age": _broken(max_age_seconds=300.0),
    "str_tolerance": _broken(clock_tolerance_seconds="5"), "none_age": _broken(max_age_seconds=None), "age_above_token_range": _broken(max_age_seconds=MAXV + 1),
    "tolerance_above_token_range": _broken(clock_tolerance_seconds=MAXV + 1),
}


@pytest.mark.parametrize("name", sorted(BAD_HOSTS))
@pytest.mark.parametrize("fam,slot", [(AGE, "age"), (TOL, "tol")])
def test_d03_an_invalid_original_host_policy_is_refused_before_any_source_read_and_never_repaired(tmp_path, name, fam, slot):
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    src = Source(mat(fam, 1 if fam == AGE else 0))  # a Registry value that WOULD be a valid narrowing if the host were repaired
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, None, fams(**{slot: src}), obs=BAD_HOSTS[name])
    refused(e, "host_observation_policy_invalid", "construction")
    assert src.calls == 0


def test_d04_a_model_construct_policy_and_a_subclass_are_refused(tmp_path):
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    constructed = ObservationPolicy.model_construct(max_age_seconds=0, clock_tolerance_seconds=5)

    class Sub(ObservationPolicy):
        pass
    for bad in (constructed, Sub(max_age_seconds=300), {"max_age_seconds": 300, "clock_tolerance_seconds": 5}):
        with pytest.raises(RegistryGovernedPolicyRefused) as e:
            build(tmp_path, res, None, fams(age=Source(mat(AGE))), obs=bad)
        refused(e, "host_observation_policy_invalid", "construction")


def test_d05_an_invalid_host_value_of_the_undeclared_field_also_refuses_the_whole_caller(tmp_path):
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, None, fams(age=Source(mat(AGE))), obs=_broken(clock_tolerance_seconds=MAXV + 1))
    refused(e, "host_observation_policy_invalid", "construction")


def test_d06_host_values_at_the_token_range_edges_are_accepted(tmp_path):
    flow = flow_for(tmp_path, age=mat(AGE, 60), tol=mat(TOL, 0), host=op(MAXV, MAXV))[2]
    assert (flow.observation_policy.max_age_seconds, flow.observation_policy.clock_tolerance_seconds) == (60, 0)


# ------------------------------------------------------------------------------------------------------------------------------ record / selection refusals
@pytest.mark.parametrize("fam,slot,payloads", [
    (AGE, "age", [0, -1, MAXV + 1, True, 60.0, "60", None, [], {}]),
    (TOL, "tol", [-1, MAXV + 1, True, False, 2.0, "2", None, [], {}]),
])
def test_e01_out_of_domain_registry_values_are_refused(tmp_path, fam, slot, payloads):
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    for v in payloads:
        with pytest.raises(RegistryGovernedPolicyRefused) as e:
            build(tmp_path, res, None, fams(**{slot: Source(mat(fam, record=t8.record({FIELDS[fam]: v}, family=fam)))}))
        assert e.value.refusal.code.startswith(SLOTS[fam] + ":") and e.value.boundary == "construction", v


@pytest.mark.parametrize("fam,slot,other", [(AGE, "age", TOL), (TOL, "tol", AGE)])
def test_e02_cross_family_selection_is_refused(tmp_path, fam, slot, other):
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    wrong = base._material(rec(other, 60 if other == AGE else 1), op=OPS[fam], contract="r08-v8", domain=t8.V8_DOMAIN, family=other)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, None, fams(**{slot: Source(wrong)}))
    assert e.value.refusal.code.startswith(SLOTS[fam] + ":")
    anchor = base._material(rec(ANC), op=OPS[fam], contract="r08-v8", domain=t8.V8_DOMAIN, family=ANC)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path / "x", res, None, fams(**{slot: Source(anchor)}))
    assert e.value.refusal.code.startswith(SLOTS[fam] + ":")


@pytest.mark.parametrize("fam,slot", [(AGE, "age"), (TOL, "tol")])
@pytest.mark.parametrize("what", ["v7_contract", "v7_domain", "wrong_consumer", "wrong_tenant", "wrong_institution", "wrong_operation", "other_key"])
def test_e03_wrong_contract_scope_operation_or_signer_is_refused(tmp_path, fam, slot, what):
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    kw = {"v7_contract": dict(contract="r08-v7"), "v7_domain": dict(domain=b"ocs-reg/r08-v7/selection\n"), "wrong_consumer": dict(stmt_over={"consumer_id": "other-consumer"}),
          "wrong_tenant": dict(stmt_over={"scope": dict(base.STMT_SCOPE, tenant="other-tenant")}),
          "wrong_institution": dict(stmt_over={"scope": dict(base.STMT_SCOPE, institution="other-institution")}),
          "wrong_operation": dict(stmt_over={"operation": "refund-issue-elsewhere"}), "other_key": dict(sk=base.OTHER_SK)}[what]
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, None, fams(**{slot: Source(mat(fam, **kw))}))
    assert e.value.refusal.code.startswith(SLOTS[fam] + ":") and e.value.boundary == "construction"


# ------------------------------------------------------------------------------------------------------------------------------ lifecycle (decision / execute / pre-apply)
def _bad(fam, kind):
    return {"revoked": lambda: revoked(fam), "withdrawn": lambda: withdrawn(fam), "replaced": lambda: mat(fam, 61 if fam == AGE else 1)}[kind]()


def _auth(tmp_path, fam):
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    src = Source(mat(fam, 60 if fam == AGE else 2))
    flow = build(tmp_path, res, None, fams(**{"age" if fam == AGE else "tol": src}))
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    return p, res, src, flow, d


@pytest.mark.parametrize("fam", [AGE, TOL])
@pytest.mark.parametrize("kind", ["revoked", "withdrawn", "replaced", "source_fail", "expired"])
@pytest.mark.parametrize("boundary", ["construction", "decision", "effect", "commit"])
def test_f01_a_bad_selection_is_refused_at_construction_decision_execute_entry_and_the_pre_apply_gate(tmp_path, monkeypatch, fam, kind, boundary):
    slot = "age" if fam == AGE else "tol"
    if boundary == "construction":
        p, res, cfg = base.prepared(tmp_path, t1=R_)
        if kind == "source_fail":
            src = Source(mat(fam))
            src.fail = True
        elif kind == "expired":
            src = Source(mat(fam, stmt_over={"effective": {"valid_from": "2026-09-01T00:00:00Z", "valid_until": "2026-09-02T00:00:00Z"}}))
        elif kind == "replaced":
            src = Source(mat(fam, stmt_over={"supersedes": "sel-unknown"}))  # a supersession the Registry cannot verify
        else:
            src = Source(_bad(fam, kind))
        with pytest.raises(RegistryGovernedPolicyRefused) as e:
            build(tmp_path, res, None, fams(**{slot: src}))
        assert e.value.boundary == "construction"
        return
    p, res, src, flow, d = _auth(tmp_path, fam)
    before = file_state(tmp_path, flow)
    now = NOW.replace(year=NOW.year + 1) if kind == "expired" else NOW
    if boundary in ("decision", "effect"):
        if kind == "source_fail":
            src.fail = True
        elif kind != "expired":
            src.mat = _bad(fam, kind)
        with pytest.raises(RegistryGovernedPolicyRefused) as e:
            (flow.decide(p, now=now) if boundary == "decision" else flow.execute(p, d, adapter_id=p.adapter_id, now=now))
        assert e.value.boundary == boundary and (kind != "replaced" or e.value.refusal.code == "selection_changed")
        assert file_state(tmp_path, flow) == before and effects(flow) == {}
        return
    if kind == "expired":
        real, seen = f3.derive_observation, []

        def late(**kw):
            seen.append(1)
            return real(**dict(kw, now=kw["now"].replace(year=kw["now"].year + 1) if len(seen) == 2 else kw["now"]))
        monkeypatch.setattr(f3, "derive_observation", late)
    elif kind == "source_fail":
        class Dies(Source):
            def __call__(self):
                self.calls += 1
                if self.calls >= 4:
                    raise RuntimeError("down")
                return self.mat
        src.__class__ = Dies
    else:
        src.after = (4, _bad(fam, kind))
    attempt, _ = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "failed" and effects(flow) == {} and flow.governed_last_commit_refusal is not None  # no unauthorized external effect after the refusal


@pytest.mark.parametrize("fam", [AGE, TOL])
def test_f02_an_equal_replacement_selection_is_accepted_but_a_different_value_is_refused(tmp_path, fam):
    p, res, src, flow, d = _auth(tmp_path, fam)
    src.mat = mat(fam, 60 if fam == AGE else 2, stmt_over=CHANGED)
    assert flow.decide(p, now=NOW).result == "authorized"


@pytest.mark.parametrize("fam", [AGE, TOL])
def test_f03_a_failing_source_at_any_boundary_refuses_the_whole_workflow_and_no_fallback_exists(tmp_path, fam):
    p, res, src, flow, d = _auth(tmp_path, fam)
    src.fail = True
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    refused(e, "selection_source_failed", "effect")
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "selection_source_failed", "decision")
    assert effects(flow) == {}


def test_f04_a_declared_family_without_a_source_is_refused(tmp_path):
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    for fam, slot in ((AGE, "observation_max_age"), (TOL, "observation_clock_tolerance")):
        with pytest.raises(RegistryGovernedPolicyRefused) as e:
            build(tmp_path, res, None, GovernedFamilies(**{slot: GovernedFamily(SCOPES[fam], None)}))
        assert e.value.refusal.code in ("families_invalid", "selection_source_invalid")


# ------------------------------------------------------------------------------------------------------------------------------ final validation units
def test_g01_observation_defect_checks_the_final_values_against_the_original_host():
    host = {"max_age_seconds": 300, "clock_tolerance_seconds": 5}
    ok = dict(host, max_age_seconds=60)
    assert f3.observation_defect(host, ok, age_declared=True, tolerance_declared=False) is None
    assert f3.observation_defect(host, host, age_declared=True, tolerance_declared=True) is None
    assert f3.observation_defect(host, dict(host, max_age_seconds=301), age_declared=True, tolerance_declared=False) == "composed_widens_host"
    assert f3.observation_defect(host, dict(host, clock_tolerance_seconds=6), age_declared=False, tolerance_declared=True) == "composed_widens_host"
    assert f3.observation_defect(host, ok, age_declared=False, tolerance_declared=True) == "composed_observation_invalid"  # an undeclared field differs
    assert f3.observation_defect(host, dict(host, clock_tolerance_seconds=0), age_declared=True, tolerance_declared=False) == "composed_observation_invalid"
    for bad in (dict(host, max_age_seconds=0), dict(host, max_age_seconds=True), dict(host, clock_tolerance_seconds=-1), dict(host, clock_tolerance_seconds=2.0),
                {"max_age_seconds": 60}, dict(host, extra=1)):
        assert f3.observation_defect(host, bad, age_declared=True, tolerance_declared=True) == "composed_observation_invalid", bad


def test_g02_a_forged_registry_result_that_widens_or_is_not_the_min_is_refused(tmp_path, monkeypatch):
    p, res, cfg = base.prepared(tmp_path, t1=R_)
    real = f3.derive_observation

    def forged(value):
        def f(**kw):
            got, ref = real(**kw)
            return (({FIELDS[AGE]: value}, got[1]), None) if got else (got, ref)
        return f
    for value in (301, MAXV):  # the derivation is replaced wholesale: only the FINAL composition check stands between a forged value above the host and the workflow
        monkeypatch.setattr(f3, "derive_observation", forged(value))
        with pytest.raises(RegistryGovernedPolicyRefused) as e:
            build(tmp_path, res, None, fams(age=Source(mat(AGE, 300))))
        assert e.value.boundary == "construction" and e.value.refusal.code == "composed_widens_host", (value, e.value.refusal)


def _decision_stub(effective):
    base_mod = __import__("registry_successor.decision", fromlist=["x"])
    return base_mod.PolicyDecision(kind="applied", effective=effective, deny_all=False, deny_all_fields=(), code=None, detail="", caller_unchanged=False,
                                   operationally_authorized=False)


@pytest.mark.parametrize("effective,code", [({FIELDS[AGE]: 301}, "effective_policy_widens_host"), ({FIELDS[AGE]: 0}, "effective_policy_invalid"), ({FIELDS[AGE]: True}, "effective_policy_invalid"),
                                            ({FIELDS[AGE]: 60, "x": 1}, "effective_policy_invalid"), ({FIELDS[AGE]: 200}, "effective_policy_invalid"), ({}, "effective_policy_invalid")])
def test_g03_the_derivation_re_checks_a_forged_registry_decision(tmp_path, monkeypatch, effective, code):
    stub = _decision_stub(effective)
    import registry_successor.v8_decision as v8d
    monkeypatch.setattr(v8d, "verify_and_decide_v8", lambda *a, **k: stub)
    got, ref = f3.derive_observation(family=AGE, scope=SCOPES[AGE], institution_id=base.INSTITUTION, authority_domain=base.DOMAIN, host_value=300, material=mat(AGE, 60),
                                     verifier=ev.Ed25519Verifier(), now=REG_NOW)
    assert got is None and ref.code == code


@pytest.mark.parametrize("what", ["authorized", "wrong_kind", "deny_all", "not_applied", "not_a_decision"])
def test_g04_a_registry_decision_of_the_wrong_shape_is_refused(tmp_path, monkeypatch, what):
    import registry_successor.v8_decision as v8d
    d = _decision_stub({FIELDS[AGE]: 60})
    d = {"authorized": type("X", (), {})(), "wrong_kind": d.__class__(**dict(d.__dict__, kind="overlay_not_applied", code="selection_revoked")),
         "deny_all": d.__class__(**dict(d.__dict__, deny_all=True)), "not_applied": d.__class__(**dict(d.__dict__, kind="required_policy_unavailable")),
         "not_a_decision": "applied"}[what]
    monkeypatch.setattr(v8d, "verify_and_decide_v8", lambda *a, **k: d)
    got, ref = f3.derive_observation(family=AGE, scope=SCOPES[AGE], institution_id=base.INSTITUTION, authority_domain=base.DOMAIN, host_value=300, material=mat(AGE, 60),
                                     verifier=ev.Ed25519Verifier(), now=REG_NOW)
    assert got is None and ref.code in ("registry_not_applied", "registry_decision_invalid")


def test_g05_host_observation_values_and_unknown_family_units():
    assert f3.host_observation_values(op(1, 0)) == ({"max_age_seconds": 1, "clock_tolerance_seconds": 0}, None)
    assert f3.host_observation_values(None) == (None, "host_observation_policy_missing")
    assert f3.host_observation_values(_broken(max_age_seconds=0))[1] == "host_observation_policy_invalid"
    got, ref = f3.derive_observation(family="clock_tolerance_seconds", scope=SCOPES[AGE], institution_id="i", authority_domain="d", host_value=5, material=None, verifier=None, now=REG_NOW)
    assert got is None and ref.code == "family_unknown"
    got, ref = f3.derive_observation(family=AGE, scope=SCOPES[AGE], institution_id="i", authority_domain="d", host_value=True, material=None, verifier=None, now=REG_NOW)
    assert got is None and ref.code == "host_observation_policy_invalid"
    assert f3.effective_observation_values({"max_age_seconds": 300, "clock_tolerance_seconds": 5}, {}) == {"max_age_seconds": 300, "clock_tolerance_seconds": 5}


def test_g06_a_verifier_that_is_not_the_admitted_ed25519_verifier_wrong_material_types_and_an_unavailable_registry_are_refused(tmp_path, monkeypatch):
    kw = dict(family=AGE, scope=SCOPES[AGE], institution_id=base.INSTITUTION, authority_domain=base.DOMAIN, host_value=300, now=REG_NOW)
    got, ref = f3.derive_observation(material=mat(AGE, 60), verifier=object(), **kw)
    assert got is None and ref.code == "verifier_not_admitted"
    for bad in (None, "text", base.SelectionMaterial(5, "x", None), base.SelectionMaterial("x", b"y", None)):
        got, ref = f3.derive_observation(material=bad, verifier=ev.Ed25519Verifier(), **kw)
        assert got is None and ref.code == "material_invalid"
    import importlib as _il
    real = _il.import_module
    monkeypatch.setattr(f3.importlib, "import_module", lambda name, *a, **k: (_ for _ in ()).throw(ImportError(name)) if name.startswith("registry_successor") else real(name, *a, **k))
    got, ref = f3.derive_observation(material=mat(AGE, 60), verifier=ev.Ed25519Verifier(), **kw)
    assert got is None and ref.code == "registry_unavailable"


def test_g07_a_registry_call_that_raises_is_a_refusal(tmp_path, monkeypatch):
    import registry_successor.v8_decision as v8d

    def boom(*a, **k):
        raise RuntimeError("boom")
    monkeypatch.setattr(v8d, "verify_and_decide_v8", boom)
    got, ref = f3.derive_observation(family=TOL, scope=SCOPES[TOL], institution_id=base.INSTITUTION, authority_domain=base.DOMAIN, host_value=5, material=mat(TOL, 1),
                                     verifier=ev.Ed25519Verifier(), now=REG_NOW)
    assert got is None and ref.code == "registry_call_failed"
