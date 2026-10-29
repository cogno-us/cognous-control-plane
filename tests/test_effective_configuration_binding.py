"""D-06 Option B oracles: the persisted effective-configuration binding through the REAL `BoundedAuthorizationWorkflow` (composed governed workflow, real synthetic Ed25519).

BUILDER_TESTED developer evidence. NOT independently qualified (F3-A independent qualification is PENDING). NOT an authorization mechanism: the binding can only add a refusal.
Authorization: Architect directive 2026-10-29 (D-06 Option B), contract frozen in docs/family-migration/final-three/02-... section 4 and in docs/effective-configuration-binding.md.

Needs the Registry r08-v7 pin (`OCS_REGISTRY_PIN_DIR`, `OCS_REQUIRE_REGISTRY_PIN=1`) like the other governed suites.
"""
from __future__ import annotations

import copy
import json

import pytest

from tests import d06_support as S  # noqa: E402  (enforces the Registry pin and PyNaCl)
from agent_control_plane import effective_configuration_binding as ecb  # noqa: E402
from agent_control_plane import registry_effective_policy as eff  # noqa: E402
from agent_control_plane import registry_governed_lifecycle as life  # noqa: E402
from agent_control_plane import registry_governed_policy as pol  # noqa: E402
from agent_control_plane.authorization_pin_export import assess_authorization_pin  # noqa: E402
from agent_control_plane.bounded import ObservationPolicy  # noqa: E402
from agent_control_plane.registry_governed_policy import GovernedActivationLedger, RegistryGovernedPolicyRefused  # noqa: E402
from agent_control_plane.runtime_authority import approval_commitment  # noqa: E402
from tests.test_effective_configuration_binding_unit import leaves, perturb, set_at  # noqa: E402

T = S.T
NOW = S.NOW
CODE = "authorization_binding_changed"


@pytest.fixture(autouse=True)
def _fixed_synthetic_clock(monkeypatch):
    S.patch_clock(monkeypatch)


def stored(flow, d):
    return flow.records.decision(d.decision_id)


def member_of(flow, d):
    return stored(flow, d).binding.runtime_authority[ecb.KEY]


def assert_binding_refusal(wf, p, d, status=ecb.MISMATCH):
    """execute refuses with the REGISTERED reason, a durable EffectTimeRefusal is written, nothing reached the destination and no attempt exists."""
    n_ref = len(wf.records.load().refusals)
    before = wf.destination.snapshot()
    assert wf.configuration_binding_status(wf.records.decision(d.decision_id)) == status
    with pytest.raises(PermissionError, match="authorization-critical inputs changed before effect"):
        wf.execute(p, wf.records.decision(d.decision_id), adapter_id=p.adapter_id, now=NOW)
    doc = wf.records.load()
    assert len(doc.refusals) == n_ref + 1
    ref = doc.refusals[-1]
    assert ref.decision_id == d.decision_id and CODE in ref.reasons and (ref.reason_vocabulary_version is not None) == (wf.runtime_authority_profile is not None)
    assert wf.destination.snapshot() == before and wf.destination.snapshot()["effects"] == {}
    assert [a for a in doc.attempts if a.effect_id == d.effect_id] == []
    return ref


def assert_executes(wf, p, d):
    attempt, observed = wf.execute(p, wf.records.decision(d.decision_id), adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and observed.state == "applied"


# =============================================================================================================================== mint
def test_a01_every_authorized_decision_carries_the_member_and_nothing_else_changes(tmp_path):
    p, res, cfg, srcs, flow, d = S.authorized(tmp_path)
    ra = member_of(flow, d)
    assert d.binding.runtime_authority[ecb.KEY] == ra == flow.effective_configuration_binding
    assert ecb.record_defect(ra) is None and ra["version"] == ecb.VERSION and ra["digest"] == ecb.digest_of(ecb.VERSION, ra["members"])
    keys = set(stored(flow, d).binding.runtime_authority)
    assert keys == {"profile", "approval_commitment", "required_inputs_digest", "catalogue_digest", "expected_effective_grant_digest", "effective_grant_derivation_version", ecb.KEY}
    assert stored(flow, d) == d  # the round trip through the JSON store is lossless
    assert flow.configuration_binding_status(d) == ecb.BOUND


def test_a02_the_members_are_the_live_configuration(tmp_path):
    p, res, cfg, srcs, flow, d = S.authorized(tmp_path)
    m = member_of(flow, d)["members"]
    assert m["scope"] == {"consumer_id": "consumer-test", "tenant_id": T.TENANT.lower(), "action_id": T.ACTION_ID, "institution_id": T.base.INSTITUTION, "authority_domain": T.base.DOMAIN}
    assert m["f4_scalars"] == {"status_max_age_seconds": 60, "approval_max_age_seconds": 60}  # live host values even though the F4 family is NOT declared
    assert m["other_scalars"] == {"clock_tolerance_seconds": 5, "identity_max_age_seconds": 60, "mandate_max_age_seconds": 60}
    assert m["observation_policy"] == {"max_age_seconds": 300, "clock_tolerance_seconds": 5}
    assert m["effective_profile_digest"] == d.binding.runtime_authority["catalogue_digest"] == flow.registry_governed_policy_identity["effective_profile_digest"]
    assert m["host_profile_digest"] == pol.agemod.profile_digest(cfg) != m["effective_profile_digest"]
    assert [(r["slot"], r["family_id"], r["contract_version"], r["family_schema_revision"]) for r in m["families"]] == [
        ("class_age", "f5-action-class-age-bounds", "r08-v2", None), ("class_unreadable", "f5-action-class-unreadable-policy", "r08-v5", None)]
    ident = flow.registry_governed_policy_identity
    assert [r["effective_policy_digest"] for r in m["families"]] == [ident["class_age"]["effective_policy_digest"], ident["class_unreadable"]["effective_policy_digest"]]
    assert "evaluated_at" not in json.dumps(m) and "selection_id" not in json.dumps(m)


def test_a03_f4_declared_binds_the_registry_narrowed_scalars_and_the_f4_family(tmp_path):
    p, res, cfg, srcs, flow, d = S.authorized(tmp_path, f=True)
    m = member_of(flow, d)["members"]
    assert m["f4_scalars"] == {"status_max_age_seconds": 30, "approval_max_age_seconds": 30}
    assert [r["slot"] for r in m["families"]] == ["f4_ages", "class_age", "class_unreadable"]


def test_a04_the_member_is_minted_by_the_always_on_lifecycle_there_is_no_off_switch(tmp_path):
    import inspect
    params = inspect.signature(pol.GovernedPolicyWorkflow.__init__).parameters
    assert [n for n in params if "binding" in n or "bind" in n or "enable" in n or "disable" in n] == []
    assert params["legacy_cutoff"].default == 0
    p, res, cfg, srcs, flow = S.ready(tmp_path)
    assert flow.decide(p, now=NOW).binding.runtime_authority[ecb.KEY]["version"] == ecb.VERSION


def test_a05_a_workflow_without_a_profile_still_binds_via_a_one_member_extension(tmp_path):
    """F4 only, no RuntimeAuthorityProfile: the persisted `runtime_authority` was null; it becomes `{effective_configuration: ...}` and nothing else."""
    p = T.base.tenant_proposal()
    res = T.base.tenant_resolver_for(p)
    flow = S.mk(tmp_path, res, None, T.families(f=T.fsrc()))
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized" and set(d.binding.runtime_authority) == {ecb.KEY}
    assert member_of(flow, d)["members"]["effective_profile_digest"] is None and member_of(flow, d)["members"]["host_profile_digest"] is None
    restarted = S.mk(tmp_path, res, None, T.families(f=T.fsrc()))
    assert_executes(restarted, p, d)


def test_a05b_a_workflow_without_a_profile_refuses_a_changed_configuration_on_execute(tmp_path):
    """No `decision=` is passed to `_resolve` on this path (no profile): the execute entry carries the decision, and a drift still refuses durably."""
    p = T.base.tenant_proposal()
    res = T.base.tenant_resolver_for(p)
    flow = S.mk(tmp_path, res, None, T.families(f=T.fsrc()))
    d = flow.decide(p, now=NOW)
    for drift in (dict(identity_max_age_seconds=59), dict(clock_tolerance_seconds=6), dict(obs=None), dict(status_max_age_seconds=25), dict(obs=ObservationPolicy(max_age_seconds=299))):
        other = S.mk(tmp_path, res, None, T.families(f=T.fsrc()), **drift)
        assert_binding_refusal(other, p, d)
    assert_executes(S.mk(tmp_path, res, None, T.families(f=T.fsrc())), p, d)


def test_a05c_a_live_configuration_that_cannot_be_bound_refuses_and_never_falls_back_to_unbound(tmp_path, monkeypatch):
    p, res, cfg, srcs, flow, d = S.authorized(tmp_path)
    monkeypatch.setattr(flow, "_gl_configuration_members", lambda: (_ for _ in ()).throw(ecb.BindingInvalid("family_slot_unknown")))
    n = len(flow.records.load().decisions)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.decide(p, now=NOW)
    assert e.value.refusal.code == "configuration_binding_invalid" and e.value.boundary == "decision"
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert e.value.refusal.code == "configuration_binding_invalid" and e.value.boundary == "effect"
    assert len(flow.records.load().decisions) == n and flow.destination.snapshot()["effects"] == {}


def test_a06_a_hold_persists_no_binding_and_the_binding_cannot_turn_a_hold_into_an_authorization(tmp_path):
    p, res, cfg, srcs, flow = S.ready(tmp_path)
    T.bind_approval(res, cfg)  # approvals over the HOST profile, not the narrowed one: the base result is a hold
    d = flow.decide(p, now=NOW)
    assert d.result == "hold" and "runtime_authority_approval_mismatch" in d.reasons and d.binding is None
    assert all(item["binding"] is None for item in S.read_doc(tmp_path)["decisions"] if item["decision_id"] == d.decision_id)
    assert flow.configuration_binding_status(d) == ecb.UNBOUND_AFTER_CUTOFF  # a hold has no member and would not be legacy either
    with pytest.raises(PermissionError, match="decision is not authorized"):
        flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    T.bind_approval(res, flow.runtime_authority_profile)
    assert flow.decide(p, now=NOW).result == "authorized"


def test_a07_a_failed_append_leaves_no_decision_and_so_no_binding(tmp_path, monkeypatch):
    p, res, cfg, srcs, flow = S.ready(tmp_path)

    def boom(_):
        raise OSError("crash before the append")
    monkeypatch.setattr(flow.records, "append_decision", boom)
    with pytest.raises(OSError):
        flow.decide(p, now=NOW)
    assert flow.records.load().decisions == []
    monkeypatch.undo()
    S.patch_clock(monkeypatch)
    assert flow.decide(p, now=NOW).binding.runtime_authority[ecb.KEY]["version"] == ecb.VERSION


# ===================================================================================================================== restart: same configuration
def test_b01_same_configuration_across_restart_is_accepted_and_reported_bound(tmp_path):
    p, res, cfg, srcs, flow, d = S.authorized(tmp_path)
    again = S.mk(tmp_path, res, cfg, T.families(None, srcs["a"], srcs["u"]))
    T.bind_approval(res, again.runtime_authority_profile)
    assert again.configuration_binding_status(again.records.decision(d.decision_id)) == ecb.BOUND
    assert again.effective_configuration_binding == member_of(flow, d)
    assert_executes(again, p, d)
    assert again._gl_last_binding_status == ecb.BOUND


def test_b02_the_member_is_read_only_evidence_and_never_written_by_execute(tmp_path):
    p, res, cfg, srcs, flow, d = S.authorized(tmp_path)
    before = member_of(flow, d)
    assert_executes(flow, p, d)
    assert member_of(flow, d) == before and sum(1 for x in S.read_doc(tmp_path)["decisions"]) == 1


# =============================================================================================================== changed configuration refuses
HOST = {"status": dict(status_max_age_seconds=59), "approval": dict(approval_max_age_seconds=59), "constructor_tolerance": dict(clock_tolerance_seconds=6),
        "identity": dict(identity_max_age_seconds=59), "mandate": dict(mandate_max_age_seconds=59),
        "obs_max_age": dict(obs=ObservationPolicy(max_age_seconds=299, clock_tolerance_seconds=5)),
        "obs_tolerance": dict(obs=ObservationPolicy(max_age_seconds=300, clock_tolerance_seconds=6)),
        "obs_absent": dict(obs=None)}


@pytest.mark.parametrize("which", sorted(HOST))
def test_c01_a_changed_host_scalar_or_observation_policy_refuses_and_the_final_profile_is_identical(tmp_path, which):
    """The documented gap of `test_i04`: same final profile (so same catalogue_digest and approval_commitment), different scalar / ObservationPolicy. Now refused."""
    p, res, cfg, srcs, flow, d = S.authorized(tmp_path)
    other = S.mk(tmp_path, res, cfg, T.families(None, srcs["a"], srcs["u"]), **HOST[which])
    assert other.runtime_authority_profile.model_dump() == flow.runtime_authority_profile.model_dump()
    assert_binding_refusal(other, p, d)


def test_c02_a_changed_f4_scalar_with_the_f4_family_declared_refuses(tmp_path):
    p, res, cfg, srcs, flow, d = S.authorized(tmp_path, f=True)
    narrower = S.mk(tmp_path, res, cfg, T.families(srcs["f"], srcs["a"], srcs["u"]), status_max_age_seconds=25)  # min(25, Registry 30): a different effective scalar
    assert narrower.status_max_age_seconds == 25 and narrower.runtime_authority_profile.model_dump() == flow.runtime_authority_profile.model_dump()
    assert_binding_refusal(narrower, p, d)


def test_c03_the_documented_i04_scenario_now_refuses(tmp_path):
    """Successor of `test_governed_policy_composition.test_i04...` (see the comment there): dropping ONLY the F4 family leaves the profile identical but the scalars and the family set differ."""
    p, res, cfg, srcs, flow, d = S.authorized(tmp_path, f=True)
    no_f4 = S.mk(tmp_path, res, cfg, T.families(None, srcs["a"], srcs["u"]))
    assert no_f4.runtime_authority_profile.model_dump() == flow.runtime_authority_profile.model_dump() and no_f4.status_max_age_seconds == 60
    assert_binding_refusal(no_f4, p, d)


def test_c04_a_dropped_family_or_a_changed_effective_value_refuses_through_the_binding(tmp_path, monkeypatch):
    p, res, cfg, srcs, flow, d = S.authorized(tmp_path)
    alone = S.mk(tmp_path, res, cfg, T.families(None, srcs["a"], None))
    T.bind_approval(res, alone.runtime_authority_profile)  # approvals follow the new final profile, so only the binding stands in the way
    assert_binding_refusal(alone, p, d)
    changed = S.mk(tmp_path, res, cfg, T.families(None, T.Source(T.amat({T.CLASS_T1: 25})), srcs["u"]))
    T.bind_approval(res, changed.runtime_authority_profile)
    assert_binding_refusal(changed, p, d)


def test_c05_a_family_contract_version_or_schema_revision_change_refuses(tmp_path, monkeypatch):
    p, res, cfg, srcs, flow, d = S.authorized(tmp_path)
    same = S.mk(tmp_path, res, cfg, T.families(None, srcs["a"], srcs["u"]))
    assert same.configuration_binding_status(d) == ecb.BOUND
    monkeypatch.setitem(eff.FAMILY_TABLE, "class_age", (eff.FAMILY_TABLE["class_age"][0], "r08-v99"))
    assert_binding_refusal(same, p, d)
    monkeypatch.undo()
    S.patch_clock(monkeypatch)
    assert same.configuration_binding_status(d) == ecb.BOUND
    monkeypatch.setitem(eff.SCHEMA_REVISIONS, "class_unreadable", 2)
    assert_binding_refusal(same, p, d)


def test_c06_a_different_host_profile_with_the_same_final_profile_refuses(tmp_path):
    p, res, cfg, srcs, flow, d = S.authorized(tmp_path)
    host2 = T.base.host_profile(p, t1=T.R_)  # host T1 `refuse` instead of `bounded_tolerance`: Registry makes both `refuse`, so the FINAL profile is identical
    other = S.mk(tmp_path, res, host2, T.families(None, srcs["a"], srcs["u"]))
    assert other.runtime_authority_profile.model_dump() == flow.runtime_authority_profile.model_dump()
    assert pol.agemod.profile_digest(host2) != pol.agemod.profile_digest(cfg)
    assert_binding_refusal(other, p, d)


def test_c07_a_different_final_profile_refuses_even_when_approvals_follow(tmp_path):
    p, res, cfg, srcs, flow, d = S.authorized(tmp_path)
    other = S.mk(tmp_path, res, cfg, T.families(None, T.Source(T.amat({T.CLASS_T1: 30})), srcs["u"]))
    assert other.runtime_authority_profile.model_dump() != flow.runtime_authority_profile.model_dump()
    T.bind_approval(res, other.runtime_authority_profile)
    ref = assert_binding_refusal(other, p, d)
    assert ref.reasons == [CODE]


def test_c08_a_replayed_member_from_another_scope_or_decision_refuses(tmp_path):
    p, res, cfg, srcs, flow, d = S.authorized(tmp_path)
    original = member_of(flow, d)
    other_scope = copy.deepcopy(original["members"])
    other_scope["scope"]["tenant_id"] = "tenant-other"
    S.rewrite_member(tmp_path, d.decision_id, lambda b: b["runtime_authority"].__setitem__(ecb.KEY, ecb.mint(other_scope)))
    assert_binding_refusal(flow, p, d)


def test_c09_every_member_leaf_perturbed_in_the_persisted_record_refuses_execute(tmp_path):
    """Table-driven end to end: the persisted member is replaced, for every leaf, by a CONSISTENT member (valid digest) that differs in that leaf only."""
    p, res, cfg, srcs, flow, d = S.authorized(tmp_path)
    original = copy.deepcopy(member_of(flow, d))
    leaf_paths = list(leaves(original["members"]))
    assert len(leaf_paths) == 5 + 2 + 2 + 3 + 2 + 2 * 5
    for path, value in leaf_paths:
        variant = copy.deepcopy(original["members"])
        set_at(variant, path, perturb(path, value))
        S.rewrite_member(tmp_path, d.decision_id, lambda b, v=variant: b["runtime_authority"].__setitem__(ecb.KEY, ecb.mint(v)))
        assert_binding_refusal(flow, p, d)
    S.rewrite_member(tmp_path, d.decision_id, lambda b: b["runtime_authority"].__setitem__(ecb.KEY, original))
    assert_executes(flow, p, d)  # the unperturbed control executes


# ============================================================================================================= invalid / unsupported / missing
def mutate_member(fn):
    return lambda b: fn(b["runtime_authority"][ecb.KEY])


INVALID_FORMS = {
    "digest_not_the_recomputation": lambda m: m.__setitem__("digest", "sha256:" + "7" * 64),
    "members_edited_digest_kept": lambda m: m["members"]["f4_scalars"].__setitem__("status_max_age_seconds", 7),
    "extra_key_in_record": lambda m: m.__setitem__("extra", 1),
    "extra_member": lambda m: m["members"].__setitem__("extra", 1),
    "missing_member_key": lambda m: m["members"].pop("families"),
    "missing_record_key": lambda m: m.pop("digest"),
    "bool_scalar": lambda m: m["members"]["f4_scalars"].__setitem__("status_max_age_seconds", True),
    "float_scalar": lambda m: m["members"]["other_scalars"].__setitem__("identity_max_age_seconds", 60.0),
    "str_scalar": lambda m: m["members"]["observation_policy"].__setitem__("max_age_seconds", "300"),
    "negative_scalar": lambda m: m["members"]["f4_scalars"].__setitem__("approval_max_age_seconds", -1),
    "huge_scalar": lambda m: m["members"]["other_scalars"].__setitem__("mandate_max_age_seconds", 2 ** 31),
    "not_a_dict": lambda m: None,
}


@pytest.mark.parametrize("form", sorted(INVALID_FORMS))
def test_d01_a_malformed_or_inconsistent_persisted_member_refuses(tmp_path, form):
    p, res, cfg, srcs, flow, d = S.authorized(tmp_path)
    if form == "not_a_dict":
        S.rewrite_member(tmp_path, d.decision_id, lambda b: b["runtime_authority"].__setitem__(ecb.KEY, "x"))
    else:
        S.rewrite_member(tmp_path, d.decision_id, mutate_member(INVALID_FORMS[form]))
    assert_binding_refusal(flow, p, d, status=ecb.INVALID)


def test_d02_an_unknown_binding_version_refuses(tmp_path):
    p, res, cfg, srcs, flow, d = S.authorized(tmp_path)
    S.rewrite_member(tmp_path, d.decision_id, mutate_member(lambda m: m.update(version="effective-configuration-binding/0.2", digest=ecb.digest_of("effective-configuration-binding/0.2", m["members"]))))
    assert_binding_refusal(flow, p, d, status=ecb.VERSION_UNSUPPORTED)


def test_d03_a_missing_member_refuses_under_the_required_semantics(tmp_path):
    p, res, cfg, srcs, flow, d = S.authorized(tmp_path)  # default cutoff 0
    S.rewrite_member(tmp_path, d.decision_id, lambda b: b["runtime_authority"].pop(ecb.KEY))
    assert_binding_refusal(flow, p, d, status=ecb.UNBOUND_AFTER_CUTOFF)


def test_d04_a_stripped_member_at_or_after_the_cutoff_refuses_but_below_it_is_indistinguishable_from_legacy(tmp_path):
    """DOCUMENTED LIMIT: below the host cutoff a stripped member is accepted as legacy (the unsigned store cannot tell the two apart). At or past it, it refuses."""
    p, res, cfg, srcs, flow, d0 = S.authorized(tmp_path)
    d1 = flow.decide(p, now=NOW)
    for d in (d0, d1):
        S.rewrite_member(tmp_path, d.decision_id, lambda b: b["runtime_authority"].pop(ecb.KEY))
    cut = S.mk(tmp_path, res, cfg, T.families(None, srcs["a"], srcs["u"]), legacy_cutoff=1)  # index 0 is below, index 1 is AT the cutoff
    T.bind_approval(res, cut.runtime_authority_profile)
    assert cut.configuration_binding_status(cut.records.decision(d0.decision_id)) == ecb.LEGACY
    assert cut.configuration_binding_status(cut.records.decision(d1.decision_id)) == ecb.UNBOUND_AFTER_CUTOFF
    assert_binding_refusal(cut, p, d1, status=ecb.UNBOUND_AFTER_CUTOFF)
    assert_executes(cut, p, d0)
    assert cut._gl_last_binding_status == ecb.LEGACY


def test_d05_the_legacy_comparison_never_ignores_any_other_key(tmp_path):
    p, res, cfg, srcs, flow, d = S.authorized(tmp_path)
    S.rewrite_member(tmp_path, d.decision_id, lambda b: (b["runtime_authority"].pop(ecb.KEY), b["runtime_authority"].__setitem__("catalogue_digest", "sha256:" + "5" * 64)))
    cut = S.mk(tmp_path, res, cfg, T.families(None, srcs["a"], srcs["u"]), legacy_cutoff=1)
    assert cut.configuration_binding_status(cut.records.decision(d.decision_id)) == ecb.LEGACY  # classified legacy ...
    n = len(cut.records.load().refusals)
    with pytest.raises(PermissionError, match="authorization-critical inputs changed"):  # ... yet the existing equality still refuses on the OTHER key
        cut.execute(p, cut.records.decision(d.decision_id), adapter_id=p.adapter_id, now=NOW)
    assert len(cut.records.load().refusals) == n + 1 and cut.destination.snapshot()["effects"] == {}


@pytest.mark.parametrize("cutoff", [True, False, -1, 1.0, "1", None, 2 ** 31, 10 ** 30, [1]])
def test_d06_an_invalid_cutoff_refuses_the_construction(tmp_path, cutoff):
    p, res, cfg, srcs, flow = S.ready(tmp_path)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        S.mk(tmp_path, res, cfg, T.families(None, srcs["a"], srcs["u"]), legacy_cutoff=cutoff)
    assert e.value.refusal.code == "legacy_cutoff_invalid" and e.value.boundary == "construction"


def test_d07_a_cutoff_beyond_the_store_does_not_accept_a_later_unbound_decision(tmp_path):
    p, res, cfg, srcs, flow, d = S.authorized(tmp_path)
    S.rewrite_member(tmp_path, d.decision_id, lambda b: b["runtime_authority"].pop(ecb.KEY))
    huge = S.mk(tmp_path, res, cfg, T.families(None, srcs["a"], srcs["u"]), legacy_cutoff=2 ** 31 - 1)
    assert huge.configuration_binding_status(huge.records.decision(d.decision_id)) == ecb.UNBOUND_AFTER_CUTOFF
    assert_binding_refusal(huge, p, d, status=ecb.UNBOUND_AFTER_CUTOFF)


# =========================================================================================================== construction validation and held state
@pytest.mark.parametrize("name", ["status_max_age_seconds", "approval_max_age_seconds", "clock_tolerance_seconds", "identity_max_age_seconds", "mandate_max_age_seconds"])
@pytest.mark.parametrize("bad", [True, 60.0, "60", -1, 2 ** 31, None])
def test_e01_a_scalar_that_cannot_be_bound_refuses_the_construction(tmp_path, name, bad):
    p, res, cfg, srcs, flow = S.ready(tmp_path)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        S.mk(tmp_path, res, cfg, T.families(None, srcs["a"], srcs["u"]), **{name: bad})
    assert e.value.refusal.code == "host_scalar_invalid" and e.value.boundary == "construction"


def test_e02_an_observation_policy_outside_the_range_refuses_the_construction(tmp_path):
    p, res, cfg, srcs, flow = S.ready(tmp_path)
    for obs in (ObservationPolicy(max_age_seconds=2 ** 31), ObservationPolicy(max_age_seconds=1, clock_tolerance_seconds=2 ** 31)):
        with pytest.raises(RegistryGovernedPolicyRefused) as e:
            S.mk(tmp_path, res, cfg, T.families(None, srcs["a"], srcs["u"]), obs=obs)
        assert e.value.refusal.code == "host_scalar_invalid"


EDITS = {
    "status_not_declared_f4": lambda f: setattr(f, "status_max_age_seconds", 59), "approval_not_declared_f4": lambda f: setattr(f, "approval_max_age_seconds", 59),
    "constructor_tolerance": lambda f: setattr(f, "clock_tolerance_seconds", 6), "identity": lambda f: setattr(f, "identity_max_age_seconds", 59),
    "mandate": lambda f: setattr(f, "mandate_max_age_seconds", 59), "bool_in_place": lambda f: setattr(f, "identity_max_age_seconds", True),
    "observation_replaced": lambda f: setattr(f, "observation_policy", ObservationPolicy(max_age_seconds=299)),
    "observation_removed": lambda f: setattr(f, "observation_policy", None),
    "observation_max_age_mutated": lambda f: setattr(f.observation_policy, "max_age_seconds", 299),
    "observation_tolerance_mutated": lambda f: setattr(f.observation_policy, "clock_tolerance_seconds", 6),
}


@pytest.mark.parametrize("edit", sorted(EDITS))
def test_e03_a_post_construction_edit_of_a_scalar_or_the_observation_policy_is_refused_at_every_boundary(tmp_path, edit):
    """New held-state coverage: before D-06 only the F4 scalars (when declared) and the profile were guarded."""
    p, res, cfg, srcs, flow, d = S.authorized(tmp_path)
    EDITS[edit](flow)
    calls = {k: x.calls for k, x in srcs.items() if x is not None}
    for boundary, call in (("decision", lambda: flow.decide(p, now=NOW)), ("effect", lambda: flow.execute(p, d, adapter_id=p.adapter_id, now=NOW))):
        with pytest.raises(RegistryGovernedPolicyRefused) as e:
            call()
        assert e.value.refusal.code == "scalars_modified" and e.value.boundary == boundary
    assert {k: x.calls for k, x in srcs.items() if x is not None} == calls  # judged FIRST: no selection source ran
    assert flow.destination.snapshot()["effects"] == {} and flow.records.load().refusals == []


def test_e04_the_held_state_is_judged_at_the_commit_gate_too(tmp_path):
    p, res, cfg, srcs, flow, d = S.authorized(tmp_path)
    real = srcs["u"].__call__

    class Tamper(T.Source):
        def __call__(self_inner):
            out = real()
            if self_inner.calls >= 4:  # the commit-gate read
                flow.identity_max_age_seconds = 59
            return out
    srcs["u"].__class__ = Tamper
    attempt, _ = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "failed" and attempt.error == pol.REJECTION_CODE and flow.governed_last_commit_refusal.code == "scalars_modified"
    assert flow.destination.snapshot()["effects"] == {}


# ======================================================================================================================== never removes a refusal
def test_f01_a_matching_binding_does_not_remove_a_base_refusal(tmp_path):
    p, res, cfg, srcs, flow, d = S.authorized(tmp_path)
    gid = d.binding.grant_id
    res.statuses[gid] = res.statuses[gid].model_copy(update={"status": "revoked"})
    n = len(flow.records.load().refusals)
    with pytest.raises(PermissionError, match="authorization-critical inputs changed"):
        flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    ref = flow.records.load().refusals[n]
    assert ref.reasons and CODE not in ref.reasons  # the base reason stands alone: the binding matched
    assert flow.destination.snapshot()["effects"] == {}


def test_f02_a_changed_configuration_plus_a_base_refusal_keeps_the_base_reasons(tmp_path):
    p, res, cfg, srcs, flow, d = S.authorized(tmp_path)
    gid = d.binding.grant_id
    res.statuses[gid] = res.statuses[gid].model_copy(update={"status": "revoked"})
    other = S.mk(tmp_path, res, cfg, T.families(None, srcs["a"], srcs["u"]), status_max_age_seconds=59)
    n = len(other.records.load().refusals)
    with pytest.raises(PermissionError):
        other.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    base_only = other.records.load().refusals[n].reasons
    assert base_only and other.destination.snapshot()["effects"] == {}
    res.statuses[gid] = res.statuses[gid].model_copy(update={"status": "active"})
    ref = assert_binding_refusal(other, p, d)
    assert ref.reasons == [CODE]  # with the base refusal gone the binding alone refuses


def test_f03_an_attempt_already_failed_still_blocks_a_retry_and_the_binding_does_not_unblock_it(tmp_path):
    p, res, cfg, srcs, flow, d = S.authorized(tmp_path)
    srcs["u"].after = (4, T.revoked_for("u"))
    attempt, _ = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "failed"
    srcs["u"].after = None
    with pytest.raises(PermissionError, match="retry eligibility"):
        flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert flow.destination.snapshot()["effects"] == {}


# ================================================================================================================================= pin-export claim
def pin_decision(tmp_path, **top):
    p, res, profile, binding = S.pin_prepared(tmp_path / "work")
    store = tmp_path / "store"
    store.mkdir()
    flow = S.pin_governed(store, res, profile, **top)
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    return p, res, profile, binding, store, flow, d


def active(flow, p, d, binding):
    return assess_authorization_pin(flow, p, flow.records.decision(d.decision_id), now=NOW, host_policy_binding=binding)


def test_g01_the_pin_export_claim_path_accepts_the_same_configuration_after_restart(tmp_path):
    p, res, profile, binding, store, flow, d = pin_decision(tmp_path)
    assert d.binding.runtime_authority[ecb.KEY]["version"] == ecb.VERSION and d.binding.runtime_authority["policy_generation"] == 1
    assert active(flow, p, d, binding)["state"] == "active"
    restarted = S.pin_governed(store, res, profile)
    assert restarted.configuration_binding_status(restarted.records.decision(d.decision_id)) == ecb.BOUND
    assert active(restarted, p, d, binding)["state"] == "active"


@pytest.mark.parametrize("drift", [dict(identity_max_age_seconds=59), dict(clock_tolerance_seconds=6), dict(obs=ObservationPolicy(max_age_seconds=299)), dict(obs=None),
                                  dict(status_max_age_seconds=25)])  # F4 is declared here: min(25, Registry 30)
def test_g02_the_pin_export_claim_path_does_not_report_active_under_a_drifted_configuration(tmp_path, drift):
    p, res, profile, binding, store, flow, d = pin_decision(tmp_path)
    drifted = S.pin_governed(store, res, profile, **drift)
    assert drifted.runtime_authority_profile.model_dump() == flow.runtime_authority_profile.model_dump()
    assert drifted.configuration_binding_status(drifted.records.decision(d.decision_id)) == ecb.MISMATCH
    out = active(drifted, p, d, binding)
    assert out["state"] != "active" and out["payload"] is None


def test_g03_a_stripped_or_corrupt_member_is_not_active_on_the_pin_export_path(tmp_path):
    p, res, profile, binding, store, flow, d = pin_decision(tmp_path)
    S.rewrite_member(store, d.decision_id, mutate_member(lambda m: m.__setitem__("digest", "sha256:" + "7" * 64)))
    out = active(flow, p, d, binding)
    assert out["state"] != "active" and out["payload"] is None
    S.rewrite_member(store, d.decision_id, lambda b: b["runtime_authority"].pop(ecb.KEY))
    out = active(flow, p, d, binding)
    assert out["state"] != "active" and out["payload"] is None
    cut = S.pin_governed(store, res, profile, legacy_cutoff=1)  # explicit cutoff: previous semantics for this one legacy-position decision
    assert cut.configuration_binding_status(cut.records.decision(d.decision_id)) == ecb.LEGACY
    assert active(cut, p, d, binding)["state"] == "active"


# ============================================================================================================== compatibility and structure
def test_h01_approval_commitment_and_catalogue_digest_are_byte_identical_to_the_prior_binary(tmp_path):
    """The legacy fixture was generated by the UNCHANGED prior code (b7eb11a) for the same configuration."""
    meta = json.loads((T.Path(__file__).parent / "fixtures" / "d06_legacy_store_meta.json").read_text())["composed"]
    p, res, cfg, srcs, flow, d = S.authorized(tmp_path, f=True)
    ra = d.binding.runtime_authority
    assert ra["catalogue_digest"] == meta["catalogue_digest"] and ra["approval_commitment"] == meta["approval_commitment"]
    assert sorted(set(ra) - {ecb.KEY}) == meta["runtime_authority_keys"]


def test_h02_the_activation_ledger_configuration_digest_is_unchanged_by_the_shared_scope_helper(tmp_path):
    pins = json.loads((T.Path(__file__).resolve().parents[1] / "docs/evidence/d06/ledger-digests-b7eb11a.json").read_text())
    p, res, cfg, srcs, flow = S.ready(tmp_path / "a", f=True)
    assert flow.registry_governed_policy_identity["configuration_digest"] == pins["composed_f_a_u"]
    p2 = T.base.tenant_proposal()
    res2 = T.base.tenant_resolver_for(p2)
    only = S.mk(tmp_path / "b", res2, None, T.families(f=T.fsrc()))
    assert only.registry_governed_policy_identity["configuration_digest"] == pins["f4_only_noprofile"]


def test_h03_the_digests_of_the_binding_and_of_the_ledger_are_distinct_values_of_distinct_material(tmp_path):
    p, res, cfg, srcs, flow = S.ready(tmp_path)
    assert flow.effective_configuration_binding["digest"] != flow.registry_governed_policy_identity["configuration_digest"]


def test_h04_the_same_configuration_gives_the_same_binding_digest_across_constructions_and_clocks(tmp_path):
    p, res, cfg, srcs, flow = S.ready(tmp_path / "a")
    other = S.mk(tmp_path / "b", res, cfg, T.families(None, srcs["a"], srcs["u"]))
    assert other.effective_configuration_binding == flow.effective_configuration_binding  # `evaluated_at` is not a member


def test_h05_the_dedicated_single_family_workflows_do_not_bind_and_are_unchanged(tmp_path):
    """Documented scope limit: the three dedicated family workflows (F4, class age, class unreadable) keep no configuration hook in this change (their modules are outside the
    authorized file set); the composed `GovernedPolicyWorkflow` is the governed lifecycle that binds. They mint nothing, so their records are byte-identical to before."""
    p = T.base.tenant_proposal()
    res = T.base.tenant_resolver_for(p)
    from agent_control_plane import registry_f4_age_governance as f4gov
    wf = f4gov.GovernedAgeWorkflow(scope=T.SCOPE_F, selection_source=T.fsrc(), verifier=S.ev.Ed25519Verifier(), construction_time=S.REG_NOW, **T.kwargs(tmp_path, res))
    d = wf.decide(p, now=NOW)
    assert d.result == "authorized" and d.binding.runtime_authority is None
    assert wf.configuration_binding_status(d) is None
    assert_executes(wf, p, d)


def test_h06_no_reason_code_is_introduced_and_the_member_never_enters_an_approval(tmp_path):
    """The refusal reuses the code registered since runtime-authority-reasons/0.1; the lifecycle and the binding module never touch `approval_commitment` or the catalogue digest."""
    import ast
    from agent_control_plane import runtime_authority as ra
    assert life.BINDING_CHANGED == CODE
    for version in ("0_1", "0_2", "0_3"):
        schema = json.loads((T.Path(__file__).resolve().parents[1] / "schemas" / f"runtime_authority_reasons_{version}.json").read_text())
        assert CODE in schema["codes"]
    assert ra.vocabulary_for([CODE]) == "runtime-authority-reasons/0.1"
    code = (T.SRC / "effective_configuration_binding.py").read_text()
    assert "approval_commitment" not in code and "catalogue_digest" not in code
    assert "approval_commitment" not in ast.unparse(ast.parse((T.SRC / "registry_governed_lifecycle.py").read_text()))
    sig = approval_commitment.__code__.co_varnames[:approval_commitment.__code__.co_argcount]
    assert "effective_configuration" not in sig and "configuration" not in sig
