"""FINAL3 composed-workflow and D-06 binding oracles for the three r08-v8 families: all families together with the existing six, the persisted effective-configuration
binding (members.families / members.observation_policy), snapshot identity, restart / rebuild / cross-process replay, byte-identical pre-existing identities, protected files.

BUILDER_TESTED developer evidence. NOT independently qualified. NOT an authorization mechanism. Needs the Registry r08-v8 pin (a40fe75) and PyNaCl; real synthetic Ed25519.
"""
from __future__ import annotations

import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

from tests.final3_support import *  # noqa: F401,F403  (enforces the r08-v8 pin)
import tests.final3_support as F
import agent_control_plane.bounded as bounded
from agent_control_plane import effective_configuration_binding as ecb
from agent_control_plane import registry_effective_policy as eff
from agent_control_plane.authorization_pin_export import assess_authorization_pin
from agent_control_plane.registry_governed_policy import RegistryGovernedPolicyRefused
from tests import d06_support as D
from tests.test_effective_configuration_binding import CODE, assert_binding_refusal, assert_executes

ROOT = Path(__file__).resolve().parents[1]
BASE = {"anc": "anchor", "age": 60, "tol": 2}


@pytest.fixture(autouse=True)
def _fixed_synthetic_clock(monkeypatch):
    D.patch_clock(monkeypatch)


def stage(tmp_path, conf=BASE, flag=False, **kw):
    p, res, cfg = base.prepared(tmp_path / "w", t1=R_, freshness=FreshnessProfile(anchor_deadline_to_inputs=flag))
    store = tmp_path / "store"
    store.mkdir(exist_ok=True)
    flow = make(store, res, cfg, conf)
    bind_approval(res, flow.runtime_authority_profile)
    return p, res, cfg, store, flow


def authorized(tmp_path, conf=BASE, flag=False):
    p, res, cfg, store, flow = stage(tmp_path, conf, flag)
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    return p, res, cfg, store, flow, d


def rebuild(store, res, cfg, conf):
    wf = make(store, res, cfg, conf)
    bind_approval(res, wf.runtime_authority_profile)
    return wf


# ------------------------------------------------------------------------------------------------------------------------------ the binding carries the new families
def test_a01_the_three_families_appear_in_the_binding_with_slot_family_contract_revision_and_digest(tmp_path):
    p, res, cfg, store, flow, d = authorized(tmp_path)
    m = d.binding.runtime_authority[ecb.KEY]["members"]
    assert m == flow.effective_configuration_binding["members"] and ecb.record_defect(d.binding.runtime_authority[ecb.KEY]) is None
    assert m["families"] == [
        {"slot": "anchor_deadline", "family_id": ANC, "contract_version": "r08-v8", "family_schema_revision": 1,
         "effective_policy_digest": v8id.effective_policy_digest(ANC, {FIELDS[ANC]: "anchor"}, "r08-v8")},
        {"slot": "observation_max_age", "family_id": AGE, "contract_version": "r08-v8", "family_schema_revision": 1,
         "effective_policy_digest": v8id.effective_policy_digest(AGE, {FIELDS[AGE]: 60}, "r08-v8")},
        {"slot": "observation_clock_tolerance", "family_id": TOL, "contract_version": "r08-v8", "family_schema_revision": 1,
         "effective_policy_digest": v8id.effective_policy_digest(TOL, {FIELDS[TOL]: 2}, "r08-v8")}]
    assert m["observation_policy"] == {"max_age_seconds": 60, "clock_tolerance_seconds": 2}  # EFFECTIVE values, not the host 300 / 5
    assert m["other_scalars"]["clock_tolerance_seconds"] == 5  # the CONSTRUCTOR tolerance is bound for equality only and is untouched
    assert m["effective_profile_digest"] == d.binding.runtime_authority["catalogue_digest"] != m["host_profile_digest"]
    assert flow.configuration_binding_status(d) == ecb.BOUND


def test_a02_families_not_declared_are_absent_so_the_declared_set_is_part_of_the_identity(tmp_path):
    p, res, cfg, store, flow = stage(tmp_path / "a", {"age": 60})
    assert [r["slot"] for r in flow.effective_configuration_binding["members"]["families"]] == ["observation_max_age"]
    p, res, cfg, store, flow2 = stage(tmp_path / "b", {"tol": 0})
    assert [r["slot"] for r in flow2.effective_configuration_binding["members"]["families"]] == ["observation_clock_tolerance"]
    assert flow.effective_configuration_binding["digest"] != flow2.effective_configuration_binding["digest"]


def test_a03_the_binding_digest_is_a_function_of_every_new_family_value_and_of_the_host_values(tmp_path):
    digests = {}
    for name, conf, flag in (("base", BASE, False), ("anc_no_change", dict(BASE, anc="no_change"), False), ("age61", dict(BASE, age=61), False), ("tol3", dict(BASE, tol=3), False),
                             ("host_obs", dict(BASE, host=[59, 5]), False), ("host_tol", dict(BASE, host=[300, 1]), False), ("no_anc", {"age": 60, "tol": 2}, False),
                             ("no_age", {"anc": "anchor", "tol": 2}, False), ("no_tol", {"anc": "anchor", "age": 60}, False), ("host_flag", BASE, True)):
        flow = stage(tmp_path / name, conf, flag)[4]
        digests[name] = flow.effective_configuration_binding["digest"]
    assert len(set(digests.values())) == len(digests), digests


# ------------------------------------------------------------------------------------------------------------------------------ restart / rebuild / drift
def test_b01_a_rebuild_with_the_same_configuration_accepts_the_persisted_decision(tmp_path):
    p, res, cfg, store, flow, d = authorized(tmp_path)
    again = rebuild(store, res, cfg, BASE)
    assert again.configuration_binding_status(again.records.decision(d.decision_id)) == ecb.BOUND
    assert_executes(again, p, d)


DRIFTS = {
    "registry_anchor_no_change": dict(BASE, anc="no_change"), "registry_age_61": dict(BASE, age=61), "registry_age_59": dict(BASE, age=59), "registry_tol_3": dict(BASE, tol=3),
    "registry_tol_0": dict(BASE, tol=0), "host_age": dict(BASE, host=[59, 5]), "host_tol": dict(BASE, host=[300, 1]),
    "family_dropped_age": {"anc": "anchor", "tol": 2}, "family_dropped_tol": {"anc": "anchor", "age": 60}, "family_dropped_anchor": {"age": 60, "tol": 2},
    "family_added_nothing_else_changes": None,
}


@pytest.mark.parametrize("name", sorted(k for k, v in DRIFTS.items() if v is not None))
def test_b02_execute_refuses_authorization_binding_changed_when_any_new_family_value_or_the_declared_set_changes(tmp_path, name):
    p, res, cfg, store, flow, d = authorized(tmp_path)
    drifted = rebuild(store, res, cfg, DRIFTS[name])
    assert drifted.configuration_binding_status(drifted.records.decision(d.decision_id)) != ecb.BOUND
    before = drifted.destination.snapshot()
    with pytest.raises(PermissionError, match="authorization-critical inputs changed|approval|binding"):
        drifted.execute(p, drifted.records.decision(d.decision_id), adapter_id=p.adapter_id, now=NOW)
    assert drifted.destination.snapshot() == before and effects(drifted) == {}


@pytest.mark.parametrize("name,conf", [("host_age", dict(BASE, host=[59, 5])), ("host_tol", dict(BASE, host=[300, 1])), ("registry_tol_3", dict(BASE, tol=3)),
                                       ("registry_age_61", dict(BASE, age=61)), ("registry_tol_0", dict(BASE, tol=0))])
def test_b03_a_change_that_leaves_the_profile_identical_is_refused_by_the_binding_itself(tmp_path, name, conf):
    p, res, cfg, store, flow, d = authorized(tmp_path)
    drifted = rebuild(store, res, cfg, conf)
    assert drifted.runtime_authority_profile.model_dump() == flow.runtime_authority_profile.model_dump()  # only the observation values moved
    assert_binding_refusal(drifted, p, d)  # status mismatch, registered reason authorization_binding_changed, no attempt, destination untouched


def test_b03b_a_host_value_that_the_narrower_registry_value_fully_masks_does_not_change_the_effective_configuration_and_is_accepted(tmp_path):
    """HONEST LIMIT (frozen D-06 contract: the binding carries the EFFECTIVE observation values, not the host's): a host change that leaves every effective value and every Registry
    digest unchanged (host 300 -> 299 under a Registry value of 60) is not a change of what the workflow enforces, so it is accepted. A host change that moves an effective value
    (host below the Registry value) is refused (test_b03)."""
    p, res, cfg, store, flow, d = authorized(tmp_path)
    masked = rebuild(store, res, cfg, dict(BASE, host=[299, 5]))
    assert (masked.observation_policy.max_age_seconds, masked.observation_policy.clock_tolerance_seconds) == (60, 2)
    assert masked.configuration_binding_status(masked.records.decision(d.decision_id)) == ecb.BOUND


def test_b04_dropping_the_observation_ctor_scalar_or_changing_the_constructor_tolerance_still_refuses(tmp_path):
    p, res, cfg, store, flow, d = authorized(tmp_path)
    for conf in (dict(BASE, ctor_tol=6), dict(BASE, identity=59)):
        assert_binding_refusal(rebuild(store, res, cfg, conf), p, d)


def test_b05_a_host_policy_removed_on_rebuild_refuses_construction_not_a_synthesized_default(tmp_path):
    p, res, cfg, store, flow, d = authorized(tmp_path)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        make(store, res, cfg, dict(BASE, host="none"))
    refused(e, "host_observation_policy_missing", "construction")


def test_b06_a_stripped_or_corrupt_member_is_refused_for_the_new_families_too(tmp_path):
    p, res, cfg, store, flow, d = authorized(tmp_path)
    D.rewrite_member(store, d.decision_id, lambda b: b["runtime_authority"].pop(ecb.KEY))
    again = rebuild(store, res, cfg, BASE)
    assert again.configuration_binding_status(again.records.decision(d.decision_id)) == ecb.UNBOUND_AFTER_CUTOFF
    with pytest.raises(PermissionError):
        again.execute(p, again.records.decision(d.decision_id), adapter_id=p.adapter_id, now=NOW)


def test_b07_a_persisted_member_whose_observation_values_are_the_host_ones_is_a_mismatch(tmp_path):
    p, res, cfg, store, flow, d = authorized(tmp_path)

    def host_values(b):
        m = b["runtime_authority"][ecb.KEY]
        m["members"]["observation_policy"] = {"max_age_seconds": 300, "clock_tolerance_seconds": 5}
        m["digest"] = ecb.digest_of(ecb.VERSION, m["members"])  # internally consistent, so it is a MISMATCH and not an invalid record
    D.rewrite_member(store, d.decision_id, host_values)
    again = rebuild(store, res, cfg, BASE)
    assert again.configuration_binding_status(again.records.decision(d.decision_id)) == ecb.MISMATCH


# ------------------------------------------------------------------------------------------------------------------------------ cross-process
def run_worker(store, decision_id, **conf):
    env = dict(os.environ, PYTHONPATH=os.pathsep.join([str(ROOT / "src"), str(ROOT)]))
    proc = subprocess.run([sys.executable, "-m", "tests.final3_worker", str(store), decision_id, json.dumps(conf)], cwd=ROOT, env=env, capture_output=True, text=True, timeout=300)
    assert proc.returncode == 0, proc.stderr[-2000:]
    return json.loads(proc.stdout.strip().splitlines()[-1])


def test_c01_a_separate_process_replays_the_same_configuration(tmp_path):
    p, res, cfg, store, flow, d = authorized(tmp_path)
    out = run_worker(store, d.decision_id, **BASE)
    assert out["outcome"] == "executed" and out["status"] == ecb.BOUND, out
    assert len(flow.destination.snapshot()["effects"]) == 1


@pytest.mark.parametrize("change", [dict(age=61), dict(age=59), dict(tol=3), dict(tol=0), dict(anc="no_change"), dict(host=[59, 5]), dict(host=[300, 1]), dict(host="none"),
                                    dict(ctor_tol=6)])
def test_c02_a_separate_process_refuses_when_any_new_family_value_changes(tmp_path, change):
    p, res, cfg, store, flow, d = authorized(tmp_path)
    out = run_worker(store, d.decision_id, **dict(BASE, **change))
    assert out["outcome"] in ("refused", "construction_refused"), out
    assert effects(flow) == {}
    if change.get("host") != "none" and out["outcome"] == "refused":
        assert out["status"] != ecb.BOUND


# ------------------------------------------------------------------------------------------------------------------------------ pin export
def pin_flow(store, res, cfg, age=60, tol=2, host=(300, 5)):
    from agent_control_plane.bounded import BoundedRecordStore
    kw = dict(allow_test_time=True, manifest=D._manifest(), resolver=res, destination=LocalRefundDestination(Path(store) / "destination.json"),
              records=BoundedRecordStore(Path(store) / "run.json", "run-1"), observation_policy=op(*host))
    return GovernedPolicyWorkflow(families=fams(age=Source(mat(AGE, age)) if age else None, tol=Source(mat(TOL, tol)) if tol is not None else None), verifier=ev.Ed25519Verifier(),
                                  runtime_authority_profile=cfg, construction_time=REG_NOW, **kw)


def pin_decision(tmp_path):
    p, res, cfg, binding = D.pin_prepared(tmp_path / "work")
    store = tmp_path / "store"
    store.mkdir()
    flow = pin_flow(store, res, cfg)
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    return p, res, cfg, binding, store, flow, d


def active(flow, p, d, binding):
    return assess_authorization_pin(flow, p, flow.records.decision(d.decision_id), now=NOW, host_policy_binding=binding)


def test_d01_the_pin_export_claim_path_accepts_the_same_configuration_and_refuses_every_drift(tmp_path):
    p, res, cfg, binding, store, flow, d = pin_decision(tmp_path)
    assert active(flow, p, d, binding)["state"] == "active"
    assert active(pin_flow(store, res, cfg), p, d, binding)["state"] == "active"
    for drift in (dict(age=61), dict(age=59), dict(tol=3), dict(tol=0), dict(age=None), dict(tol=None), dict(host=(59, 5)), dict(host=(300, 1))):
        drifted = pin_flow(store, res, cfg, **dict(dict(age=60, tol=2, host=(300, 5)), **drift))
        assert drifted.configuration_binding_status(drifted.records.decision(d.decision_id)) == ecb.MISMATCH, drift
        out = active(drifted, p, d, binding)
        assert out["state"] != "active" and out["payload"] is None, drift


# ------------------------------------------------------------------------------------------------------------------------------ all nine families together
def nine(tmp_path, **kw):
    p, res, cfg = base.prepared(tmp_path, t1=R_, freshness=FreshnessProfile())
    cfg = rv.with_inventory(cfg)
    srcs = irt.sources(ir_={CLASS_T1: irt.IRR}, ra={CLASS_T1: rv.RQ}, tr="on", f=True, a=True, u=True)
    six = irt.fams(srcs["ir"], srcs["ra"], srcs["tr"], srcs["f"], srcs["a"], srcs["u"])
    families = fams(anc=Source(mat(ANC)), age=Source(mat(AGE, 60)), tol=Source(mat(TOL, 2)), base_fams=six)
    flow = build(tmp_path, res, cfg, families, **kw)
    bind_approval(res, flow.runtime_authority_profile)
    return p, res, cfg, srcs, flow


def test_e01_all_nine_families_compose_authorize_and_execute_in_the_fixed_order(tmp_path):
    p, res, cfg, srcs, flow = nine(tmp_path)
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    rows = d.binding.runtime_authority[ecb.KEY]["members"]["families"]
    assert [r["slot"] for r in rows] == ["f4_ages", "class_age", "class_unreadable", "class_revocation_assurance", "class_irreversible", "anchor_deadline",
                                          "observation_max_age", "observation_clock_tolerance", "terminal_revocation"]
    assert [r["slot"] for r in rows] == list(pol.FAMILY_NAMES) and [flow.effective_policy_snapshot.families[i].slot for i in range(9)] == list(pol.FAMILY_NAMES)
    assert flow.runtime_authority_profile.freshness.anchor_deadline_to_inputs is True and flow.runtime_authority_profile.actions[ACTION_ID].irreversible is True
    attempt, observed = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and observed.state == "applied"


def test_e02_the_existing_six_rows_and_the_six_family_final_profile_are_unchanged_by_the_new_slots(tmp_path):
    p, res, cfg, srcs, flow9 = nine(tmp_path / "n")
    p2, res2, cfg2 = base.prepared(tmp_path / "s", t1=R_, freshness=FreshnessProfile())
    cfg2 = rv.with_inventory(cfg2)
    srcs2 = irt.sources(ir_={CLASS_T1: irt.IRR}, ra={CLASS_T1: rv.RQ}, tr="on", f=True, a=True, u=True)
    flow6 = build(tmp_path / "s", res2, cfg2, irt.fams(srcs2["ir"], srcs2["ra"], srcs2["tr"], srcs2["f"], srcs2["a"], srcs2["u"]))
    six_rows = flow6.effective_configuration_binding["members"]["families"]
    nine_rows = [r for r in flow9.effective_configuration_binding["members"]["families"] if r["slot"] in {x["slot"] for x in six_rows}]
    assert nine_rows == six_rows
    a, b = flow9.runtime_authority_profile.model_dump(mode="json"), flow6.runtime_authority_profile.model_dump(mode="json")
    a["freshness"].pop("anchor_deadline_to_inputs")
    assert a == b  # only the anchor flag differs
    assert flow6.runtime_authority_profile.freshness.anchor_deadline_to_inputs is False
    assert flow9.registry_governed_policy_identity["configuration_digest"] != flow6.registry_governed_policy_identity["configuration_digest"]


@pytest.mark.parametrize("drop", ["anc", "age", "tol", "irreversible", "terminal"])
def test_e03_each_of_the_nine_is_mandatory_a_failing_source_refuses_the_whole_workflow(tmp_path, drop):
    p, res, cfg, srcs, flow = nine(tmp_path)
    d = flow.decide(p, now=NOW)
    target = {"anc": flow._gp_families.anchor_deadline, "age": flow._gp_families.observation_max_age, "tol": flow._gp_families.observation_clock_tolerance,
              "irreversible": flow._gp_families.class_irreversible, "terminal": flow._gp_families.terminal_revocation}[drop]
    target.selection_source.fail = True
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert e.value.refusal.code == "selection_source_failed" and effects(flow) == {}


def test_e04_the_nine_family_snapshot_is_deterministic_and_covers_the_new_families(tmp_path):
    p, res, cfg, srcs, flow = nine(tmp_path)
    snap = flow.effective_policy_snapshot
    for slot, fam, val in (("anchor_deadline", ANC, (("anchor_deadline_to_inputs", "anchor"),)), ("observation_max_age", AGE, ((FIELDS[AGE], 60),)),
                           ("observation_clock_tolerance", TOL, ((FIELDS[TOL], 2),))):
        f = snap.family(slot)
        assert (f.family_id, f.contract_version, f.family_schema_revision, f.effective) == (fam, "r08-v8", 1, val) and f.selection_id and f.selection_epoch is not None
        assert f.effective_policy_digest == v8id.effective_policy_digest(fam, dict(val), "r08-v8")
    snap_dict = eff.resolve_effective_policy(families=flow._gp_families, host=flow._gp_host, host_scalars=flow._gp_host_scalars,
                                             materials={n: f.selection_source() for n, f in pol._declared(flow._gp_families)}, verifier=ev.Ed25519Verifier(),
                                             institution_id=base.INSTITUTION, authority_domain=base.DOMAIN, now=REG_NOW, host_ages=flow._gp_host_ages,
                                             host_values=flow._gp_host_values, host_assurance=flow._gp_host_assurance, host_irreversible=flow._gp_host_irreversible,
                                             host_terminal=flow._gp_host_terminal, host_observation=flow._gp_host_observation)
    assert snap_dict.identity_digest == snap.identity_digest


@pytest.mark.parametrize("change", [dict(anc="no_change"), dict(age=61), dict(tol=3)])
def test_e05_the_snapshot_identity_changes_when_any_new_family_changes(tmp_path, change):
    a = stage(tmp_path / "a", BASE)[4].effective_policy_snapshot.identity_digest
    b = stage(tmp_path / "b", dict(BASE, **change))[4].effective_policy_snapshot.identity_digest
    assert a != b


# ------------------------------------------------------------------------------------------------------------------------------ pre-existing identities, protected files, vectors
def test_f01_workflows_without_the_new_families_keep_their_pinned_configuration_digests(tmp_path):
    pins = json.loads((ROOT / "docs/evidence/d06/ledger-digests-b7eb11a.json").read_text())
    p, res, cfg, srcs, flow = D.ready(tmp_path / "a", f=True)
    assert flow.registry_governed_policy_identity["configuration_digest"] == pins["composed_f_a_u"]
    only = D.mk(tmp_path / "b", D.tenant_resolver_for(D.tenant_proposal()), None, D.T.families(f=D.T.fsrc()))
    assert only.registry_governed_policy_identity["configuration_digest"] == pins["f4_only_noprofile"]
    full = irt.ready(tmp_path / "c", ir_={CLASS_T1: irt.IRR}, f=True, a=True, u=True, host=rv.with_inventory)[4]
    assert full.registry_governed_policy_identity["configuration_digest"] == pins["irreversible_f_a_u"]
    assert flow.effective_configuration_binding["members"]["observation_policy"] == {"max_age_seconds": 300, "clock_tolerance_seconds": 5}


def test_f02_the_registry_vectors_of_the_three_families_are_pinned():
    assert v8id.effective_policy_digest(AGE, {FIELDS[AGE]: 60}, "r08-v8") == "sha256:5c4f58a3713719a5399534314927a843228f59da09b0bb362202239313a02bdc"  # docs/r08-v8-contract.md section 3.4
    vectors = json.loads((Path(base.PIN_DIR) / "tests/vectors/r08v8/identity_vectors.json").read_text())
    rows = vectors["vectors"] if isinstance(vectors, dict) and "vectors" in vectors else vectors
    assert len(rows) >= 9


def test_f03_the_protected_evaluators_are_byte_identical_to_the_integration_base():
    base_sha = subprocess.run(["git", "rev-parse", "86148b6"], cwd=ROOT, capture_output=True, text=True).stdout.strip()
    if not base_sha:
        pytest.fail("the integration base commit is not available in this checkout")
    for name in ("bounded.py", "runtime_authority.py", "freshness.py", "policy_binding.py", "rule_revision.py", "reversibility.py", "holder_inventory.py"):
        old = subprocess.run(["git", "show", f"{base_sha}:src/agent_control_plane/{name}"], cwd=ROOT, capture_output=True).stdout
        assert hashlib.sha256((SRC / name).read_bytes()).hexdigest() == hashlib.sha256(old).hexdigest(), name
    assert not list((ROOT / "schemas").glob("*.new"))


def test_f04_the_new_module_adds_no_workflow_class_no_evaluator_import_and_no_new_reason_code():
    import ast
    tree = ast.parse((SRC / "registry_final3_governance.py").read_text())
    assert [n.name for n in ast.walk(tree) if isinstance(n, ast.ClassDef)] == []
    imported = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module}
    assert not any(m.endswith(("freshness", "policy_binding", "holder_inventory", "reversibility", "rule_revision")) for m in imported), imported
    for node in ast.walk(tree):  # docstrings are prose, not code
        if isinstance(node, (ast.Module, ast.FunctionDef)) and node.body and isinstance(node.body[0], ast.Expr) and isinstance(getattr(node.body[0], "value", None), ast.Constant):
            node.body = node.body[1:] or [ast.Pass()]
    code = ast.unparse(tree)
    assert "eval(" not in code and "exec(" not in code and "approval_commitment" not in code
    assert "authorization_binding_changed" not in code and "observation_stale" not in code  # the module introduces and emits no durable reason code


def test_g01_a_host_change_masked_by_the_registry_value_still_changes_the_activation_ledger_identity(tmp_path):
    """The activation ledger identity covers the HOST observation values (unlike the persisted binding, which carries the effective ones): a differently configured second workflow
    for the same scope is refused even when both enforce the same effective policy."""
    a = stage(tmp_path / "a", BASE)[4]
    b = stage(tmp_path / "b", dict(BASE, host=[299, 5]))[4]
    assert a.registry_governed_policy_identity["configuration_digest"] != b.registry_governed_policy_identity["configuration_digest"]
    assert a.effective_configuration_binding["digest"] == b.effective_configuration_binding["digest"]
    ledger = pol.GovernedActivationLedger()
    p, res, cfg = base.prepared(tmp_path / "l", t1=R_, freshness=FreshnessProfile())
    build(tmp_path / "l", res, cfg, fams(anc=Source(mat(ANC)), age=Source(mat(AGE, 60))), activation_ledger=ledger)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path / "l2", res, cfg, fams(anc=Source(mat(ANC)), age=Source(mat(AGE, 60))), obs=op(299, 5), activation_ledger=ledger)
    refused(e, "conflicting_governed_configuration", "construction")


def test_g02_the_configuration_digest_is_a_function_of_the_anchor_state_and_of_every_declared_family(tmp_path):
    ids = {}
    for name, conf, flag in (("base", BASE, False), ("flag", BASE, True), ("no_anc", {"age": 60, "tol": 2}, False), ("no_tol", {"anc": "anchor", "age": 60}, False)):
        ids[name] = stage(tmp_path / name, conf, flag)[4].registry_governed_policy_identity["configuration_digest"]
    assert len(set(ids.values())) == 4
