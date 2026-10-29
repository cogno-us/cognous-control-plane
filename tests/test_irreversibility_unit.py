"""Unit tests of the Registry-governed `ActionClass.irreversible` derivation (`registry_irreversibility_governance`), the final-composition validator and the immutable
`EffectivePolicySnapshot` (`registry_effective_policy`) that need NO Registry checkout and NO Ed25519: the Registry is replaced by explicit named FAKES of its RESULT, so these
tests run in every environment (they are not skipped without `OCS_REGISTRY_PIN_DIR`). The signed end-to-end tests are in `tests/test_irreversibility_governance.py`.

BUILDER_TESTED developer evidence. NOT independently qualified. NOT an authorization mechanism.
"""
from __future__ import annotations

import dataclasses
from dataclasses import dataclass
from datetime import datetime, timezone
from types import SimpleNamespace
from typing import Any, Optional

import pytest

from agent_control_plane import registry_effective_policy as eff
from agent_control_plane import registry_governed_policy as pol
from agent_control_plane import registry_irreversibility_governance as ir
from agent_control_plane.registry_governed_lifecycle import GovernedScope, Refusal, SelectionMaterial
from agent_control_plane.runtime_authority import ActionClass, RuntimeAuthorityProfile
from tests.test_runtime_authority import PUBLIC

NOW = datetime(2026, 10, 5, 12, 0, tzinfo=timezone.utc)
T1, T2 = "cls-reversible", "cls-irreversible"
A1, A2 = "urn:cognous:action:a1-v1", "urn:cognous:action:a2-v1"
IRR, NC = "irreversible", "no_change"
FIELD = ir.FIELD_IR
SCOPE = GovernedScope("consumer-test", "tenant-test", A1, "op-irreversible")
SCALARS = {"status_max_age_seconds": 60, "approval_max_age_seconds": 60}


def profile(*, a1=None, a2=None, **extra):
    actions = {A1: a1 or ActionClass(class_id=T1, irreversible=False, on_unreadable="refuse"), A2: a2 or ActionClass(class_id=T2, irreversible=True, on_unreadable="refuse")}
    return RuntimeAuthorityProfile(catalogue_version="synthetic-catalogue/1", actions=actions, producer_keys={"synthetic-validator": PUBLIC}, allow_synthetic_resolver=True, **extra)


def flags(p):
    return {a.class_id: a.irreversible for a in p.actions.values()}


class _Str(str):
    pass


# --------------------------------------------------------------------------------------------------------------- a fake Registry RESULT (named double, not a verdict)
@dataclass(frozen=True)
class FakeDecision:
    kind: str = "applied"
    effective: Any = None
    deny_all: bool = False
    deny_all_fields: tuple = ()
    code: Optional[str] = None
    detail: str = ""
    caller_unchanged: bool = False
    operationally_authorized: bool = False


class FakeVerifier:
    pass


def fake_registry(monkeypatch, result, *, digest=lambda family, payload, contract: "sha256:" + "ab" * 32, calls=None):
    def decide(participation, caller, record_text, selection_text, context, trust, verifier, now):
        if calls is not None:
            calls.append((participation, caller, record_text, selection_text, context, trust, verifier, now))
        if isinstance(result, Exception):
            raise result
        return result(caller, record_text) if callable(result) else result
    mods = (SimpleNamespace(PolicyDecision=FakeDecision), SimpleNamespace(ExpectedContext=lambda *a: a), SimpleNamespace(verify_and_decide_v7=decide),
            SimpleNamespace(effective_policy_digest=digest), FakeVerifier)
    monkeypatch.setattr(ir, "_registry_modules", lambda: mods)


def record_text(m):
    import json
    return json.dumps({"payload": {FIELD: m}})


def material(m=None):
    return SelectionMaterial(record_text(m if m is not None else {T1: IRR}), '{"statement":{"selection_id":"sel-1","epoch":1}}', object())


def derive(cfg, *, m=None, material_=None, verifier=None, scope=SCOPE, host_values=None):
    return ir.derive_irreversible(scope=scope, institution_id="inst", authority_domain="dom", host=cfg, host_values=host_values or ir.host_class_irreversible(cfg)[0],
                                  material=material_ if material_ is not None else material(m), verifier=verifier or FakeVerifier(), now=NOW)


def stricter(caller, record_text):
    import json
    try:
        reg = json.loads(record_text)["payload"][FIELD]
    except Exception:
        reg = {}
    return FakeDecision(effective={FIELD: {k: (IRR if IRR in (v, reg.get(k)) else NC) for k, v in caller[FIELD].items()}})


# =============================================================================================================== host values
def test_host_values_map_the_flag_per_class_and_fail_closed():
    assert ir.host_class_irreversible(profile()) == ({T1: NC, T2: IRR}, None)
    shared = profile(a2=ActionClass(class_id=T1, irreversible=True, on_unreadable="refuse"))
    assert ir.host_class_irreversible(shared) == (None, "class_irreversible_ambiguous")
    both = profile(a2=ActionClass(class_id=T1, irreversible=False, on_unreadable="refuse"))
    assert ir.host_class_irreversible(both) == ({T1: NC}, None)
    p = profile()
    bad_flag = p.model_copy(update={"actions": {**p.actions, A1: p.actions[A1].model_copy(update={"irreversible": 1})}})
    assert ir.host_class_irreversible(bad_flag) == (None, "host_class_irreversible_invalid")
    bad_id = p.model_copy(update={"actions": {**p.actions, A1: p.actions[A1].model_copy(update={"class_id": ""})}})
    assert ir.host_class_irreversible(bad_id) == (None, "host_class_irreversible_invalid")


def test_stricter_is_the_two_point_order():
    assert [ir.stricter_irreversible(a, b) for a in (IRR, NC) for b in (IRR, NC)] == [IRR, IRR, IRR, NC]


# =============================================================================================================== flip pre-check
CAUSES = [({"reversibility": "reversible_at_cost"}, "reversibility_declared"), ({"reversible_until": "2030-01-01T00:00:00+00:00"}, "reversible_until_declared"),
          ({"reversal_cost": "5"}, "reversal_cost_declared"), ({"on_unreadable": "bounded_tolerance"}, "on_unreadable_not_refuse"),
          ({"reads_protected_data": True}, "reads_protected_data"), ({"counterparty_observable": False}, "counterparty_observable_not_default")]


@pytest.mark.parametrize("update,cause", CAUSES)
def test_each_flip_condition_has_its_own_cause_and_only_a_flip_is_checked(update, cause):
    cl = ActionClass(class_id=T1, irreversible=False, on_unreadable="refuse").model_copy(update=update)
    assert ir.flip_causes(cl) == [cause]
    p = profile()
    forged = p.model_copy(update={"actions": {**p.actions, A1: cl}})
    values = {T1: NC, T2: IRR}
    assert ir.flip_conflict(forged, values, {T1: IRR, T2: IRR}) == "irreversible_flip_conflict:" + cause
    assert ir.flip_conflict(forged, values, {T1: NC, T2: IRR}) is None  # nothing flips
    assert ir.flip_conflict(forged, {T1: IRR, T2: IRR}, {T1: IRR, T2: IRR}) is None  # a host class that is already irreversible is not a flip


def test_a_clean_legacy_reversible_class_has_no_cause_and_all_causes_are_reported_in_a_fixed_order():
    assert ir.flip_causes(ActionClass(class_id=T1, irreversible=False, on_unreadable="refuse")) == []
    cl = ActionClass(class_id=T1, irreversible=False, on_unreadable="refuse").model_copy(update={"reversal_cost": "1", "reversible_until": "2030-01-01T00:00:00+00:00",
                                                                                                 "reversibility": "reversible_at_cost", "on_unreadable": "bounded_tolerance"})
    assert ir.flip_causes(cl) == list(ir.FLIP_CAUSES[:4])


def test_the_first_conflicting_action_in_sorted_order_is_reported():
    bad_a = ActionClass(class_id="cls-a", irreversible=False, on_unreadable="refuse").model_copy(update={"reversal_cost": "1"})
    bad_b = ActionClass(class_id="cls-b", irreversible=False, on_unreadable="refuse").model_copy(update={"reads_protected_data": True})
    p = profile()
    forged = p.model_copy(update={"actions": {"z-action": bad_b, "a-action": bad_a, **p.actions}})
    got = ir.flip_conflict(forged, {"cls-a": NC, "cls-b": NC, T1: NC, T2: IRR}, {"cls-a": IRR, "cls-b": IRR, T1: NC, T2: IRR})
    assert got == "irreversible_flip_conflict:reversal_cost_declared"


# =============================================================================================================== composer
def test_compose_only_ever_sets_true_and_changes_nothing_else():
    p = profile()
    flipped = ir.compose_irreversible(p, {T1: IRR, T2: IRR})
    assert flags(flipped) == {T1: True, T2: True}
    d0, d1 = p.model_dump(mode="json"), flipped.model_dump(mode="json")
    assert {(a, k) for a in d0["actions"] for k in d0["actions"][a] if d0["actions"][a][k] != d1["actions"][a][k]} == {(A1, "irreversible")}
    d0["actions"][A1].pop("irreversible"), d1["actions"][A1].pop("irreversible")
    assert d0 == d1
    assert flags(ir.compose_irreversible(p, {T1: NC, T2: NC})) == {T1: False, T2: True}  # a host true is never cleared, whatever `effective` says
    assert ir.compose_irreversible(p, {T1: NC, T2: IRR}).model_dump() == p.model_dump()
    with pytest.raises(KeyError):
        ir.compose_irreversible(p, {T2: IRR})  # an effective map that misses a host class is not silently completed


def test_every_action_of_a_class_flips():
    p = profile(a2=ActionClass(class_id=T1, irreversible=False, on_unreadable="refuse"))
    assert [a.irreversible for a in ir.compose_irreversible(p, {T1: IRR}).actions.values()] == [True, True]


# =============================================================================================================== derive (fake Registry result)
def test_a_valid_result_is_accepted_and_the_registry_is_asked_with_the_host_values(monkeypatch):
    calls = []
    seen = {}

    def digest(family, payload, contract):
        seen["args"] = (family, payload, contract)
        return "sha256:" + "cd" * 32
    fake_registry(monkeypatch, stricter, digest=digest, calls=calls)
    cfg = profile()
    got, refusal = derive(cfg)
    assert refusal is None and got == ({T1: IRR, T2: IRR}, "sha256:" + "cd" * 32)
    assert seen["args"] == (ir.FAMILY_IR, {FIELD: {T1: IRR, T2: IRR}}, "r08-v7")
    assert calls[0][0] == "required" and calls[0][1] == {FIELD: {T1: NC, T2: IRR}} and calls[0][4] == ("consumer-test", "tenant-test", "inst", "dom", "op-irreversible")


@pytest.mark.parametrize("result,code", [
    (FakeDecision(effective={FIELD: {T1: NC, T2: NC}}), "effective_policy_widens_host"),  # lowers the host true
    (FakeDecision(effective={FIELD: {T1: NC, T2: IRR}}), "effective_policy_invalid"),  # looser than the record for a named class
    (FakeDecision(effective={FIELD: {T1: IRR}}), "effective_policy_invalid"),  # a host class is missing
    (FakeDecision(effective={FIELD: {T1: IRR, T2: IRR, "x": NC}}), "effective_policy_invalid"),  # an invented class
    (FakeDecision(effective={FIELD: {T1: True, T2: IRR}}), "effective_policy_invalid"),
    (FakeDecision(effective={FIELD: {T1: "IRREVERSIBLE", T2: IRR}}), "effective_policy_invalid"),
    (FakeDecision(effective={FIELD: {T1: _Str(IRR), T2: IRR}}), "effective_policy_invalid"),  # a str subclass is not an exact value
    (FakeDecision(effective={FIELD: [T1]}), "effective_policy_invalid"),
    (FakeDecision(effective={FIELD: {T1: IRR, T2: IRR}, "extra": 1}), "effective_policy_invalid"),
    (FakeDecision(effective={"other": {T1: IRR}}), "effective_policy_invalid"),
    (FakeDecision(effective=None), "effective_policy_invalid"),
    (FakeDecision(effective=[("a", 1)]), "effective_policy_invalid"),
    (FakeDecision(kind="applied_deny_all"), "registry_decision_invalid"),
    (FakeDecision(deny_all=True, effective={FIELD: {T1: IRR, T2: IRR}}), "registry_decision_invalid"),
    (FakeDecision(operationally_authorized=True, effective={FIELD: {T1: IRR, T2: IRR}}), "registry_decision_invalid"),
    (FakeDecision(kind="overlay_not_applied", code="selection_revoked"), "registry_not_applied"),
    (FakeDecision(kind="required_policy_unavailable", code="record_invalid"), "registry_not_applied"),
    ("not a decision", "registry_decision_invalid"), (FakeDecision(kind=3, effective={FIELD: {T1: IRR, T2: IRR}}), "registry_decision_invalid"),
    (RuntimeError("down"), "registry_call_failed")])
def test_a_forged_or_failing_registry_result_is_refused(monkeypatch, result, code):
    fake_registry(monkeypatch, result)
    got, refusal = derive(profile())
    assert got is None and refusal.code == code and refusal.non_authorizing is True


def test_a_not_applied_result_carries_the_registry_code_and_kind(monkeypatch):
    fake_registry(monkeypatch, FakeDecision(kind="overlay_not_applied", code="selection_revoked"))
    got, refusal = derive(profile())
    assert (refusal.code, refusal.registry_code, refusal.registry_kind) == ("registry_not_applied", "selection_revoked", "overlay_not_applied")


def test_an_effective_map_that_is_not_the_stricter_of_host_and_record_is_refused_per_class(monkeypatch):
    cfg = profile(a2=ActionClass(class_id="cls-third", irreversible=False, on_unreadable="refuse"))
    values = ir.host_class_irreversible(cfg)[0]
    # the record names only T1; an unnamed host class must keep its host value, so flipping "cls-third" is refused
    fake_registry(monkeypatch, FakeDecision(effective={FIELD: {T1: IRR, "cls-third": IRR}}))
    got, refusal = derive(cfg, host_values=values)
    assert got is None and refusal.code == "effective_policy_invalid"
    fake_registry(monkeypatch, FakeDecision(effective={FIELD: {T1: IRR, "cls-third": NC}}))
    got, refusal = derive(cfg, host_values=values)
    assert refusal is None and got[0] == {T1: IRR, "cls-third": NC}


def test_the_record_must_name_the_scoped_class_and_only_host_classes(monkeypatch):
    fake_registry(monkeypatch, stricter)
    cfg = profile()
    assert derive(cfg, m={T2: IRR})[1].code == "scoped_class_not_governed"
    assert derive(cfg, m={T1: IRR, "unknown-class": IRR})[1].code == "effective_policy_invalid"
    ghost = GovernedScope("consumer-test", "tenant-test", "urn:cognous:action:ghost-v1", "op")
    assert derive(cfg, scope=ghost)[1].code == "action_class_unknown"
    for bad in ("not json", '{"payload":{"class_irreversible":{}}}', '{"payload":{"class_irreversible":{"a":"reversible"}}}'):
        assert derive(cfg, material_=SelectionMaterial(bad, "{}", object()))[1].code == "effective_policy_invalid", bad


def test_the_flip_pre_check_runs_before_the_digest_and_reads_the_host_object(monkeypatch):
    fake_registry(monkeypatch, stricter, digest=lambda *a: pytest.fail("the digest must not be computed for a refused flip"))
    bad = ActionClass(class_id=T1, irreversible=False, on_unreadable="bounded_tolerance")
    got, refusal = derive(profile(a1=bad))
    assert got is None and refusal.code == "irreversible_flip_conflict:on_unreadable_not_refuse" and refusal.registry_kind == "applied"


def test_a_failing_digest_and_a_missing_registry_and_a_foreign_verifier_and_wrong_material_are_refusals(monkeypatch):
    def boom(*a):
        raise ValueError("x")
    fake_registry(monkeypatch, stricter, digest=boom)
    assert derive(profile())[1].code == "effective_policy_digest_unavailable"
    fake_registry(monkeypatch, stricter)
    assert derive(profile(), verifier=object())[1].code == "verifier_not_admitted"
    for bad in ("text", SelectionMaterial(b"b", "x", None), SelectionMaterial("x", 3, None)):
        assert derive(profile(), material_=bad)[1].code == "material_invalid"
    monkeypatch.setattr(ir, "_registry_modules", lambda: (_ for _ in ()).throw(ImportError("none")))
    assert derive(profile())[1].code == "registry_unavailable"


def test_the_real_registry_import_failure_is_a_refusal_not_an_exception(monkeypatch):
    import importlib
    real = importlib.import_module

    def fail(name, *a, **k):
        if name.startswith("registry_successor"):
            raise ImportError(name)
        return real(name, *a, **k)
    monkeypatch.setattr(ir.importlib, "import_module", fail)
    assert derive(profile())[1].code == "registry_unavailable"


# =============================================================================================================== record second parse
def test_the_second_strict_parse_refuses_anything_unusual():
    assert ir.registry_irreversible_map('{"payload":{"class_irreversible":{"a":"irreversible","b":"no_change"}}}') == {"a": "irreversible", "b": "no_change"}
    for bad in ('{"payload":{"class_irreversible":{"a":"irreversible","a":"no_change"}}}', '{"payload":{"class_irreversible":{"a":1}}}', '{"payload":{"class_irreversible":{"a":null}}}',
                '{"payload":{"class_irreversible":{"a":"irreversible"},"x":1}}', '{"payload":{"class_irreversible":{}}}', '{"payload":{"class_irreversible":[]}}', "[]", "{}",
                '{"payload":{"class_irreversible":{"a":"irreversible"}},"x":1.5}', '{"payload":{"class_irreversible":{"a":"irreversible"}},"x":Infinity}'):
        assert ir.registry_irreversible_map(bad) is None, bad


# =============================================================================================================== final composition
def test_final_composition_irreversible_rules():
    host = profile()
    flipped = ir.compose_irreversible(host, {T1: IRR, T2: IRR})
    assert pol.final_composition_defect(host, host, SCALARS, None, irreversible_declared=True) is None
    assert pol.final_composition_defect(host, flipped, SCALARS, None, irreversible_declared=True) is None
    assert pol.final_composition_defect(host, flipped, SCALARS, None) == "composed_profile_invalid"
    lowered = host.model_dump(mode="json")
    lowered["actions"][A2]["irreversible"] = False
    lowered = RuntimeAuthorityProfile.model_validate(lowered)
    assert pol.final_composition_defect(host, lowered, SCALARS, None, irreversible_declared=True) == "composed_widens_host"
    assert pol.final_composition_defect(host, lowered, SCALARS, None) == "composed_profile_invalid"
    # a flip over a host class whose HOST on_unreadable is not refuse is refused even when another family made the final value refuse
    h2 = profile(a1=ActionClass(class_id=T1, irreversible=False, on_unreadable="bounded_tolerance"))
    f2 = h2.model_dump(mode="json")
    f2["actions"][A1].update(irreversible=True, on_unreadable="refuse")
    f2 = RuntimeAuthorityProfile.model_validate(f2)
    assert pol.final_composition_defect(h2, f2, SCALARS, None, irreversible_declared=True) == "irreversible_flip_conflict:on_unreadable_not_refuse"
    # a flipped class whose final on_unreadable is above the host value is an invalid composed profile (irreversible AND not refuse), reported before the widening scan
    f3 = flipped.model_dump(mode="json")
    f3["actions"][A1]["on_unreadable"] = "bounded_tolerance"
    assert pol.final_composition_defect(host, RuntimeAuthorityProfile.model_validate(f3), SCALARS, None, irreversible_declared=True) == "composed_profile_invalid"
    # a declared flip may not carry another changed member
    other = flipped.model_dump(mode="json")
    other["catalogue_version"] = "tampered/1"
    assert pol.final_composition_defect(host, RuntimeAuthorityProfile.model_validate(other), SCALARS, None, irreversible_declared=True) == "composed_profile_invalid"
    assert pol.final_composition_defect(host, flipped, SCALARS, None, irreversible_declared=True, assurance_declared=True, terminal_declared=True) is None


# =============================================================================================================== snapshot
def bound_fixture():
    return {"f4_ages": None, "class_age": None, "class_unreadable": None, "class_revocation_assurance": ({T1: "required"}, "sha256:" + "88" * 32), "terminal_revocation": ({"x": 1}, "sha256:" + "11" * 32),
            "class_irreversible": ({T1: IRR, T2: IRR}, "sha256:" + "22" * 32), "effective_profile_digest": "sha256:" + "33" * 32}


def snapshot(bound=None, refs=None, **over):
    args = dict(bound=bound or bound_fixture(), host_profile_digest="sha256:" + "44" * 32, refs=refs if refs is not None else {"class_irreversible": ("sel-1", 1), "terminal_revocation": ("sel-2", 7), "class_revocation_assurance": ("sel-3", 4)},
                scope=SCOPE, operation_ids={"class_irreversible": "op-irreversible", "terminal_revocation": "op-terminal"}, evaluated_at=NOW, order=pol.FAMILY_NAMES)
    args.update(over)
    return eff.build_snapshot(**args)


def test_snapshot_order_content_and_immutability():
    s = snapshot()
    assert [f.slot for f in s.families] == ["class_revocation_assurance", "class_irreversible", "terminal_revocation"]  # the composition order, not the dict or alphabetical order
    f = s.family("class_irreversible")
    assert (f.family_id, f.contract_version, f.family_schema_revision, f.effective_policy_digest, f.selection_id, f.selection_epoch) == (
        ir.FAMILY_IR, "r08-v7", 1, "sha256:" + "22" * 32, "sel-1", 1)
    assert f.effective == ((T2, IRR), (T1, IRR))  # sorted pairs
    assert s.family("terminal_revocation").family_schema_revision is None and s.family("class_age") is None
    assert s.host_profile_digest == "sha256:" + "44" * 32 and s.effective_profile_digest == "sha256:" + "33" * 32 and s.evaluated_at == NOW.isoformat()
    assert dict(s.scope)["consumer_id"] == "consumer-test" and dict(dict(s.scope)["operation_ids"]) == {"class_irreversible": "op-irreversible", "terminal_revocation": "op-terminal"}
    with pytest.raises(dataclasses.FrozenInstanceError):
        s.families = ()  # type: ignore[misc]
    with pytest.raises(dataclasses.FrozenInstanceError):
        f.selection_epoch = 9  # type: ignore[misc]
    with pytest.raises(TypeError):
        f.effective[0] = ("a", "b")  # type: ignore[index]
    # the snapshot does not alias the mutable bound identity
    b = bound_fixture()
    s2 = snapshot(bound=b)
    b["class_irreversible"][0][T1] = NC
    assert s2.family("class_irreversible").effective == ((T2, IRR), (T1, IRR))


def test_snapshot_is_deterministic_and_the_identity_changes_with_every_component():
    base_digest = snapshot().identity_digest
    assert snapshot().identity_digest == base_digest and snapshot() == snapshot()
    changes = []
    b = bound_fixture()
    b["class_irreversible"] = ({T1: NC, T2: IRR}, "sha256:" + "22" * 32)
    changes.append(snapshot(bound=b))  # value
    b = bound_fixture()
    b["class_irreversible"] = ({T1: IRR, T2: IRR}, "sha256:" + "55" * 32)
    changes.append(snapshot(bound=b))  # registry digest
    changes.append(snapshot(refs={"class_irreversible": ("sel-1", 2), "terminal_revocation": ("sel-2", 7), "class_revocation_assurance": ("sel-3", 4)}))  # epoch
    changes.append(snapshot(refs={"class_irreversible": ("sel-9", 1), "terminal_revocation": ("sel-2", 7), "class_revocation_assurance": ("sel-3", 4)}))  # selection id
    changes.append(snapshot(refs={"class_irreversible": ("sel-1", 1), "terminal_revocation": ("sel-2", 8), "class_revocation_assurance": ("sel-3", 4)}))  # another family's epoch
    b = bound_fixture()
    b["terminal_revocation"] = None
    changes.append(snapshot(bound=b))  # a family dropped
    b = bound_fixture()
    b["effective_profile_digest"] = "sha256:" + "66" * 32
    changes.append(snapshot(bound=b))  # effective profile
    changes.append(snapshot(host_profile_digest="sha256:" + "77" * 32))  # host profile
    changes.append(snapshot(evaluated_at=NOW.replace(minute=1)))
    changes.append(snapshot(scope=dataclasses.replace(SCOPE, tenant_id="other")))
    changes.append(snapshot(operation_ids={"class_irreversible": "op-other", "terminal_revocation": "op-terminal"}))
    digests = {c.identity_digest for c in changes} | {base_digest}
    assert len(digests) == len(changes) + 1


def test_snapshot_without_a_ref_records_none_and_a_family_slot_table_is_complete():
    s = snapshot(refs={})
    assert s.family("class_irreversible").selection_id is None and s.family("class_irreversible").selection_epoch is None
    assert set(eff.FAMILY_TABLE) == set(pol.FAMILY_NAMES)
    assert eff.FAMILY_TABLE["class_irreversible"] == (ir.FAMILY_IR, ir.CONTRACT_V7) and eff.SCHEMA_REVISIONS == {"class_irreversible": ir.FAMILY_SCHEMA_REVISION}


def test_selection_ref_is_strict():
    assert eff.selection_ref('{"statement":{"selection_id":"s1","epoch":3}}') == ("s1", 3)
    for bad in ('{"statement":{"selection_id":"s1","epoch":3,"epoch":4}}', '{"statement":{"selection_id":"s1","epoch":3.0}}', '{"statement":{"selection_id":"","epoch":3}}',
                '{"statement":{"selection_id":"s1","epoch":true}}', '{"statement":{"selection_id":1,"epoch":3}}', '{"statement":3}', "not json", None, "[]",
                '{"statement":{"selection_id":"s1","epoch":NaN}}', '{"statement":{"selection_id":"s1"}}'):
        assert eff.selection_ref(bad) is None, bad


def test_resolve_refuses_missing_material_and_an_empty_declaration_before_any_registry_call():
    fam = pol.GovernedFamily(SCOPE, lambda: None)
    args = dict(host=profile(), host_scalars=SCALARS, verifier=object(), institution_id="i", authority_domain="d", now=NOW)
    with pytest.raises(pol.RegistryGovernedPolicyRefused) as e:
        eff.resolve_effective_policy(families=pol.GovernedFamilies(class_irreversible=fam), materials={}, **args)
    assert (e.value.refusal.code, e.value.boundary) == ("selection_missing", "resolution")
    with pytest.raises(pol.RegistryGovernedPolicyRefused) as e:
        eff.resolve_effective_policy(families=pol.GovernedFamilies(class_irreversible=fam), materials={"class_irreversible": None}, **args)
    assert e.value.refusal.code == "selection_missing"
    with pytest.raises(pol.RegistryGovernedPolicyRefused) as e:
        eff.resolve_effective_policy(families=pol.GovernedFamilies(), materials={}, **args)
    assert e.value.refusal.code == "no_family_declared"


def test_resolve_returns_the_snapshot_of_the_existing_derivation_with_a_fake_registry(monkeypatch):
    fake_registry(monkeypatch, stricter)
    fam = pol.GovernedFamily(SCOPE, lambda: None)
    cfg = profile()
    snap = eff.resolve_effective_policy(families=pol.GovernedFamilies(class_irreversible=fam), host=cfg, host_scalars=SCALARS, materials={"class_irreversible": material()},
                                        verifier=FakeVerifier(), institution_id="inst", authority_domain="dom", now=NOW, host_irreversible=ir.host_class_irreversible(cfg)[0])
    f = snap.family("class_irreversible")
    assert dict(f.effective) == {T1: IRR, T2: IRR} and (f.selection_id, f.selection_epoch) == ("sel-1", 1) and snap.host_profile_digest != snap.effective_profile_digest
    # a derivation refusal is raised as the existing refusal type, with the family prefix, and no snapshot exists
    fake_registry(monkeypatch, FakeDecision(effective={FIELD: {T1: NC, T2: NC}}))
    with pytest.raises(pol.RegistryGovernedPolicyRefused) as e:
        eff.resolve_effective_policy(families=pol.GovernedFamilies(class_irreversible=fam), host=cfg, host_scalars=SCALARS, materials={"class_irreversible": material()},
                                     verifier=FakeVerifier(), institution_id="inst", authority_domain="dom", now=NOW, host_irreversible=ir.host_class_irreversible(cfg)[0])
    assert e.value.refusal.code == "class_irreversible:effective_policy_widens_host" and e.value.boundary == "resolution"
