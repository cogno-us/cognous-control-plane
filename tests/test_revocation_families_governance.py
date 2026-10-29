"""Registry-governed `requires_revocation_assurance` (per action class) and terminal-revocation enablement (Registry `r08-v6`) reaching the real `BoundedAuthorizationWorkflow`
through the composed `GovernedPolicyWorkflow`, with every governing selection re-validated at construction, decision entry, execute entry and the pre-dispatch commit gate.

BUILDER_TESTED developer evidence. NOT independently qualified. NOT an authorization mechanism. Real synthetic Ed25519 (no test doubles for the Registry verdict) through the real
workflow; the only doubles are explicit monkeypatches of a Registry RESULT used to prove the Control Plane re-checks it (they are named as such).

What is proven here: a Registry `required` (assurance) can only ADD the existing `holder_inventory_missing` hold and a Registry `on` (terminal revocation) can only ADD the existing
`grant_revocation_recorded` refusal; neither creates an inventory, a revocation, an assurance receipt or any authority; both live inside the profile that `approval_commitment` and the
persisted `catalogue_digest` already hash.

Needs a Registry checkout at the exact r08-v6 `PIN_V6` in `OCS_REGISTRY_PIN_DIR` and PyNaCl (`tests/test_f5_class_unreadable_governance.py` enforces both and `OCS_REQUIRE_REGISTRY_PIN=1`).
"""
from __future__ import annotations

import dataclasses
import hashlib
import importlib
from pathlib import Path

import pytest

import tests.test_f5_class_unreadable_governance as base  # noqa: E402  (also enforces the Registry pin and PyNaCl requirement)
import tests.test_governed_policy_composition as comp  # noqa: E402

from agent_control_plane import registry_governed_policy as pol  # noqa: E402
from agent_control_plane import registry_revocation_governance as rev  # noqa: E402
from agent_control_plane.holder_inventory import AuthorityHolder, HolderInventory  # noqa: E402
from agent_control_plane.registry_governed_policy import (  # noqa: E402
    GovernedActivationLedger, GovernedFamilies, GovernedFamily, GovernedPolicyWorkflow, RegistryGovernedPolicyRefused,
)
from agent_control_plane.runtime_authority import CODE_REVOCATION_RECORDED, RuntimeAuthorityProfile, approval_commitment  # noqa: E402

v6ra = importlib.import_module("registry_successor.v6_class_revocation_assurance")
v6tr = importlib.import_module("registry_successor.v6_terminal_revocation")
v6id = importlib.import_module("registry_successor.v6_policy_identity")
v6dec = importlib.import_module("registry_successor.v6_decision")

ev, trust_for, bind_approval, file_state, Source, kwargs = base.ev, base.trust_for, base.bind_approval, base.file_state, base.Source, base.kwargs
CLASS_T1, CLASS_T2, TENANT, ACTION_ID, NOW, REG_NOW, PROFILE = base.CLASS_T1, base.CLASS_T2, base.TENANT, base.ACTION_ID, base.NOW, base.REG_NOW, base.PROFILE
R_, B_ = base.R_, base.B_
GovernedScope = base.GovernedScope
V6_DOMAIN = b"ocs-reg/r08-v6/selection\n"
OP_RA, OP_TR = "refund-issue-assurance", "refund-issue-terminal"
SCOPE_RA = GovernedScope("consumer-test", TENANT.lower(), ACTION_ID, OP_RA)
SCOPE_TR = GovernedScope("consumer-test", TENANT.lower(), ACTION_ID, OP_TR)
NR, RQ = "not_required", "required"
SRC = Path(pol.__file__).resolve().parent
INV = HolderInventory(inventory_id="inv-1", recorded_by="urn:cognous:principal:inventory-owner", recorded_at=NOW.isoformat(),
                      holders=[AuthorityHolder(holder_id="h-routed", kind="routed", enforcement_point="control plane effect check")])
EMPTY_INV = HolderInventory(inventory_id="inv-0", recorded_by="urn:cognous:principal:inventory-owner", recorded_at=NOW.isoformat(), holders=[])
RV = frozenset({("sel-test-1", 1)})
CHANGED = {"selection_id": "sel-test-2", "epoch": 2}


@pytest.fixture(autouse=True)
def _fixed_synthetic_clock(monkeypatch):
    import agent_control_plane.bounded as bounded_module
    monkeypatch.setattr(bounded_module, "_now", lambda: NOW)
    for m in (pol, base.gov, base.agegov, base.f4gov):
        monkeypatch.setattr(m, "_now", lambda: NOW)


# --------------------------------------------------------------------------------------------------------------- Registry-side builders (real Ed25519)
def rrec(m=None, *, family=None, contract="r08-v6", payload=None, **over):
    body = dict(base.r.make_record(), contract_version=contract, family=family or v6ra.FAMILY_F5RA, record_id="f5ra-record",
                payload=payload if payload is not None else {v6ra.F5RA_FIELD: m if m is not None else {CLASS_T1: RQ}})
    body.update(over)
    return base.r.seal_record(body)


def trec(v="on", *, family=None, contract="r08-v6", payload=None, **over):
    body = dict(base.r.make_record(), contract_version=contract, family=family or v6tr.FAMILY_TR, record_id="f5tr-record",
                payload=payload if payload is not None else {v6tr.TR_FIELD: v})
    body.update(over)
    return base.r.seal_record(body)


def _mat(rec, op, default_family, contract, domain, **kw):
    stmt_over = dict(kw.pop("stmt_over", {}))
    stmt_over.setdefault("operation", op)
    stmt_over["family"] = stmt_over.get("family", rec.get("family", default_family))
    return base._material(rec, op=stmt_over.pop("operation"), contract=contract, domain=domain or V6_DOMAIN, family=stmt_over.pop("family"), stmt_over=stmt_over, **kw)


def rmat(m=None, *, rec=None, contract="r08-v6", domain=None, **kw):
    return _mat(rec or rrec(m), OP_RA, v6ra.FAMILY_F5RA, contract, domain, **kw)


def tmat(v="on", *, rec=None, contract="r08-v6", domain=None, **kw):
    return _mat(rec or trec(v), OP_TR, v6tr.FAMILY_TR, contract, domain, **kw)


# --------------------------------------------------------------------------------------------------------------- Control-Plane-side builders
def variant(cfg, *, assure=None, inventory=None, terminal=False, **over):
    """The host profile `cfg` with per-class revocation-assurance flags, a holder inventory and/or the terminal-revocation section added."""
    doc = cfg.model_dump(mode="json")
    for a in doc["actions"].values():
        if assure and assure.get(a["class_id"]):
            a["requires_revocation_assurance"] = True
    if inventory is not None:
        doc["holder_inventory"] = inventory.model_dump(mode="json")
    if terminal:
        doc["terminal_revocation"] = {"version": "terminal-revocation/0.1"}
    doc.update(over)
    return RuntimeAuthorityProfile.model_validate(doc)


def flags(profile):
    return {a.class_id: a.requires_revocation_assurance for a in profile.actions.values()}


def without(profile, *, flag=False, terminal=False):
    doc = profile.model_dump(mode="json")
    for a in doc["actions"].values():
        if flag:
            a.pop("requires_revocation_assurance", None)
    if terminal:
        doc.pop("terminal_revocation", None)
    return doc


def fams(ra=None, tr=None, f=None, a=None, u=None):
    return GovernedFamilies(f4_ages=GovernedFamily(comp.SCOPE_F, f) if f is not None else None, class_age=GovernedFamily(base.SCOPE_A, a) if a is not None else None,
                            class_unreadable=GovernedFamily(base.SCOPE, u) if u is not None else None,
                            class_revocation_assurance=GovernedFamily(SCOPE_RA, ra) if ra is not None else None,
                            terminal_revocation=GovernedFamily(SCOPE_TR, tr) if tr is not None else None)


def build(tmp_path, res, cfg, families, **kw):
    return GovernedPolicyWorkflow(families=families, verifier=ev.Ed25519Verifier(), runtime_authority_profile=kw.pop("profile", cfg), construction_time=REG_NOW,
                                  **kw.pop("pol", {}), **kwargs(tmp_path, res, **kw))


def sources(*, ra=None, tr=None, f=False, a=False, u=False):
    return {"ra": Source(rmat(ra)) if ra is not False and ra is not None else None, "tr": Source(tmat(tr)) if tr is not None else None,
            "f": comp.fsrc() if f else None, "a": comp.asrc() if a else None, "u": comp.usrc() if u else None}


def ready(tmp_path, *, ra=None, tr=None, f=False, a=False, u=False, host=None, bind=True, **profile_kw):
    """(proposal, resolver, HOST profile, {sources}, flow). `ra` is the assurance class map, `tr` the terminal value; `host` transforms the host profile. Approvals are issued against
    the FINAL effective profile (the commitment the issuer must use)."""
    p, res, cfg = base.prepared(tmp_path, **profile_kw)
    if host is not None:
        cfg = host(cfg)
    srcs = sources(ra=ra, tr=tr, f=f, a=a, u=u)
    flow = build(tmp_path, res, cfg, fams(srcs["ra"], srcs["tr"], srcs["f"], srcs["a"], srcs["u"]))
    if bind:
        bind_approval(res, flow.runtime_authority_profile)
    return p, res, cfg, srcs, flow


def with_inventory(cfg):
    return variant(cfg, inventory=INV)


def authorized(tmp_path, **kw):
    kw.setdefault("host", with_inventory)
    p, res, cfg, srcs, flow = ready(tmp_path, **kw)
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    return p, res, cfg, srcs, flow, d


def refused(exc, code=None, boundary=None, registry_code=None, prefix=None):
    e = exc.value
    assert isinstance(e, PermissionError) and isinstance(e, RegistryGovernedPolicyRefused) and e.refusal.non_authorizing is True
    if code:
        assert e.refusal.code == code, e.refusal
    if prefix:
        assert e.refusal.code.startswith(prefix), e.refusal
    if boundary:
        assert e.boundary == boundary, e.boundary
    if registry_code:
        assert e.refusal.registry_code == registry_code, e.refusal
    return e


def revoked_for(k):
    return {"ra": lambda: rmat(trust=trust_for(OP_RA, revoked_selections=RV)), "tr": lambda: tmat(trust=trust_for(OP_TR, revoked_selections=RV))}[k]()


def changed_for(k):
    return {"ra": lambda: rmat({CLASS_T1: RQ, CLASS_T2: RQ}, stmt_over=CHANGED), "tr": lambda: tmat("off", stmt_over=CHANGED)}[k]()


def grant_status(res, d):
    return res.statuses[d.binding.grant_id]


# =============================================================================================================== A: requires_revocation_assurance alone
def test_a01_a_valid_selection_requires_assurance_for_the_governed_class_and_changes_nothing_else(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, ra={CLASS_T1: RQ})
    assert flags(cfg) == {CLASS_T1: False, CLASS_T2: False}
    assert flags(flow.runtime_authority_profile) == {CLASS_T1: True, CLASS_T2: False}
    assert without(flow.runtime_authority_profile, flag=True) == without(cfg, flag=True)  # only the governed field differs, everything else byte for byte
    ident = flow.registry_governed_policy_identity
    assert ident["families"] == ["class_revocation_assurance"] and ident["class_revocation_assurance"]["effective"] == {CLASS_T1: RQ, CLASS_T2: NR}
    assert ident["host"]["class_revocation_assurance"] == {CLASS_T1: NR, CLASS_T2: NR} and ident["terminal_revocation"] is None


@pytest.mark.parametrize("host_flag", [False, True])
@pytest.mark.parametrize("reg", [NR, RQ])
def test_a02_the_effective_value_is_the_stricter_of_host_and_registry_and_never_looser(tmp_path, host_flag, reg):
    p, res, cfg, srcs, flow = ready(tmp_path, ra={CLASS_T1: reg}, host=lambda c: variant(c, assure={CLASS_T1: host_flag}, inventory=INV))
    assert flags(flow.runtime_authority_profile)[CLASS_T1] == (host_flag or reg == RQ)
    assert flags(flow.runtime_authority_profile)[CLASS_T2] is False
    if reg == NR:  # a Registry value that narrows nothing leaves the profile and every existing approval unchanged
        assert flow.runtime_authority_profile.model_dump() == cfg.model_dump()


def test_a03_the_registry_digest_is_the_independent_v6_effective_policy_identity(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, ra={CLASS_T1: RQ})
    expect = v6id.effective_policy_digest(v6ra.FAMILY_F5RA, {v6ra.F5RA_FIELD: {CLASS_T1: RQ, CLASS_T2: NR}})
    assert flow.registry_governed_policy_identity["class_revocation_assurance"]["effective_policy_digest"] == expect
    other = v6id.effective_policy_digest(v6ra.FAMILY_F5RA, {v6ra.F5RA_FIELD: {CLASS_T1: RQ, CLASS_T2: RQ}})
    assert other != expect  # every class and value is bound


def test_a04_missing_required_assurance_evidence_holds_the_class_and_dispatches_nothing(tmp_path):
    for label, inv in (("none", None), ("empty", EMPTY_INV)):
        p, res, cfg, srcs, flow = ready(tmp_path / label, ra={CLASS_T1: RQ}, host=(lambda c: c) if inv is None else (lambda c, i=inv: variant(c, inventory=i)))
        d = flow.decide(p, now=NOW)
        assert d.result == "hold" and "holder_inventory_missing" in d.reasons, d.reasons
        assert flow.destination.snapshot()["effects"] == {} and not flow.records.load().attempts


def test_a05_with_a_host_inventory_the_same_call_authorizes_and_executes(tmp_path):
    p, res, cfg, srcs, flow, d = authorized(tmp_path, ra={CLASS_T1: RQ})
    attempt, observed = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and observed.state == "applied"


def test_a06_a_registry_required_never_creates_or_verifies_an_inventory(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, ra={CLASS_T1: RQ})
    assert flow.runtime_authority_profile.holder_inventory is None and cfg.holder_inventory is None
    p, res, cfg, srcs, flow = ready(tmp_path / "b", ra={CLASS_T1: RQ}, host=with_inventory)
    assert flow.runtime_authority_profile.holder_inventory == INV  # the host's own claim, untouched


def test_a07_governed_decisions_equal_the_existing_workflow_built_with_the_effective_profile(tmp_path):
    for label, host in (("noinv", lambda c: c), ("inv", with_inventory)):
        p, res, cfg, srcs, flow = ready(tmp_path / label, ra={CLASS_T1: RQ}, host=host)
        oracle = base.plain(tmp_path / (label + "-oracle"), res, flow.runtime_authority_profile)
        bind_approval(res, oracle.runtime_authority_profile)
        dg, do = flow.decide(p, now=NOW), oracle.decide(p, now=NOW)
        assert (dg.result, dg.reasons) == (do.result, do.reasons), label


def test_a08_an_approval_issued_for_the_host_profile_does_not_authorize_the_forced_one(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, ra={CLASS_T1: RQ}, host=with_inventory, bind=False)
    ctx = res.contexts[PROFILE]
    assert approval_commitment(flow.runtime_authority_profile, ctx) != approval_commitment(cfg, ctx)
    bind_approval(res, cfg)  # issued for the HOST profile
    d = flow.decide(p, now=NOW)
    assert d.result == "hold" and "runtime_authority_approval_mismatch" in d.reasons
    assert flow.destination.snapshot()["effects"] == {} and not flow.records.load().attempts
    bind_approval(res, flow.runtime_authority_profile)
    assert flow.decide(p, now=NOW).result == "authorized"


def test_a09_a_registry_value_that_narrows_nothing_keeps_an_existing_approval_valid(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, ra={CLASS_T1: NR}, host=with_inventory, bind=False)
    bind_approval(res, cfg)
    assert flow.decide(p, now=NOW).result == "authorized"


def test_a10_a_registry_class_unknown_to_the_host_is_refused_and_the_record_must_name_the_scoped_class(tmp_path):
    p, res, cfg = base.prepared(tmp_path)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, fams(ra=Source(rmat({CLASS_T1: RQ, "class-not-in-host": RQ}))))
    refused(e, prefix="class_revocation_assurance:", boundary="construction")
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path / "b", res, cfg, fams(ra=Source(rmat({CLASS_T2: RQ}))))
    refused(e, "class_revocation_assurance:scoped_class_not_governed", "construction")


@pytest.mark.parametrize("payload", [{}, {"class_requires_revocation_assurance": {}}, {"class_requires_revocation_assurance": {CLASS_T1: True}},
                                     {"class_requires_revocation_assurance": {CLASS_T1: "REQUIRED"}}, {"class_requires_revocation_assurance": {CLASS_T1: RQ}, "extra": 1},
                                     {"class_requires_revocation_assurance": [CLASS_T1]}])
def test_a11_malformed_assurance_records_are_refused(tmp_path, payload):
    p, res, cfg = base.prepared(tmp_path)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, fams(ra=Source(rmat(rec=rrec(payload=payload)))))
    refused(e, prefix="class_revocation_assurance:", boundary="construction")


# =============================================================================================================== B: terminal-revocation enablement alone
def test_b01_a_valid_selection_forces_the_terminal_section_on_and_changes_nothing_else(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, tr="on")
    assert cfg.terminal_revocation is None and flow.runtime_authority_profile.terminal_revocation is not None
    assert without(flow.runtime_authority_profile, terminal=True) == without(cfg, terminal=True)
    ident = flow.registry_governed_policy_identity
    assert ident["families"] == ["terminal_revocation"] and ident["terminal_revocation"]["effective"] == "on" and ident["host"]["terminal_revocation"] == "off"
    assert ident["terminal_revocation"]["effective_policy_digest"] == v6id.effective_policy_digest(v6tr.FAMILY_TR, {v6tr.TR_FIELD: "on"})
    assert ident["terminal_revocation"]["effective_policy_digest"] != v6id.effective_policy_digest(v6tr.FAMILY_TR, {v6tr.TR_FIELD: "off"})


@pytest.mark.parametrize("host_on", [False, True])
@pytest.mark.parametrize("reg", ["off", "on"])
def test_b02_the_effective_value_is_on_if_either_side_is_on_and_a_registry_off_never_turns_it_off(tmp_path, host_on, reg):
    p, res, cfg, srcs, flow = ready(tmp_path, tr=reg, host=lambda c: variant(c, terminal=host_on))
    assert (flow.runtime_authority_profile.terminal_revocation is not None) == (host_on or reg == "on")
    if host_on or reg == "off":
        assert flow.runtime_authority_profile.model_dump() == cfg.model_dump()  # nothing narrowed: the host profile byte for byte
    assert flow.registry_governed_policy_identity["terminal_revocation"]["effective"] == ("on" if (host_on or reg == "on") else "off")
    assert flow.decide(p, now=NOW).result == "authorized"  # every boundary re-derives with the SAME host value: no spurious selection_changed


def _revoke_then_restore(flow, p, res, d):
    grant_status(res, d).status = "revoked"
    with pytest.raises(PermissionError):
        flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    grant_status(res, d).status = "active"


def test_b03_with_the_forced_section_a_recorded_revocation_stays_refused_after_the_status_reads_active(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, tr="on")
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    _revoke_then_restore(flow, p, res, d)
    with pytest.raises(PermissionError):
        flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert flow.records.load().refusals[-1].reasons == [CODE_REVOCATION_RECORDED]
    again = flow.decide(p, now=NOW)
    assert again.result == "hold" and again.reasons == [CODE_REVOCATION_RECORDED] and again.binding is None
    assert flow.destination.snapshot()["effects"] == {} and not flow.records.load().attempts


def test_b04_without_the_section_the_host_baseline_accepts_a_status_that_returns_to_active(tmp_path):
    """The control: the identical sequence under a Registry `off` over a host `off` (the legacy behaviour) is accepted - proving the refusal above comes from the forced section."""
    p, res, cfg, srcs, flow = ready(tmp_path, tr="off")
    d = flow.decide(p, now=NOW)
    _revoke_then_restore(flow, p, res, d)
    attempt, observed = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and observed.state == "applied"


def test_b05_suspension_stays_reversible_under_the_forced_section(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, tr="on")
    d = flow.decide(p, now=NOW)
    grant_status(res, d).status = "suspended"
    with pytest.raises(PermissionError):
        flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    grant_status(res, d).status = "active"
    attempt, observed = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and observed.state == "applied"


def test_b06_a_revocation_of_another_revision_does_not_count_and_the_unrevoked_flow_is_unchanged(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, tr="on")
    d = flow.decide(p, now=NOW)
    status = grant_status(res, d)
    status.status, status.revision = "revoked", "some-other-revision"
    with pytest.raises(PermissionError):
        flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    status.status, status.revision = "active", d.binding.grant_revision
    attempt, _ = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged"


def test_b07_prior_negative_records_survive_and_are_never_rewritten_by_the_adapter(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, tr="on")
    d = flow.decide(p, now=NOW)
    _revoke_then_restore(flow, p, res, d)
    before = flow.records.load()
    with pytest.raises(PermissionError):
        flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    after = flow.records.load()
    assert [c.model_dump() for c in before.resolution_checks] == [c.model_dump() for c in after.resolution_checks[:len(before.resolution_checks)]]
    assert len(after.refusals) == len(before.refusals) + 1


def test_b08_a_registry_selection_never_decides_who_may_revoke(tmp_path):
    """The adapter has no revocation entry point: the governed workflow exposes no method that records, performs or reverses a revocation."""
    p, res, cfg, srcs, flow = ready(tmp_path, tr="on")
    assert not [n for n in dir(flow) if "revoke" in n.lower() and not n.startswith("_")]
    assert not [n for n in dir(rev) if "revoke" in n.lower() and not n.startswith("_")]


def test_b09_an_approval_issued_for_the_host_profile_does_not_authorize_the_forced_section(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, tr="on", bind=False)
    bind_approval(res, cfg)
    d = flow.decide(p, now=NOW)
    assert d.result == "hold" and "runtime_authority_approval_mismatch" in d.reasons
    bind_approval(res, flow.runtime_authority_profile)
    assert flow.decide(p, now=NOW).result == "authorized"


@pytest.mark.parametrize("payload", [{}, {"terminal_revocation": True}, {"terminal_revocation": "ON"}, {"terminal_revocation": "on", "x": 1}, {"terminal_revocation": ["on"]}])
def test_b10_malformed_terminal_records_are_refused(tmp_path, payload):
    p, res, cfg = base.prepared(tmp_path)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, fams(tr=Source(tmat(rec=trec(payload=payload)))))
    refused(e, prefix="terminal_revocation:", boundary="construction")


# =============================================================================================================== C: composition (both together, and with F4 / F5 age / F5 on_unreadable)
def test_c01_both_new_families_together_compose_one_profile_with_both_effects(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, ra={CLASS_T1: RQ}, tr="on")
    eff = flow.runtime_authority_profile
    assert flags(eff) == {CLASS_T1: True, CLASS_T2: False} and eff.terminal_revocation is not None
    assert flow.registry_governed_policy_identity["families"] == ["class_revocation_assurance", "terminal_revocation"]
    d = flow.decide(p, now=NOW)
    assert d.result == "hold" and "holder_inventory_missing" in d.reasons  # the host has no inventory: the requirement holds the class


def test_c02_all_five_families_compose_deterministically_and_execute_end_to_end(tmp_path):
    p, res, cfg, srcs, flow, d = authorized(tmp_path, ra={CLASS_T1: RQ}, tr="on", f=True, a=True, u=True)
    eff = flow.runtime_authority_profile
    assert flags(eff)[CLASS_T1] is True and eff.terminal_revocation is not None
    assert base.uvals(eff)[CLASS_T1] == R_ and base.ages(eff)[CLASS_T1] == 20 and (flow.status_max_age_seconds, flow.approval_max_age_seconds) == (30, 30)
    assert flow.registry_governed_policy_identity["families"] == ["f4_ages", "class_age", "class_unreadable", "class_revocation_assurance", "terminal_revocation"]
    attempt, observed = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and observed.state == "applied"


@pytest.mark.parametrize("use", [dict(f=True), dict(a=True), dict(u=True), dict(f=True, a=True), dict(a=True, u=True), dict(f=True, u=True), dict(f=True, a=True, u=True)])
@pytest.mark.parametrize("new", [dict(ra={CLASS_T1: RQ}), dict(tr="on"), dict(ra={CLASS_T1: RQ}, tr="on")])
def test_c03_every_supported_combination_with_the_existing_families_authorizes_and_executes(tmp_path, use, new):
    p, res, cfg, srcs, flow, d = authorized(tmp_path, **use, **new)
    attempt, observed = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and observed.state == "applied"


def test_c04_the_existing_families_alone_are_byte_identical_to_the_consolidated_behaviour(tmp_path):
    """Adding the two new members to GovernedFamilies changes nothing for a workflow that does not declare them."""
    p, res, cfg, srcs, flow = ready(tmp_path, f=True, a=True, u=True)
    ident = flow.registry_governed_policy_identity
    assert ident["class_revocation_assurance"] is None and ident["terminal_revocation"] is None
    assert flags(flow.runtime_authority_profile) == flags(cfg) and flow.runtime_authority_profile.terminal_revocation is None
    reference = base.gbuild(tmp_path / "ref", Source(base.mat(base.umap(t1=R_))), res, cfg, age=Source(base.amat(comp.AGE_M)))
    assert flow.runtime_authority_profile.model_dump() == reference.runtime_authority_profile.model_dump()


def test_c05_the_final_profile_equals_the_sequential_application_of_each_family(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, ra={CLASS_T1: RQ}, tr="on", a=True, u=True)
    expect = variant(base.gbuild(tmp_path / "e", Source(base.mat(base.umap(t1=R_))), res, cfg, age=Source(base.amat(comp.AGE_M))).runtime_authority_profile,
                     assure={CLASS_T1: True}, terminal=True)
    assert flow.runtime_authority_profile.model_dump() == expect.model_dump()
    assert approval_commitment(flow.runtime_authority_profile, res.contexts[PROFILE]) == approval_commitment(expect, res.contexts[PROFILE])


def test_c06_a_declared_family_is_mandatory_no_partial_activation_and_no_fallback(tmp_path):
    p, res, cfg = base.prepared(tmp_path)
    ok_ra, bad = Source(rmat({CLASS_T1: RQ})), Source(tmat("on"))
    bad.fail = True
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, fams(ra=ok_ra, tr=bad))
    refused(e, "selection_source_failed", "construction")
    assert ok_ra.calls == 1 and bad.calls == 1 and not Path(tmp_path / "run.json").read_text().count("decision_id")  # no partial activation, nothing persisted
    bad2 = Source(rmat({CLASS_T1: RQ}, stmt_over={"operation": "wrong-operation-name"}))
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path / "b", res, cfg, fams(ra=bad2, tr=Source(tmat("on"))))
    refused(e, prefix="class_revocation_assurance:", boundary="construction")


def test_c07_scopes_must_share_consumer_tenant_and_action(tmp_path):
    p, res, cfg = base.prepared(tmp_path)
    other = GovernedScope("consumer-test", TENANT.lower(), "urn:cognous:action:other-v1", OP_TR)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, GovernedFamilies(class_revocation_assurance=GovernedFamily(SCOPE_RA, Source(rmat())), terminal_revocation=GovernedFamily(other, Source(tmat()))))
    refused(e, "family_scope_mismatch", "construction")


def test_c08_a_profile_is_required_for_both_new_families_and_policy_binding_is_refused(tmp_path):
    p, res, cfg = base.prepared(tmp_path)
    for which in (dict(ra=Source(rmat())), dict(tr=Source(tmat()))):
        with pytest.raises(RegistryGovernedPolicyRefused) as e:
            GovernedPolicyWorkflow(families=fams(**which), verifier=ev.Ed25519Verifier(), construction_time=REG_NOW, **kwargs(tmp_path, res))
        refused(e, "runtime_authority_profile_required", "construction")
    from agent_control_plane.policy_binding import PolicyBinding
    pb = PolicyBinding(binding_digest="sha256:" + "1" * 64, selection_epoch=1, activation_ref="sha256:" + "2" * 64, policy_generation=1, disposition="selected")
    for which in (dict(ra=Source(rmat())), dict(tr=Source(tmat()))):
        with pytest.raises(RegistryGovernedPolicyRefused) as e:
            build(tmp_path / "pb", res, cfg, fams(**which), profile=cfg.model_copy(update={"policy_binding": pb}))
        assert e.value.refusal.code in ("policy_binding_unsupported", "host_profile_invalid")


# =============================================================================================================== D/E: scope, host invalidity
@pytest.mark.parametrize("over", [{"consumer_id": "other-consumer"}, {"scope": dict(base.STMT_SCOPE, tenant="other-tenant")}, {"scope": dict(base.STMT_SCOPE, institution="other-institution")},
                                  {"scope": dict(base.STMT_SCOPE, authority_domain="other-domain")}])
@pytest.mark.parametrize("k", ["ra", "tr"])
def test_d01_a_selection_for_another_consumer_tenant_institution_or_domain_is_refused(tmp_path, over, k):
    p, res, cfg = base.prepared(tmp_path)
    material = rmat(stmt_over=over) if k == "ra" else tmat(stmt_over=over)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, fams(**{k: Source(material)}))
    refused(e, prefix={"ra": "class_revocation_assurance:", "tr": "terminal_revocation:"}[k], boundary="construction")


@pytest.mark.parametrize("k", ["ra", "tr"])
def test_d02_a_selection_pinned_to_another_operation_is_refused(tmp_path, k):
    p, res, cfg = base.prepared(tmp_path)
    material = rmat(stmt_over={"operation": "some-other-operation"}) if k == "ra" else tmat(stmt_over={"operation": "some-other-operation"})
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, fams(**{k: Source(material)}))
    refused(e, boundary="construction")


def test_d03_a_proposal_for_another_action_or_tenant_is_out_of_scope(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, ra={CLASS_T1: RQ}, tr="on")
    other = p.model_copy(update={"action_id": "urn:cognous:action:other-v1"})
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.decide(other, now=NOW)
    refused(e, "proposal_out_of_scope", "decision")


@pytest.mark.parametrize("k", ["ra", "tr"])
def test_e01_an_invalid_original_host_is_refused_before_any_source_read_and_never_repaired(tmp_path, k):
    """An irreversible class whose `on_unreadable` is not `refuse` is already invalid for the evaluator (`action_class_invalid`); a Registry value must never conceal that."""
    p, res, cfg = base.prepared(tmp_path, t1=B_, t1_irrev=True)
    srcs = sources(ra={CLASS_T1: RQ} if k == "ra" else None, tr="on" if k == "tr" else None)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, fams(srcs["ra"], srcs["tr"]))
    refused(e, "host_class_invalid", "construction")
    assert all(s.calls == 0 for s in srcs.values() if s is not None)


def test_e02_an_unknown_scoped_action_class_is_refused(tmp_path):
    p, res, cfg = base.prepared(tmp_path)
    ghost = GovernedScope("consumer-test", TENANT.lower(), "urn:cognous:action:ghost-v1", OP_TR)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, GovernedFamilies(terminal_revocation=GovernedFamily(ghost, Source(tmat()))))
    refused(e, boundary="construction")


# =============================================================================================================== F: attempted widening (a Registry RESULT forged inside the Control Plane's call)
def _forge(monkeypatch, effective_of):
    real = v6dec.verify_and_decide_v6

    def forged(*a, **k):
        d = real(*a, **k)
        return dataclasses.replace(d, effective=effective_of(d.effective)) if d.kind == "applied" else d
    monkeypatch.setattr(v6dec, "verify_and_decide_v6", forged)


def test_f01_a_forged_registry_result_that_loosens_a_required_host_class_is_refused(tmp_path, monkeypatch):
    _forge(monkeypatch, lambda eff: {v6ra.F5RA_FIELD: {CLASS_T1: NR, CLASS_T2: NR}})
    p, res, cfg = base.prepared(tmp_path)
    host = variant(cfg, assure={CLASS_T1: True}, inventory=INV)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, host, fams(ra=Source(rmat({CLASS_T1: RQ}))))
    refused(e, "class_revocation_assurance:effective_policy_widens_host", "construction")


def test_f02_a_forged_registry_result_that_turns_a_host_on_off_is_refused(tmp_path, monkeypatch):
    _forge(monkeypatch, lambda eff: {v6tr.TR_FIELD: "off"})
    p, res, cfg = base.prepared(tmp_path)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, variant(cfg, terminal=True), fams(tr=Source(tmat("on"))))
    refused(e, "terminal_revocation:effective_policy_widens_host", "construction")


@pytest.mark.parametrize("forged,code", [({v6ra.F5RA_FIELD: {CLASS_T1: RQ}}, "effective_policy_invalid"),  # a class the host defines is missing
                                         ({v6ra.F5RA_FIELD: {CLASS_T1: RQ, CLASS_T2: RQ}}, "effective_policy_invalid"),  # stricter than registry+host for a class the record does not name
                                         ({v6ra.F5RA_FIELD: {CLASS_T1: True, CLASS_T2: NR}}, "effective_policy_invalid"),
                                         ({"other": 1}, "effective_policy_invalid")])
def test_f03_a_forged_registry_result_that_is_not_the_stricter_of_host_and_record_is_refused(tmp_path, monkeypatch, forged, code):
    _forge(monkeypatch, lambda eff: forged)
    p, res, cfg = base.prepared(tmp_path)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, fams(ra=Source(rmat({CLASS_T1: RQ}))))
    refused(e, "class_revocation_assurance:" + code, "construction")


DECL = dict(assurance_declared=True, terminal_declared=True)


def test_f04_the_final_composition_validator_rejects_a_dropped_requirement_a_dropped_section_and_foreign_changes(tmp_path):
    p, res, cfg = base.prepared(tmp_path)
    host = variant(cfg, assure={CLASS_T1: True}, inventory=INV, terminal=True)
    scalars = {"status_max_age_seconds": 60, "approval_max_age_seconds": 60}
    assert pol.final_composition_defect(host, host, scalars, None, **DECL) is None
    dropped_flag = variant(cfg, assure={CLASS_T1: False}, inventory=INV, terminal=True)
    assert pol.final_composition_defect(host, dropped_flag, scalars, None, **DECL) == "composed_widens_host"
    dropped_section = variant(cfg, assure={CLASS_T1: True}, inventory=INV, terminal=False)
    assert pol.final_composition_defect(host, dropped_section, scalars, None, **DECL) == "composed_widens_host"
    foreign = host.model_copy(update={"catalogue_version": "tampered/1"})
    assert pol.final_composition_defect(host, foreign, scalars, None, **DECL) == "composed_profile_invalid"
    no_inventory = RuntimeAuthorityProfile.model_validate({**host.model_dump(mode="json"), "holder_inventory": None})
    assert pol.final_composition_defect(host, no_inventory, scalars, None, **DECL) == "composed_profile_invalid"  # the inventory is a host claim: a composition may not remove it
    base_host = variant(cfg, inventory=INV)
    # adding is the only permitted change, and only by a DECLARED family: undeclared, the same gained flag or section is a foreign change
    assert pol.final_composition_defect(base_host, variant(cfg, assure={CLASS_T1: True}, inventory=INV), scalars, None) == "composed_profile_invalid"
    assert pol.final_composition_defect(base_host, variant(cfg, inventory=INV, terminal=True), scalars, None) == "composed_profile_invalid"
    assert pol.final_composition_defect(base_host, variant(cfg, assure={CLASS_T1: True}, inventory=INV), scalars, None, assurance_declared=True) is None
    assert pol.final_composition_defect(base_host, variant(cfg, inventory=INV, terminal=True), scalars, None, terminal_declared=True) is None
    assert pol.final_composition_defect(base_host, variant(cfg, assure={CLASS_T1: True}, inventory=INV, terminal=True), scalars, None, **DECL) is None


# =============================================================================================================== G/H/I: mandatory selection, replacement, revocation and withdrawal
@pytest.mark.parametrize("k", ["ra", "tr"])
def test_g01_a_failing_source_at_any_boundary_refuses_the_whole_workflow(tmp_path, k):
    p, res, cfg, srcs, flow, d = authorized(tmp_path, ra={CLASS_T1: RQ}, tr="on")
    srcs[k].fail = True
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    refused(e, "selection_source_failed", "effect")
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "selection_source_failed", "decision")
    assert flow.destination.snapshot()["effects"] == {}


@pytest.mark.parametrize("k", ["ra", "tr"])
def test_h01_a_replaced_selection_with_different_effective_values_is_refused_at_every_boundary(tmp_path, k):
    p, res, cfg, srcs, flow, d = authorized(tmp_path, ra={CLASS_T1: RQ}, tr="on")
    before = file_state(tmp_path, flow)
    srcs[k].mat = changed_for(k)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "selection_changed", "decision")
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    refused(e, "selection_changed", "effect")
    assert file_state(tmp_path, flow) == before


@pytest.mark.parametrize("k", ["ra", "tr"])
def test_i01_key_or_selection_revocation_blocks_the_decision_without_state_change(tmp_path, k):
    p, res, cfg, srcs, flow = ready(tmp_path, ra={CLASS_T1: RQ}, tr="on", host=with_inventory)
    before = file_state(tmp_path, flow)
    srcs[k].mat = revoked_for(k)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, prefix={"ra": "class_revocation_assurance:", "tr": "terminal_revocation:"}[k], boundary="decision", registry_code="selection_revoked")
    assert file_state(tmp_path, flow) == before and flow.records.load().decisions == []


@pytest.mark.parametrize("k", ["ra", "tr"])
def test_j01_revocation_between_decision_and_effect_blocks_the_effect(tmp_path, k):
    p, res, cfg, srcs, flow, d = authorized(tmp_path, ra={CLASS_T1: RQ}, tr="on")
    before = file_state(tmp_path, flow)
    srcs[k].mat = revoked_for(k)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    refused(e, boundary="effect", registry_code="selection_revoked")
    assert file_state(tmp_path, flow) == before and flow.destination.snapshot()["effects"] == {}


@pytest.mark.parametrize("k", ["ra", "tr"])
def test_k01_revocation_after_execute_entry_is_refused_at_the_commit_gate_and_nothing_is_dispatched(tmp_path, k):
    p, res, cfg, srcs, flow, d = authorized(tmp_path, ra={CLASS_T1: RQ}, tr="on")
    srcs[k].after = (4, revoked_for(k))  # construction, decision, effect entry, then the commit gate
    attempt, _ = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "failed" and attempt.error == pol.REJECTION_CODE and flow.destination.snapshot()["effects"] == {}
    assert flow.governed_last_commit_refusal.registry_code == "selection_revoked"
    persisted = [x for x in flow.records.load().attempts if x.effect_id == d.effect_id]
    assert persisted[-1].status == "failed" and not any(x.status == "acknowledged" for x in persisted)


@pytest.mark.parametrize("k", ["ra", "tr"])
def test_k02_a_replacement_between_execute_entry_and_dispatch_is_refused_at_the_commit_gate(tmp_path, k):
    p, res, cfg, srcs, flow, d = authorized(tmp_path, ra={CLASS_T1: RQ}, tr="on")
    srcs[k].after = (4, changed_for(k))
    attempt, _ = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "failed" and flow.destination.snapshot()["effects"] == {}
    assert flow.governed_last_commit_refusal.code == "selection_changed"


@pytest.mark.parametrize("k", ["ra", "tr"])
def test_k03_the_source_dying_exactly_at_the_commit_gate_blocks_the_effect(tmp_path, k):
    p, res, cfg, srcs, flow, d = authorized(tmp_path, ra={CLASS_T1: RQ}, tr="on")

    class Dies(Source):
        def __call__(self):
            self.calls += 1
            if self.calls >= 4:
                raise RuntimeError("down")
            return self.mat
    srcs[k].__class__ = Dies
    attempt, _ = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "failed" and flow.destination.snapshot()["effects"] == {}
    assert flow.governed_last_commit_refusal.code == "selection_source_failed"


@pytest.mark.parametrize("k", ["ra", "tr"])
def test_i02_a_withdrawn_selection_is_never_an_application(tmp_path, k):
    p, res, cfg, srcs, flow = ready(tmp_path, ra={CLASS_T1: RQ}, tr="on", host=with_inventory)
    if k == "ra":
        srcs[k].mat = base.withdrawn(lambda: rrec({CLASS_T1: RQ}), None, OP_RA, V6_DOMAIN, "r08-v6", v6ra.FAMILY_F5RA)
    else:
        srcs[k].mat = base.withdrawn(lambda: trec("on"), None, OP_TR, V6_DOMAIN, "r08-v6", v6tr.FAMILY_TR)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, boundary="decision", registry_code="selection_withdrawn")
    assert flow.destination.snapshot()["effects"] == {}


@pytest.mark.parametrize("k", ["ra", "tr"])
def test_i03_an_expired_selection_is_refused_after_construction(tmp_path, k):
    p, res, cfg, srcs, flow = ready(tmp_path, ra={CLASS_T1: RQ}, tr="on", host=with_inventory)
    late = NOW.replace(year=NOW.year + 1)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.decide(p, now=late)
    refused(e, boundary="decision")


def test_k04_a_failed_attempt_blocks_the_automatic_retry_and_never_reaches_the_destination(tmp_path):
    comp.Spy.applies = 0
    p, res, cfg = base.prepared(tmp_path)
    cfg = with_inventory(cfg)
    srcs = sources(ra={CLASS_T1: RQ}, tr="on")
    flow = build(tmp_path, res, cfg, fams(srcs["ra"], srcs["tr"]), destination=comp.Spy(tmp_path / "spy.json"))
    bind_approval(res, flow.runtime_authority_profile)
    d = flow.decide(p, now=NOW)
    srcs["tr"].after = (4, revoked_for("tr"))
    attempt, _ = flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "failed" and comp.Spy.applies == 0
    srcs["tr"].after = None
    with pytest.raises(PermissionError, match="retry eligibility"):
        flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert comp.Spy.applies == 0


# =============================================================================================================== L-O, P: evidence, replay, stale state, bindings
def test_l01_no_synthetic_assurance_evidence_is_ever_produced(tmp_path):
    """There is no receipt, token or evidence object for assurance: the only observable outcomes are the existing hold or the existing decision."""
    p, res, cfg, srcs, flow = ready(tmp_path, ra={CLASS_T1: RQ})
    ident = flow.registry_governed_policy_identity
    assert set(ident["class_revocation_assurance"]) == {"effective", "effective_policy_digest"}
    assert not [n for n in dir(rev) if any(w in n.lower() for w in ("receipt", "attest", "evidence", "inventory_create", "make_inventory"))]


def test_n01_a_decision_persisted_under_the_forced_profile_cannot_be_executed_by_a_workflow_with_the_host_profile(tmp_path):
    p, res, cfg, srcs, flow, d = authorized(tmp_path, ra={CLASS_T1: RQ}, tr="on")
    host_only = base.plain(tmp_path, res, cfg)
    bind_approval(res, host_only.runtime_authority_profile)
    with pytest.raises(PermissionError, match="authorization-critical inputs changed"):
        host_only.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert host_only.destination.snapshot()["effects"] == {}


def test_n02_a_decision_persisted_under_the_host_profile_cannot_be_executed_by_the_forced_workflow(tmp_path):
    p, res, cfg = base.prepared(tmp_path)
    cfg = with_inventory(cfg)
    plain = base.plain(tmp_path, res, cfg)
    bind_approval(res, plain.runtime_authority_profile)
    d = plain.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    forced = build(tmp_path, res, cfg, fams(Source(rmat({CLASS_T1: RQ})), Source(tmat("on"))))
    bind_approval(res, forced.runtime_authority_profile)
    with pytest.raises(PermissionError, match="authorization-critical inputs changed"):
        forced.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert forced.destination.snapshot()["effects"] == {}


def test_o01_restart_with_the_same_families_resumes_a_persisted_decision(tmp_path):
    p, res, cfg, srcs, flow, d = authorized(tmp_path, ra={CLASS_T1: RQ}, tr="on")
    restarted = build(tmp_path, res, cfg, fams(srcs["ra"], srcs["tr"]))
    assert restarted.records.decision(d.decision_id) == d
    attempt, observed = restarted.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and observed.state == "applied"


def test_o02_restart_after_an_interrupted_attempt_keeps_the_negative_record_and_the_terminal_refusal(tmp_path):
    p, res, cfg, srcs, flow, d = authorized(tmp_path, tr="on")
    _revoke_then_restore(flow, p, res, d)
    restarted = build(tmp_path, res, cfg, fams(tr=srcs["tr"]))
    again = restarted.decide(p, now=NOW)
    assert again.result == "hold" and again.reasons == [CODE_REVOCATION_RECORDED]  # a restart never turns the memory off


def test_n03_post_construction_edits_of_the_held_profile_are_refused_at_every_boundary(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, ra={CLASS_T1: RQ}, tr="on", host=with_inventory)
    flow.runtime_authority_profile = variant(cfg)  # the host profile put back over the effective one
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "profile_modified", "decision")


@pytest.mark.parametrize("part", ["class_revocation_assurance", "terminal_revocation"])
def test_n04_each_new_component_of_the_bound_identity_is_compared_on_its_own(tmp_path, monkeypatch, part):
    p, res, cfg, srcs, flow = ready(tmp_path, ra={CLASS_T1: RQ}, tr="on", host=with_inventory)
    bound = dict(flow._gl_bound)
    v = bound[part]
    bound[part] = (v[0], "sha256:" + "0" * 64)
    monkeypatch.setattr(flow, "_gl_bound", bound)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "selection_changed", "decision")


# =============================================================================================================== ledger: configuration identity covers the new families
def test_l02_two_configurations_that_differ_only_in_a_new_family_never_share_an_identity(tmp_path):
    ledger = GovernedActivationLedger()
    p, res, cfg = base.prepared(tmp_path / "a")
    first = build(tmp_path / "a", res, cfg, fams(ra=Source(rmat({CLASS_T1: RQ}))), pol={"activation_ledger": ledger})
    p2, res2, cfg2 = base.prepared(tmp_path / "b")
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path / "b", res2, cfg2, fams(ra=Source(rmat({CLASS_T1: RQ, CLASS_T2: RQ}, stmt_over=CHANGED))), pol={"activation_ledger": ledger})
    refused(e, "conflicting_governed_configuration", "construction")
    same = build(tmp_path / "c", res2, cfg2, fams(ra=Source(rmat({CLASS_T1: RQ}))), pol={"activation_ledger": ledger})
    assert same.registry_governed_policy_identity["configuration_digest"] == first.registry_governed_policy_identity["configuration_digest"]


def test_l03_a_host_value_difference_changes_the_identity_even_with_the_same_registry_material(tmp_path):
    p, res, cfg = base.prepared(tmp_path / "a")
    a = build(tmp_path / "a", res, cfg, fams(tr=Source(tmat("on"))))
    b = build(tmp_path / "b", res, variant(cfg, terminal=True), fams(tr=Source(tmat("on"))))
    assert a.registry_governed_policy_identity["configuration_digest"] != b.registry_governed_policy_identity["configuration_digest"]
    assert a.runtime_authority_profile.terminal_revocation == b.runtime_authority_profile.terminal_revocation  # same effective profile, different governance


# =============================================================================================================== R/S/T: frozen Registry compatibility, protected files, existing suites
def test_r01_the_new_families_use_only_the_r08_v6_contract_and_the_older_contracts_still_work(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, ra={CLASS_T1: RQ}, tr="on", u=True, a=True, f=True)
    assert '"r08-v6"' in srcs["ra"].mat.selection_text.replace(" ", "") and '"r08-v6"' in srcs["tr"].mat.selection_text.replace(" ", "")
    for k, ctr in (("f", "r08-v2"), ("a", "r08-v2"), ("u", "r08-v5")):
        assert ctr in srcs[k].mat.selection_text


@pytest.mark.parametrize("k", ["ra", "tr"])
def test_r02_a_record_of_another_contract_or_family_in_a_new_slot_is_refused(tmp_path, k):
    p, res, cfg = base.prepared(tmp_path)
    prefix = {"ra": "class_revocation_assurance:", "tr": "terminal_revocation:"}[k]
    wrong = {"ra": [rmat(rec=rrec(contract="r08-v5")), rmat(contract="r08-v5", domain=base.V5_DOMAIN), tmat("on")],
             "tr": [tmat(rec=trec(contract="r08-v5")), tmat(contract="r08-v5", domain=base.V5_DOMAIN), rmat({CLASS_T1: RQ})]}[k]
    for i, material in enumerate(wrong):
        if k == "ra" and i == 2:
            material = dataclasses.replace(material, selection_text=material.selection_text)  # a terminal-family selection in the assurance slot
        with pytest.raises(RegistryGovernedPolicyRefused) as e:
            build(tmp_path / f"{k}{i}", res, cfg, fams(**{k: Source(material)}))
        refused(e, prefix=prefix, boundary="construction")


def test_s01_the_protected_evaluators_and_the_holder_inventory_module_are_byte_identical_to_main(tmp_path):
    pins = dict(comp.PROTECTED)
    pins["holder_inventory.py"] = "76f5aaa63f49bac182439ea3768798bf42ecbda2c586f20fd450a7053271f7ba"
    for name, digest in pins.items():
        assert hashlib.sha256((SRC / name).read_bytes()).hexdigest() == digest, name


def test_s02_the_new_module_adds_no_workflow_no_evaluator_import_and_no_policy_interpreter():
    import ast
    tree = ast.parse((SRC / "registry_revocation_governance.py").read_text())
    for node in ast.walk(tree):
        if isinstance(node, (ast.Module, ast.ClassDef, ast.FunctionDef)) and node.body and isinstance(node.body[0], ast.Expr) and isinstance(getattr(node.body[0], "value", None), ast.Constant):
            node.body = node.body[1:] or [ast.Pass()]
    assert not [n for n in ast.walk(tree) if isinstance(n, ast.ClassDef)], "no workflow subclass may be added by this module"
    imported = {n.module for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) and n.module} | {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names}
    assert not any(m.endswith(("bounded", "freshness", "policy_binding", "holder_inventory", "reversibility", "rule_revision")) for m in imported), imported
    code = ast.unparse(tree)
    assert "eval(" not in code and "exec(" not in code and "on_unreadable" not in code and "approval_commitment" not in code


def test_s03_only_the_composed_module_changes_composition_and_no_protected_field_is_written_by_the_new_module(tmp_path):
    p, res, cfg, srcs, flow = ready(tmp_path, ra={CLASS_T1: RQ}, tr="on", host=with_inventory)
    changed = {k for k, v in flow.runtime_authority_profile.model_dump(mode="json").items() if cfg.model_dump(mode="json").get(k) != v}
    assert changed == {"actions", "terminal_revocation"}


# =============================================================================================================== defensive checks (direct): second parse, decision shape, verifier, material, host values
def test_u01_the_second_strict_parse_of_the_verified_record_text_refuses_anything_unusual():
    ok = '{"payload":{"class_requires_revocation_assurance":{"a":"required"}}}'
    assert rev.registry_assurance_map(ok) == {"a": "required"}
    for bad in ('{"payload":{"class_requires_revocation_assurance":{"a":"required","a":"required"}}}', '{"payload":{"class_requires_revocation_assurance":{"a":1}}}',
                '{"payload":{"class_requires_revocation_assurance":{"a":"required"},"x":1}}', '{"payload":{"class_requires_revocation_assurance":{}}}',
                '{"payload":{"class_requires_revocation_assurance":{"a":"REQUIRED"}}}', '{"payload":{"class_requires_revocation_assurance":{"a":"required"}},"x":1.5}',
                '{"payload":{"class_requires_revocation_assurance":{"a":"required"}},"x":NaN}', "not json", '{"payload":3}', '{"payload":{"other":{"a":"required"}}}'):
        assert rev.registry_assurance_map(bad) is None, bad
    assert rev.registry_terminal_value('{"payload":{"terminal_revocation":"on"}}') == "on"
    for bad in ('{"payload":{"terminal_revocation":"on","terminal_revocation":"off"}}', '{"payload":{"terminal_revocation":1}}', '{"payload":{"terminal_revocation":"on","x":1}}',
                '{"payload":{"terminal_revocation":true}}', '{"payload":{"terminal_revocation":"On"}}', '{"payload":{"terminal_revocation":"on"},"x":1.5}', "[]"):
        assert rev.registry_terminal_value(bad) is None, bad


def _direct(k, cfg, **over):
    common = dict(scope=SCOPE_RA if k == "ra" else SCOPE_TR, institution_id=base.INSTITUTION, authority_domain=base.DOMAIN, verifier=ev.Ed25519Verifier(), now=REG_NOW)
    common["material"] = Source(rmat() if k == "ra" else tmat()).__call__()
    common.update(over)
    if k == "ra":
        return rev.derive_assurance(host=cfg, host_values={CLASS_T1: NR, CLASS_T2: NR}, **common)
    return rev.derive_terminal(host_value="off", **common)


@pytest.mark.parametrize("k", ["ra", "tr"])
def test_u02_a_verifier_that_is_not_the_admitted_ed25519_verifier_and_wrong_material_types_are_refused(tmp_path, k):
    p, res, cfg = base.prepared(tmp_path)
    assert _direct(k, cfg)[1] is None  # positive control: the same call succeeds
    assert _direct(k, cfg, verifier=object())[1].code == "verifier_not_admitted"
    for bad in ("text", None, base.SelectionMaterial(b"bytes", "x", None), base.SelectionMaterial("x", 3, None)):
        assert _direct(k, cfg, material=bad)[1].code == "material_invalid"


def test_u03_a_host_class_with_two_assurance_values_or_a_non_bool_flag_is_refused_before_any_registry_call(tmp_path):
    p, res, cfg = base.prepared(tmp_path, shared=B_, t2_irrev=False)  # the T2 action shares the T1 class id
    doc = cfg.model_dump(mode="json")
    doc["actions"][list(doc["actions"])[0]]["requires_revocation_assurance"] = True  # one action of the shared class flagged, the other not
    split = RuntimeAuthorityProfile.model_validate(doc)
    assert rev.host_class_assurance(split) == (None, "class_assurance_ambiguous")
    srcs = sources(ra={CLASS_T1: RQ})
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, split, fams(ra=srcs["ra"]))
    refused(e, "class_assurance_ambiguous", "construction")
    assert srcs["ra"].calls == 0
    first = next(iter(cfg.actions))
    forged = cfg.model_copy(update={"actions": {**cfg.actions, first: cfg.actions[first].model_copy(update={"requires_revocation_assurance": "yes"})}})
    assert rev.host_class_assurance(forged) == (None, "host_class_assurance_invalid")


@pytest.mark.parametrize("k", ["ra", "tr"])
@pytest.mark.parametrize("what", ["authorized", "wrong_kind", "deny_all", "not_applied"])
def test_f05_a_registry_decision_of_the_wrong_shape_is_refused(tmp_path, monkeypatch, k, what):
    real = v6dec.verify_and_decide_v6
    change = {"authorized": dict(operationally_authorized=True), "wrong_kind": dict(kind="applied_deny_all"), "deny_all": dict(deny_all=True),
              "not_applied": dict(kind="overlay_not_applied")}[what]
    monkeypatch.setattr(v6dec, "verify_and_decide_v6", lambda *a, **kw: dataclasses.replace(real(*a, **kw), **change))
    p, res, cfg = base.prepared(tmp_path)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, fams(**{k: Source(rmat() if k == "ra" else tmat())}))
    refused(e, prefix={"ra": "class_revocation_assurance:", "tr": "terminal_revocation:"}[k], boundary="construction")
    assert e.value.refusal.code.split(":", 1)[1] in ("registry_decision_invalid", "registry_not_applied")


class _Str(str):
    pass


def test_f06_a_forged_effective_value_that_is_not_the_stricter_of_host_and_record_or_not_an_exact_str_is_refused(tmp_path, monkeypatch):
    p, res, cfg = base.prepared(tmp_path)
    for forged, code in (({v6ra.F5RA_FIELD: {CLASS_T1: NR, CLASS_T2: NR}}, "effective_policy_invalid"),  # looser than the record: not a widening of the host, but not the stricter value
                         ({v6ra.F5RA_FIELD: {CLASS_T1: _Str(RQ), CLASS_T2: NR}}, "effective_policy_invalid")):
        _forge(monkeypatch, lambda eff, f=forged: f)
        with pytest.raises(RegistryGovernedPolicyRefused) as e:
            build(tmp_path / code[:3] / str(id(forged)), res, cfg, fams(ra=Source(rmat({CLASS_T1: RQ}))))
        refused(e, "class_revocation_assurance:" + code, "construction")
    _forge(monkeypatch, lambda eff: {v6tr.TR_FIELD: "off"})
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path / "t", res, cfg, fams(tr=Source(tmat("on"))))  # host off, record on, forged off: not the stricter value
    refused(e, "terminal_revocation:effective_policy_invalid", "construction")


def test_f07_a_forged_effective_class_set_that_differs_from_the_host_classes_is_refused(tmp_path, monkeypatch):
    p, res, cfg = base.prepared(tmp_path)
    _forge(monkeypatch, lambda eff: {v6ra.F5RA_FIELD: {CLASS_T1: RQ, CLASS_T2: NR, "class-extra": NR}})
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, fams(ra=Source(rmat({CLASS_T1: RQ}))))
    refused(e, "class_revocation_assurance:effective_policy_invalid", "construction")


def test_f08_a_forged_value_outside_the_closed_vocabulary_is_refused(tmp_path, monkeypatch):
    p, res, cfg = base.prepared(tmp_path)
    _forge(monkeypatch, lambda eff: {v6tr.TR_FIELD: "ON"})
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, fams(tr=Source(tmat("on"))))
    refused(e, "terminal_revocation:effective_policy_invalid", "construction")
    _forge(monkeypatch, lambda eff: {v6ra.F5RA_FIELD: {CLASS_T1: "maybe", CLASS_T2: NR}})
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path / "b", res, cfg, fams(ra=Source(rmat({CLASS_T1: RQ}))))
    refused(e, "class_revocation_assurance:effective_policy_invalid", "construction")


def test_l04_a_difference_only_in_the_host_assurance_flag_changes_the_configuration_identity(tmp_path):
    p, res, cfg = base.prepared(tmp_path / "a")
    unflagged = build(tmp_path / "a", res, cfg, fams(ra=Source(rmat({CLASS_T1: RQ}))))
    flagged = build(tmp_path / "b", res, variant(cfg, assure={CLASS_T1: True}), fams(ra=Source(rmat({CLASS_T1: RQ}))))
    assert unflagged.runtime_authority_profile.model_dump() == flagged.runtime_authority_profile.model_dump()  # same effective profile ...
    assert unflagged.registry_governed_policy_identity["configuration_digest"] != flagged.registry_governed_policy_identity["configuration_digest"]  # ... different governance


@pytest.mark.parametrize("k", ["ra", "tr"])
def test_n05_editing_the_held_profile_is_refused_when_that_family_governs_alone(tmp_path, k):
    p, res, cfg, srcs, flow = ready(tmp_path, ra={CLASS_T1: RQ} if k == "ra" else None, tr="on" if k == "tr" else None, host=with_inventory)
    flow.runtime_authority_profile = with_inventory(cfg)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        flow.decide(p, now=NOW)
    refused(e, "profile_modified", "decision")


def test_u04_the_composers_only_ever_add_and_the_defensive_checks_hold_when_reached_directly(tmp_path, monkeypatch):
    p, res, cfg = base.prepared(tmp_path)
    flagged = variant(cfg, assure={CLASS_T1: True}, inventory=INV, terminal=True)
    kept = rev.compose_assurance(flagged, {CLASS_T1: NR, CLASS_T2: NR})
    assert flags(kept) == {CLASS_T1: True, CLASS_T2: False}  # a host flag is never cleared
    assert rev.compose_terminal(flagged, "off").terminal_revocation is not None  # a host section is never removed
    assert rev.compose_terminal(cfg, "on").terminal_revocation == flagged.terminal_revocation and rev.compose_terminal(cfg, "off").terminal_revocation is None
    assert rev.compose_assurance(cfg, {CLASS_T1: RQ, CLASS_T2: NR}).model_dump(mode="json")["actions"][ACTION_ID]["requires_revocation_assurance"] is True
    # the derive functions refuse these on their own even though the workflow refuses them earlier
    ghost = GovernedScope("consumer-test", TENANT.lower(), "urn:cognous:action:ghost-v1", OP_RA)
    assert _direct("ra", cfg, scope=ghost)[1].code == "action_class_unknown"
    assert rev.derive_terminal(scope=SCOPE_TR, institution_id=base.INSTITUTION, authority_domain=base.DOMAIN, host_value="bogus", material=Source(tmat()).__call__(),
                               verifier=ev.Ed25519Verifier(), now=REG_NOW)[1].code == "host_terminal_invalid"
    from registry_successor.decision import PolicyDecision
    monkeypatch.setattr(v6dec, "verify_and_decide_v6", lambda *a, **k: PolicyDecision("applied", {v6ra.F5RA_FIELD: {CLASS_T1: RQ, CLASS_T2: NR}}, False, (), None, "", False))
    unknown = Source(rmat(rec=rrec(payload={v6ra.F5RA_FIELD: {CLASS_T1: RQ, "class-x": RQ}}))).__call__()
    got = _direct("ra", cfg, material=unknown)
    assert got[1].code == "effective_policy_invalid"  # a record naming a class the host does not define is refused here too, independent of the Registry composer
    section = flagged.terminal_revocation.model_construct(version="terminal-revocation/9.9")
    foreign = flagged.model_copy(update={"terminal_revocation": section})
    assert pol.final_composition_defect(flagged, foreign, {"status_max_age_seconds": 60, "approval_max_age_seconds": 60}, None, terminal_declared=True) == "composed_profile_invalid"


@pytest.mark.parametrize("sneak", ["flag", "section"])
def test_f09_another_composer_that_adds_a_revocation_field_without_the_family_being_declared_is_refused(tmp_path, monkeypatch, sneak):
    """Defence in depth: the new fields may differ only when their family is declared. A (buggy) composer of ANOTHER family that gains a flag or the section is a foreign change."""
    real = base.gov.compose_unreadable
    monkeypatch.setattr(pol.unrmod, "compose_unreadable", lambda b, e: rev.compose_assurance(real(b, e), {CLASS_T1: RQ, CLASS_T2: NR}) if sneak == "flag" else rev.compose_terminal(real(b, e), "on"))
    p, res, cfg = base.prepared(tmp_path)
    with pytest.raises(RegistryGovernedPolicyRefused) as e:
        build(tmp_path, res, cfg, fams(u=comp.usrc()))
    refused(e, "composed_profile_invalid", "construction")
