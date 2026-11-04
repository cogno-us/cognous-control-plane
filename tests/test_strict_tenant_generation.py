"""CP-2 (csf_4a764c7437e3bd47679c7b44): strict tenant-binding generation alongside unchanged legacy bounded-authorization-effect/0.2.

Strict: for a tenant-aware proposal, evidence.tenant_id must EXACTLY equal proposal.tenant_id; None is never a wildcard. The generation is
persisted in the decision binding and is never re-judged: a legacy decision stays legacy, a strict decision stays strict, at effect, claim and
pin time. Synthetic fixtures only; builder-authored, not independent qualification.
"""
from __future__ import annotations

import json

import pytest

from agent_control_plane.authorization_pin_export import assess_authorization_pin
from agent_control_plane.bounded import (
    TENANT_GENERATION_LEGACY, TENANT_GENERATION_STRICT, BoundedAuthorizationWorkflow, BoundedRecordStore, EvidenceStatus,
    LocalRefundDestination, ObservationPolicy, TenantAuthorizationBinding, commitment,
)
from agent_control_plane.local_authority_effect import provision_local_execution_claim
from tests import v02_support as v02
from tests.test_bounded_authorization import (  # noqa: F401  (autouse clock)
    NOW, TENANT, _fixed_synthetic_clock, manifest, proposal, resolver_for, tenant_proposal, tenant_resolver_for, workflow,
)
from tests.test_runtime_authority import sign_evidence

OTHER = "tenant-beta"
LEGACY = {"tenant_binding_generation": TENANT_GENERATION_LEGACY}


def _flow(tmp_path, evidence_tenant, *, tenant=TENANT, generation=None):
    p = tenant_proposal(tenant)
    r = tenant_resolver_for(p, tenant_id=tenant, evidence_tenant=evidence_tenant)
    kw = {"tenant_binding_generation": generation} if generation else {}
    return p, r, workflow(tmp_path, p, resolver=r, **kw)


def _set_evidence(r, tenant):
    for ev in r.evidence.values():
        ev.tenant_id = tenant


# ---- default, constants, construction ---------------------------------------------------------------------------------------------
def test_default_for_new_tenant_aware_workflow_is_strict_and_stamped(tmp_path):
    p, r, f = _flow(tmp_path, TENANT)
    assert f.tenant_binding_generation == TENANT_GENERATION_STRICT
    d = f.decide(p, now=NOW)
    assert d.result == "authorized" and isinstance(d.binding, TenantAuthorizationBinding)
    assert d.binding.generation == TENANT_GENERATION_STRICT != TENANT_GENERATION_LEGACY
    assert json.loads(d.binding.model_dump_json())["generation"] == TENANT_GENERATION_STRICT


def test_unmarked_persisted_tenant_binding_parses_as_legacy():
    """A tenant binding persisted before this change has generation 0.2 in its bytes; a binding without the member means legacy too."""
    assert TenantAuthorizationBinding.model_fields["generation"].default == TENANT_GENERATION_LEGACY


@pytest.mark.parametrize("bad", ["", "bounded-authorization-effect/0.3", None, 1, "bounded-authorization-effect/0.2 ", "STRICT"])
def test_unknown_generation_refused_at_construction(tmp_path, bad):
    p = tenant_proposal()
    with pytest.raises(ValueError):
        workflow(tmp_path, p, resolver=tenant_resolver_for(p), tenant_binding_generation=bad)


def test_str_subclass_generation_refused_at_construction(tmp_path):
    class S(str):
        pass
    p = tenant_proposal()
    with pytest.raises(ValueError):
        workflow(tmp_path, p, resolver=tenant_resolver_for(p), tenant_binding_generation=S(TENANT_GENERATION_STRICT))


def test_tenantless_v01_proposal_is_unaffected_by_generation(tmp_path):
    for name, kw in (("s", {}), ("l", LEGACY)):
        (tmp_path / name).mkdir()
        p = proposal()
        d = workflow(tmp_path / name, p, **kw).decide(p, now=NOW)
        assert d.result == "authorized" and type(d.binding).__name__ == "AuthorizationBinding"
        assert "generation" not in d.binding.model_dump(mode="json")


# ---- decision time ----------------------------------------------------------------------------------------------------------------
def test_a_plus_a_allowed(tmp_path):
    p, r, f = _flow(tmp_path, TENANT)
    assert f.decide(p, now=NOW).result == "authorized"


def test_a_plus_b_refused_in_both_generations(tmp_path):
    for name, g in (("s", None), ("l", TENANT_GENERATION_LEGACY)):
        (tmp_path / name).mkdir()
        p, r, f = _flow(tmp_path / name, OTHER, generation=g)
        d = f.decide(p, now=NOW)
        assert d.result == "hold" and "evidence_binding_mismatch" in d.reasons and d.binding is None


def test_a_plus_tenantless_refused_strict(tmp_path):
    p, r, f = _flow(tmp_path, None)
    d = f.decide(p, now=NOW)
    assert d.result == "hold" and "evidence_binding_mismatch" in d.reasons and d.binding is None


def test_legacy_explicit_keeps_tenantless_wildcard(tmp_path):
    p, r, f = _flow(tmp_path, None, generation=TENANT_GENERATION_LEGACY)
    d = f.decide(p, now=NOW)
    assert d.result == "authorized" and d.binding.generation == TENANT_GENERATION_LEGACY


def test_tenantless_proposal_cannot_consume_tenant_evidence_in_either_generation(tmp_path):
    for name, kw in (("s", {}), ("l", LEGACY)):
        (tmp_path / name).mkdir()
        p = proposal()
        r = resolver_for(p)
        _set_evidence(r, TENANT)
        d = workflow(tmp_path / name, p, resolver=r, **kw).decide(p, now=NOW)
        assert d.result == "hold" and "tenant_proposal_required" in d.reasons


def test_shared_resolver_serving_tenantless_evidence_to_two_tenants_refused_strict(tmp_path):
    """One tenantless evidence record must not authorize tenant A and tenant B (legacy wildcard); legacy still does, explicitly."""
    for generation, expect in ((None, "hold"), (TENANT_GENERATION_LEGACY, "authorized")):
        results = []
        for t in ("tenant-alpha", "tenant-beta"):
            d_ = tmp_path / f"{generation is None}-{t}"
            d_.mkdir()
            p, r, f = _flow(d_, None, tenant=t, generation=generation)
            results.append(f.decide(p, now=NOW).result)
        assert results == [expect, expect]


# ---- exact string semantics -------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("variant", [" tenant-alpha", "tenant-alpha ", "Tenant-Alpha", "tenant-alpha​", "tenant-alpha\n", "tenant–alpha"])
def test_padded_or_case_variant_evidence_tenant_refused_strict(tmp_path, variant):
    p, r, f = _flow(tmp_path, variant)
    d = f.decide(p, now=NOW)
    assert d.result == "hold" and "evidence_binding_mismatch" in d.reasons


def test_padded_proposal_tenant_requires_same_padding_on_evidence(tmp_path):
    p, r, f = _flow(tmp_path, "tenant-alpha", tenant=" tenant-alpha")
    _set_evidence(r, "tenant-alpha")
    assert f.decide(p, now=NOW).result == "hold"
    _set_evidence(r, " tenant-alpha")
    assert f.decide(p, now=NOW).result == "authorized"


def test_str_subclass_evidence_tenant_with_lying_eq_refused_strict(tmp_path):
    class Liar(str):
        def __eq__(self, other):
            return True
        def __ne__(self, other):
            return False
        __hash__ = str.__hash__
    p, r, f = _flow(tmp_path, TENANT)
    for key, ev in list(r.evidence.items()):
        r.evidence[key] = EvidenceStatus.model_construct(**{**ev.__dict__, "tenant_id": Liar("tenant-beta")})
    d = f.decide(p, now=NOW)
    assert d.result == "hold" and "evidence_binding_mismatch" in d.reasons


def test_str_subclass_equal_value_is_also_refused_strict(tmp_path):
    """Exactness is type AND value: a subclass instance is not accepted even when its value is equal."""
    class Sub(str):
        pass
    p, r, f = _flow(tmp_path, TENANT)
    for key, ev in list(r.evidence.items()):
        r.evidence[key] = EvidenceStatus.model_construct(**{**ev.__dict__, "tenant_id": Sub(TENANT)})
    assert f.decide(p, now=NOW).result == "hold"


# ---- effect time ------------------------------------------------------------------------------------------------------------------
@pytest.mark.parametrize("changed", [None, OTHER, " tenant-alpha"])
def test_effect_time_strict_refuses_when_evidence_stops_naming_the_tenant(tmp_path, changed):
    p, r, f = _flow(tmp_path, TENANT)
    d = f.decide(p, now=NOW)
    assert d.result == "authorized"
    _set_evidence(r, changed)
    with pytest.raises(PermissionError):
        f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert f.destination.snapshot()["effects"] == {}
    reasons = [x for ref in f.records.load().refusals for x in ref.reasons]
    assert "evidence_binding_mismatch" in reasons


def test_end_to_end_a_plus_a_applies_effect(tmp_path):
    p, r, f = _flow(tmp_path, TENANT)
    d = f.decide(p, now=NOW)
    attempt, obs = f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and len(f.destination.snapshot()["effects"]) == 1


def test_tenantless_evidence_never_reaches_an_effect_under_strict(tmp_path):
    p, r, f = _flow(tmp_path, None)
    d = f.decide(p, now=NOW)
    assert d.result == "hold"
    with pytest.raises(PermissionError):
        f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert f.destination.snapshot()["effects"] == {}


# ---- persisted generation stays ---------------------------------------------------------------------------------------------------
def _reopen(tmp_path, p, r, **kw):
    """A fresh workflow object over the SAME persisted records, with the given configured generation."""
    return BoundedAuthorizationWorkflow(
        allow_test_time=True, manifest=manifest(), resolver=r, destination=LocalRefundDestination(tmp_path / "destination.json"),
        records=BoundedRecordStore(tmp_path / "run.json", "run-1"), observation_policy=ObservationPolicy(max_age_seconds=300, clock_tolerance_seconds=5), **kw)


def test_persisted_legacy_decision_stays_legacy_under_strict_configured_workflow(tmp_path):
    p, r, f = _flow(tmp_path, None, generation=TENANT_GENERATION_LEGACY)
    d = f.decide(p, now=NOW)
    assert d.result == "authorized" and d.binding.generation == TENANT_GENERATION_LEGACY
    strict_default = _reopen(tmp_path, p, r)  # default strict
    assert strict_default.tenant_binding_generation == TENANT_GENERATION_STRICT
    persisted = strict_default.records.decision(d.decision_id)
    assert persisted.binding.generation == TENANT_GENERATION_LEGACY
    attempt, _ = strict_default.execute(p, persisted, adapter_id=p.adapter_id, now=NOW)  # judged under 0.2, not re-judged strict
    assert attempt.status == "acknowledged"
    # and a NEW decision of that same strict workflow is strict
    assert strict_default.decide(p, now=NOW).result == "hold"


def test_persisted_strict_decision_stays_strict_under_legacy_configured_workflow(tmp_path):
    p, r, f = _flow(tmp_path, TENANT)
    d = f.decide(p, now=NOW)
    assert d.binding.generation == TENANT_GENERATION_STRICT
    legacy_cfg = _reopen(tmp_path, p, r, **LEGACY)
    persisted = legacy_cfg.records.decision(d.decision_id)
    _set_evidence(r, None)  # legacy would accept this; the strict decision must not
    with pytest.raises(PermissionError):
        legacy_cfg.execute(p, persisted, adapter_id=p.adapter_id, now=NOW)
    assert legacy_cfg.destination.snapshot()["effects"] == {}
    _set_evidence(r, TENANT)
    attempt, _ = legacy_cfg.execute(p, persisted, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged"


def test_effect_id_commits_to_strict_generation_only(tmp_path):
    """Legacy and historical effect identities are unchanged; strict adds the generation so a stored flip is detectable."""
    p, r, f = _flow(tmp_path, TENANT)
    ds = f.decide(p, now=NOW)
    legacy = tmp_path / "l"
    legacy.mkdir()
    p2, r2, f2 = _flow(legacy, TENANT, generation=TENANT_GENERATION_LEGACY)
    dl = f2.decide(p2, now=NOW)
    b = dl.binding
    assert dl.effect_id == commitment({"proposal": b.proposal_commitment, "grant_id": b.grant_id, "grant_revision": b.grant_revision})
    assert ds.effect_id != commitment({"proposal": ds.binding.proposal_commitment, "grant_id": ds.binding.grant_id, "grant_revision": ds.binding.grant_revision})


@pytest.mark.parametrize("start, flip_to", [(None, TENANT_GENERATION_LEGACY), (TENANT_GENERATION_LEGACY, TENANT_GENERATION_STRICT)])
def test_generation_downgrade_and_upgrade_refused(tmp_path, start, flip_to):
    p, r, f = _flow(tmp_path, TENANT, generation=start)
    d = f.decide(p, now=NOW)
    # (a) the caller presents the decision with the generation flipped: it is not the immutable persisted decision
    forged = d.model_copy(update={"binding": d.binding.model_copy(update={"generation": flip_to})})
    with pytest.raises(PermissionError, match="persisted decision"):
        f.execute(p, forged, adapter_id=p.adapter_id, now=NOW)
    # (b) the stored decision itself is flipped (store tamper): the effect identity no longer matches
    doc = json.loads((tmp_path / "run.json").read_text())
    for row in doc["decisions"]:
        row["binding"]["generation"] = flip_to
    (tmp_path / "run.json").write_text(json.dumps(doc))
    tampered = _reopen(tmp_path, p, r)
    persisted = tampered.records.decision(d.decision_id)
    assert persisted.binding.generation == flip_to
    _set_evidence(r, None)  # the point of a downgrade
    with pytest.raises(PermissionError):
        tampered.execute(p, persisted, adapter_id=p.adapter_id, now=NOW)
    assert tampered.destination.snapshot()["effects"] == {}


# ---- claim and pin time -----------------------------------------------------------------------------------------------------------
def _journal(tmp_path, **kw):
    p, r, f, d, cfg, = v02.tenant_flow(tmp_path, v02.canonical_binding(), **kw)
    return p, r, f, d, cfg


def test_journal_strict_decision_records_strict_generation(tmp_path):
    p, r, f, d, cfg = _journal(tmp_path)
    assert d.binding.generation == TENANT_GENERATION_STRICT


@pytest.mark.parametrize("changed", [None, OTHER])
def test_claim_time_strict_refuses_and_never_provisions(tmp_path, changed):
    p, r, f, d, cfg = _journal(tmp_path)
    sink = []
    _set_evidence(r, changed)
    with pytest.raises(PermissionError):
        provision_local_execution_claim(f, p, d, now=NOW, provision=sink.append, claim_id="c1")
    assert sink == []


def test_claim_time_a_plus_a_still_provisions(tmp_path):
    p, r, f, d, cfg = _journal(tmp_path)
    sink = []
    provision_local_execution_claim(f, p, d, now=NOW, provision=sink.append, claim_id="c1")
    assert len(sink) == 1 and sink[0].tenant_id == TENANT


@pytest.mark.parametrize("changed", [None, OTHER])
def test_pin_time_strict_refuses(tmp_path, changed):
    p, r, f, d, cfg = _journal(tmp_path)
    b = v02.canonical_binding()
    _set_evidence(r, changed)
    try:
        out = assess_authorization_pin(f, p, d, now=NOW, host_policy_binding=b)
    except PermissionError:
        return
    assert out["state"] != "active" and out["payload"] is None


def test_pin_time_a_plus_a_active(tmp_path):
    p, r, f, d, cfg = _journal(tmp_path)
    assert assess_authorization_pin(f, p, d, now=NOW, host_policy_binding=v02.canonical_binding())["state"] == "active"


def test_claim_and_pin_time_legacy_decision_stays_legacy(tmp_path):
    """A legacy decision made on tenantless evidence is still claimable and pinnable by a default (strict) workflow object: no re-judging."""
    p, r, f, d, cfg = _journal(tmp_path, workflow_kwargs=LEGACY, evidence_tenant=None)
    assert d.binding.generation == TENANT_GENERATION_LEGACY
    assert f.tenant_binding_generation == TENANT_GENERATION_LEGACY
    f.tenant_binding_generation = TENANT_GENERATION_STRICT  # the configured generation changes; the persisted one governs
    sink = []
    provision_local_execution_claim(f, p, d, now=NOW, provision=sink.append, claim_id="c1")
    assert len(sink) == 1
    assert assess_authorization_pin(f, p, d, now=NOW, host_policy_binding=v02.canonical_binding())["state"] == "active"


def test_claim_and_pin_time_strict_decision_stays_strict(tmp_path):
    p, r, f, d, cfg = _journal(tmp_path)
    f.tenant_binding_generation = TENANT_GENERATION_LEGACY
    _set_evidence(r, None)
    with pytest.raises(PermissionError):
        provision_local_execution_claim(f, p, d, now=NOW, provision=lambda c: None, claim_id="c1")
    try:
        out = assess_authorization_pin(f, p, d, now=NOW, host_policy_binding=v02.canonical_binding())
    except PermissionError:
        return
    assert out["state"] != "active"


def test_claim_downgrade_attempt_refused(tmp_path):
    p, r, f, d, cfg = _journal(tmp_path)
    forged = d.model_copy(update={"binding": d.binding.model_copy(update={"generation": TENANT_GENERATION_LEGACY})})
    with pytest.raises(PermissionError, match="persisted decision"):
        provision_local_execution_claim(f, p, forged, now=NOW, provision=lambda c: None, claim_id="c1")
    with pytest.raises(PermissionError, match="persisted decision"):
        assess_authorization_pin(f, p, forged, now=NOW, host_policy_binding=v02.canonical_binding())


def test_claim_without_profile_is_judged_under_persisted_generation(tmp_path):
    """The non-journal claim path passes no decision to the resolver; the persisted generation still governs it (both directions)."""
    from agent_control_plane.local_authority_effect import materialize_local_execution_claim
    p, r, f = _flow(tmp_path, None, generation=TENANT_GENERATION_LEGACY)
    d = f.decide(p, now=NOW)
    assert d.result == "authorized"
    f.tenant_binding_generation = TENANT_GENERATION_STRICT  # legacy decision stays legacy
    assert materialize_local_execution_claim(f, p, d, now=NOW, claim_id="c1").tenant_id == TENANT
    other = tmp_path / "s"
    other.mkdir()
    p2, r2, f2 = _flow(other, TENANT)
    d2 = f2.decide(p2, now=NOW)
    f2.tenant_binding_generation = TENANT_GENERATION_LEGACY  # strict decision stays strict
    _set_evidence(r2, None)
    with pytest.raises(PermissionError):
        materialize_local_execution_claim(f2, p2, d2, now=NOW, claim_id="c2")


# ---- signed runtime-authority evidence --------------------------------------------------------------------------------------------
def test_signed_evidence_tenant_must_match_proposal_tenant_strict(tmp_path):
    p, r, f, d, cfg = _journal(tmp_path)
    for ev in r.evidence.values():
        if ev.validation_record is not None:
            sign_evidence(ev, tenant_id=OTHER)  # a validly signed statement for another tenant
    d2 = f.decide(p, now=NOW)
    assert d2.result == "hold" and "evidence_binding_mismatch" in d2.reasons


def test_signed_tenantless_statement_refused_strict(tmp_path):
    p, r, f, d, cfg = _journal(tmp_path)
    for ev in r.evidence.values():
        if ev.validation_record is not None:
            sign_evidence(ev, tenant_id=None)
    assert f.decide(p, now=NOW).result == "hold"


def test_signed_evidence_matching_tenant_allowed_strict(tmp_path):
    p, r, f, d, cfg = _journal(tmp_path)
    assert d.result == "authorized"
    assert any(ev.validation_record and ev.validation_record["statement"]["tenant_id"] == TENANT for ev in r.evidence.values())


# ---- stored-decision tamper (flip / strip) at claim and pin time ------------------------------------------------------------------
def _tamper_store(tmp_path, how):
    path = tmp_path / "run.json"
    doc = json.loads(path.read_text())
    for row in doc["decisions"]:
        if how == "flip":
            row["binding"]["generation"] = TENANT_GENERATION_LEGACY
        else:
            row["binding"].pop("generation")  # parses to the legacy default
    path.write_text(json.dumps(doc))


@pytest.mark.parametrize("how", ["flip", "strip"])
def test_stored_tamper_refused_at_provision_and_pin(tmp_path, how):
    p, r, f, d, cfg = _journal(tmp_path)
    _tamper_store(tmp_path, how)
    _set_evidence(r, None)  # the point of the downgrade
    sink = []
    with pytest.raises(PermissionError, match="effect identity"):
        provision_local_execution_claim(f, p, f.records.decision(d.decision_id), now=NOW, provision=sink.append, claim_id="c1")
    assert sink == []
    with pytest.raises(PermissionError, match="effect identity"):
        assess_authorization_pin(f, p, f.records.decision(d.decision_id), now=NOW, host_policy_binding=v02.canonical_binding())


@pytest.mark.parametrize("how", ["flip", "strip"])
def test_stored_tamper_refused_at_materialize_without_profile(tmp_path, how):
    from agent_control_plane.local_authority_effect import materialize_local_execution_claim
    p, r, f = _flow(tmp_path, TENANT)
    d = f.decide(p, now=NOW)
    _tamper_store(tmp_path, how)
    _set_evidence(r, None)
    with pytest.raises(PermissionError, match="effect identity"):
        materialize_local_execution_claim(f, p, f.records.decision(d.decision_id), now=NOW, claim_id="c1")
