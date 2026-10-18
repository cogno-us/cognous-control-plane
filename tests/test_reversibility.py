"""reversibility/0.1: opt-in `reversibility` values on the action class and a bounded use of a cached "open" purpose snapshot.

Synthetic fixtures only. The composed cross-component scenarios live in the qualification suite (suites/operation-identity,
test_reversibility_profile.py). The member rules follow the draft ODES `effect-reversibility` contract.

Provenance of "expected today" values (default path, profile unset): the `*_today` rows were RUN on main 3f6a766 before this change
and are re-run on every test run. Nothing here is taken from code reading alone.
"""
import ast
import json
import pathlib
from datetime import timedelta

import pytest

import agent_control_plane.bounded as bounded
from agent_control_plane import reversibility as rv
from agent_control_plane.freshness import FreshnessProfile
from agent_control_plane.reversibility import (ReversibilityProfile, effective_reversibility, effectively_irreversible,
                                               judge_cached_purpose)
from agent_control_plane.rule_revision import RuleRevision, RuleRevisionProfile, append_rule_revision
from agent_control_plane.runtime_authority import ActionClass, PurposeStatus, RuntimeAuthorityProfile
from tests.test_bounded_authorization import INSTITUTION, NOW, POLICY_REF
from tests.test_runtime_authority import bind_approval, setup_flow

REGISTRY = json.loads((pathlib.Path(__file__).resolve().parents[1] / "schemas" / "runtime_authority_reasons_0_2.json").read_text())
UNTIL = (NOW + timedelta(minutes=10)).isoformat()


@pytest.fixture(autouse=True)
def _clock(monkeypatch):
    monkeypatch.setattr(bounded, "_now", lambda: NOW)


def cls(value="irreversible", **kw):
    members = dict(reversibility=value, class_id="synthetic-" + value, max_status_age_seconds=60)
    if value == "reversible_until":
        members.setdefault("reversible_until", UNTIL)
    if value == "reversible_at_cost":
        members.setdefault("reversal_cost", "refund can be clawed back at a fee")
    if value != "irreversible":
        members.setdefault("on_unreadable", "bounded_tolerance")
    members.update(kw)
    return ActionClass(**members)


def flow(tmp_path, action_class, **extra):
    p, r, f, c = setup_flow(tmp_path, purpose=True)
    update = {"actions": {p.action_id: action_class}, "reversibility": ReversibilityProfile(), **extra}
    cfg = c.model_copy(update=update)
    bind_approval(r, cfg)
    f.runtime_authority_profile = cfg.snapshot()
    r.cached = r.purpose.model_copy()
    r.cached_purpose_status = lambda ref: r.cached.model_dump()
    return p, r, f, cfg


def outage(r):
    def broken(ref):
        raise TimeoutError("purpose store unavailable")
    r.purpose_status = broken


def run(f, p, d, seconds=0):
    return f.execute(p, d, adapter_id=p.adapter_id, now=NOW + timedelta(seconds=seconds))


# ---------------------------------------------------------------- the member rules (ODES effect-reversibility)
def test_legacy_boolean_is_derived_true_iff_irreversible():
    assert cls("irreversible").irreversible is True
    assert cls("reversible_until").irreversible is False
    assert cls("reversible_at_cost").irreversible is False, "reversible_at_cost has the legacy flag false (ODES default 4)"


@pytest.mark.parametrize("members,code", [
    (dict(reversibility="irreversible", irreversible=False), "irreversible_flag_mismatch"),
    (dict(reversibility="reversible_until", irreversible=True, reversible_until=UNTIL), "irreversible_flag_mismatch"),
    (dict(reversibility="reversible_until"), "reversibility_member_mismatch"),
    (dict(reversibility="reversible_at_cost"), "reversibility_member_mismatch"),
    (dict(reversibility="irreversible", reversible_until=UNTIL), "reversibility_member_mismatch"),
    (dict(reversibility="reversible_at_cost", reversal_cost="x", reversible_until=UNTIL), "reversibility_member_mismatch"),
    (dict(reversible_until=UNTIL), "reversibility_member_mismatch"),
    (dict(reversibility="reversible_until", reversible_until="2026-10-05T19:00:00"), "timestamp_invalid"),
    (dict(reversibility="reversible_until", reversible_until="soon"), "timestamp_invalid"),
    (dict(reversibility="reversible_until", reversible_until=UNTIL, reads_protected_data=True), "protected_read_not_irreversible"),
    (dict(reversibility="reversible_at_cost", reversal_cost="x", counterparty_observable=False), "unobservable_not_strict"),
    (dict(reversibility="sometimes"), "unknown_enum_value"),
])
def test_class_member_violations_are_refused_with_the_contract_code(members, code):
    with pytest.raises(ValueError, match=code):
        ActionClass(class_id="x", **members)


def test_protected_read_and_unobservable_counterparty_default_to_the_strictest_value():
    assert ActionClass(class_id="x", reads_protected_data=True).reversibility == "irreversible"
    assert ActionClass(class_id="x", counterparty_observable=False).reversibility == "irreversible"
    assert ActionClass(class_id="x", counterparty_observable=False).irreversible is True


def test_strictness_order_is_irreversible_then_at_cost_then_until():
    s = rv.STRICTNESS
    assert s["irreversible"] > s["reversible_at_cost"] > s["reversible_until"]


def test_effective_reversibility_window_and_defaults():
    assert effective_reversibility(cls("reversible_until"), NOW) == ("reversible_until", "declared")
    assert effective_reversibility(cls("reversible_until"), NOW + timedelta(minutes=10)) == ("irreversible", "window_passed")
    assert effective_reversibility(cls("reversible_at_cost"), NOW + timedelta(days=9)) == ("reversible_at_cost", "declared")
    assert effective_reversibility(ActionClass(class_id="legacy", irreversible=False), NOW) == ("irreversible", "undeclared")
    assert effectively_irreversible(ActionClass(class_id="legacy", irreversible=False), NOW) is False, "legacy field is used as is"
    assert effectively_irreversible(cls("reversible_until"), NOW + timedelta(hours=1)) is True


def test_effective_value_does_not_trust_the_stored_value_over_the_strict_defaults():
    """Defence in depth: a class built without validation (model_copy) that reads protected data or has an unobservable
    counterparty is still treated as irreversible at use time."""
    base = cls("reversible_until")
    assert effective_reversibility(base.model_copy(update={"reads_protected_data": True}), NOW) == ("irreversible", "protected_read")
    assert effective_reversibility(base.model_copy(update={"counterparty_observable": False}), NOW) == (
        "irreversible", "counterparty_unobservable")


def _purpose(state="open", at=NOW, epoch="epoch-1"):
    return PurposeStatus(system="synthetic", record_id="rec", epoch=epoch, institution_id=INSTITUTION, authority_domain="d",
                         state=state, observed_at=at.isoformat(), epoch_capability="authoritative")


def _judge(value="reversible_at_cost", cached=None, closures=(), bound=60, now=NOW):
    return judge_cached_purpose(action_class=cls(value), now=now, purpose_ref="ref", cached=cached, closures=list(closures),
                                bound_seconds=bound, extension_id=None, check_id="c1", recorded_at=now.isoformat())


def test_judge_cached_purpose_directly_pins_each_refusal_and_its_order():
    use, accepted = _judge(cached=_purpose())
    assert accepted is not None and use.accepted and use.reasons == [] and use.effective_status == "open"
    use, accepted = _judge(cached=_purpose(state="closed"))
    assert accepted is None and use.reasons == ["purpose_closed"] and use.effective_status == "closed" and use.basis == "cached_snapshot"
    use, accepted = _judge(cached=_purpose(at=NOW + timedelta(seconds=5)))  # a snapshot from the future is not fresh
    assert accepted is None and use.reasons == ["purpose_cache_stale"] and use.age_seconds == -5
    use, accepted = _judge(cached=_purpose(at=NOW - timedelta(seconds=61)))
    assert accepted is None and use.reasons == ["purpose_cache_stale"]
    use, accepted = _judge(cached=None)
    assert accepted is None and use.reasons == ["purpose_unreadable"] and use.basis == "strict_default" and use.effective_status == "closed"
    closure = [{"check_id": "c0", "recorded_at": NOW.isoformat()}]
    use, _ = _judge(cached=_purpose(), closures=closure)
    assert use.reasons == ["purpose_closure_recorded"], "a recorded closure beats an open cache"
    use, _ = _judge(value="irreversible", cached=_purpose(), closures=closure)
    assert use.reasons == ["purpose_cache_irreversible_class"], "the class refuses before the closure is even consulted"


def test_values_need_the_profile_and_default_dump_is_unchanged():
    with pytest.raises(ValueError, match="reversibility values need"):
        RuntimeAuthorityProfile(catalogue_version="x", actions={"a": cls("reversible_at_cost")})
    legacy = ActionClass(class_id="x", irreversible=False)
    assert set(legacy.model_dump(mode="json")) == {"class_id", "irreversible", "max_status_age_seconds", "on_unreadable"}
    dumped = cls("reversible_until").model_dump(mode="json")
    assert set(dumped) == {"class_id", "irreversible", "max_status_age_seconds", "on_unreadable", "x-reversibility"}


def test_dump_carries_the_five_members_as_one_x_reversibility_object_and_round_trips():
    """The ODES effect-reversibility class profile shape: all five members, null where not applicable, cost as {description}."""
    dumped = cls("reversible_at_cost").model_dump(mode="json")
    assert dumped["x-reversibility"] == {"reversibility": "reversible_at_cost", "reversible_until": None,
                                         "reversal_cost": {"description": "refund can be clawed back at a fee"},
                                         "reads_protected_data": False, "counterparty_observable": True}
    assert not {"reversibility", "reversible_until", "reversal_cost", "reads_protected_data", "counterparty_observable"} & set(dumped)
    assert ActionClass.model_validate(dumped) == cls("reversible_at_cost")
    until = cls("reversible_until").model_dump(mode="json")
    assert until["x-reversibility"]["reversible_until"] == UNTIL and until["x-reversibility"]["reversal_cost"] is None
    strict = ActionClass(class_id="p", reads_protected_data=True).model_dump(mode="json")["x-reversibility"]
    assert strict["reversibility"] == "irreversible" and strict["reads_protected_data"] is True


@pytest.mark.parametrize("nested,code", [
    ({"reversibility": "irreversible", "extra": 1}, "undeclared_member"),
    ({"reversibility": "reversible_at_cost", "reversal_cost": {"description": ""}}, "schema_violation"),
    ({"reversibility": "reversible_at_cost", "reversal_cost": {"description": "x", "amount": 1}}, "schema_violation"),
    ({"reversibility": "reversible_until"}, "reversibility_member_mismatch"),
])
def test_x_reversibility_input_is_closed_and_checked(nested, code):
    with pytest.raises(ValueError, match=code):
        ActionClass.model_validate({"class_id": "x", "x-reversibility": nested})
    with pytest.raises(ValueError, match="alternatives"):
        ActionClass.model_validate({"class_id": "x", "reversibility": "irreversible", "x-reversibility": {"reversibility": "irreversible"}})


# ---------------------------------------------------------------- default path: a purpose outage refuses for every class
def test_purpose_outage_refuses_for_a_reversible_legacy_class_today(tmp_path):
    """Expected today (ran): without the profile a purpose outage refuses even for a reversible class with a cache."""
    p, r, f, c = setup_flow(tmp_path, purpose=True, reversible=True)
    d = f.decide(p, now=NOW)
    assert d.result == "authorized"
    r.cached = r.purpose.model_copy()
    r.cached_purpose_status = lambda ref: r.cached.model_dump()
    outage(r)
    with pytest.raises(PermissionError):
        run(f, p, d)
    assert f.records.load().refusals[-1].reasons == ["purpose_unreadable"] and f.destination.snapshot()["effects"] == {}
    assert "snapshot_uses" not in json.loads(f.records.path.read_text())


# ---------------------------------------------------------------- cached open snapshot, reversible class, within bound
@pytest.mark.parametrize("value", ["reversible_until", "reversible_at_cost"])
def test_cached_open_snapshot_for_a_reversible_class_proceeds_and_records_the_age(tmp_path, value):
    p, r, f, cfg = flow(tmp_path, cls(value))
    d = f.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    outage(r)
    attempt, _ = run(f, p, d, seconds=30)
    assert attempt.status == "acknowledged" and list(f.destination.snapshot()["effects"]) == [d.effect_id]
    (use,) = f.records.load().snapshot_uses
    assert use.accepted and use.basis == "cached_snapshot" and use.effective_status == "open"
    assert use.epoch == "epoch-1" and use.age_seconds == 30 and use.age_bound_seconds == 60 and use.reversibility == value
    assert use.age_basis == "source_asserted" and use.snapshot_observed_at == NOW.isoformat()
    effect_check = [x for x in f.records.load().resolution_checks if x.stage == "effect"][-1]
    item = next(i for i in effect_check.inputs if i.input_type == "purpose")
    assert item.read_state == "cached_positive" and item.observed["age_seconds"] == "30.0" and item.observed["epoch"] == "epoch-1"
    journal = [e.check_id for e in f.records.load().check_events if e.stage == "effect" and e.phase == "opened"]
    assert use.check_id == journal[-1], "the use joins to its journal check by id (the ResolutionCheck id is the legacy uuid here)"


def test_cache_age_bound_is_inclusive_and_stale_is_refused(tmp_path):
    p, r, f, cfg = flow(tmp_path, cls("reversible_at_cost"))
    d = f.decide(p, now=NOW)
    outage(r)
    run(f, p, d, seconds=60)  # age 60 s at the effect-time read: inside the bound, inclusive
    assert f.records.load().snapshot_uses[-1].accepted and f.records.load().snapshot_uses[-1].age_seconds == 60
    p2, r2, f2, _ = flow(tmp_path / "b", cls("reversible_at_cost"))
    d2 = f2.decide(p2, now=NOW)
    outage(r2)
    with pytest.raises(PermissionError):
        run(f2, p2, d2, seconds=61)
    use = f2.records.load().snapshot_uses[-1]
    assert not use.accepted and use.reasons == ["purpose_cache_stale"] and use.age_seconds == 61 and use.effective_status == "closed"
    assert "purpose_cache_stale" in f2.records.load().refusals[-1].reasons and f2.destination.snapshot()["effects"] == {}


def test_a_cache_older_than_a_purpose_read_already_recorded_is_a_regression(tmp_path):
    """The per-input time floor still applies to a cached snapshot: it cannot be older than what this control plane already read."""
    p, r, f, cfg = flow(tmp_path, cls("reversible_at_cost"))
    d = f.decide(p, now=NOW)
    outage(r)
    r.cached.observed_at = (NOW - timedelta(seconds=30)).isoformat()
    with pytest.raises(PermissionError):
        run(f, p, d, seconds=30)
    assert "input_observation_time_regressed" in f.records.load().refusals[-1].reasons


def test_protected_read_refuses_a_cached_snapshot(tmp_path):
    p, r, f, cfg = flow(tmp_path, cls("irreversible", reads_protected_data=True))
    d = f.decide(p, now=NOW)
    assert d.result == "authorized"
    outage(r)
    with pytest.raises(PermissionError):
        run(f, p, d)
    row = f.records.load().refusals[-1]
    assert row.reasons == ["purpose_cache_irreversible_class", "purpose_unreadable"] and f.destination.snapshot()["effects"] == {}
    assert f.records.load().snapshot_uses[-1].basis == "cached_snapshot" and not f.records.load().snapshot_uses[-1].accepted


def test_irreversible_class_refuses_a_cached_snapshot(tmp_path):
    p, r, f, cfg = flow(tmp_path, cls("irreversible"))
    d = f.decide(p, now=NOW)
    outage(r)
    with pytest.raises(PermissionError):
        run(f, p, d)
    assert "purpose_cache_irreversible_class" in f.records.load().refusals[-1].reasons


def test_reversible_until_past_its_deadline_is_treated_as_irreversible(tmp_path):
    p, r, f, cfg = flow(tmp_path, cls("reversible_until", reversible_until=(NOW + timedelta(seconds=40)).isoformat()))
    d = f.decide(p, now=NOW)
    outage(r)
    p2, r2, f2, _ = flow(tmp_path / "inside", cls("reversible_until", reversible_until=(NOW + timedelta(seconds=40)).isoformat()))
    d2 = f2.decide(p2, now=NOW)
    outage(r2)
    run(f2, p2, d2, seconds=39)  # control: inside the window the same cache is accepted
    assert f2.records.load().snapshot_uses[-1].accepted
    with pytest.raises(PermissionError):
        run(f, p, d, seconds=40)
    row = f.records.load().refusals[-1]
    assert row.reasons == ["purpose_cache_after_reversal_window", "purpose_unreadable"]
    assert f.records.load().snapshot_uses[-1].reversibility == "irreversible"


def test_recorded_closure_overrides_a_cached_open_snapshot(tmp_path):
    p, r, f, cfg = flow(tmp_path, cls("reversible_at_cost"))
    d = f.decide(p, now=NOW)
    assert d.result == "authorized"
    r.purpose.state = "closed"                      # the control plane reads the closure live and records it
    held = f.decide(p, now=NOW)
    assert held.result == "hold" and "purpose_closed" in held.reasons
    outage(r)                                       # later the purpose store is down; the cache still says open
    with pytest.raises(PermissionError):
        run(f, p, d, seconds=1)
    assert f.records.load().refusals[-1].reasons == ["purpose_closure_recorded", "purpose_unreadable"]
    assert f.destination.snapshot()["effects"] == {}


def test_a_closed_snapshot_never_supports_open(tmp_path):
    p, r, f, cfg = flow(tmp_path, cls("reversible_at_cost"))
    d = f.decide(p, now=NOW)
    outage(r)
    r.cached.state = "closed"
    with pytest.raises(PermissionError):
        run(f, p, d)
    assert "purpose_closed" in f.records.load().refusals[-1].reasons


def test_no_cache_provider_is_a_strict_default(tmp_path):
    p, r, f, cfg = flow(tmp_path, cls("reversible_at_cost"))
    d = f.decide(p, now=NOW)
    outage(r)
    del r.cached_purpose_status
    with pytest.raises(PermissionError):
        run(f, p, d)
    use = f.records.load().snapshot_uses[-1]
    assert use.basis == "strict_default" and use.effective_status == "closed" and not use.accepted
    assert f.records.load().refusals[-1].reasons == ["purpose_unreadable"]


def test_a_live_readable_purpose_does_not_touch_the_cache(tmp_path):
    p, r, f, cfg = flow(tmp_path, cls("reversible_at_cost"))
    d = f.decide(p, now=NOW)
    run(f, p, d)
    assert f.records.load().snapshot_uses == []


# ---------------------------------------------------------------- N3's outage extension is reused, and narrowed by reversibility
def test_extension_raises_the_cache_bound_for_a_reversible_class_only(tmp_path):
    for value, expected in (("reversible_at_cost", 200), ("irreversible", 60)):
        p, r, f, cfg = flow(tmp_path / value, cls(value), freshness=FreshnessProfile(max_age_extension_seconds=300))
        f.rule_revision_profile = RuleRevisionProfile(signers=["urn:cognous:principal:outage-signer"])
        f.record_age_extension(class_id="synthetic-" + value, to_max_age_seconds=200, not_before=NOW.isoformat(),
                               expires_at=(NOW + timedelta(hours=1)).isoformat(), outage_ref="outage-1",
                               requested_by="urn:cognous:principal:requester", signer="urn:cognous:principal:outage-signer",
                               authority_ref="urn:cognous:authority:outage-1", now=NOW)
        bound, extension_id, defects = f._class_age_bound(p.action_id, NOW)
        assert bound == expected, (value, bound)
        assert bool(extension_id) == (value != "irreversible")
        assert ("age_extension_irreversible_class" in defects) == (value == "irreversible")


def test_extension_bound_is_what_judges_the_cache_age():
    from agent_control_plane.runtime_authority import PurposeStatus
    snapshot = PurposeStatus(system="s", record_id="r", epoch="e", institution_id="i", authority_domain="d", state="open",
                             observed_at=(NOW - timedelta(seconds=150)).isoformat(), epoch_capability="authoritative")
    kw = dict(action_class=cls("reversible_at_cost"), now=NOW, purpose_ref="ref", cached=snapshot, closures=[], check_id=None,
              recorded_at=NOW.isoformat())
    use, accepted = judge_cached_purpose(bound_seconds=60, extension_id=None, **kw)
    assert accepted is None and use.reasons == ["purpose_cache_stale"]
    use, accepted = judge_cached_purpose(bound_seconds=200, extension_id="ext-1", **kw)
    assert accepted is snapshot and use.extension_id == "ext-1" and use.age_seconds == 150


def test_age_extension_without_the_reversibility_profile_still_applies_to_an_irreversible_class(tmp_path):
    """N3 behaviour kept: the narrowing exists only under reversibility/0.1."""
    p, r, f, cfg = setup_flow(tmp_path)
    cfg = cfg.model_copy(update={"freshness": FreshnessProfile(max_age_extension_seconds=300)})
    f.runtime_authority_profile = cfg.snapshot()
    f.rule_revision_profile = RuleRevisionProfile(signers=["urn:cognous:principal:outage-signer"])
    f.record_age_extension(class_id="synthetic-irreversible", to_max_age_seconds=200, not_before=NOW.isoformat(),
                           expires_at=(NOW + timedelta(hours=1)).isoformat(), outage_ref="o", requested_by="urn:cognous:principal:requester",
                           signer="urn:cognous:principal:outage-signer", now=NOW)
    assert f._class_age_bound(p.action_id, NOW)[0] == 200


# ---------------------------------------------------------------- registry
def test_every_reversibility_code_is_registered():
    codes = {getattr(rv, n) for n in dir(rv) if n.startswith("CODE_")}
    assert len(codes) == 5 and codes <= set(REGISTRY["codes"])
    source = pathlib.Path(rv.__file__).read_text()
    literals = {n.value for n in ast.walk(ast.parse(source)) if isinstance(n, ast.Constant) and isinstance(n.value, str)
                and n.value.startswith("purpose_")}
    assert literals <= set(REGISTRY["codes"]) | {"purpose_ref"}


def test_profile_is_part_of_the_approval_commitment(tmp_path):
    from agent_control_plane.runtime_authority import approval_commitment
    p, r, f, cfg = flow(tmp_path, cls("reversible_at_cost"))
    ctx = r.contexts[next(iter(r.contexts))]
    assert approval_commitment(cfg, ctx) != approval_commitment(cfg.model_copy(update={"reversibility": None}), ctx)


def test_a_passed_reversal_window_also_stops_the_cached_grant_status(tmp_path):
    """The legacy cached grant status is tolerated only for a reversible class; once reversible_until has passed it is not."""
    until = (NOW + timedelta(seconds=40)).isoformat()
    for seconds, expected in ((39, "authorized"), (40, "hold")):
        p, r, f, cfg = flow(tmp_path / str(seconds), cls("reversible_until", reversible_until=until))
        status = next(iter(r.statuses.values())).model_copy(deep=True)
        r.grant_status = lambda ref: None
        r.cached_grant_status = lambda ref, s=status: s
        d = f.decide(p, now=NOW + timedelta(seconds=seconds))
        assert d.result == expected, (seconds, d.reasons)
        assert expected == "authorized" or "status_unreadable" in d.reasons


def test_a_cached_purpose_read_is_recorded_as_source_asserted_never_nonce_bound(tmp_path):
    p, r, f, cfg = flow(tmp_path, cls("reversible_at_cost"), freshness=FreshnessProfile())
    d = f.decide(p, now=NOW)
    outage(r)
    run(f, p, d, seconds=30)
    refusals = f.records.load().resolution_checks
    item = next(i for c in refusals for i in c.inputs if i.input_type == "purpose" and i.read_state == "cached_positive")
    assert item.age_basis == "source_asserted"
