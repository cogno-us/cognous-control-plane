"""D-07 residual-window characterization: the purpose observation under anchor_deadline_to_inputs WITHOUT a policy binding.

What this file pins (current behaviour of unchanged protected evaluators; it is NOT a guarantee and NOT a fix):

* ``anchor_deadline_to_inputs=True`` anchors every input judged through ``bounded._fresh`` (identity, mandate, grant status, ...) to
  ``observed_at + own bound``. The PURPOSE observation is judged once at evaluation (``runtime_authority.py`` purpose block) and joins
  the deadline collector ONLY when the profile carries a ``policy_binding``. So with the flag True and no binding, a purpose
  observation that is exactly at a Registry-narrowed class bound at evaluation can still be dispatched up to one more bound later:
  its age at dispatch is about 2x the narrowed ceiling. The same holds for an accepted cached-purpose snapshot (bounded.py
  ``_cached_purpose``; anchored only in the binding branch).
* With a ``PolicyBinding`` the purpose observation (live or cached) is anchored and the same stall is refused.
* The other ``_fresh`` inputs ARE anchored with the flag True and no binding (control).

Tests whose name contains ``residual`` characterize a gap: if a protected-evaluator change closes it, they are EXPECTED to fail and
must be inverted by that change (their assertions then become the contrast tests below). Deterministic: the service clock is the
repo's fake ``Clock`` (tests/test_freshness.py); nothing sleeps. Synthetic fixtures only.
"""
from datetime import timedelta

import pytest

from agent_control_plane.freshness import FreshnessProfile
from tests.test_bounded_authorization import NOW
from tests.test_freshness import clock, execute, stale_grant  # noqa: F401  (clock is a fixture)
from tests.test_policy_binding_approval_generation import adopt, binding
from tests.test_runtime_authority import bind_approval, setup_flow

CEILING = 30  # the narrowed class bound (a Registry-narrowed ceiling of 30 s)


def _stall_once(f, clock, seconds):
    """Tick the fake clock once, inside the destination observation between the effect check and the dispatch gate."""
    original, calls, pinned = f.destination.observe, [], clock.now

    def stalled(effect_id):
        calls.append(1)
        if len(calls) == 1:
            clock.tick(seconds)
        return original(effect_id).model_copy(update={"observed_at": pinned.isoformat()})
    f.destination.observe = stalled


def _narrow(p, c):
    cl = c.actions[p.action_id].model_copy(update={"max_status_age_seconds": CEILING})
    return c.model_copy(update={"actions": {p.action_id: cl}})


def _anchored_no_binding(r, f, c, p):
    """Narrowed class bound, freshness/0.1 with the anchor flag True, NO policy_binding."""
    cfg = _narrow(p, c).model_copy(update={"freshness": FreshnessProfile(max_age_extension_seconds=0, anchor_deadline_to_inputs=True)})
    bind_approval(r, cfg)
    f.runtime_authority_profile = cfg.snapshot()
    assert f.runtime_authority_profile.policy_binding is None and f.runtime_authority_profile.freshness.anchor_deadline_to_inputs is True
    return cfg


def _purpose_flow(tmp_path, *, with_binding):
    p, r, f, c = setup_flow(tmp_path, purpose=True)
    r.purpose.observed_at = (NOW - timedelta(seconds=CEILING)).isoformat()       # exactly at the narrowed bound at evaluation
    if with_binding:
        fresh = FreshnessProfile(max_age_extension_seconds=0, anchor_deadline_to_inputs=True)
        cfg = adopt(r, f, _narrow(p, c), binding(age_ceilings={p.action_id: CEILING}), freshness=fresh)
        assert f.runtime_authority_profile.policy_binding is not None and cfg.policy_binding is not None
    else:
        _anchored_no_binding(r, f, c, p)
    return p, r, f


def _opened_deadline(f):
    ev = [e for e in f.records.load().check_events if e.phase == "completed"][-1]
    return ev.deadline


# ------------------------------------------------------------------------------------------------ (a) live purpose observation
def test_residual_purpose_observation_age_at_dispatch_is_twice_the_narrowed_ceiling_when_anchored_without_a_binding(tmp_path, clock):
    p, r, f = _purpose_flow(tmp_path, with_binding=False)
    d = f.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons                                   # age 30 <= 30 at evaluation
    _stall_once(f, clock, CEILING - 1)                                           # dispatch stalled 29 s
    attempt, _ = execute(f, p, d)
    assert attempt.status == "acknowledged", "RESIDUAL: dispatched although the purpose observation is past the ceiling"
    purpose_age_at_dispatch = (clock.now - (NOW - timedelta(seconds=CEILING))).total_seconds()
    assert purpose_age_at_dispatch == 2 * CEILING - 1 == 59 and purpose_age_at_dispatch > CEILING
    # The opened deadline is opened_at + the class bound: the purpose observation is not in the calculation.
    assert _opened_deadline(f) == (NOW + timedelta(seconds=CEILING)).isoformat()


def test_residual_purpose_observation_is_dispatched_up_to_the_end_of_the_unanchored_window(tmp_path, clock):
    """Boundary of the window: the deadline is NOW + 30, so a 30 s stall still dispatches (purpose age 60 = 2x) and 31 s refuses."""
    p, r, f = _purpose_flow(tmp_path, with_binding=False)
    d = f.decide(p, now=NOW)
    _stall_once(f, clock, CEILING)
    attempt, _ = execute(f, p, d)
    assert attempt.status == "acknowledged"
    assert (clock.now - (NOW - timedelta(seconds=CEILING))).total_seconds() == 2 * CEILING


def test_residual_window_is_closed_only_by_the_class_deadline_not_by_the_purpose_age(tmp_path, clock):
    p, r, f = _purpose_flow(tmp_path, with_binding=False)
    d = f.decide(p, now=NOW)
    _stall_once(f, clock, CEILING + 1)
    with pytest.raises(PermissionError, match="check_expired_before_dispatch"):
        execute(f, p, d)
    assert f.destination.snapshot()["effects"] == {}


# ------------------------------------------------------------------------------------------------ (b) cached-purpose snapshot
def _cached_flow(tmp_path, *, with_binding):
    from tests.test_reversibility import cls, flow as rev_flow, outage
    p, r, f, c = rev_flow(tmp_path, cls("reversible_until", max_status_age_seconds=CEILING))
    r.cached.observed_at = (NOW - timedelta(seconds=CEILING)).isoformat()
    outage(r)                                                                    # live purpose store down: the cached snapshot stands in
    fresh = FreshnessProfile(max_age_extension_seconds=0, anchor_deadline_to_inputs=True)
    if with_binding:
        adopt(r, f, c, binding(age_ceilings={p.action_id: CEILING}), freshness=fresh)
    else:
        cfg = c.model_copy(update={"freshness": fresh})
        bind_approval(r, cfg)
        f.runtime_authority_profile = cfg.snapshot()
        assert f.runtime_authority_profile.policy_binding is None
    return p, r, f


def test_residual_cached_purpose_snapshot_age_at_dispatch_is_twice_the_narrowed_ceiling_when_anchored_without_a_binding(tmp_path, clock):
    p, r, f = _cached_flow(tmp_path, with_binding=False)
    d = f.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    assert any(x.input_type == "purpose" and x.read_state == "cached_positive" for x in d.resolution_inputs)
    _stall_once(f, clock, CEILING - 1)
    attempt, _ = execute(f, p, d)
    assert attempt.status == "acknowledged", "RESIDUAL: dispatched although the cached purpose snapshot is past the ceiling"
    assert (clock.now - (NOW - timedelta(seconds=CEILING))).total_seconds() == 2 * CEILING - 1


# ------------------------------------------------------------------------------------------------ (c) contrast: a PolicyBinding anchors both
def test_contrast_with_a_policy_binding_the_live_purpose_observation_is_anchored_and_the_same_stall_is_refused(tmp_path, clock):
    p, r, f = _purpose_flow(tmp_path, with_binding=True)
    d = f.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    _stall_once(f, clock, CEILING - 1)                                           # the same 29 s stall as the residual test
    with pytest.raises(PermissionError, match="check_expired_before_dispatch"):
        execute(f, p, d)
    assert f.destination.snapshot()["effects"] == {}
    assert _opened_deadline(f) == NOW.isoformat()                               # tightened to purpose observed_at + bound


def test_contrast_with_a_policy_binding_the_cached_purpose_snapshot_is_anchored_and_the_same_stall_is_refused(tmp_path, clock):
    p, r, f = _cached_flow(tmp_path, with_binding=True)
    d = f.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    assert any(x.input_type == "purpose" and x.read_state == "cached_positive" for x in d.resolution_inputs)
    _stall_once(f, clock, CEILING - 1)
    with pytest.raises(PermissionError, match="check_expired_before_dispatch"):
        execute(f, p, d)
    assert f.destination.snapshot()["effects"] == {}


# ------------------------------------------------------------------------------------------------ (d) control: other _fresh inputs ARE anchored
def test_control_grant_status_is_anchored_with_the_flag_and_no_binding(tmp_path, clock):
    p, r, f, c = setup_flow(tmp_path)
    _anchored_no_binding(r, f, c, p)
    stale_grant(r, CEILING)                                                      # exactly at the narrowed bound at evaluation
    d = f.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    _stall_once(f, clock, CEILING - 1)                                           # the stall that the purpose observation survives
    with pytest.raises(PermissionError, match="check_expired_before_dispatch"):
        execute(f, p, d)
    assert f.destination.snapshot()["effects"] == {}


@pytest.mark.parametrize("scalar,store,key", [("identity_max_age_seconds", "identities", None), ("mandate_max_age_seconds", "mandates", None)])
def test_control_identity_and_mandate_are_anchored_with_the_flag_and_no_binding(tmp_path, clock, scalar, store, key):
    p, r, f, c = setup_flow(tmp_path)
    _anchored_no_binding(r, f, c, p)
    setattr(f, scalar, CEILING)
    for item in getattr(r, store).values():
        item.observed_at = (NOW - timedelta(seconds=CEILING)).isoformat()
    d = f.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    _stall_once(f, clock, CEILING - 1)
    with pytest.raises(PermissionError, match="check_expired_before_dispatch"):
        execute(f, p, d)
    assert f.destination.snapshot()["effects"] == {}


def test_control_without_the_flag_grant_status_has_the_documented_two_times_window(tmp_path, clock):
    """Baseline for the controls above: the flag is what closes the window for the _fresh inputs."""
    p, r, f, c = setup_flow(tmp_path)
    cfg = _narrow(p, c).model_copy(update={"freshness": FreshnessProfile(max_age_extension_seconds=0)})
    bind_approval(r, cfg)
    f.runtime_authority_profile = cfg.snapshot()
    stale_grant(r, CEILING)
    d = f.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    _stall_once(f, clock, CEILING - 1)
    attempt, _ = execute(f, p, d)
    assert attempt.status == "acknowledged"
