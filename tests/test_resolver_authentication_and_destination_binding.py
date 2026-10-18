"""Reason coverage: an unauthenticated resolver is refused, and a destination state naming another effect is not accepted."""
from __future__ import annotations

import pytest

import agent_control_plane.bounded as bounded
from agent_control_plane.bounded import (
    BoundedAuthorizationWorkflow,
    BoundedRecordStore,
    EffectObservation,
    LocalRefundDestination,
    ObservationPolicy,
)
from tests.test_bounded_authorization import NOW, manifest
from tests.test_runtime_authority import bind_approval, setup_flow


@pytest.fixture(autouse=True)
def _clock(monkeypatch):
    monkeypatch.setattr(bounded, "_now", lambda: NOW)


def _without_synthetic_resolver_allowance(r, f, cfg):
    """Host profile that does not allow a synthetic resolver (the default for a deployment)."""
    cfg2 = cfg.model_copy(update={"allow_synthetic_resolver": False})
    bind_approval(r, cfg2)
    f.runtime_authority_profile = cfg2.snapshot()
    return cfg2


def test_unauthenticated_resolver_is_refused_without_the_synthetic_allowance(tmp_path):
    p, r, f, cfg = setup_flow(tmp_path)
    _without_synthetic_resolver_allowance(r, f, cfg)
    assert r.authenticated is False
    decision = f.decide(p, now=NOW)
    assert decision.result == "hold"
    assert decision.reasons == ["resolver_not_authenticated"]
    assert decision.binding is None
    assert f.destination.snapshot()["effects"] == {} and not f.records.load().attempts


def test_resolver_without_an_authenticated_attribute_is_refused_too(tmp_path):
    p, r, f, cfg = setup_flow(tmp_path)
    _without_synthetic_resolver_allowance(r, f, cfg)
    r_missing = _Bare(r)
    f.resolver = r_missing
    decision = f.decide(p, now=NOW)
    assert decision.result == "hold" and decision.reasons == ["resolver_not_authenticated"]


class _Bare:
    """Delegates every read to a synthetic resolver but declares no ``authenticated`` attribute."""

    def __init__(self, inner):
        self._inner = inner

    def __getattr__(self, name):
        if name == "authenticated":
            raise AttributeError(name)
        return getattr(self._inner, name)


def test_authenticated_resolver_control_still_authorizes_and_executes(tmp_path):
    p, r, f, cfg = setup_flow(tmp_path)
    _without_synthetic_resolver_allowance(r, f, cfg)
    r.authenticated = True  # a deployment resolver declares itself authenticated
    decision = f.decide(p, now=NOW)
    assert decision.result == "authorized", decision.reasons
    attempt, observation = f.execute(p, decision, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and observation.state == "applied"


def test_resolver_flag_is_read_at_effect_time_too(tmp_path):
    p, r, f, cfg = setup_flow(tmp_path)
    _without_synthetic_resolver_allowance(r, f, cfg)
    r.authenticated = True
    decision = f.decide(p, now=NOW)
    assert decision.result == "authorized", decision.reasons
    r.authenticated = False
    with pytest.raises(PermissionError):
        f.execute(p, decision, adapter_id=p.adapter_id, now=NOW)
    refusal = f.records.load().refusals[0]
    assert "resolver_not_authenticated" in refusal.reasons
    assert f.destination.snapshot()["effects"] == {} and not f.records.load().attempts


# ---------------------------------------------------------------- destination_effect_id_mismatch

class _Fixed:
    """A destination that returns one scripted observation and never applies anything."""

    def __init__(self, observation):
        self.observation = observation

    def observe(self, effect_id):
        return self.observation


def _observation_flow(tmp_path, observation):
    records = BoundedRecordStore(tmp_path / "run.json", "run-1")
    flow = BoundedAuthorizationWorkflow(
        allow_test_time=True, manifest=manifest(), resolver=None, destination=_Fixed(observation),
        records=records, observation_policy=ObservationPolicy(max_age_seconds=300, clock_tolerance_seconds=5),
    )
    return flow, records


def _applied(destination_effect_id, state="applied"):
    return EffectObservation(
        effect_id="effect-1", observed_at=NOW.isoformat(), state="applied",
        destination_state={"effect_id": destination_effect_id, "state": state},
    )


def test_destination_state_naming_another_effect_is_held_with_its_own_reason(tmp_path):
    flow, records = _observation_flow(tmp_path, _applied("some-other-effect"))
    result = flow.reconcile("effect-1", now=NOW)
    assert result.result == "hold" and result.observation_accepted is False
    assert result.reasons == ["destination_effect_id_mismatch"]
    assert records.load().observations == []


def test_destination_state_without_an_effect_id_is_held_with_the_same_reason(tmp_path):
    observation = EffectObservation(
        effect_id="effect-1", observed_at=NOW.isoformat(), state="applied", destination_state={"state": "applied"},
    )
    flow, _ = _observation_flow(tmp_path, observation)
    result = flow.reconcile("effect-1", now=NOW)
    assert result.result == "hold" and result.reasons == ["destination_effect_id_mismatch"]


def test_matching_destination_state_control_is_accepted(tmp_path):
    flow, records = _observation_flow(tmp_path, _applied("effect-1"))
    result = flow.reconcile("effect-1", now=NOW)
    assert result.result == "applied" and result.observation_accepted is True and result.reasons == []
    assert records.load().observations[-1].state == "applied"
