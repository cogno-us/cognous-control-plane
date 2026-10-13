"""Regression checks for I1, I2 and I5, using only local synthetic effects."""
from datetime import timedelta

import pytest

import agent_control_plane.bounded as bounded
from agent_control_plane.bounded import (
    BoundedRecordStore, DefinitiveDestinationRejection, EffectAttempt,
    EffectObservation, commitment,
)
from tests.test_bounded_authorization import NOW, PROFILE, proposal, resolver_for, workflow


class DestinationProxy:
    def __init__(self, base, *, commit=True, rejection=False, lag=False):
        self.base, self.commit, self.rejection, self.lag = base, commit, rejection, lag

    def apply(self, **kwargs):
        if self.commit:
            self.base.apply(**kwargs)
        if self.rejection:
            raise DefinitiveDestinationRejection('synthetic_provider_rejected')
        raise ConnectionError('SYNTHETIC_PRIVATE_TRANSPORT_DETAIL')

    def observe(self, effect_id):
        if self.lag:
            return EffectObservation(effect_id=effect_id, observed_at=NOW.isoformat(), state='absent')
        return self.base.observe(effect_id)


@pytest.fixture(autouse=True)
def service_clock(monkeypatch):
    monkeypatch.setattr(bounded, '_now', lambda: NOW)


@pytest.mark.parametrize('lag', [False, True])
def test_client_error_after_provider_accept(tmp_path, lag):
    p = proposal()
    f = workflow(tmp_path, p)
    d = f.decide(p, now=NOW)
    base = f.destination
    f.destination = DestinationProxy(base, lag=lag)
    attempt, observation = f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == 'unknown'
    assert attempt.error == 'destination_outcome_unknown:ConnectionError'
    assert len(base.snapshot()['effects']) == 1
    assert not any(r.retry_eligible for r in f.records.load().reconciliations)
    if lag:
        assert f.records.load().closeouts == []
        with pytest.raises(PermissionError, match='prior attempt'):
            f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
        f.destination.lag = False
        f.reconcile(d.effect_id, now=NOW)
    closeout = f.records.load().closeouts[0]
    assert closeout.attempt_id == attempt.attempt_id
    assert closeout.original_status == 'unknown' and closeout.observed_state == 'applied'
    assert 'SYNTHETIC_PRIVATE_TRANSPORT_DETAIL' not in f.records.path.read_text()


def test_definitive_rejection_is_failed(tmp_path):
    p = proposal()
    f = workflow(tmp_path, p)
    d = f.decide(p, now=NOW)
    base = f.destination
    f.destination = DestinationProxy(base, commit=False, rejection=True)
    attempt, observation = f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == 'failed' and attempt.error == 'synthetic_provider_rejected'
    assert base.snapshot()['effects'] == {} and f.records.load().closeouts == []
    with pytest.raises(PermissionError, match='prior attempt'):
        f.execute(p, d, adapter_id=p.adapter_id, now=NOW)


def test_later_observation_closes_original_historical_failed_attempt(tmp_path):
    p = proposal()
    f = workflow(tmp_path, p)
    d = f.decide(p, now=NOW)
    f.records.append_attempt(EffectAttempt(
        attempt_id='historical-attempt', effect_id=d.effect_id, decision_id=d.decision_id,
        started_at=NOW.isoformat(), status='failed', error='historical_transport_error',
    ))
    f.destination.apply(effect_id=d.effect_id, grant_id=d.binding.grant_id,
                        max_effects=1, target=p.target, amount=p.amount, unit=p.unit, payload=p.payload)
    f.reconcile(d.effect_id, now=NOW)
    f.reconcile(d.effect_id, now=NOW)
    restored = BoundedRecordStore(f.records.path, 'run-1').load()
    assert restored.attempts[0].status == 'failed'
    assert len(restored.closeouts) == 1
    assert restored.closeouts[0].attempt_id == 'historical-attempt'
    assert restored.closeouts[0].observed_state == 'applied'


def test_backdated_now_and_resolver_after_expiry(tmp_path, monkeypatch):
    p = proposal()
    r = resolver_for(p)
    f = workflow(tmp_path, p, resolver=r)
    f.allow_test_time = False  # deployment default, fixture opt-in removed
    d = f.decide(p, now=NOW)
    expires = bounded._parse(r.contexts[PROFILE]['grant']['expires_at'])
    service_now = expires + timedelta(seconds=1)
    monkeypatch.setattr(bounded, '_now', lambda: service_now)
    with pytest.raises(PermissionError, match='authorization-critical inputs changed'):
        f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    refusal = f.records.load().refusals[0]
    assert 'grant_outside_validity' in refusal.reasons
    assert refusal.recorded_at == service_now.isoformat()
    assert refusal.time_source == 'control_plane'
    assert f.destination.snapshot()['effects'] == {}


def test_default_decision_time_ignores_caller_and_test_opt_in_is_recorded(tmp_path):
    p = proposal()
    f = workflow(tmp_path, p)
    f.allow_test_time = False
    d = f.decide(p, now=NOW - timedelta(hours=1))
    assert d.decided_at == NOW.isoformat() and d.time_source == 'control_plane'
    f.allow_test_time = True
    held = f.decide(p, now=NOW - timedelta(hours=1))
    assert held.result == 'hold' and held.time_source == 'test_override'


def test_status_observed_at_regresses_across_restart(tmp_path):
    p = proposal()
    r = resolver_for(p)
    f = workflow(tmp_path, p, resolver=r)
    d = f.decide(p, now=NOW)
    r.statuses[d.binding.grant_id].observed_at = (NOW - timedelta(seconds=1)).isoformat()
    f.records = BoundedRecordStore(f.records.path, 'run-1')
    with pytest.raises(PermissionError):
        f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    row = f.records.load().refusals[0]
    assert 'input_observation_time_regressed' in row.reasons
    item = next(i for i in row.resolution_inputs if i.input_type == 'grant')
    assert item.previous_observed_at == NOW.isoformat()
    key = commitment(['grant', item.input_id])
    assert f.records.load().input_time_floors[key] == NOW.isoformat()
    assert f.destination.snapshot()['effects'] == {}


def test_invalid_future_observation_does_not_advance_floor(tmp_path):
    p = proposal()
    r = resolver_for(p)
    f = workflow(tmp_path, p, resolver=r)
    gid = r.contexts[PROFILE]['grant']['grant_id']
    r.statuses[gid].observed_at = (NOW + timedelta(days=100)).isoformat()
    assert f.decide(p, now=NOW).result == 'hold'
    assert commitment(['grant', gid]) not in f.records.load().input_time_floors
    r.statuses[gid].observed_at = NOW.isoformat()
    assert f.decide(p, now=NOW).result == 'authorized'


def test_resolution_checkpoint_write_failure_never_dispatches(tmp_path, monkeypatch):
    p = proposal()
    f = workflow(tmp_path, p)
    d = f.decide(p, now=NOW)
    def fail(**kwargs):
        raise OSError('synthetic checkpoint failure')
    monkeypatch.setattr(f.records, 'record_resolution_check', fail)
    with pytest.raises(OSError):
        f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert f.destination.snapshot()['effects'] == {} and not f.records.load().attempts


def test_resume_after_horizon_records_both_values(tmp_path):
    p = proposal()
    p.not_before = (NOW - timedelta(minutes=1)).isoformat()
    p.expires_at = (NOW + timedelta(seconds=10)).isoformat()
    f = workflow(tmp_path, p)
    d = f.decide(p, now=NOW)
    assert d.result == 'authorized'
    resumed = p.model_copy(update={'expires_at': (NOW + timedelta(seconds=15)).isoformat()})
    with pytest.raises(PermissionError):
        f.execute(resumed, d, adapter_id=p.adapter_id, now=NOW + timedelta(seconds=20))
    row = BoundedRecordStore(f.records.path, 'run-1').load().refusals[0]
    assert 'proposal_expired' in row.reasons
    assert row.original_operation_horizon.expires_at == p.expires_at
    assert row.operation_horizon.expires_at == resumed.expires_at
    assert row.original_operation_horizon.source == row.operation_horizon.source == 'runtime_proposal'
    assert row.original_operation_horizon.proposal_commitment != row.operation_horizon.proposal_commitment
    assert f.destination.snapshot()['effects'] == {}


def test_default_reconciliation_uses_service_time_without_caller_timestamp(tmp_path):
    p = proposal()
    f = workflow(tmp_path, p)
    f.allow_test_time = False
    result = f.reconcile('synthetic-absent-effect', now=NOW - timedelta(days=1))
    assert result.result == 'observed_absent'
    assert result.evaluation_time == NOW.isoformat()
    assert not result.retry_eligible
