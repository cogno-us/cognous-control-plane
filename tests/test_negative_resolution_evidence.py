"""Blocked-path evidence from actual reads; no external effects or credentials."""
import json
from datetime import timedelta

import pytest

from agent_control_plane.bounded import BoundedRecordStore, BoundedRunRecord, commitment
from tests.test_bounded_authorization import (
    NOW, PROFILE, POLICY_REF, proposal, resolver_for, workflow,
)


def inputs_of(record, kind):
    return [item for item in record.resolution_inputs if item.input_type == kind]


@pytest.mark.parametrize('case,reason', [
    ('target', 'target_out_of_scope'),
    ('schema', 'missing_required_payload_field'),
    ('stale', 'grant_status_stale_or_future'),
    ('revoke', 'grant_not_active'),
    ('withdraw', 'approval_not_active'),
])
def test_held_decision_retains_actual_input_evidence_after_restart(tmp_path, case, reason):
    p = proposal()
    r = resolver_for(p)
    f = workflow(tmp_path, p, resolver=r)
    grant_id = r.contexts[PROFILE]['grant']['grant_id']
    if case == 'target':
        p.target = 'urn:synthetic:denied'
    elif case == 'schema':
        del p.payload['customer_id']
        p.payload_commitment = commitment(p.payload)
    elif case == 'stale':
        r.statuses[grant_id].observed_at = (NOW - timedelta(seconds=61)).isoformat()
    elif case == 'revoke':
        r.statuses[grant_id].status = 'revoked'
    else:
        next(iter(r.approvals.values())).status = 'revoked'
    d = f.decide(p, now=NOW)
    assert d.result == 'hold' and d.binding is None
    assert reason in d.reasons
    reloaded = BoundedRecordStore(f.records.path, 'run-1').load().decisions[0]
    assert reloaded == d
    assert inputs_of(d, 'manifest')[0].record_commitment == commitment(f.manifest)
    assert inputs_of(d, 'grant')[0].record_commitment == commitment(r.statuses[grant_id].model_dump(mode='json'))
    assert inputs_of(d, 'grant')[0].observed['revision'] == r.statuses[grant_id].revision
    assert inputs_of(d, 'policy')[0].observed['version'] == r.policies[POLICY_REF].version
    evidence = inputs_of(d, 'evidence')[0]
    assert evidence.record_commitment and evidence.observed['observed_at'] == NOW.isoformat()
    with pytest.raises(PermissionError, match='not authorized'):
        f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert f.destination.snapshot()['effects'] == {}
    assert not f.records.load().attempts


@pytest.mark.parametrize('case,reason', [
    ('missing', 'policy_missing'), ('superseded', 'policy_superseded'),
    ('unknown', 'policy_status_unknown'), ('version', 'policy_version_changed'),
])
def test_policy_refusals_distinguish_causes(tmp_path, case, reason):
    p = proposal()
    r = resolver_for(p)
    if case == 'missing':
        del r.policies[POLICY_REF]
    elif case == 'version':
        r.policies[POLICY_REF].version = '2.0'
    else:
        r.policies[POLICY_REF].status = case
    d = workflow(tmp_path, p, resolver=r).decide(p, now=NOW)
    assert d.result == 'hold'
    assert reason in d.reasons and 'policy_stale_or_changed' in d.reasons
    specific = {'policy_missing', 'policy_superseded', 'policy_status_unknown', 'policy_version_changed'}
    assert set(d.reasons) & specific == {reason}
    item = inputs_of(d, 'policy')[0]
    assert item.expected == {'version': '1.0', 'status': 'active'}
    assert item.missing == (case == 'missing')


def test_approve_revoke_replay_uses_the_read_that_caused_refusal(tmp_path, monkeypatch):
    p = proposal()
    r = resolver_for(p)
    f = workflow(tmp_path, p, resolver=r)
    d = f.decide(p, now=NOW)
    assert d.result == 'authorized'
    original = r.statuses[d.binding.grant_id].model_copy(deep=True)
    revoked = original.model_copy(update={'status': 'revoked', 'revision': 'revoked-r2', 'version': '7'})
    calls = []
    def unstable_read(grant_id):
        calls.append(grant_id)
        return revoked.model_copy(deep=True) if len(calls) == 1 else original.model_copy(deep=True)
    monkeypatch.setattr(r, 'grant_status', unstable_read)
    with pytest.raises(PermissionError, match='authorization-critical inputs changed'):
        f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert calls == [d.binding.grant_id]  # evidence must not do a second resolver read
    restored = BoundedRunRecord.model_validate_json(f.records.path.read_text())
    assert restored.decisions[0] == d
    refusal = restored.refusals[0]
    assert refusal.decision_id == d.decision_id and refusal.effect_id == d.effect_id
    assert 'grant_not_active' in refusal.reasons
    item = inputs_of(refusal, 'grant')[0]
    assert item.observed['revision'] == 'revoked-r2'
    assert item.observed['status'] == 'revoked'
    assert item.record_commitment == commitment(revoked.model_dump(mode='json'))
    assert 'revision=revoked-r2;status=revoked;version=7' in refusal.changed_inputs[0].observed_version
    assert f.destination.snapshot()['effects'] == {} and restored.attempts == []


def test_approval_withdrawal_is_durable_without_creating_override_authority(tmp_path):
    p = proposal()
    r = resolver_for(p)
    f = workflow(tmp_path, p, resolver=r)
    d = f.decide(p, now=NOW)
    ref = next(iter(r.approvals))
    r.approvals[ref].status = 'revoked'
    with pytest.raises(PermissionError):
        f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    row = BoundedRecordStore(f.records.path, 'run-1').load().refusals[0]
    assert 'approval_not_active' in row.reasons
    assert inputs_of(row, 'approval')[0].observed['status'] == 'revoked'
    assert any(i.input_id == ref for i in row.changed_inputs)
    assert f.destination.snapshot()['effects'] == {}


def test_missing_context_is_explicit_and_unread_grant_is_not_fabricated(tmp_path):
    p = proposal()
    r = resolver_for(p)
    r.contexts.clear()
    d = workflow(tmp_path, p, resolver=r).decide(p, now=NOW)
    assert d.result == 'hold'
    assert inputs_of(d, 'authority_context')[0].missing
    assert inputs_of(d, 'authority_context')[0].record_commitment is None
    assert not inputs_of(d, 'grant')


def test_diagnostic_projection_excludes_raw_payload_and_approver(tmp_path):
    p = proposal()
    p.payload['refund_reason'] = 'SYNTHETIC_PRIVATE_PAYLOAD_SENTINEL'
    p.payload_commitment = commitment(p.payload)
    r = resolver_for(p)
    next(iter(r.approvals.values())).approver = 'SYNTHETIC_PRIVATE_APPROVER_SENTINEL'
    r.contexts[PROFILE]['private_note'] = 'SYNTHETIC_PRIVATE_CONTEXT_SENTINEL'
    p.target = 'urn:synthetic:denied'
    f = workflow(tmp_path, p, resolver=r)
    f.decide(p, now=NOW)
    text = f.records.path.read_text()
    assert 'SYNTHETIC_PRIVATE_' not in text
    assert 'refund_reason' not in text and 'approver' not in text and 'private_note' not in text


def test_refusal_write_failure_never_dispatches(tmp_path, monkeypatch):
    p = proposal()
    r = resolver_for(p)
    f = workflow(tmp_path, p, resolver=r)
    d = f.decide(p, now=NOW)
    r.statuses[d.binding.grant_id].status = 'revoked'
    def fail_write(row):
        raise OSError('synthetic storage failure')
    monkeypatch.setattr(f.records, 'append_refusal', fail_write)
    with pytest.raises(OSError, match='synthetic storage failure'):
        f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert f.destination.snapshot()['effects'] == {} and not f.records.load().attempts


def test_historical_records_load_with_empty_evidence(tmp_path):
    p = proposal()
    f = workflow(tmp_path, p)
    f.decide(p, now=NOW)
    doc = json.loads(f.records.path.read_text())
    del doc['decisions'][0]['resolution_inputs']
    f.records.path.write_text(json.dumps(doc))
    assert BoundedRecordStore(f.records.path, 'run-1').load().decisions[0].resolution_inputs == []


def test_permitted_path_still_executes_with_non_authorizing_evidence(tmp_path, monkeypatch):
    import agent_control_plane.bounded as bounded
    monkeypatch.setattr(bounded, '_now', lambda: NOW)
    p = proposal()
    f = workflow(tmp_path, p)
    d = f.decide(p, now=NOW)
    attempt, observation = f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == 'acknowledged' and observation.state == 'applied'
    restored = BoundedRecordStore(f.records.path, 'run-1').load()
    assert restored.decisions[0].resolution_inputs and not restored.refusals
    assert len(f.destination.snapshot()['effects']) == 1


@pytest.mark.parametrize('kind,reason', [
    ('policy', 'policy_version_changed'),
    ('evidence', 'required_evidence_not_current'),
    ('role_mapping', 'authorization_binding_changed'),
])
def test_changed_input_projections_remain_attributed(tmp_path, kind, reason):
    p = proposal()
    r = resolver_for(p)
    f = workflow(tmp_path, p, resolver=r)
    d = f.decide(p, now=NOW)
    if kind == 'policy':
        r.policies[POLICY_REF].version = '2.0'
    elif kind == 'evidence':
        r.evidence['urn:cognous:evidence:refund-entitlement'].state = 'stale'
    else:
        mapping = next(iter(r.role_mappings.values()))
        mapping.version = '2'
        mapping.digest = commitment({'institution_id': mapping.institution_id,
                                     'version': mapping.version, 'aliases': mapping.aliases})
    with pytest.raises(PermissionError):
        f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    row = f.records.load().refusals[0]
    assert reason in row.reasons
    assert any(i.input_type == kind for i in row.changed_inputs)
    assert f.destination.snapshot()['effects'] == {}


def test_mutation_control_missing_decision_evidence_breaks_assertion(tmp_path, monkeypatch):
    p = proposal()
    f = workflow(tmp_path, p)
    p.target = 'urn:synthetic:denied'
    resolve = f._resolve
    def without_evidence(proposal, now, *, inputs=None):
        return resolve(proposal, now)  # disable only evidence collection
    monkeypatch.setattr(f, '_resolve', without_evidence)
    d = f.decide(p, now=NOW)
    assert d.result == 'hold'
    with pytest.raises(AssertionError):
        assert inputs_of(f.records.load().decisions[0], 'grant')
