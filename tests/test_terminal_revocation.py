"""Opt-in terminal-revocation/0.1: a grant revision observed revoked stays refused even if its status later reads active."""

import pytest

import agent_control_plane.bounded as bounded
from agent_control_plane.bounded import BoundedAuthorizationWorkflow, BoundedRecordStore, LocalRefundDestination, ObservationPolicy
from agent_control_plane.runtime_authority import (CODE_REVOCATION_RECORDED, VOCABULARY_VERSION, VOCABULARY_VERSION_0_2,
                                                   TerminalRevocationProfile)
from tests.test_bounded_authorization import NOW, manifest
from tests.test_runtime_authority import bind_approval, setup_flow


@pytest.fixture(autouse=True)
def _clock(monkeypatch):
    monkeypatch.setattr(bounded, "_now", lambda: NOW)


def flow(tmp_path, *, enabled):
    p, r, f, cfg = setup_flow(tmp_path)
    if not enabled:
        return p, r, f
    cfg = cfg.model_copy(update={"terminal_revocation": TerminalRevocationProfile()})
    bind_approval(r, cfg)
    root = tmp_path / "terminal"
    root.mkdir()
    f = BoundedAuthorizationWorkflow(manifest=manifest(), resolver=r, destination=LocalRefundDestination(root / "destination.json"),
                                     records=BoundedRecordStore(root / "run.json", "run-1"),
                                     observation_policy=ObservationPolicy(max_age_seconds=300), allow_test_time=True,
                                     runtime_authority_profile=cfg)
    return p, r, f


def _set_status(r, decision, status):
    r.statuses[decision.binding.grant_id].status = status


def _refused_once_then_status_back(f, p, r, status):
    d = f.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    _set_status(r, d, status)
    with pytest.raises(PermissionError):
        f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    _set_status(r, d, "active")
    return d


def test_profile_is_omitted_from_dumps_while_unset(tmp_path):
    _, _, f = flow(tmp_path, enabled=False)
    assert "terminal_revocation" not in f.runtime_authority_profile.model_dump(mode="json")
    assert f._terminal_revocation is None


def test_without_the_profile_a_status_back_to_active_at_the_same_revision_is_accepted(tmp_path):
    """Legacy behaviour, unchanged: the default and plain-profile paths accept a status that returns to active."""
    p, r, f = flow(tmp_path, enabled=False)
    d = _refused_once_then_status_back(f, p, r, "revoked")
    attempt, observation = f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and observation.state == "applied"


def test_with_the_profile_execution_is_refused_after_a_recorded_revocation(tmp_path):
    p, r, f = flow(tmp_path, enabled=True)
    d = _refused_once_then_status_back(f, p, r, "revoked")
    with pytest.raises(PermissionError):
        f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    row = f.records.load().refusals[-1]
    assert row.reasons == [CODE_REVOCATION_RECORDED]
    assert row.reason_vocabulary_version == VOCABULARY_VERSION_0_2
    assert {"kind": "successor_grant_revision", "input_id": d.binding.grant_id,
            "previous_revision": d.binding.grant_revision} in row.reopen_conditions
    assert f.destination.snapshot()["effects"] == {} and not f.records.load().attempts


def test_with_the_profile_a_new_decision_holds_after_a_recorded_revocation(tmp_path):
    p, r, f = flow(tmp_path, enabled=True)
    _refused_once_then_status_back(f, p, r, "revoked")
    again = f.decide(p, now=NOW)
    assert again.result == "hold" and again.reasons == [CODE_REVOCATION_RECORDED]
    assert again.binding is None


def test_with_the_profile_a_suspension_stays_reversible(tmp_path):
    p, r, f = flow(tmp_path, enabled=True)
    d = _refused_once_then_status_back(f, p, r, "suspended")
    attempt, observation = f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and observation.state == "applied"


def test_with_the_profile_and_no_revocation_the_flow_is_unchanged(tmp_path):
    p, r, f = flow(tmp_path, enabled=True)
    d = f.decide(p, now=NOW)
    assert d.result == "authorized" and d.reason_vocabulary_version == VOCABULARY_VERSION
    attempt, observation = f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and observation.state == "applied"
    assert not f.records.load().refusals


def test_a_revocation_of_another_revision_does_not_count(tmp_path):
    p, r, f = flow(tmp_path, enabled=True)
    d = f.decide(p, now=NOW)
    assert not f._recorded_grant_denial(d.binding.grant_id, {"some-other-revision"}, {"revoked"})
    status = r.statuses[d.binding.grant_id]
    status.status, status.revision = "revoked", "some-other-revision"
    with pytest.raises(PermissionError):
        f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    status.status, status.revision = "active", d.binding.grant_revision
    attempt, _ = f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged"
