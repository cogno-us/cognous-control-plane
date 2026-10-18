"""One run: a refused request, then a validly authorised request with its own effect_id.

The refusal row persists and is never overwritten, the later request is accepted and applied, and the journal the run
produced conforms to the vendored execution-attempt-lifecycle validator.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

import agent_control_plane.bounded as bounded
from agent_control_plane.bounded import commitment
from tests.test_bounded_authorization import NOW, proposal
from tests.test_contract_lifecycle_conformance import codes, to_document
from tests.test_runtime_authority import setup_flow


@pytest.fixture(autouse=True)
def _clock(monkeypatch):
    monkeypatch.setattr(bounded, "_now", lambda: NOW)


def approve(r, proposal_):
    """The approver approves one more proposal: the approval row binds that proposal's commitment."""
    for approval in r.approvals.values():
        approval.proposal_commitment = commitment(proposal_.model_dump(mode="json", exclude_none=False))


def run_refusal_then_valid(tmp_path):
    """Request A is authorised, then refused at effect time; request B (own correlation, own effect_id) is authorised and applied."""
    p_a, r, f, cfg = setup_flow(tmp_path)
    d_a = f.decide(p_a, now=NOW)
    assert d_a.result == "authorized", d_a.reasons

    real_grant_status = r.grant_status
    r.grant_status = lambda ref: None  # the authority source is unreadable for A's effect-time check
    with pytest.raises(PermissionError):
        f.execute(p_a, d_a, adapter_id=p_a.adapter_id, now=NOW)
    r.grant_status = real_grant_status  # the source answers again

    p_b = proposal(correlation_id="case-2")
    approve(r, p_b)
    d_b = f.decide(p_b, now=NOW)
    assert d_b.result == "authorized", d_b.reasons
    assert d_b.effect_id != d_a.effect_id
    attempt_b, observation_b = f.execute(p_b, d_b, adapter_id=p_b.adapter_id, now=NOW)
    return f, d_a, d_b, attempt_b, observation_b


def test_refusal_persists_and_the_later_valid_request_is_accepted(tmp_path):
    f, d_a, d_b, attempt_b, observation_b = run_refusal_then_valid(tmp_path)
    assert attempt_b.status == "acknowledged" and observation_b.state == "applied"

    record = f.records.load()
    assert [x.effect_id for x in record.refusals] == [d_a.effect_id]  # the refusal row is still there, exactly once
    assert "status_unreadable" in record.refusals[0].reasons
    assert [x.effect_id for x in record.attempts if x.status == "acknowledged"] == [d_b.effect_id]
    assert all(x.effect_id != d_a.effect_id for x in record.attempts)  # the refused request never became an attempt
    assert set(f.destination.snapshot()["effects"]) == {d_b.effect_id}


def test_refusal_row_is_unchanged_by_later_writes(tmp_path):
    p_a, r, f, cfg = setup_flow(tmp_path)
    d_a = f.decide(p_a, now=NOW)
    r.grant_status = lambda ref: None
    with pytest.raises(PermissionError):
        f.execute(p_a, d_a, adapter_id=p_a.adapter_id, now=NOW)
    before = f.records.load().refusals[0].model_dump(mode="json")
    del r.grant_status  # back to the class method
    p_b = proposal(correlation_id="case-2")
    approve(r, p_b)
    d_b = f.decide(p_b, now=NOW)
    f.execute(p_b, d_b, adapter_id=p_b.adapter_id, now=NOW)
    assert f.records.load().refusals[0].model_dump(mode="json") == before


def test_journal_of_the_run_conforms_to_the_vendored_contract(tmp_path):
    f, *_ = run_refusal_then_valid(tmp_path)
    document = to_document(f.records.path)
    assert codes(document) == []
    # Four checks (decision A, effect A refused, decision B, effect B); the refused effect check carries its reasons.
    assert [c["stage"] for c in document["resolution_checks"]] == ["decision", "effect", "decision", "effect"]
    assert [row["status"] for row in document["control_plane_attempts"]] == ["attempted", "acknowledged"]
    assert sum(1 for c in document["resolution_checks"] if c["reasons"]) == 1


def test_producer_fixture_is_regenerated_identically_in_shape(tmp_path):
    """The run is deterministic under the fixed clock; ``save_fixture`` below writes the same document."""
    f, *_ = run_refusal_then_valid(tmp_path)
    first = to_document(f.records.path)
    f2, *_ = run_refusal_then_valid(tmp_path / "again")
    second = to_document(f2.records.path)
    assert [c["stage"] for c in first["resolution_checks"]] == [c["stage"] for c in second["resolution_checks"]]
    assert [c["reasons"] for c in first["resolution_checks"]] == [c["reasons"] for c in second["resolution_checks"]]


def save_fixture(path: Path) -> None:  # used by hand to publish the producer fixture; not collected as a test
    import tempfile
    with tempfile.TemporaryDirectory() as tmp:
        f, *_ = run_refusal_then_valid(Path(tmp))
        document = to_document(f.records.path)
    path.write_text(json.dumps({"description": "A refused request followed by a validly authorised request in one run.",
                                "document": document}, indent=2, sort_keys=True) + "\n", encoding="utf-8")
