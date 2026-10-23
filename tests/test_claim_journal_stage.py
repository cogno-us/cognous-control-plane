"""F3: claim provisioning must record a distinct, correctly bound claim-stage journal check.

Uses the real provision_local_execution_claim API in journal mode (runtime_authority_profile set) and,
when installed, the pinned Verifier. Non-authorizing evidence tests; no production effects.
"""
from __future__ import annotations

import copy
import json

import pytest

import agent_control_plane.bounded as bounded
from agent_control_plane.local_authority_effect import provision_local_execution_claim
from tests.test_bounded_authorization import NOW
from tests.test_operation_identity import enable
from tests.test_runtime_authority import setup_flow

engine = pytest.importorskip("cognous_verify.engine")

FRESHNESS_DEFAULTS = ("merge_records", "compensation_obligations", "snapshot_uses", "dedupe_escalations")
OPTIONAL_NULLS = ("evaluated_at", "deadline", "age_bound_seconds", "extension_id", "nonce", "recorded_at",
                  "check_id", "operation_id", "operation_issuer")


def _normalise(rec):
    """Same input normalisation as the reproduction harness (drop empty/None optional members)."""
    rec = copy.deepcopy(rec)
    for key in FRESHNESS_DEFAULTS:
        if rec.get(key) == []:
            rec.pop(key)
    for rows in rec.values():
        if isinstance(rows, list):
            for row in rows:
                if isinstance(row, dict):
                    for member in OPTIONAL_NULLS:
                        if row.get(member, 0) is None:
                            row.pop(member)
    return rec


def _verify(rec):
    return engine.evaluate([engine.InputFile("run_record", "r.json", json.dumps(_normalise(rec)).encode())])


def _refutations(evaluation):
    return {(c.check_id, f.code) for c in evaluation.checks if c.verdict == "refuted" for f in c.findings}


@pytest.fixture(params=["journal", "journal+operation-identity"])
def flow(request, tmp_path, monkeypatch):
    monkeypatch.setattr(bounded, "_now", lambda: NOW)
    p, r, f, cfg = setup_flow(tmp_path)
    if request.param != "journal":
        enable(r, f, cfg)          # route B configuration: journal mode + operation identity
    d = f.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    return tmp_path, p, f, d


def _claim(flow):
    tmp, p, f, d = flow
    c = provision_local_execution_claim(f, p, d, now=NOW, provision=lambda claim: None, claim_id="claim-1")
    return c, json.loads((tmp / "run.json").read_text())


def _opened(rec):
    return [e for e in rec["check_events"] if e["phase"] == "opened"]


def test_claim_stage_journal_is_distinct_and_bound(flow):
    claim, rec = _claim(flow)
    assert claim.claim_id == "claim-1"
    decision_id = flow[3].decision_id
    opened = _opened(rec)
    assert [e["stage"] for e in opened] == ["decision", "claim"]
    assert len({e["check_id"] for e in opened}) == 2
    assert opened[0].get("decision_id") is None                    # decision stage unchanged
    assert opened[1]["decision_id"] == decision_id                 # claim stage bound to the decision
    assert opened[1]["effect_id"] == flow[3].effect_id
    # every journal event keeps the stage of its opening row
    stage_by_check = {e["check_id"]: e["stage"] for e in opened}
    assert all(e["stage"] == stage_by_check[e["check_id"]] for e in rec["check_events"])
    assert [c["stage"] for c in rec["resolution_checks"]] == ["decision", "claim"]
    if flow[2]._identity or flow[2]._freshness:
        # the recorded resolution checks use exactly the journal check ids (as on the decision/effect paths)
        assert [(c["stage"], c["check_id"]) for c in rec["resolution_checks"]] == [
            (e["stage"], e["check_id"]) for e in opened]
    completed = [e for e in rec["check_events"] if e["phase"] == "completed"]
    assert sorted(e["check_id"] for e in completed) == sorted(e["check_id"] for e in opened)


def test_claim_record_has_no_journal_reuse_and_no_refutation_with_pinned_verifier(flow):
    _, rec = _claim(flow)
    ev = _verify(rec)
    assert not ev.crashed
    assert _refutations(ev) == set()
    assert ev.overall != "reject"


def test_effect_after_claim_keeps_effect_stage_semantics(flow):
    tmp, p, f, d = flow
    _claim(flow)
    f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    rec = json.loads((tmp / "run.json").read_text())
    assert [e["stage"] for e in _opened(rec)] == ["decision", "claim", "effect"]
    assert _opened(rec)[2]["decision_id"] == d.decision_id
    assert _refutations(_verify(rec)) == set()


# ---- documented pre-patch observation: the old call pattern is refuted by the pinned Verifier ----
def test_prepatch_call_pattern_is_refuted_as_journal_check_reused(flow):
    """Replays the pre-patch claim body (no stage/check_ref). Proves the oracle detects the defect."""
    tmp, p, f, d = flow
    inputs = []
    with f.resolver.authority_effect_handoff(p.authority_context_ref or ""):
        reasons, _ = f._resolve(p.model_copy(deep=True), NOW, inputs=inputs)
        f._record_check(inputs, NOW, reasons, "claim")
    rec = json.loads((tmp / "run.json").read_text())
    assert ("v2.lifecycle.journal_protocol", "journal_check_reused") in _refutations(_verify(rec))


# ---- negative controls on the patched record ----
def test_negative_reused_check_ref_is_refuted(flow):
    _, rec = _claim(flow)
    decision_check = rec["resolution_checks"][0]["check_id"]
    bad = copy.deepcopy(rec)
    claim_id = bad["resolution_checks"][1]["check_id"]
    bad["resolution_checks"][1]["check_id"] = decision_check
    for e in bad["check_events"]:
        if e["check_id"] == claim_id:
            e["check_id"] = decision_check
    refuted = _refutations(_verify(bad))
    # observed: the Verifier reports this mutation as v2.journal.check_ids/duplicate_check_id
    assert ("v2.journal.check_ids", "duplicate_check_id") in refuted or (
        "v2.lifecycle.journal_protocol", "journal_check_reused") in refuted


def test_negative_missing_stage_identity_is_refused(flow):
    _, rec = _claim(flow)
    bad = copy.deepcopy(rec)
    for e in bad["check_events"]:
        if e["stage"] == "claim":
            del e["stage"]
    with pytest.raises(Exception):
        bounded.BoundedRunRecord.model_validate(bad)        # Control Plane schema refuses it
    ev = _verify(bad)
    assert ev.crashed or ev.overall == "reject" or _refutations(ev) or any(
        c.verdict == "refuted" for c in ev.checks)          # and the Verifier does not accept it


def test_negative_incorrect_journal_linkage_is_detected(flow):
    if not (flow[2]._identity or flow[2]._freshness):
        pytest.skip("check-id linkage is only recorded with operation identity/freshness (same as decision/effect paths)")
    _, rec = _claim(flow)
    bad = copy.deepcopy(rec)
    bad["resolution_checks"][1]["check_id"] = "00000000-0000-0000-0000-000000000000"   # no such journal row
    ev = _verify(bad)
    assert any(c.verdict == "refuted" for c in ev.checks) or ev.overall == "reject"
    # and a claim journal row that lies about its stage is detected too
    bad2 = copy.deepcopy(rec)
    for e in bad2["check_events"]:
        if e["stage"] == "claim":
            e["stage"] = "decision"
    assert any(c.verdict == "refuted" for c in _verify(bad2).checks)
