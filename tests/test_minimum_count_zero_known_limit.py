"""minimum_count 0 is an explicit operator declaration and passes with a count of 0 (a later change must be deliberate)."""
import pytest

import agent_control_plane.bounded as bounded
from tests.test_runtime_authority import NOW, PROFILE, bind_approval, setup_flow, sign_evidence


@pytest.fixture(autouse=True)
def _clock(monkeypatch):
    monkeypatch.setattr(bounded, "_now", lambda: NOW)


def test_minimum_count_zero_with_count_zero_is_accepted_known_limit(tmp_path):
    p, r, f, cfg = setup_flow(tmp_path, kind="minimum_count")
    for oid, criterion in r.contexts[PROFILE]["runtime_authority"]["evidence_criteria"].items():
        criterion["minimum_count"] = 0
        sign_evidence(r.evidence[oid], count=0)
    bind_approval(r, cfg)
    decision = f.decide(p, now=NOW)
    assert decision.result == "authorized", decision.reasons
