"""exact_members: an approved member set that is empty does not pass, even when the signed record lists no members either."""
from __future__ import annotations

import pytest

import agent_control_plane.bounded as bounded
from tests.test_runtime_authority import MEMBERS, NOW, PROFILE, bind_approval, held, setup_flow, sign_evidence


@pytest.fixture(autouse=True)
def _clock(monkeypatch):
    monkeypatch.setattr(bounded, "_now", lambda: NOW)


def _set_members(r, cfg, *, approved, signed, kind="exact_members"):
    context = r.contexts[PROFILE]
    for obligation_id, criterion in context["runtime_authority"]["evidence_criteria"].items():
        criterion["kind"] = kind
        criterion["members"] = approved
        sign_evidence(r.evidence[obligation_id], members=signed)
    bind_approval(r, cfg)


def test_empty_approved_set_with_empty_signed_set_is_held(tmp_path):
    p, r, f, cfg = setup_flow(tmp_path)
    _set_members(r, cfg, approved=[], signed=[])
    held(f, p, "evidence_criterion_unmet")


def test_criterion_without_a_members_member_is_held_the_same_way(tmp_path):
    p, r, f, cfg = setup_flow(tmp_path)
    _set_members(r, cfg, approved=[], signed=[])
    for criterion in r.contexts[PROFILE]["runtime_authority"]["evidence_criteria"].values():
        del criterion["members"]  # the model default is the empty list
    bind_approval(r, cfg)
    held(f, p, "evidence_criterion_unmet")


@pytest.mark.parametrize("approved,signed", [([], ["x"]), (["x"], [])])
def test_one_sided_empty_sets_stay_held(tmp_path, approved, signed):
    p, r, f, cfg = setup_flow(tmp_path)
    _set_members(r, cfg, approved=approved, signed=signed)
    held(f, p, "evidence_criterion_unmet")


def test_nonempty_exact_set_control_still_authorizes(tmp_path):
    p, r, f, cfg = setup_flow(tmp_path)
    decision = f.decide(p, now=NOW)
    assert decision.result == "authorized", decision.reasons
    _set_members(r, cfg, approved=MEMBERS, signed=list(reversed(MEMBERS)))  # order does not matter
    decision = f.decide(p, now=NOW)
    assert decision.result == "authorized", decision.reasons
