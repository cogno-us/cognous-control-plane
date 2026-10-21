"""Scan 4 hardening of the bounded decision gate (CP-1 to CP-5 plus two crash-to-hold cases).

Every case holds with a code already in the 0.2 reason registry; no code is added. Malformed declarations fail closed instead of
being read leniently (a falsy `required`, a case variant of an enum value, a stringly typed age bound) or crashing the run.
"""
from __future__ import annotations

import copy
from datetime import timedelta

import pytest

from agent_control_plane.bounded import commitment
from tests.test_bounded_authorization import NOW, proposal, resolver_for, workflow
from tests.test_manifest_gate_limits import _gate

ENTITLEMENT = "urn:cognous:evidence:refund-entitlement"
STALE = timedelta(hours=9)


def _decide(tmp_path, mutate_ctx=None, mutate_manifest=None, mutate_resolver=None, **proposal_update):
    p = proposal()
    r = resolver_for(p)
    ctx = r.contexts[next(iter(r.contexts))]
    if mutate_ctx:
        mutate_ctx(ctx)
    if mutate_resolver:
        mutate_resolver(r)
    flow = workflow(tmp_path, p, resolver=r)
    action = next(a for a in flow.manifest["actions"] if a["action_id"] == p.action_id)
    if mutate_manifest:
        mutate_manifest(flow.manifest, action)
    p = p.model_copy(update={"manifest_digest": commitment(flow.manifest), **proposal_update})
    return flow.decide(p, now=NOW)


def test_baseline_is_authorized(tmp_path):
    assert _decide(tmp_path).result == "authorized"


# CP-1: a non-boolean `required` on authority_required is never read as "not required".
@pytest.mark.parametrize("value", [0, "", None, "false", 1, "yes"])
def test_non_boolean_required_scope_is_not_dropped(tmp_path, value):
    def mutate(m, a):
        a["authority_required"][0]["required"] = value
    flow, p = _gate(tmp_path, mutate, requested_permissions=[])
    assert "missing_requested_permission" in flow._manifest_mismatches(p, NOW)
    d = flow.decide(p, now=NOW)
    assert d.result == "hold" and "missing_requested_permission" in d.reasons


def test_boolean_false_required_scope_is_still_optional(tmp_path):
    def mutate(m, a):
        a["authority_required"][0]["required"] = False
    flow, p = _gate(tmp_path, mutate, requested_permissions=[])
    assert "missing_requested_permission" not in flow._manifest_mismatches(p, NOW)


# CP-2: two declared actions sharing an action_name are ambiguous for name-keyed grants.
def test_shared_action_name_is_not_authorized_by_the_other_actions_grant(tmp_path):
    def dup(m, a):
        twin = copy.deepcopy(a)
        twin["action_id"] = "urn:cognous:action:twin"
        m["actions"].append(twin)
    p = proposal()
    flow = workflow(tmp_path, p)
    action = next(a for a in flow.manifest["actions"] if a["action_id"] == p.action_id)
    dup(flow.manifest, action)
    twin = p.model_copy(update={"manifest_digest": commitment(flow.manifest), "action_id": "urn:cognous:action:twin"})
    d = flow.decide(twin, now=NOW)
    assert d.result == "hold"
    assert {"grant_scope_mismatch", "requirement_scope_mismatch"} <= set(d.reasons)
    # the original action is equally ambiguous: a name-keyed permission cannot say which action it grants
    orig = p.model_copy(update={"manifest_digest": commitment(flow.manifest)})
    assert flow.decide(orig, now=NOW).result == "hold"


# CP-3: an unrecognised review mode is not "no review".
@pytest.mark.parametrize("mode", ["HUMAN_REVIEW", "Approval_Required", "human-review", "", "other"])
def test_unrecognised_review_mode_holds(tmp_path, mode):
    def mutate(m, a):
        a["review_requirement"] = {"mode": mode, "reviewer_role": "nonexistent"}
    d = _decide(tmp_path, mutate_manifest=mutate)
    assert d.result == "hold" and "review_requirement_not_resolved" in d.reasons


@pytest.mark.parametrize("mode", ["none", "draft_first"])
def test_declared_non_reviewing_modes_are_unchanged(tmp_path, mode):
    def mutate(m, a):
        a["review_requirement"] = {"mode": mode}
    d = _decide(tmp_path, mutate_manifest=mutate)
    assert "review_requirement_not_resolved" not in d.reasons


# CP-4: evidence kind / unknown_behavior vocabularies are exact.
def _stale(r):
    r.evidence[ENTITLEMENT].observed_at = (NOW - STALE).isoformat()


def _obligation(ctx, **update):
    ob = next(o for o in ctx["requirement"]["evidence"] if o["obligation_id"] == ENTITLEMENT)
    ob.update(update)


@pytest.mark.parametrize("kind", ["Authorization", "AUTHORIZATION", "auth", ""])
def test_unrecognised_evidence_kind_holds_with_stale_evidence(tmp_path, kind):
    d = _decide(tmp_path, mutate_ctx=lambda c: _obligation(c, kind=kind), mutate_resolver=_stale)
    assert d.result == "hold" and "required_evidence_not_current" in d.reasons


@pytest.mark.parametrize("behavior", ["Hold_Effect", "HOLD_EFFECT", "hold", ""])
def test_unrecognised_unknown_behavior_holds_with_stale_evidence(tmp_path, behavior):
    d = _decide(tmp_path, mutate_ctx=lambda c: _obligation(c, kind="context", required=False, unknown_behavior=behavior),
                mutate_resolver=_stale)
    assert d.result == "hold" and "context_unknown_requires_hold" in d.reasons


@pytest.mark.parametrize("required", [0, 1, "true", None])
def test_non_boolean_evidence_required_holds(tmp_path, required):
    d = _decide(tmp_path, mutate_ctx=lambda c: _obligation(c, required=required))
    assert d.result == "hold" and "required_evidence_not_current" in d.reasons


def test_vocabulary_values_in_the_schema_enums_are_unchanged(tmp_path):
    for kind in ("context", "post_effect"):
        for behavior in ("preserve_if_other_basis_suffices", "reconcile_no_blind_retry"):
            d = _decide(tmp_path / f"{kind}-{behavior}",
                        mutate_ctx=lambda c: _obligation(c, kind=kind, required=False, unknown_behavior=behavior))
            assert d.result == "authorized", (kind, behavior, d.reasons)
