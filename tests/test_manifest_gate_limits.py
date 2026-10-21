"""Manifest gate parity with the action-manifest runtime consumption contract, and strict numeric limits (scan 3, CP-1 and CP-2).

The decision gate refuses an action whose effective default is block or whose tool is not allowed (`action_blocked`), an action that
declares no effect_limits for a proposal with an amount or more than one effect (`missing_effect_limits`), and effect_limits without a
max_amount for a proposal with an amount (`missing_amount_limit`). A manifest limit or a context permission limit that is not a finite
JSON number (max_amount) or an exact JSON integer (max_effects) is refused, never coerced.
"""
from __future__ import annotations

import copy

import pytest

from agent_control_plane.bounded import commitment
from tests.test_bounded_authorization import NOW, proposal, resolver_for, workflow


def _gate(tmp_path, mutate, **proposal_update):
    p = proposal()
    flow = workflow(tmp_path, p)
    action = next(a for a in flow.manifest["actions"] if a["action_id"] == p.action_id)
    mutate(flow.manifest, action)
    rebound = p.model_copy(update={"manifest_digest": commitment(flow.manifest), **proposal_update})
    return flow, rebound


def test_shipped_example_has_no_manifest_mismatch(tmp_path):
    flow, p = _gate(tmp_path, lambda m, a: None)
    assert flow._manifest_mismatches(p, NOW) == []
    assert flow.decide(p, now=NOW).result == "authorized"


@pytest.mark.parametrize("name,mutate", [
    ("action default block", lambda m, a: a.update(default_action="block")),
    ("manifest default block", lambda m, a: (m.update(default_action="block"), a.pop("default_action", None))),
    ("tool not allowed", lambda m, a: m["tools"][0].update(allowed=False)),
    ("tool allowed not boolean", lambda m, a: m["tools"][0].update(allowed="true")),
])
def test_a_blocked_action_or_disallowed_tool_is_refused(tmp_path, name, mutate):
    flow, p = _gate(tmp_path, mutate)
    assert "action_blocked" in flow._manifest_mismatches(p, NOW)
    decision = flow.decide(p, now=NOW)
    assert decision.result == "hold" and "action_blocked" in decision.reasons


def test_action_override_of_a_blocked_manifest_default_is_not_blocked(tmp_path):
    flow, p = _gate(tmp_path, lambda m, a: m.update(default_action="block"))  # action keeps its own escalate default
    assert "action_blocked" not in flow._manifest_mismatches(p, NOW)


def test_missing_effect_limits_refuses_an_amount_or_several_effects(tmp_path):
    flow, p = _gate(tmp_path, lambda m, a: a.pop("effect_limits"))
    assert flow._manifest_mismatches(p, NOW) == ["missing_effect_limits"]
    assert flow.decide(p, now=NOW).result == "hold"
    flow, p = _gate(tmp_path, lambda m, a: a.pop("effect_limits"), amount=0.0, effects=2)
    assert flow._manifest_mismatches(p, NOW) == ["missing_effect_limits"]


def test_missing_effect_limits_allows_the_implicit_zero_amount_single_effect(tmp_path):
    flow, p = _gate(tmp_path, lambda m, a: a.pop("effect_limits"), amount=0.0, effects=1)
    assert flow._manifest_mismatches(p, NOW) == []


def test_effect_limits_without_max_amount_refuses_an_amount(tmp_path):
    flow, p = _gate(tmp_path, lambda m, a: a.update(effect_limits={"max_effects": 1}))
    assert flow._manifest_mismatches(p, NOW) == ["missing_amount_limit"]
    assert flow.decide(p, now=NOW).result == "hold"
    flow, p = _gate(tmp_path, lambda m, a: a.update(effect_limits={"max_effects": 1}), amount=0.0)
    assert flow._manifest_mismatches(p, NOW) == []


@pytest.mark.parametrize("limits", [
    {"max_effects": 1, "max_amount": "nan"},
    {"max_effects": 1, "max_amount": "1000"},
    {"max_effects": 1, "max_amount": True},
    {"max_effects": 1.9, "max_amount": 100.0},
    {"max_effects": "1", "max_amount": 100.0},
    {"max_effects": True, "max_amount": 100.0},
])
def test_a_manifest_limit_that_is_not_an_exact_number_is_refused(tmp_path, limits):
    flow, p = _gate(tmp_path, lambda m, a: a.update(effect_limits={**limits, "unit": "USD"}))
    assert "effect_limit_malformed" in flow._manifest_mismatches(p, NOW)


def test_a_fractional_max_effects_is_not_truncated_into_a_limit(tmp_path):
    flow, p = _gate(tmp_path, lambda m, a: a.update(effect_limits={"max_effects": 1.9, "max_amount": 100.0, "unit": "USD"}), effects=2)
    reasons = flow._manifest_mismatches(p, NOW)
    assert "effect_limit_malformed" in reasons


@pytest.mark.parametrize("field,bad", [
    ("max_amount", "nan"), ("max_amount", "10"), ("max_amount", True),
    ("max_effects", 1.9), ("max_effects", "1"), ("max_effects", True),
])
@pytest.mark.parametrize("where", ["requirement", "grant"])
def test_a_context_permission_limit_that_is_not_an_exact_number_is_refused(tmp_path, where, field, bad):
    p = proposal()
    r = resolver_for(p)
    ctx = r.contexts[next(iter(r.contexts))]
    container = ctx["requirement"] if where == "requirement" else ctx["grant"]
    container["permissions"][0][field] = bad
    flow = workflow(tmp_path, p, resolver=r)
    decision = flow.decide(p, now=NOW)
    assert decision.result == "hold"
    assert "authority_limit_malformed" in decision.reasons


def test_numeric_context_limits_still_compare_normally(tmp_path):
    p = proposal()
    r = resolver_for(p)
    ctx = r.contexts[next(iter(r.contexts))]
    for container in (ctx["requirement"], ctx["grant"]):
        container["permissions"][0]["max_amount"] = 10  # a plain integer is a valid number
    flow = workflow(tmp_path, p, resolver=r)
    decision = flow.decide(p, now=NOW)
    assert decision.result == "hold" and "authority_limit_malformed" not in decision.reasons
    assert "grant_scope_mismatch" in decision.reasons  # 50.0 > 10: the ordinary over-limit refusal
