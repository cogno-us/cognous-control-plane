"""Decision-step action identity binding: a manifest that declares one action_id more than once binds no action.

The decision looked an action up by ``action_id`` and took the first declaration, so the outcome depended on declaration
order. The decision now refuses (``unknown_action``, the reason used for an absent action; fail closed) whenever the manifest
declares the requested action_id more than once. The valid single-declaration flow is the control and is unchanged.
"""
from __future__ import annotations

import pytest

from agent_control_plane.bounded import commitment

from tests.test_bounded_authorization import NOW, manifest, proposal, workflow


@pytest.fixture(autouse=True)
def _fixed_synthetic_clock(monkeypatch):
    import agent_control_plane.bounded as bounded_module
    monkeypatch.setattr(bounded_module, "_now", lambda: NOW)


def action_index(m, p):
    return next(i for i, a in enumerate(m["actions"]) if a["action_id"] == p.action_id)


def duplicated_manifest(kind, *, twin_first):
    m = manifest()
    real = m["actions"][action_index(m, proposal())]
    if kind == "tool_name":
        twin = dict(real, tool_name="other_tool")
    elif kind == "effect_limits":
        twin = dict(real, effect_limits=dict(real.get("effect_limits") or {}, max_effects=99))
    else:
        twin = dict(real)
    rest = [a for a in m["actions"] if a is not real]
    m["actions"] = ([twin, real] if twin_first else [real, twin]) + rest
    return m


def decide(tmp_path, m):
    p = proposal()
    p = p.model_copy(update={"manifest_digest": commitment(m)})
    flow = workflow(tmp_path, p)
    flow.manifest = m
    return p, flow, flow.decide(p, now=NOW)


def test_single_declaration_is_authorized_control(tmp_path):
    p, flow, decision = decide(tmp_path, manifest())
    assert decision.result == "authorized"
    attempt, observed = flow.execute(p, decision, adapter_id=p.adapter_id, now=NOW)
    assert observed.state == "applied"


@pytest.mark.parametrize("twin_first", [True, False], ids=["twin-first", "twin-last"])
@pytest.mark.parametrize("kind", ["tool_name", "effect_limits", "identical"])
def test_action_declared_twice_binds_nothing(tmp_path, kind, twin_first):
    _, flow, decision = decide(tmp_path, duplicated_manifest(kind, twin_first=twin_first))
    assert decision.result != "authorized"
    assert decision.binding is None
    assert decision.reasons
    assert "unknown_action" in decision.reasons
    assert flow.destination.snapshot()["effects"] == {}
    persisted = flow.records.decision(decision.decision_id)
    assert persisted is not None and persisted.result == decision.result and "unknown_action" in persisted.reasons
