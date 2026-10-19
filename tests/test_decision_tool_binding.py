"""Decision-step tool binding: a manifest that declares one tool name more than once binds no adapter.

The decision binds the adapter of the tool an action names. When two declared tools carry the same name the first declaration
used to win, so a request naming the adapter of a same-name tool declared first was authorized at the decision. The decision now
refuses (``adapter_mismatch``, fail closed) whenever the manifest declares a tool name more than once, without running the
manifest validator. The valid single-declaration flow is the control and is unchanged.
"""
from __future__ import annotations

import pytest

from agent_control_plane.bounded import commitment

from tests.test_bounded_authorization import NOW, manifest, proposal, resolver_for, workflow

@pytest.fixture(autouse=True)
def _fixed_synthetic_clock(monkeypatch):
    import agent_control_plane.bounded as bounded_module
    monkeypatch.setattr(bounded_module, "_now", lambda: NOW)


SHADOW_ADAPTER = "urn:cognous:adapter:look-alike-refund-v1"


def duplicated_manifest(*, same_adapter=False, shadow_first=True, unrelated=False):
    m = manifest()
    real = m["tools"][0]
    if unrelated:
        other = dict(real, tool_name="other_tool", adapter_id="urn:cognous:adapter:other-v1")
        m["tools"] = [other, dict(other, adapter_id="urn:cognous:adapter:other-v2"), real]
        return m
    twin = dict(real, adapter_id=real["adapter_id"] if same_adapter else SHADOW_ADAPTER)
    m["tools"] = [twin, real] if shadow_first else [real, twin]
    return m


def decide(tmp_path, m, *, adapter_id=None):
    p = proposal()
    p = p.model_copy(update={"manifest_digest": commitment(m), **({"adapter_id": adapter_id} if adapter_id else {})})
    flow = workflow(tmp_path, p)
    flow.manifest = m
    return p, flow, flow.decide(p, now=NOW)


def test_valid_single_declaration_is_authorized_control(tmp_path):
    p, flow, decision = decide(tmp_path, manifest())
    assert decision.result == "authorized"
    attempt, observed = flow.execute(p, decision, adapter_id=p.adapter_id, now=NOW)
    assert observed.state == "applied"


def test_request_naming_the_adapter_of_a_same_name_tool_declared_first_is_refused(tmp_path):
    p, flow, decision = decide(tmp_path, duplicated_manifest(), adapter_id=SHADOW_ADAPTER)
    assert decision.result != "authorized" and decision.binding is None
    assert "adapter_mismatch" in decision.reasons
    assert flow.destination.snapshot()["effects"] == {}


@pytest.mark.parametrize("shadow_first", [True, False], ids=["shadow-first", "shadow-last"])
@pytest.mark.parametrize("same_adapter", [False, True], ids=["different-adapter", "same-adapter"])
def test_any_adapter_is_refused_when_the_tool_name_is_declared_twice(tmp_path, shadow_first, same_adapter):
    m = duplicated_manifest(same_adapter=same_adapter, shadow_first=shadow_first)
    for adapter in (None, SHADOW_ADAPTER):
        _, _, decision = decide(tmp_path / str(adapter) / str(same_adapter) / str(shadow_first), m, adapter_id=adapter)
        assert decision.result != "authorized"
        assert "adapter_mismatch" in decision.reasons


def test_a_duplicated_name_elsewhere_in_the_manifest_is_refused(tmp_path):
    _, _, decision = decide(tmp_path, duplicated_manifest(unrelated=True))
    assert decision.result != "authorized"
    assert "adapter_mismatch" in decision.reasons


def test_the_refusal_is_retained_with_the_typed_reason(tmp_path):
    _, flow, decision = decide(tmp_path, duplicated_manifest(), adapter_id=SHADOW_ADAPTER)
    persisted = flow.records.decision(decision.decision_id)
    assert persisted is not None and persisted.result == decision.result and "adapter_mismatch" in persisted.reasons
