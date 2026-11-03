"""R1-A2 (csf_4e1e796e81b0407be8a54206): AGT must evaluate the tool identity Cognous authorizes.

``tool_name`` (AGT) and ``proposal.adapter_id`` (Cognous) are one bound identity: exact equality without ``tool_bindings``, exact
``{adapter_id: tool_name}`` entry with them. No mapping is inferred; transform cannot change the bound adapter.
"""
from __future__ import annotations

import pytest

from agent_control_plane.bounded import RuntimeProposal
from agent_control_plane.microsoft_agt import AgtDecision, MicrosoftAgtPreToolCallAdapter
from tests.test_microsoft_agt import FakeAuthority, FakeBackend, proposal

ADAPTER = "urn:cognous:adapter:synthetic-refund-v1"
OTHER = "urn:cognous:adapter:synthetic-wire-v1"


def _adapter(bindings=None, decision=None, authority=None):
    backend = FakeBackend(decision or AgtDecision(decision="allow"))
    authority = authority or FakeAuthority("authorized")
    return MicrosoftAgtPreToolCallAdapter(backend=backend, authority=authority, tool_bindings=bindings), backend, authority


def _other_proposal():
    return proposal().model_copy(update={"adapter_id": OTHER})


async def _run(adapter, tool_name, p=None):
    return await adapter.evaluate(tenant_id="tenant-alpha", proposal=p or proposal(), tool_name=tool_name, tool_call_id="c1")


def _held_before_anything(result, backend, authority, reason):
    assert result.result == "hold" and reason in result.reasons
    assert result.proposal is None and result.cognous_decision is None
    assert backend.calls == [] and authority.calls == []


@pytest.mark.asyncio
async def test_1_tool_name_equal_to_adapter_id_passes():
    adapter, backend, authority = _adapter()
    r = await _run(adapter, ADAPTER)
    assert r.result == "authorized" and r.reasons == ()
    assert backend.calls[0]["tool_name"] == ADAPTER and authority.calls[0][0].adapter_id == ADAPTER


@pytest.mark.asyncio
@pytest.mark.parametrize("tool_name", ["read_only_lookup", ADAPTER + " ", ADAPTER.upper(), "", None],
                         ids=["benign", "padded", "case", "empty", "none"])
async def test_2_mismatch_without_bindings_is_held_before_agt(tool_name):
    adapter, backend, authority = _adapter()
    _held_before_anything(await _run(adapter, tool_name), backend, authority, "tool_identity_unbound")


@pytest.mark.asyncio
async def test_2b_benign_tool_name_with_different_adapter_proposal_is_held():  # the finding's exact scenario
    adapter, backend, authority = _adapter()
    _held_before_anything(await _run(adapter, ADAPTER, _other_proposal()), backend, authority, "tool_identity_unbound")


@pytest.mark.asyncio
async def test_3_explicit_binding_resolving_to_adapter_passes():
    adapter, backend, authority = _adapter({ADAPTER: "refund_adapter"})
    r = await _run(adapter, "refund_adapter")
    assert r.result == "authorized"
    assert backend.calls[0]["tool_name"] == "refund_adapter" and authority.calls[0][0].adapter_id == ADAPTER
    # with bindings the adapter_id itself is not an accepted alias: no inference
    held, b2, a2 = _adapter({ADAPTER: "refund_adapter"})
    _held_before_anything(await _run(held, ADAPTER), b2, a2, "tool_binding_mismatch")


@pytest.mark.asyncio
async def test_4_binding_mapping_the_tool_elsewhere_is_held():
    # the tool is bound to a different adapter than the proposal's; and the proposal's adapter is bound to a different tool
    adapter, backend, authority = _adapter({ADAPTER: "other_tool", OTHER: "refund_adapter"})
    _held_before_anything(await _run(adapter, "refund_adapter"), backend, authority, "tool_binding_mismatch")


@pytest.mark.asyncio
@pytest.mark.parametrize("bindings", [{}, {OTHER: "refund_adapter"}], ids=["empty", "other_entry_only"])
async def test_5_missing_binding_entry_is_held(bindings):
    adapter, backend, authority = _adapter(bindings)
    _held_before_anything(await _run(adapter, "refund_adapter"), backend, authority, "tool_binding_mismatch")


class _AdapterSwappingProposal(RuntimeProposal):
    """Simulates a transform path that tries to change the adapter identity of the effective proposal."""

    def model_copy(self, *, update=None, deep=False):
        if update and "payload" in update:
            update = {**update, "adapter_id": OTHER}
        return super().model_copy(update=update, deep=deep)


@pytest.mark.asyncio
async def test_7_transform_cannot_alter_adapter_identity_after_binding():
    p = _AdapterSwappingProposal(**proposal().model_dump())
    adapter, backend, authority = _adapter(decision=AgtDecision(
        decision="transform", transformed_policy_target={"customer_id": "c2"}, transformed_policy_target_applied=True))
    r = await _run(adapter, ADAPTER, p)
    assert r.result == "hold" and r.reasons == ("transform_identity_changed",)
    assert authority.calls == [] and r.proposal is None and r.cognous_decision is None
    assert r.evidence.bound_adapter_id == ADAPTER


@pytest.mark.asyncio
async def test_7b_ordinary_transform_keeps_the_bound_adapter():
    adapter, backend, authority = _adapter(decision=AgtDecision(
        decision="transform", transformed_policy_target={"customer_id": "c2"}, transformed_policy_target_applied=True))
    r = await _run(adapter, ADAPTER)
    assert r.result == "authorized" and r.evidence.transformed and r.proposal.adapter_id == ADAPTER
    assert authority.calls[0][0].adapter_id == ADAPTER


@pytest.mark.asyncio
@pytest.mark.parametrize("bindings,tool", [(None, ADAPTER), ({ADAPTER: "refund_adapter"}, "refund_adapter")])
async def test_8_agt_and_cognous_see_the_same_identity(bindings, tool):
    adapter, backend, authority = _adapter(bindings)
    r = await _run(adapter, tool)
    assert r.result == "authorized"
    assert backend.calls[0]["tool_name"] == r.evidence.tool_name == tool
    assert authority.calls[0][0].adapter_id == r.proposal.adapter_id == r.evidence.bound_adapter_id == ADAPTER
    if bindings:
        assert bindings[r.evidence.bound_adapter_id] == r.evidence.tool_name


@pytest.mark.asyncio
async def test_identity_is_checked_on_the_snapshot_not_the_live_proposal():
    caller = proposal()
    adapter, backend, authority = _adapter()
    r = await _run(adapter, ADAPTER, caller)
    caller.adapter_id = OTHER  # after the call: no effect on the recorded result
    assert r.proposal.adapter_id == ADAPTER and r.evidence.bound_adapter_id == ADAPTER


class _AlwaysEqual(str):
    def __eq__(self, other):
        return True

    def __ne__(self, other):
        return False

    __hash__ = str.__hash__


@pytest.mark.asyncio
async def test_9_str_subclass_tool_name_without_bindings_is_held():
    adapter, backend, authority = _adapter()
    _held_before_anything(await _run(adapter, _AlwaysEqual("read_only_lookup")), backend, authority, "tool_identity_unbound")


@pytest.mark.asyncio
async def test_9b_str_subclass_tool_name_with_bindings_is_held():
    adapter, backend, authority = _adapter({ADAPTER: "refund_adapter"})
    _held_before_anything(await _run(adapter, _AlwaysEqual("read_only_lookup")), backend, authority, "tool_identity_unbound")


@pytest.mark.asyncio
async def test_9c_str_subclass_adapter_id_is_held():
    p = proposal()
    object.__setattr__(p, "adapter_id", _AlwaysEqual("urn:other"))
    adapter, backend, authority = _adapter()
    _held_before_anything(await _run(adapter, ADAPTER, p), backend, authority, "tool_identity_unbound")


@pytest.mark.parametrize("bad", [{_AlwaysEqual(ADAPTER): "refund_adapter"}, {ADAPTER: _AlwaysEqual("refund_adapter")},
                                 {ADAPTER: 1}, {1: "x"}, {"": "x"}, {ADAPTER: ""}],
                         ids=["key_subclass", "value_subclass", "int_value", "int_key", "empty_key", "empty_value"])
def test_9d_non_exact_str_bindings_are_refused_at_construction(bad):
    with pytest.raises(ValueError):
        _adapter(bad)


@pytest.mark.asyncio
async def test_9e_mutating_the_callers_bindings_after_construction_changes_nothing():
    source = {ADAPTER: "refund_adapter"}
    adapter, backend, authority = _adapter(source)
    source[ADAPTER] = "read_only_lookup"
    source[OTHER] = "refund_adapter"
    assert (await _run(adapter, "refund_adapter")).result == "authorized"
    source2 = {ADAPTER: "refund_adapter"}
    adapter2, b3, a3 = _adapter(source2)
    source2[ADAPTER] = "read_only_lookup"
    r = await _run(adapter2, "read_only_lookup")
    assert r.result == "hold" and "tool_binding_mismatch" in r.reasons and b3.calls == [] and a3.calls == []


@pytest.mark.asyncio
async def test_9f_agt_and_evidence_receive_exact_plain_str():
    adapter, backend, authority = _adapter()
    r = await _run(adapter, ADAPTER)
    assert type(backend.calls[0]["tool_name"]) is str and type(r.evidence.tool_name) is str
    assert type(r.evidence.bound_adapter_id) is str
