"""Declared string lists in the manifest and the authority context must be lists of exact strings.

The members read by the target, payload-field and data-scope checks (`allowed_targets`, `required_fields`, `optional_fields`,
`forbidden_fields`, permission `targets` and `data_scopes`, and the `permissions` list itself) are compared by exact string
equality. Any other shape is malformed: it declares nothing, so the check it feeds refuses with its existing registered reason
(`target_out_of_scope`, `missing_payload_policy`, `requirement_scope_mismatch`, `grant_scope_mismatch`) and nothing is applied.
Well-formed inputs are unchanged (see the byte-identity tests in test_cli_run.py).

The numeric members of a RuntimeProposal are read strictly as well: `amount` must be a JSON number and `effects` a JSON integer.
"""

from __future__ import annotations

import json

import pytest

from agent_control_plane.bounded import RuntimeProposal, _exact_strings, commitment
from tests.test_cli_run import EXAMPLES, _inputs, _run

TARGET = "urn:cognous:synthetic-account:customer-001"  # the target of the authorized example

MALFORMED = [
    pytest.param(TARGET, id="single-string-equal-to-target"),
    pytest.param(TARGET + "2", id="single-string-longer-than-target"),
    pytest.param({TARGET: True}, id="object"),
    pytest.param(7, id="number"),
    pytest.param(None, id="null"),
    pytest.param([TARGET, 1], id="list-with-non-string-item"),
    pytest.param([[TARGET]], id="nested-list"),
]


def _read(path):
    return json.loads(path.read_text(encoding="utf-8"))


def _write_rebound(inputs, manifest=None, context=None):
    """Write changed inputs and re-bind the proposal (manifest digest) and its approval (proposal commitment) to them, so the
    only difference from the authorized example is the changed member."""
    if context is not None:
        inputs["authority-context"].write_text(json.dumps(context), encoding="utf-8")
    if manifest is None:
        return
    inputs["manifest"].write_text(json.dumps(manifest), encoding="utf-8")
    proposal = _read(inputs["proposal"])
    proposal["manifest_digest"] = commitment(manifest)
    inputs["proposal"].write_text(json.dumps(proposal), encoding="utf-8")
    bound = commitment(RuntimeProposal.model_validate(proposal).model_dump(mode="json", exclude_none=False))
    state = _read(inputs["resolver-state"])
    for approval in state.get("approvals", {}).values():
        if "proposal_commitment" in approval:
            approval["proposal_commitment"] = bound
    inputs["resolver-state"].write_text(json.dumps(state), encoding="utf-8")


def _outcome(tmp_path, inputs):
    code, stdout, _ = _run(tmp_path, inputs=inputs)
    result = _read(tmp_path / "out" / "result.json")
    effects = _read(tmp_path / "store" / "destination.json").get("effects", {})
    return code, set(result["reason_codes"]), effects, stdout


def test_rebinding_helper_keeps_the_well_formed_example_authorized(tmp_path):
    inputs = _inputs(tmp_path, "authorized")
    _write_rebound(inputs, manifest=_read(inputs["manifest"]), context=_read(inputs["authority-context"]))
    code, reasons, effects, stdout = _outcome(tmp_path, inputs)
    assert code == 0 and not reasons and len(effects) == 1, stdout


@pytest.mark.parametrize("value", MALFORMED)
def test_malformed_manifest_allowed_targets_is_refused(tmp_path, value):
    inputs = _inputs(tmp_path, "authorized")
    manifest = _read(inputs["manifest"])
    manifest["actions"][0]["target_policy"]["allowed_targets"] = value
    _write_rebound(inputs, manifest=manifest)
    code, reasons, effects, _ = _outcome(tmp_path, inputs)
    assert code == 1 and "target_out_of_scope" in reasons and not effects


@pytest.mark.parametrize("value", MALFORMED)
@pytest.mark.parametrize("holder,reason", [("requirement", "requirement_scope_mismatch"), ("grant", "grant_scope_mismatch")])
def test_malformed_permission_targets_is_refused(tmp_path, value, holder, reason):
    inputs = _inputs(tmp_path, "authorized")
    context = _read(inputs["authority-context"])
    context[holder]["permissions"][0]["targets"] = value
    _write_rebound(inputs, context=context)
    code, reasons, effects, _ = _outcome(tmp_path, inputs)
    assert code == 1 and reason in reasons and not effects


@pytest.mark.parametrize("holder,reason", [("requirement", "requirement_scope_mismatch"), ("grant", "grant_scope_mismatch")])
def test_malformed_permission_data_scopes_is_refused(tmp_path, holder, reason):
    inputs = _inputs(tmp_path, "authorized")
    context = _read(inputs["authority-context"])
    scopes = context[holder]["permissions"][0]["data_scopes"]
    context[holder]["permissions"][0]["data_scopes"] = "".join(scopes)  # one string instead of a list
    _write_rebound(inputs, context=context)
    code, reasons, effects, _ = _outcome(tmp_path, inputs)
    assert code == 1 and reason in reasons and not effects


@pytest.mark.parametrize("value", [{}, "permissions", 3, None])
def test_permissions_that_are_not_a_list_grant_nothing(tmp_path, value):
    inputs = _inputs(tmp_path, "authorized")
    context = _read(inputs["authority-context"])
    context["grant"]["permissions"] = value
    _write_rebound(inputs, context=context)
    code, reasons, effects, _ = _outcome(tmp_path, inputs)
    assert code == 1 and "grant_scope_mismatch" in reasons and not effects


@pytest.mark.parametrize("field", ["required_fields", "optional_fields", "forbidden_fields"])
def test_malformed_payload_field_list_is_refused(tmp_path, field):
    inputs = _inputs(tmp_path, "authorized")
    manifest = _read(inputs["manifest"])
    manifest["actions"][0]["payload_policy"][field] = "amount"
    _write_rebound(inputs, manifest=manifest)
    code, reasons, effects, _ = _outcome(tmp_path, inputs)
    assert code == 1 and "missing_payload_policy" in reasons and not effects


def test_exact_strings_accepts_only_collections_of_strings():
    assert _exact_strings(["a", "b"]) == frozenset({"a", "b"})
    assert _exact_strings(("a",)) == frozenset({"a"}) and _exact_strings({"a"}) == frozenset({"a"})
    assert _exact_strings([]) == frozenset()
    for bad in ("ab", b"ab", {"a": 1}, 1, None, ["a", None], [["a"]]):
        assert _exact_strings(bad) is None, bad


# -- RuntimeProposal numeric members are not coerced from other JSON types ---------------------------------------------

@pytest.mark.parametrize("member,value", [
    ("amount", "50.0"), ("amount", True), ("amount", None), ("amount", [50.0]),
    ("effects", True), ("effects", 1.0), ("effects", "1"), ("effects", None),
])
def test_proposal_numeric_members_of_another_json_type_are_invalid_input(tmp_path, member, value):
    inputs = _inputs(tmp_path, "authorized")
    proposal = _read(inputs["proposal"])
    proposal[member] = value
    inputs["proposal"].write_text(json.dumps(proposal), encoding="utf-8")
    code, _, _ = _run(tmp_path, inputs=inputs)
    assert code == 2
    destination = tmp_path / "store" / "destination.json"
    assert not destination.exists() or not _read(destination).get("effects")


def test_proposal_numbers_keep_their_values_and_commitment():
    base = json.loads((EXAMPLES / "authorized" / "proposal.json").read_text(encoding="utf-8"))
    reference = RuntimeProposal.model_validate(base)
    for amount in (50.0, 50, 5e1):
        same = RuntimeProposal.model_validate({**base, "amount": amount})
        assert same.amount == 50.0 and isinstance(same.amount, float)
        assert commitment(same.model_dump(mode="json", exclude_none=False)) == commitment(
            reference.model_dump(mode="json", exclude_none=False))
    assert RuntimeProposal.model_validate({**base, "effects": 1}).effects == 1
