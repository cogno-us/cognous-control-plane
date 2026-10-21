"""Parity of the in-tree validator port (manifest_validation.py) with ``agent_action_manifest.validate_manifest``, and typed refusal of
malformed members (scan 6, CP-5; fix wave 7, T2-A and T2-B).

Parity runs only when ``agent_action_manifest`` is installed (skipped otherwise). It compares the sorted error codes for every mutation
whose manifest the real package accepts as a schema, restricted to the rule codes the installed validator implements: the revision the
repo pins (``MANIFEST_UPSTREAM_COMMIT``) implements E001-E021, a later one also E022-E025 and treats ``export`` as effectful. Mutations
the Pydantic schema rejects are not parity cases; they must never raise and never decide ``authorized`` (the typed-refusal tests).
"""
from __future__ import annotations

import copy
import inspect
import re

import pytest

from agent_control_plane import manifest_validation
from agent_control_plane.manifest_validation import manifest_errors
from tests.test_bounded_authorization import NOW, manifest as shipped_manifest
from tests.test_manifest_gate_limits import _gate

TARGET = "urn:cognous:synthetic-account:customer-001"


def _a(m):
    return m["actions"][0]


def _second_action(m, **update):
    other = copy.deepcopy(_a(m))
    other.update({"action_name": "refund_issue_second", "action_id": "urn:cognous:action:refund-issue-second-v1", **update})
    m["actions"].append(other)


def _set(path_fn, **update):
    return lambda m: path_fn(m).update(**update)


def _drop(path_fn, key):
    return lambda m: path_fn(m).pop(key, None)


def _type_default(action_type, default="escalate", **extra):
    return lambda m: _a(m).update(action_type=action_type, default_action=default, **extra)


def _no_review_allow(action_type):
    def mutate(m):
        _a(m).update(action_type=action_type, default_action="allow")
        _a(m).pop("review_requirement", None)
    return mutate


# (case id, mutation). Codes in the id are the rule the case is aimed at; parity compares the full code set either way.
CASES = [
    ("valid-shipped", lambda m: None),
    ("valid-v1.0", lambda m: m.update(manifest_version="1.0")),
    ("valid-read-no-limits", _type_default("read", effect_limits=None)),
    ("E001-empty-version", lambda m: m.update(manifest_version="")),
    ("E001-blank-version", lambda m: m.update(manifest_version="   ")),
    ("E016-v2", lambda m: m.update(manifest_version="2.0")),
    ("E016-v1.2", lambda m: m.update(manifest_version="1.2")),
    ("E016-padded-version", lambda m: m.update(manifest_version=" 1.1")),
    ("E002-empty-id", lambda m: m.update(manifest_id="")),
    ("E002-blank-id", lambda m: m.update(manifest_id=" ")),
    ("E003-empty-agent", lambda m: m.update(agent_name="")),
    ("E003-blank-agent", lambda m: m.update(agent_name="\t")),
    ("E004-duplicate-action-name", lambda m: _second_action(m, action_name=_a(m)["action_name"])),
    ("E017-duplicate-action-id", lambda m: _second_action(m, action_id=_a(m)["action_id"])),
    ("E005-duplicate-tool-name", lambda m: m["tools"].append(copy.deepcopy(m["tools"][0]))),
    ("E006-unknown-tool", _set(_a, tool_name="no_such_tool")),
    ("E007-external-send-no-authority", _type_default("external_send", authority_required=[])),
    ("E007-external-send-optional-authority",
     lambda m: _a(m).update(action_type="external_send", authority_required=[{"scope": "s", "required": False}])),
    ("E008-write-no-authority", _set(_a, authority_required=[])),
    ("E008-write-optional-authority", _set(_a, authority_required=[{"scope": "refund.issue.routine", "required": False}])),
    ("E008-write-blank-scope", _set(_a, authority_required=[{"scope": "  ", "required": True}])),
    ("E008-delete-no-authority", _type_default("delete", authority_required=[])),
    ("E008-approve-no-authority", _type_default("approve", authority_required=[])),
    ("E008-purchase-no-authority", _type_default("purchase", authority_required=[])),
    ("E009-forbidden-overlaps-required",
     lambda m: _a(m)["payload_policy"].update(forbidden_fields=["customer_id"])),
    ("E010-forbidden-overlaps-optional",
     lambda m: _a(m)["payload_policy"].update(optional_fields=["note"], forbidden_fields=["note"])),
    ("E011-sensitive-not-allowed", lambda m: _a(m)["payload_policy"].update(sensitive_fields=["ssn"])),
    ("E011-sensitive-with-optional-only",
     lambda m: _a(m)["payload_policy"].update(required_fields=[], optional_fields=["note"], sensitive_fields=["customer_id"])),
    ("E012-blank-redaction-path", lambda m: _a(m).update(redaction_hints=[{"field_path": " ", "reason": "x"}])),
    ("E012-empty-redaction-path", lambda m: _a(m).update(redaction_hints=[{"field_path": "", "reason": "x"}])),
    ("E013-approval-without-reviewer",
     lambda m: _a(m).update(review_requirement={"mode": "approval_required", "reason": "x"})),
    ("E013-approval-empty-reviewer",
     lambda m: _a(m).update(review_requirement={"mode": "approval_required", "reviewer_role": "", "reason": "x"})),
    ("E014-purchase-allow-no-review", _no_review_allow("purchase")),
    ("E014-external-send-allow-no-review", _no_review_allow("external_send")),
    ("E014-delete-allow-no-review", _no_review_allow("delete")),
    ("E014-approve-allow-review-none",
     _type_default("approve", "allow", review_requirement={"mode": "none"})),
    ("E014-purchase-allow-no-authority",
     _type_default("purchase", "allow", authority_required=[])),
    ("E015-tool-not-allowed", lambda m: m["tools"][0].update(allowed=False)),
    ("E015-tool-not-allowed-block-default", lambda m: (m["tools"][0].update(allowed=False), _a(m).update(default_action="block"))),
    ("E018-missing-action-id", _drop(_a, "action_id")),
    ("E018-empty-action-id", _set(_a, action_id="")),
    ("E018-v1.0-missing-action-id", lambda m: (m.update(manifest_version="1.0"), _a(m).pop("action_id"))),
    ("E019-missing-adapter", lambda m: m["tools"][0].pop("adapter_id")),
    ("E019-empty-adapter", lambda m: m["tools"][0].update(adapter_id="")),
    ("E020-allow-any-target", lambda m: _a(m)["target_policy"].update(allow_any_target=True)),
    ("E020-empty-targets", lambda m: _a(m)["target_policy"].update(allowed_targets=[])),
    ("E020-no-target-policy", _drop(_a, "target_policy")),
    ("E020-purchase-no-target-policy", _type_default("purchase", target_policy=None)),
    ("E021-no-authority-context", _drop(_a, "authority_context")),
    ("E021-external-send-no-authority-context", _type_default("external_send", authority_context=None)),
    ("E022-no-effect-limits", _drop(_a, "effect_limits")),
    ("E022-delete-no-effect-limits", _type_default("delete", effect_limits=None)),
    ("E023-no-unit", lambda m: _a(m)["effect_limits"].pop("unit")),
    ("E023-blank-unit", lambda m: _a(m)["effect_limits"].update(unit="  ")),
    ("E023-no-max-amount", lambda m: _a(m)["effect_limits"].pop("max_amount")),
    ("E023-zero-amount-no-unit-ok", lambda m: _a(m)["effect_limits"].update(max_amount=0, unit="")),
    ("E024-padded-action-id", _set(_a, action_id=" urn:cognous:action:refund-issue-routine-v1")),
    ("E024-control-action-id", _set(_a, action_id="urn:cognous:action:refund\n")),
    ("E024-padded-target", lambda m: _a(m)["target_policy"].update(allowed_targets=[TARGET + " "])),
    ("E024-blank-target", lambda m: _a(m)["target_policy"].update(allowed_targets=[TARGET, ""])),
    ("E024-padded-adapter", lambda m: m["tools"][0].update(adapter_id="urn:cognous:adapter:synthetic-refund-v1 ")),
    ("E025-duplicate-targets", lambda m: _a(m)["target_policy"].update(allowed_targets=[TARGET, TARGET])),
    ("block-default-hides-effect-errors",
     _set(_a, default_action="block", authority_required=[], effect_limits=None)),
    ("manifest-block-default",
     lambda m: (m.update(default_action="block"), _a(m).pop("default_action"), _a(m).update(authority_required=[]))),
    ("read-no-authority-ok", _type_default("read", authority_required=[])),
    ("export-no-authority", _type_default("export", authority_required=[])),
    ("export-no-limits", _type_default("export", effect_limits=None)),
]

# Members of the wrong type. The Pydantic schema rejects these, so they are not parity cases: the port must not raise and the gate must
# refuse (never authorize). Before wave 7 each of the first four raised TypeError out of ``flow.decide``.
MALFORMED = [
    ("version-list", lambda m: m.update(manifest_version=["1.1"])),
    ("version-dict", lambda m: m.update(manifest_version={"v": "1.1"})),
    ("required-fields-nested-list", lambda m: _a(m)["payload_policy"].update(required_fields=[["customer_id"]])),
    ("optional-fields-dict-entry", lambda m: _a(m)["payload_policy"].update(optional_fields=[{"a": 1}])),
    ("action-type-list", _set(_a, action_type=["write"])),
    ("action-type-dict", _set(_a, action_type={"a": 1})),
    ("action-tool-name-list", _set(_a, tool_name=["refund_adapter"])),
    ("tool-name-list", lambda m: m["tools"][0].update(tool_name=["refund_adapter"])),
    ("default-action-list", _set(_a, default_action=["block"])),
    ("allowed-targets-dict", lambda m: _a(m)["target_policy"].update(allowed_targets={"a": 1})),
    ("targets-nested-list", lambda m: _a(m)["target_policy"].update(allowed_targets=[[TARGET]])),
    ("forbidden-fields-string", lambda m: _a(m)["payload_policy"].update(forbidden_fields="customer_id")),
    ("actions-not-list", lambda m: m.update(actions="nope")),
    ("action-id-list", _set(_a, action_id=["a"])),
]


def _validator_source():
    try:
        import agent_action_manifest.validator as validator
    except ImportError:
        return ""
    return inspect.getsource(validator)


def _installed_codes():
    return set(re.findall(r"E\d{3}", _validator_source()))


def _real_error_codes(manifest_dict, implemented):
    """Sorted error codes of the real validator, or None when the schema rejects the manifest."""
    from agent_action_manifest import AgentActionManifest, validate_manifest
    from pydantic import ValidationError
    try:
        parsed = AgentActionManifest.model_validate(copy.deepcopy(manifest_dict))
    except ValidationError:
        return None
    report = validate_manifest(parsed)
    return sorted({i.code for i in report.issues if i.severity.value == "error"} & implemented)


def test_the_case_table_covers_every_validator_rule_with_at_least_sixty_mutations():
    assert len(CASES) + len(MALFORMED) >= 60
    text = " ".join(name for name, _ in CASES)
    for number in range(1, 26):
        assert f"E{number:03d}" in text, f"E{number:03d} has no case"


@pytest.mark.parametrize("name,mutate", CASES, ids=[n for n, _ in CASES])
def test_the_port_matches_the_real_validator(name, mutate):
    pytest.importorskip("agent_action_manifest")
    implemented = _installed_codes()
    m = shipped_manifest()
    mutate(m)
    real = _real_error_codes(m, implemented)
    if real is None:
        pytest.skip("the schema rejects this mutation, so it is not a validator-rule case")
    later = "E024" in implemented  # a revision with E022-E025 also treats export as effectful
    if name.startswith("export") and not later:
        pytest.skip("the pinned revision does not treat export as effectful")
    if ("optional-authority" in name or "blank-scope" in name) and "item.required and item.scope.strip()" not in _validator_source():
        pytest.skip("the pinned revision tests authority_required for presence only, not for a required non-blank scope")
    ported = sorted(set(manifest_errors(m)) & implemented)
    assert ported == real, f"{name}: port {ported} != validator {real}"


@pytest.mark.parametrize("code", ["E022", "E023", "E024", "E025"])
def test_later_rules_are_reported_by_the_port_even_when_the_pinned_validator_lacks_them(code):
    m = shipped_manifest()
    dict(CASES)[{"E022": "E022-no-effect-limits", "E023": "E023-no-unit", "E024": "E024-padded-target",
                 "E025": "E025-duplicate-targets"}[code]](m)
    assert code in manifest_errors(m)


def test_every_case_is_a_mutation_of_the_shipped_manifest_and_the_shipped_manifest_is_clean():
    assert manifest_errors(shipped_manifest()) == []


@pytest.mark.parametrize("name,mutate", MALFORMED, ids=[n for n, _ in MALFORMED])
def test_a_malformed_member_never_raises_from_the_port(name, mutate):
    m = shipped_manifest()
    mutate(m)
    assert isinstance(manifest_errors(m), list)


@pytest.mark.parametrize("name,mutate", MALFORMED, ids=[n for n, _ in MALFORMED])
def test_a_malformed_member_is_a_typed_refusal_from_the_gate(tmp_path, name, mutate):
    flow, p = _gate(tmp_path, lambda m, a: mutate(m))
    decision = flow.decide(p, now=NOW)
    assert decision.result != "authorized" and decision.binding is None and decision.reasons


@pytest.mark.parametrize("name", ["version-list", "version-dict", "tool-name-list"])
def test_a_malformed_identity_member_is_invalid_manifest(tmp_path, name):
    flow, p = _gate(tmp_path, lambda m, a: dict(MALFORMED)[name](m))
    assert manifest_errors(flow.manifest)
    assert "invalid_manifest" in flow.decide(p, now=NOW).reasons


def test_an_unexpected_exception_in_the_port_fails_closed(tmp_path, monkeypatch):
    def boom(manifest):
        raise RuntimeError("unexpected")
    monkeypatch.setattr(manifest_validation, "_manifest_errors", boom)
    assert manifest_errors(shipped_manifest()) == ["E999"]
    flow, p = _gate(tmp_path, lambda m, a: None)
    decision = flow.decide(p, now=NOW)
    assert decision.result != "authorized" and "invalid_manifest" in decision.reasons


@pytest.mark.parametrize("value", [None, [], "manifest", 5])
def test_a_manifest_that_is_not_an_object_fails_closed(value):
    assert manifest_errors(value) == ["E999"]
