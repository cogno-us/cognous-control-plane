"""The decision gate runs the action-manifest validator's error rules and refuses with `invalid_manifest` (scan 6, CP-5).

Before, a manifest the validator rejects (`authority_required: []` on a write action, E008; `effect_limits` without a unit, E023; a purchase
with `default_action: allow` and no review requirement, E014; a duplicate `allowed_targets` entry, E025) still decided `authorized`.
"""
from __future__ import annotations

import copy
import json
from pathlib import Path

import pytest

from agent_control_plane.manifest_validation import manifest_errors
from tests.test_bounded_authorization import NOW, manifest as shipped_manifest, proposal
from tests.test_manifest_gate_limits import _gate

TARGET = "urn:cognous:synthetic-account:customer-001"


def _action(m):
    return next(a for a in m["actions"] if a["action_id"] == "urn:cognous:action:refund-issue-routine-v1")


def _purchase_allow_without_review(m, a):
    a.update(action_type="purchase", default_action="allow")
    a.pop("review_requirement", None)


MUTATIONS = {
    "E008": lambda m, a: a.update(authority_required=[]),
    "E023": lambda m, a: a["effect_limits"].pop("unit"),
    "E014": _purchase_allow_without_review,
    "E025": lambda m, a: a["target_policy"].update(allowed_targets=[TARGET, TARGET]),
}


def test_the_shipped_manifest_has_no_validator_error():
    assert manifest_errors(shipped_manifest()) == []


@pytest.mark.parametrize("code", sorted(MUTATIONS))
def test_a_manifest_the_validator_rejects_is_refused_by_the_gate(tmp_path, code):
    flow, p = _gate(tmp_path, MUTATIONS[code])
    assert code in manifest_errors(flow.manifest)
    assert "invalid_manifest" in flow._manifest_mismatches(p, NOW)
    decision = flow.decide(p, now=NOW)
    assert decision.result != "authorized" and decision.binding is None
    assert "invalid_manifest" in decision.reasons


def test_the_shipped_manifest_is_still_authorized(tmp_path):
    flow, p = _gate(tmp_path, lambda m, a: None)
    decision = flow.decide(p, now=NOW)
    assert decision.result == "authorized" and "invalid_manifest" not in decision.reasons


def test_invalid_manifest_is_a_registered_reason():
    root = Path(__file__).resolve().parents[1] / "schemas"
    assert "invalid_manifest" in json.loads((root / "runtime_authority_reasons_0_2.json").read_text())["codes"]
    assert "invalid_manifest" not in json.loads((root / "runtime_authority_reasons_0_1.json").read_text())["codes"]


def _corpus():
    base = shipped_manifest()
    cases = {"clean": lambda m: None}
    for code, mutate in MUTATIONS.items():
        cases[code] = (lambda f: lambda m: f(m, _action(m)))(mutate)
    cases.update({
        "E001": lambda m: m.update(manifest_version=""),
        "E002": lambda m: m.update(manifest_id=" "),
        "E003": lambda m: m.update(agent_name=""),
        "E004": lambda m: m["actions"][1].update(action_name=m["actions"][0]["action_name"]),
        "E005": lambda m: m["tools"].append(copy.deepcopy(m["tools"][0])),
        "E006": lambda m: _action(m).update(tool_name="missing_tool"),
        "E009": lambda m: _action(m)["payload_policy"].update(forbidden_fields=["customer_id"]),
        "E013": lambda m: _action(m)["review_requirement"].update(mode="approval_required", reviewer_role=None),
        "E015": lambda m: (m["tools"][0].update(allowed=False), m["actions"][0].update(default_action="escalate")),
        "E016": lambda m: m.update(manifest_version="9.9"),
        "E017": lambda m: m["actions"][1].update(action_id=m["actions"][0]["action_id"]),
        "E018": lambda m: _action(m).pop("action_id"),
        "E019": lambda m: m["tools"][0].pop("adapter_id"),
        "E020": lambda m: _action(m)["target_policy"].update(allow_any_target=True),
        "E021": lambda m: _action(m).pop("authority_context"),
        "E022": lambda m: _action(m).pop("effect_limits"),
        "E024": lambda m: _action(m)["target_policy"].update(allowed_targets=[TARGET + " "]),
    })
    return base, cases


@pytest.mark.parametrize("name", sorted(_corpus()[1]))
def test_the_port_agrees_with_the_real_validator_when_it_is_installed(name):
    """Parity with `agent_action_manifest.validate_manifest` (skipped where that package is absent); error codes only."""
    pytest.importorskip("agent_action_manifest")
    from agent_action_manifest.loader import ManifestLoadError, load_manifest_json
    from agent_action_manifest.validator import validate_manifest
    base, cases = _corpus()
    document = copy.deepcopy(base)
    cases[name](document)
    try:
        report = validate_manifest(load_manifest_json(copy.deepcopy(document)))
    except ManifestLoadError:
        pytest.skip("the case is not schema-loadable; the port does not model the schema")
    expected = sorted({i.code for i in report.issues if i.severity.value == "error"})
    assert manifest_errors(document) == expected
