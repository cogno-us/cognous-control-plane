"""Every reason code the control plane appends after the journal completion row is in the closed ODES set.

The set is owned by the ODES execution-attempt-lifecycle contract (``POST_JOURNAL_GATE_CODES`` in its ``validate.py``). The vendored
contract copy here predates that member, so the set is recorded below with its digest; when the vendored copy carries the member,
the test reads it from there and also checks it equals this record.
"""
from __future__ import annotations

import ast
import hashlib
import importlib.util
from pathlib import Path

import agent_control_plane.dedupe as dedupe
import agent_control_plane.merge as merge

SRC = Path(__file__).resolve().parents[1] / "src" / "agent_control_plane"
VENDORED_VALIDATOR = Path(__file__).parent / "contracts" / "execution-attempt-lifecycle" / "validate.py"

# Recorded from open-decision-evidence-standard 01aa9fc (contracts/execution-attempt-lifecycle/validate.py).
RECORDED_SET = frozenset({
    "operation_grant_mismatch",
    "operation_renewal_unrecorded",
    "operation_not_admitted",
    "operation_merged_effect_exists",
    "operation_merged_effect_unresolved",
    "dedupe_unresolved_attempt_blocks_new_key",
    "dedupe_operation_effect_applied",
    "input_observation_time_regressed",
})
RECORDED_DIGEST = "sha256:040aaaa5496111e90c8a13068577b99c07c010d5f57387a09ff63d683e753613"  # sha256 of the sorted codes joined by newlines

# The functions that add a code after the journal completion row is written: the admission gate at decision time, the effect-time
# operation, merge and dedupe gates, and the time-regression code added when the resolution check row is recorded.
BOUNDED_FUNCTIONS = {"_admit_operation", "_operation_gate", "_effect_gate_n4", "record_resolution_check"}


def _vendored_set():
    spec = importlib.util.spec_from_file_location("vendored_eal_validate", VENDORED_VALIDATOR)
    module = importlib.util.module_from_spec(spec)
    import sys
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return getattr(module, "POST_JOURNAL_GATE_CODES", None)


def _appended_literals(tree: ast.AST, function_names: set[str]) -> set[str]:
    found: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name in function_names:
            for call in ast.walk(node):
                if (isinstance(call, ast.Call) and isinstance(call.func, ast.Attribute) and call.func.attr == "append"
                        and call.args and isinstance(call.args[0], ast.Constant) and isinstance(call.args[0].value, str)):
                    found.add(call.args[0].value)
    return found


def appended_after_journal() -> set[str]:
    bounded_tree = ast.parse((SRC / "bounded.py").read_text(encoding="utf-8"))
    codes = _appended_literals(bounded_tree, BOUNDED_FUNCTIONS)
    # merge_gate returns the code that _effect_gate_n4 appends.
    codes.update({merge.CODE_EFFECT_EXISTS, merge.CODE_EFFECT_UNRESOLVED})
    # The dedupe codes are named constants appended in _effect_gate_n4 as literals; keep the module constants in step.
    assert {"dedupe_unresolved_attempt_blocks_new_key", "dedupe_operation_effect_applied"} == {
        dedupe.CODE_BLOCKS_NEW_KEY, dedupe.CODE_ALREADY_APPLIED}
    return codes


def test_recorded_set_digest_is_the_one_in_the_notes():
    assert len(RECORDED_SET) == 8
    assert RECORDED_DIGEST == "sha256:" + hashlib.sha256("\n".join(sorted(RECORDED_SET)).encode()).hexdigest()  # a change to the set must change the recorded digest


def test_every_code_appended_after_the_journal_row_is_in_the_closed_set():
    appended = appended_after_journal()
    assert len(appended) >= 7, appended  # the discovery itself must not silently find nothing
    assert appended <= RECORDED_SET, sorted(appended - RECORDED_SET)


def test_the_discovery_can_fail_when_a_new_code_is_appended():
    tree = ast.parse("def _operation_gate(self, binding, reasons):\n    reasons.append('operation_brand_new_code')\n")
    assert _appended_literals(tree, BOUNDED_FUNCTIONS) == {"operation_brand_new_code"}
    assert not {"operation_brand_new_code"} <= RECORDED_SET


def test_vendored_contract_copy_agrees_when_it_carries_the_set():
    vendored = _vendored_set()
    if vendored is None:
        return  # the pin round re-vendors the contract; from then on this compares the two
    assert frozenset(vendored) == RECORDED_SET
    assert appended_after_journal() <= frozenset(vendored)
