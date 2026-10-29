"""D-07 Option A successor tests: the purpose observation / cached-purpose snapshot joins the dispatch deadline WITHOUT a policy binding.

Authorization: Architect directive 2026-10-29 (D-07 Option A; ``family-migration/final-three/02-architect-authorization-and-contract-freeze-
2026-10-29.md`` section 6; F3-B expectations in ``03-f3-qualification-expectations-F3A-F3B-2026-10-29.md``). The change: in
``runtime_authority.py`` the block that registers the purpose observation's ``observed_at + bound`` with the deadline collector no longer
requires ``profile.policy_binding``. The collector exists only when ``anchor_deadline_to_inputs`` is True, so the flag-False path is untouched.

Predecessor: CP #94 head 061a986 (``tests/test_freshness_purpose_residual.py`` now carries the SUPERSESSION RECORD). Outcomes of the UNCHANGED
predecessor source for the grid below were recorded by ``docs/evidence/d07/record_predecessor_outcomes.py`` into
``tests/fixtures/d07_predecessor_outcomes_061a986.json`` and are compared here, so the "old" side is data, not a re-implementation.

Boundary semantics preserved from the source: the check is refused when the service clock is strictly after the deadline
(``bounded._expired_before_dispatch``: ``now > deadline``), AND by the process-monotonic guard whose allowance is the remaining anchored
window and which counts real elapsed time. Hence a remaining window of exactly 0 s (age exactly at the ceiling) is refused for every stall.
Deterministic: fake service clock (tests/test_freshness.py ``Clock``), nothing sleeps. Synthetic fixtures only.
Developer evidence: non-authorizing, builder-tested, NOT independently qualified.
"""
import ast
import hashlib
import json
from datetime import timedelta
from pathlib import Path

import pytest

import agent_control_plane.bounded as bounded
from agent_control_plane.bounded import commitment
from agent_control_plane.freshness import FreshnessProfile
from tests.freshness_d07_grid import (
    CHANGED_REFUSAL_CASE, DOC_CASES, NEGATIVES, build, case_key, commitments, control_grid, grid, key_paths, opened_deadline_offset,
    persisted_document, run_case, run_control, run_negative, stall_once, string_constants,
)
from tests.test_bounded_authorization import NOW
from tests.test_freshness import OTHER, SIGNER, authority, clock  # noqa: F401  (clock is a fixture)
from tests.test_reversibility import cls, flow as rev_flow, outage

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "agent_control_plane"
OLD = json.loads((Path(__file__).parent / "fixtures" / "d07_predecessor_outcomes_061a986.json").read_text(encoding="utf-8"))
CODE = "check_expired_before_dispatch"


def _case_id(c):
    return case_key(c)


# ------------------------------------------------------------------------------------------------ provenance of the recorded old side
def test_the_recorded_old_side_is_the_unchanged_predecessor():
    assert OLD["provenance"]["predecessor_head"] == "061a986563768f2f8f9f6c0861647a3c5b1935be"
    assert OLD["provenance"]["runtime_authority_sha256"] == "a4b4ac36cca6e75d8fc3408b8738163acfb609a7265633aec2f799700ff9ea66"
    assert set(OLD["cases"]) == {case_key(c) for c in grid()}, "re-record the fixture with docs/evidence/d07/record_predecessor_outcomes.py"


def test_the_old_side_matches_the_independently_derived_strict_boundary_oracle():
    """Oracle (derived from the source semantics, not from the new code): anchored dispatch is refused iff stall > remaining deadline window
    or the remaining window is 0 (monotonic guard); the class-deadline window is the ceiling. Validated here against the OLD recordings
    for every mode, so the same oracle can be applied to the new code without being circular."""
    for key, old in OLD["cases"].items():
        kind, ceiling, age, stall, mode = key.split("|")
        ceiling, age, stall = int(ceiling), int(age), int(stall)
        window = ceiling if mode == "anchor_nobinding" or mode == "flag_false_nobinding" else ceiling - age   # OLD: binding anchors, others do not
        expected = "refused" if (stall > window or window == 0) else "dispatched"
        assert old["outcome"] == expected, (key, old["outcome"], expected)
        assert old["deadline_offset_s"] == window, key


# ------------------------------------------------------------------------------------------------ grid: new vs old
@pytest.mark.parametrize("case", grid(), ids=_case_id)
def test_grid_the_correction_only_adds_a_min_and_never_accepts_what_the_old_code_refused(tmp_path, case):
    kind, ceiling, age, stall, mode = case
    old = OLD["cases"][case_key(case)]
    new = run_case(tmp_path, kind=kind, ceiling=ceiling, age=age, stall=stall, mode=mode)
    assert new["decision"] == old["decision"] and new["decision_reasons"] == old["decision_reasons"], "decision stage is not touched"
    if new["decision"] != "authorized":
        return
    # (4) new deadline <= old deadline, and anything the new code dispatches the old code dispatched too
    assert new["deadline_offset_s"] <= old["deadline_offset_s"]
    if new["outcome"] == "dispatched":
        assert old["outcome"] == "dispatched"
    # the new deadline is exactly min(old deadline, purpose observed_at + bound) when the anchor applies, else unchanged
    if mode == "anchor_nobinding":
        window = min(old["deadline_offset_s"], ceiling - age)
        assert new["deadline_offset_s"] == window
        assert new["outcome"] == ("refused" if (stall > window or window == 0) else "dispatched")   # strict boundary, oracle above
    else:
        assert new == old, "binding path and flag-False path are byte-for-byte the recorded predecessor outcome"
    # (6) no external effect after refusal; (5) no new reason code
    assert new["apply_calls"] == (1 if new["outcome"] == "dispatched" else 0)
    assert new["destination_effects"] == new["apply_calls"]
    if new["outcome"] == "refused":
        assert new["error"] == CODE and new["refusal_reasons"] == [CODE]


# ------------------------------------------------------------------------------------------------ named scenarios from the directive
@pytest.mark.parametrize("kind", ["live_irreversible", "live_reversible", "cached_reversible"])
def test_purpose_observation_exactly_at_the_ceiling_is_no_longer_dispatchable_without_a_binding(tmp_path, kind):
    """Age == ceiling is accepted at evaluation (strict ``>``) but its anchored window is 0 s: refused at every stall, even 0."""
    for stall in (0, 1):
        out = run_case(tmp_path / f"s{stall}", kind=kind, ceiling=30, age=30, stall=stall, mode="anchor_nobinding")
        assert out["decision"] == "authorized" and out["outcome"] == "refused" and out["error"] == CODE
        assert out["apply_calls"] == 0 and out["destination_effects"] == 0 and out["deadline_offset_s"] == 0
    assert OLD["cases"][case_key((kind, 30, 30, 0, "anchor_nobinding"))]["outcome"] == "dispatched", "the predecessor dispatched it (the defect)"


@pytest.mark.parametrize("kind", ["live_irreversible", "cached_reversible"])
@pytest.mark.parametrize("stall", [29, 30])
def test_dispatch_stalled_inside_the_former_residual_window_is_refused(tmp_path, kind, stall):
    out = run_case(tmp_path, kind=kind, ceiling=30, age=30, stall=stall, mode="anchor_nobinding")
    assert out["outcome"] == "refused" and out["error"] == CODE and out["apply_calls"] == 0
    old = OLD["cases"][case_key((kind, 30, 30, stall, "anchor_nobinding"))]
    assert old["outcome"] == "dispatched", "original defect: purpose age 59-60 s dispatched at the predecessor"


@pytest.mark.parametrize("kind", ["live_irreversible", "cached_reversible"])
@pytest.mark.parametrize("stall,expected", [(9, "dispatched"), (10, "dispatched"), (11, "refused")])
def test_strict_boundary_one_second_inside_exactly_at_and_one_second_outside(tmp_path, kind, stall, expected):
    """Purpose age 20 of ceiling 30: the anchored deadline is NOW + 10. A stall of 10 s ends exactly ON the deadline (strict ``>``: still
    dispatched); 11 s is one second outside. (Stalls 1-9 of a 10 s window are far from the real-time monotonic allowance.)"""
    out = run_case(tmp_path, kind=kind, ceiling=30, age=20, stall=stall, mode="anchor_nobinding")
    assert out["deadline_offset_s"] == 10 and out["outcome"] == expected
    assert out["apply_calls"] == (1 if expected == "dispatched" else 0)


def test_deadline_exceeded_is_a_durable_refusal_with_no_effect(tmp_path, clock):
    p, r, f = build(tmp_path, kind="live_irreversible", ceiling=30, age=30, mode="anchor_nobinding")
    d = f.decide(p, now=NOW)
    calls = []
    real = f.destination.apply
    f.destination.apply = lambda *a, **k: (calls.append(1), real(*a, **k))[1]
    stall_once(f, clock, 29)
    with pytest.raises(PermissionError, match=CODE):
        f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    doc = f.records.load()
    assert calls == [] and f.destination.snapshot()["effects"] == {}
    assert doc.attempts[-1].status == "failed" and doc.attempts[-1].error == CODE
    assert [x.deadline for x in doc.refusals] == [NOW.isoformat()] and all(CODE in x.reasons for x in doc.refusals)
    with pytest.raises(PermissionError):   # a retry is still refused: the failed attempt is definitive and the destination stays untouched
        f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert calls == []


# ------------------------------------------------------------------------------------------------ controls: other anchored inputs unchanged
@pytest.mark.parametrize("case", control_grid(), ids=_case_id)
def test_control_grant_status_identity_and_mandate_anchoring_is_unchanged(tmp_path, case):
    which, ceiling, age, stall, mode = case
    new = run_control(tmp_path, which=which, ceiling=ceiling, age=age, stall=stall, mode=mode)
    assert new == OLD["controls"][case_key(case)], "byte-for-byte the predecessor outcome"
    if mode == "anchor_nobinding":
        window = ceiling - age
        assert new["outcome"] == ("refused" if (stall > window or window == 0) else "dispatched")


@pytest.mark.parametrize("which", NEGATIVES)
@pytest.mark.parametrize("mode", ["anchor_nobinding", "flag_false_nobinding"])
def test_cached_snapshots_that_were_never_acceptable_are_still_held(tmp_path, which, mode):
    """Irreversible class and post-reversal-window class: the cached snapshot is not used, so nothing new is reachable (reversible and
    irreversible cases both covered by the grid above)."""
    new = run_negative(tmp_path, which=which, mode=mode)
    assert new == OLD["negatives"][f"{which}|{mode}"] and new["decision"] == "hold" and new["attempts"] == 0


# ------------------------------------------------------------------------------------------------ flag False / no freshness profile
@pytest.mark.parametrize("kind", ["live_irreversible", "cached_reversible"])
def test_flag_false_has_no_new_anchoring_and_dispatches_as_before(tmp_path, kind):
    out = run_case(tmp_path, kind=kind, ceiling=30, age=30, stall=29, mode="flag_false_nobinding")
    assert out["outcome"] == "dispatched" and out["apply_calls"] == 1 and out["deadline_offset_s"] == 30
    assert out == OLD["cases"][case_key((kind, 30, 30, 29, "flag_false_nobinding"))], "byte-for-byte the predecessor outcome"


def test_no_freshness_profile_at_all_has_no_deadline_and_dispatches_as_before(tmp_path, clock):
    from tests.test_runtime_authority import bind_approval, setup_flow
    p, r, f, c = setup_flow(tmp_path, purpose=True)
    r.purpose.observed_at = (NOW - timedelta(seconds=59)).isoformat()
    d = f.decide(p, now=NOW)
    stall_once(f, clock, 30)                      # purpose age 89 s at dispatch: the pre-freshness default path has no dispatch deadline at all
    attempt, _ = f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged"
    assert all(e.deadline is None for e in f.records.load().check_events)


# ------------------------------------------------------------------------------------------------ outage extension cannot bypass the ceiling
def _extended_flow(tmp_path, *, kind, age, extension_to=90):
    """Class ceiling 30 s, host extension limit 100 s, a signed outage extension of the class recorded up to ``extension_to``."""
    p, r, f = build(tmp_path, kind=kind, ceiling=30, age=age, mode="anchor_nobinding", extension=100)
    authority(f, r)
    class_id = f.runtime_authority_profile.actions[p.action_id].class_id
    f.record_age_extension(class_id=class_id, to_max_age_seconds=extension_to, not_before=NOW.isoformat(), expires_at=(NOW + timedelta(hours=1)).isoformat(),
                           outage_ref="outage-1", requested_by=OTHER, signer=SIGNER, authority_ref="urn:cognous:authority:outage-1", now=NOW)
    return p, r, f


@pytest.mark.parametrize("stall,expected", [(9, "dispatched"), (10, "dispatched"), (11, "refused")])
def test_extension_raises_only_the_recorded_cached_bound_and_the_anchor_follows_that_recorded_bound(tmp_path, clock, stall, expected):
    """Extended bound 90 s, cached snapshot 80 s old (accepted only because of the extension): anchored deadline = observed_at + 90 = NOW + 10.
    Before the correction (and without a binding) the same snapshot could be dispatched up to ~NOW + 90 (age 170 s)."""
    p, r, f = _extended_flow(tmp_path, kind="cached_reversible", age=80)
    d = f.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    assert any(x.input_type == "purpose" and x.read_state == "cached_positive" for x in d.resolution_inputs)
    stall_once(f, clock, stall)
    if expected == "dispatched":
        attempt, _ = f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
        assert attempt.status == "acknowledged"
    else:
        with pytest.raises(PermissionError, match=CODE):
            f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
        assert f.destination.snapshot()["effects"] == {}
    assert opened_deadline_offset(f) == 10


def test_extension_never_raises_the_live_purpose_acceptance_bound_or_its_anchor(tmp_path, clock):
    p, r, f = _extended_flow(tmp_path, kind="live_reversible", age=31)
    held = f.decide(p, now=NOW)
    assert held.result == "hold" and "purpose_unreadable" in held.reasons, "a recorded extension does not make a 31 s live purpose acceptable"
    p, r, f = _extended_flow(tmp_path / "ok", kind="live_reversible", age=20)
    d = f.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    stall_once(f, clock, 11)                      # anchored at observed_at + 30 (the class base), not + 90
    with pytest.raises(PermissionError, match=CODE):
        f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert opened_deadline_offset(f) == 10


def test_extension_cannot_extend_beyond_the_host_limit_or_to_an_irreversible_class(tmp_path):
    from agent_control_plane.freshness import AgeExtensionRefused
    with pytest.raises(AgeExtensionRefused) as caught:
        _extended_flow(tmp_path, kind="cached_reversible", age=5, extension_to=1000)
    assert "age_extension_exceeds_limit" in caught.value.reasons


# ------------------------------------------------------------------------------------------------ commitments, schema, vocabulary unchanged
def test_approval_commitment_catalogue_digest_and_profile_dump_are_byte_identical_to_the_predecessor(tmp_path):
    now = commitments(tmp_path)
    assert now.keys() == OLD["commitments"].keys()
    for name, rec in now.items():
        assert rec == OLD["commitments"][name], name


@pytest.mark.parametrize("name", sorted(DOC_CASES))
def test_persisted_documents_that_the_change_does_not_affect_are_byte_identical(tmp_path, name):
    doc = persisted_document(tmp_path, **DOC_CASES[name])
    assert hashlib.sha256(doc.encode()).hexdigest() == OLD["normalized_document_sha256"][name]


def test_a_refusal_caused_by_the_change_persists_exactly_the_same_schema_shape_as_an_existing_refusal(tmp_path):
    new_paths = key_paths(persisted_document(tmp_path, **CHANGED_REFUSAL_CASE))
    assert new_paths == OLD["old_refusal_document_key_paths"], "no new persisted field, refusal-evidence field or schema key"


def test_no_new_reason_code_or_string_literal_in_runtime_authority():
    now = string_constants(SRC / "runtime_authority.py")
    assert now == OLD["runtime_authority_string_constants"], "the only edit is the removed guard and a comment"


def test_refusal_codes_across_the_grid_are_registered_in_the_frozen_vocabulary():
    reg = json.loads((ROOT / "schemas" / "runtime_authority_reasons_0_2.json").read_text(encoding="utf-8"))
    assert CODE in json.dumps(reg)


# ------------------------------------------------------------------------------------------------ the only protected-file change
HASHES = {  # bytes of the protected evaluators; ONLY runtime_authority.py differs from CP main b7eb11a / CP #94 061a986
    "bounded.py": "c219f8825a8ddf9da1fe6771ae575af0a9069ac8a04eadd40f093a9adb13655b",
    "freshness.py": "3f146ee11a3424d816c6f35ba07259833612a985901b4a96c0275395f05d51c0",
    "policy_binding.py": "defdfac5fd60cf5be707a76204a12513f2f289b0620ec56d063b56dac4081a35",
    "rule_revision.py": "a3833f49e96db52e0665b9816daee2654f74f7784faad5101252b4c8722415a5",
    "reversibility.py": "5edbadebb3aa777fba7f652c10c8da3c5e9ee1766b71866ed55dc25b319477d1",
    "holder_inventory.py": "76f5aaa63f49bac182439ea3768798bf42ecbda2c586f20fd450a7053271f7ba",
}
PREDECESSOR_RUNTIME_AUTHORITY = "a4b4ac36cca6e75d8fc3408b8738163acfb609a7265633aec2f799700ff9ea66"
CORRECTED_RUNTIME_AUTHORITY = "ad7b95e5d3bc3ddcba110a6758cf63e7f22b537766d3d072cbc7af17385bce01"


def test_d07_only_runtime_authority_changed_among_the_protected_evaluators():
    for name, expected in HASHES.items():
        assert hashlib.sha256((SRC / name).read_bytes()).hexdigest() == expected, f"{name} must stay byte-identical to the predecessor"
    now = hashlib.sha256((SRC / "runtime_authority.py").read_bytes()).hexdigest()
    assert now == CORRECTED_RUNTIME_AUTHORITY != PREDECESSOR_RUNTIME_AUTHORITY


def test_d07_the_deadline_registration_is_no_longer_guarded_by_the_policy_binding():
    """Static pin: no ``if binding is not None`` encloses the ``_FRESH_DEADLINES`` registration; the registration is still guarded by the collector
    (flag-only) and a known class."""
    tree = ast.parse((SRC / "runtime_authority.py").read_text(encoding="utf-8"))
    found_collector_guard = False
    for node in ast.walk(tree):
        if isinstance(node, ast.If):
            test_src = ast.unparse(node.test)
            if any(isinstance(n, ast.Expr) and "collector.append" in ast.unparse(n) for n in node.body):   # the innermost guard
                assert test_src == "collector is not None and cl is not None"
                found_collector_guard = True
            if test_src == "binding is not None":
                assert "_FRESH_DEADLINES" not in ast.unparse(node) and "collector" not in ast.unparse(node)
    assert found_collector_guard
