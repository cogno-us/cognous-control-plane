"""Producer conformance: execution-attempt lifecycle contract (ODES, 0.1.0-draft).

Role: producer (Control Plane bounded workflow), level P (structure, rules and a real producer run).

The vendored contract lives in tests/contracts/execution-attempt-lifecycle. Real records are produced by
running ``bounded.py`` on synthetic proposals, mapped into contract documents, and checked with the
vendored ``validate.py``. Negative controls plant each defect the contract names for this side and
assert the vendored validator refuses it, which shows this suite can fail.
"""
from __future__ import annotations

import copy
import hashlib
import importlib.util
import json
import shutil
import sys
import threading
from pathlib import Path

import pytest

from agent_control_plane.bounded import (
    BoundedAuthorizationWorkflow,
    BoundedRecordStore,
    LocalRefundDestination,
    ObservationPolicy,
)
from tests.test_bounded_authorization import NOW, manifest, proposal
from tests.test_runtime_authority import setup_flow

CONTRACT_DIR = Path(__file__).parent / "contracts" / "execution-attempt-lifecycle"
CONTRACT_ID = "execution-attempt-lifecycle"
CONTRACT_VERSION = "0.1.0-draft"


# --------------------------------------------------------------------------- vendored contract

def verify_contract_dir(root: Path) -> list[str]:
    """Return drift findings: modified, missing or unlisted files (SHA-256 against CONTRACT.json)."""
    findings: list[str] = []
    listed = json.loads((root / "CONTRACT.json").read_text(encoding="utf-8"))["files"]
    for rel, digest in sorted(listed.items()):
        path = root / rel
        if not path.is_file():
            findings.append(f"missing: {rel}")
        elif hashlib.sha256(path.read_bytes()).hexdigest() != digest:
            findings.append(f"modified: {rel}")
    for path in sorted(root.rglob("*")):
        if not path.is_file() or "__pycache__" in path.parts or path.suffix == ".pyc":
            continue
        rel = path.relative_to(root).as_posix()
        if rel != "CONTRACT.json" and rel not in listed:
            findings.append(f"unlisted: {rel}")
    return findings


def _load_validator():
    spec = importlib.util.spec_from_file_location("eal_contract_validate", CONTRACT_DIR / "validate.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module  # validate.py defines a dataclass; register before exec
    spec.loader.exec_module(module)
    return module


VALIDATOR = _load_validator()


def codes(doc) -> list[str]:
    return [v.code for v in VALIDATOR.validate(doc)]


def test_vendored_contract_identity():
    meta = json.loads((CONTRACT_DIR / "CONTRACT.json").read_text(encoding="utf-8"))
    assert meta["contract"] == CONTRACT_ID
    assert meta["contract_version"] == CONTRACT_VERSION
    assert meta["role"] == "producer"
    assert meta["conformance_level"] == "P"
    assert meta["odes_commit"] == "e5fe3822a2d3c3f6885fd61acccb4bb6281041be"
    assert VALIDATOR.CONTRACT == CONTRACT_ID and VALIDATOR.CONTRACT_VERSION == CONTRACT_VERSION


def test_vendored_copy_has_no_drift():
    assert verify_contract_dir(CONTRACT_DIR) == []


@pytest.mark.parametrize("mutation", ["modify", "delete", "add"])
def test_drift_check_can_fail(tmp_path, mutation):
    root = tmp_path / "copy"
    shutil.copytree(CONTRACT_DIR, root, ignore=shutil.ignore_patterns("__pycache__"))
    assert verify_contract_dir(root) == []
    if mutation == "modify":
        (root / "schema.json").write_text((root / "schema.json").read_text() + " ", encoding="utf-8")
        expected = "modified: schema.json"
    elif mutation == "delete":
        (root / "validate.py").unlink()
        expected = "missing: validate.py"
    else:
        (root / "extra.json").write_text("{}", encoding="utf-8")
        expected = "unlisted: extra.json"
    assert expected in verify_contract_dir(root)


def test_vendored_fixtures_behave_as_declared():
    """Sanity: the vendored validator accepts its valid fixtures and refuses its invalid ones."""
    for path in sorted((CONTRACT_DIR / "fixtures" / "valid").glob("*.json")):
        fixture = json.loads(path.read_text(encoding="utf-8"))
        assert codes(fixture["document"]) == [], path.name
    for path in sorted((CONTRACT_DIR / "fixtures" / "invalid").glob("*.json")):
        fixture = json.loads(path.read_text(encoding="utf-8"))
        assert codes(fixture["document"]) == [fixture["expected_refusal"]], path.name


# --------------------------------------------------------------------------- real runs -> documents

@pytest.fixture(autouse=True)
def _fixed_synthetic_clock(monkeypatch):
    import agent_control_plane.bounded as bounded_module
    monkeypatch.setattr(bounded_module, "_now", lambda: NOW)


def to_document(records_path: Path) -> dict:
    """Map the persisted bounded-workflow record into a contract document (producer control-plane)."""
    raw = json.loads(Path(records_path).read_text(encoding="utf-8"))
    doc: dict = {"contract": CONTRACT_ID, "contract_version": CONTRACT_VERSION, "producer": "control-plane"}
    if raw.get("attempts"):
        doc["control_plane_attempts"] = raw["attempts"]
    if raw.get("check_events"):
        doc["resolution_journal"] = raw["check_events"]
    if raw.get("resolution_checks"):
        doc["resolution_checks"] = raw["resolution_checks"]
    return doc


def statuses(doc) -> list[str]:
    return [row["status"] for row in doc.get("control_plane_attempts", [])]


def restart(f, r, cfg):
    return BoundedAuthorizationWorkflow(
        allow_test_time=True, manifest=manifest(), resolver=r,
        destination=LocalRefundDestination(f.destination.path),
        records=BoundedRecordStore(f.records.path, "run-1"),
        observation_policy=ObservationPolicy(max_age_seconds=300, clock_tolerance_seconds=5),
        runtime_authority_profile=cfg,
    )


def run_normal(tmp_path):
    p, r, f, cfg = setup_flow(tmp_path)
    d = f.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    attempt, obs = f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "acknowledged" and obs.state == "applied"
    return p, r, f, cfg, d


def test_normal_attempted_acknowledged_lifecycle(tmp_path):
    *_, f, _cfg, _d = run_normal(tmp_path)
    doc = to_document(f.records.path)
    assert statuses(doc) == ["attempted", "acknowledged"]
    assert codes(doc) == []


def test_normal_run_sequential_checks_and_journal(tmp_path):
    """decide then execute: two journal checks that do not overlap, listed in journal order."""
    *_, f, _cfg, _d = run_normal(tmp_path)
    doc = to_document(f.records.path)
    assert [c["stage"] for c in doc["resolution_checks"]] == ["decision", "effect"]
    assert [e["phase"] for e in doc["resolution_journal"]].count("completed") == 2
    assert codes(doc) == []


def test_failed_attempt_lifecycle(tmp_path):
    p, r, f, cfg = setup_flow(tmp_path)
    d = f.decide(p, now=NOW)
    # Exhaust the cumulative grant cap at the destination so dispatch is definitively rejected.
    from agent_control_plane.bounded import DefinitiveDestinationRejection

    def reject(**kwargs):
        raise DefinitiveDestinationRejection("synthetic_definitive_rejection")

    f.destination.apply = reject
    attempt, _ = f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert attempt.status == "failed"
    doc = to_document(f.records.path)
    assert statuses(doc) == ["attempted", "failed"]
    assert codes(doc) == []


def test_partial_dispatch_lifecycle(tmp_path):
    p, r, f, cfg = setup_flow(tmp_path)
    d = f.decide(p, now=NOW)
    attempt, obs = f.execute(p, d, adapter_id=p.adapter_id, now=NOW, partial=True)
    assert attempt.status == "partial" and obs.state == "partial"
    doc = to_document(f.records.path)
    assert statuses(doc) == ["attempted", "partial"]
    assert codes(doc) == []


def test_uncertain_attempt_lifecycle_and_closeout(tmp_path):
    """Lost acknowledgement: attempted then unknown. The later reconcile appends a closeout."""
    p, r, f, cfg = setup_flow(tmp_path)
    d = f.decide(p, now=NOW)
    attempt, obs = f.execute(p, d, adapter_id=p.adapter_id, now=NOW, lose_ack=True)
    assert attempt.status == "unknown" and obs.state == "applied"
    before = to_document(f.records.path)
    assert statuses(before) == ["attempted", "unknown"]
    assert codes(before) == []

    assert restart(f, r, cfg).reconcile(d.effect_id, now=NOW).result == "applied"
    raw = json.loads(f.records.path.read_text(encoding="utf-8"))
    assert [c["original_status"] for c in raw["closeouts"]] == ["unknown"]
    after = to_document(f.records.path)
    # The closeout is a separate append-only record: it never rewrites the attempt rows. The contract
    # has no member for closeouts (README, known gaps), so only the attempt rows are in scope.
    assert after["control_plane_attempts"] == before["control_plane_attempts"]
    assert "closeouts" not in after and codes(after) == []


def test_reconciled_existing_acknowledged_single_record(tmp_path):
    p, r, f, cfg = setup_flow(tmp_path)
    d = f.decide(p, now=NOW)
    first, _ = f.execute(p, d, adapter_id=p.adapter_id, now=NOW, lose_ack=True)
    assert first.status == "unknown"
    again = restart(f, r, cfg)
    retry, obs = again.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert retry.status == "acknowledged" and retry.acknowledgement == {"reconciled_existing": True}
    doc = to_document(f.records.path)
    assert statuses(doc) == ["attempted", "unknown", "acknowledged"]
    single = [row for row in doc["control_plane_attempts"] if row["attempt_id"] == retry.attempt_id]
    assert len(single) == 1 and single[0]["acknowledgement"] == {"reconciled_existing": True}
    assert codes(doc) == []


def test_reconciled_existing_partial_single_record(tmp_path):
    p, r, f, cfg = setup_flow(tmp_path)
    d = f.decide(p, now=NOW)
    first, _ = f.execute(p, d, adapter_id=p.adapter_id, now=NOW, partial=True)
    assert first.status == "partial"
    retry, obs = f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert retry.status == "partial" and retry.acknowledgement == {"reconciled_existing": True}
    doc = to_document(f.records.path)
    assert statuses(doc) == ["attempted", "partial", "partial"]
    single = [row for row in doc["control_plane_attempts"] if row["attempt_id"] == retry.attempt_id]
    assert len(single) == 1
    assert codes(doc) == []


def test_effect_time_refusal_produces_no_lifecycle_rows(tmp_path):
    """A refusal is not an attempt: no control_plane_attempts rows, but the journal and checks conform."""
    p, r, f, cfg = setup_flow(tmp_path)
    d = f.decide(p, now=NOW)
    r.grant_status = lambda ref: None
    with pytest.raises(PermissionError):
        f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    raw = json.loads(f.records.path.read_text(encoding="utf-8"))
    assert raw["refusals"] and not raw["attempts"]
    doc = to_document(f.records.path)
    assert "control_plane_attempts" not in doc
    assert [c["stage"] for c in doc["resolution_checks"]] == ["decision", "effect"]
    assert codes(doc) == []


# --------------------------------------------------------------------------- overlapping checks

def _overlap_run(tmp_path, *, complete_first: str, list_first: str) -> dict:
    """Two real decisions on one shared record, overlapped on threads, with scripted ordering.

    Both journal checks open before either completes. ``complete_first`` is the check whose journal
    completion is written first; ``list_first`` is the check whose resolution check row is appended
    first. Gates sit at the first resolver read (inside open..complete) and at
    ``record_resolution_check`` (after completion).
    """
    pa, ra, fa, cfg = setup_flow(tmp_path / "a")
    pb, rb, fb, _ = setup_flow(tmp_path / "b")
    pb = pb.model_copy(update={"correlation_id": "case-b"})
    # Distinct policy version so the two checks bind to different resolution checks by content.
    next(iter(rb.policies.values())).version = "policy-b"
    store = fa.records
    fb.records = store
    flows = {"A": (fa, pa), "B": (fb, pb)}
    resolvers = {"A": ra, "B": rb}

    read_started = {k: threading.Event() for k in flows}
    release_read = {k: threading.Event() for k in flows}
    completed = {k: threading.Event() for k in flows}
    release_record = {k: threading.Event() for k in flows}
    recorded = {k: threading.Event() for k in flows}
    local = threading.local()

    for key, resolver in resolvers.items():
        original = resolver.grant_status

        def gated(ref, _key=key, _orig=original):
            if not read_started[_key].is_set():
                read_started[_key].set()
                assert release_read[_key].wait(30)
            return _orig(ref)

        resolver.grant_status = gated

    orig_event = store.append_check_event
    orig_record = store.record_resolution_check

    def append_event(event):
        orig_event(event)
        if event.phase == "completed":
            completed[local.key].set()

    def record(**kwargs):
        assert release_record[local.key].wait(30)
        result = orig_record(**kwargs)
        recorded[local.key].set()
        return result

    store.append_check_event = append_event
    store.record_resolution_check = record

    errors: list[BaseException] = []

    def work(key):
        local.key = key
        flow, prop = flows[key]
        try:
            flow.decide(prop, now=NOW)
        except BaseException as exc:  # surfaced below
            errors.append(exc)

    threads = {k: threading.Thread(target=work, args=(k,), name=f"decide-{k}") for k in flows}
    second = "B" if complete_first == "A" else "A"
    for key in ("A", "B"):
        threads[key].start()
        assert read_started[key].wait(30)
    release_read[complete_first].set()
    assert completed[complete_first].wait(30)
    release_read[second].set()
    assert completed[second].wait(30)
    other = "B" if list_first == "A" else "A"
    release_record[list_first].set()
    assert recorded[list_first].wait(30)
    release_record[other].set()
    for t in threads.values():
        t.join(30)
        assert not t.is_alive()
    assert errors == []
    return to_document(store.path)


def _journal_shape(doc):
    """(check order of openings, order of completions) as journal indices, to prove real overlap."""
    opened, closed = {}, {}
    for seq, event in enumerate(doc["resolution_journal"]):
        (opened if event["phase"] == "opened" else closed if event["phase"] == "completed" else {})[
            event["check_id"]] = seq
    return opened, closed


@pytest.mark.parametrize(
    ("complete_first", "list_first"),
    [("A", "A"), ("A", "B"), ("B", "B"), ("B", "A")],
    ids=["a-completes-first-listed-a-first", "a-completes-first-listed-b-first",
         "b-completes-first-listed-b-first", "b-completes-first-listed-a-first"],
)
def test_overlapping_resolution_checks_any_completion_and_listing_order(tmp_path, complete_first, list_first):
    doc = _overlap_run(tmp_path, complete_first=complete_first, list_first=list_first)
    opened, closed = _journal_shape(doc)
    assert len(opened) == 2 and len(closed) == 2
    assert max(opened.values()) < min(closed.values()), "checks did not overlap in the journal"
    assert len(doc["resolution_checks"]) == 2
    assert codes(doc) == []


# --------------------------------------------------------------------------- negative controls

@pytest.fixture
def real_lifecycle_doc(tmp_path):
    *_, f, _cfg, _d = run_normal(tmp_path)
    doc = to_document(f.records.path)
    assert codes(doc) == []
    return doc


def test_negative_dropped_start_record(real_lifecycle_doc):
    doc = copy.deepcopy(real_lifecycle_doc)
    assert doc["control_plane_attempts"][0]["status"] == "attempted"
    del doc["control_plane_attempts"][0]
    assert codes(doc) == ["missing_start_record"]


def test_negative_reconciled_existing_false_on_start_row(real_lifecycle_doc):
    doc = copy.deepcopy(real_lifecycle_doc)
    doc["control_plane_attempts"][0]["acknowledgement"] = {"reconciled_existing": False}
    assert codes(doc) == ["invalid_reconciled_marker"]


def test_negative_sequential_reorder(real_lifecycle_doc):
    doc = copy.deepcopy(real_lifecycle_doc)
    assert [c["stage"] for c in doc["resolution_checks"]] == ["decision", "effect"]
    doc["resolution_checks"].reverse()
    assert codes(doc) == ["resolution_checks_out_of_order"]
