"""operation-identity/0.1: opt-in identity join (component-local tests).

Synthetic fixtures only. The composed cross-component scenarios live in the qualification
suite (suites/operation-identity); these tests cover the control plane's own rules.

Provenance of "expected today" values (the default path, with the profile unset): the
legacy rows below were RUN on main 5f5ae03f before this change and are re-run here on every
test run; none is taken from code reading alone.
"""
import json
import threading

import pytest

import agent_control_plane.bounded as bounded
from agent_control_plane.bounded import (BoundedRunRecord, DefinitiveDestinationRejection,
                                         LocalRefundDestination, commitment)
from agent_control_plane.operation_identity import (OperationIdentityProfile, valid_operation_id)
from agent_control_plane.runtime_authority import RuntimeAuthorityProfile
from tests.test_bounded_authorization import ISSUER, NOW, PROFILE
from tests.test_runtime_authority import bind_approval, setup_flow

OPERATION = "op-order-100/refund-1"
IDENTITY = OperationIdentityProfile(resolver_id="synthetic-resolver", resolver_version="1")


@pytest.fixture(autouse=True)
def _clock(monkeypatch):
    monkeypatch.setattr(bounded, "_now", lambda: NOW)


def enable(r, f, cfg, *, operation_id=OPERATION):
    """Switch a setup_flow workflow to operation-identity/0.1 (host config + issuer-approved extension)."""
    cfg2 = cfg.model_copy(update={"operation_identity": IDENTITY})
    if operation_id is not None:
        r.contexts[PROFILE]["runtime_authority"]["operation_id"] = operation_id
    bind_approval(r, cfg2)
    f.runtime_authority_profile = cfg2.snapshot()
    return cfg2


def renew(r, cfg, revision):
    """The authority side publishes a new revision of the same grant (a renewal candidate)."""
    ctx = r.contexts[PROFILE]
    ctx["grant"]["revision"] = revision
    for status in r.statuses.values():
        status.revision = revision
    for approval in r.approvals.values():
        approval.grant_revision = revision
    bind_approval(r, cfg)


def two_effects_manifest(monkeypatch):
    """Raise the manifest effect limit to 2 (before setup_flow) so only identity can prevent a second effect.

    With the stock fixtures the cumulative cap is 1 per grant id and masks the duplicate; that value was
    RUN on main 5f5ae03f (see test_legacy_cap_of_one_masks_the_duplicate_today).
    """
    import tests.test_bounded_authorization as tba
    import tests.test_runtime_authority as tra
    original = tba.manifest

    def wide():
        m = original()
        for action in m["actions"]:
            action["effect_limits"]["max_effects"] = 2
        return m
    monkeypatch.setattr(tba, "manifest", wide)
    monkeypatch.setattr(tra, "manifest", wide)


def two_effects(r):
    ctx = r.contexts[PROFILE]
    ctx["requirement"]["permissions"][0]["max_effects"] = 2
    ctx["grant"]["permissions"][0]["max_effects"] = 2


def run_document(f):
    return json.loads(f.records.path.read_text(encoding="utf-8"))


# ---------------------------------------------------------------- default path unchanged
def test_default_path_has_no_identity_rows_and_profile_dump_is_unchanged(tmp_path):
    p, r, f, c = setup_flow(tmp_path)
    assert "operation_identity" not in c.model_dump(mode="json")
    d = f.decide(p, now=NOW)
    attempt, _ = f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    document = run_document(f)
    assert not {"operations", "operation_renewals", "attempt_joins"} & set(document)
    assert all("check_id" not in row for row in document["refusals"])
    assert f.destination.snapshot().keys() == {"effects", "grant_effect_counts"}
    resolution = BoundedRunRecord.model_validate(document).resolution_checks
    opened = {e["check_id"] for e in document["check_events"] if e["phase"] == "opened"}
    # Legacy today (ran): the ResolutionCheck mints its own uuid, so it shares no id with the journal.
    assert opened and not opened & {x.check_id for x in resolution}


def test_operation_id_in_extension_is_unsupported_without_the_profile(tmp_path):
    p, r, f, c = setup_flow(tmp_path)
    r.contexts[PROFILE]["runtime_authority"]["operation_id"] = OPERATION
    bind_approval(r, c)
    d = f.decide(p, now=NOW)
    assert d.result == "hold" and "runtime_authority_field_unsupported" in d.reasons


# ---------------------------------------------------------------- operation id comes from the issuer-approved extension
@pytest.mark.parametrize("value,code", [(None, "operation_id_missing"), ("has space", "operation_id_invalid"),
                                         ("", "operation_id_invalid"), (7, "operation_id_invalid")])
def test_profile_requires_a_wellformed_operation_id(tmp_path, value, code):
    p, r, f, c = setup_flow(tmp_path)
    enable(r, f, c, operation_id=None)
    if value is not None:
        r.contexts[PROFILE]["runtime_authority"]["operation_id"] = value
        bind_approval(r, f.runtime_authority_profile)
    d = f.decide(p, now=NOW)
    assert d.result == "hold" and code in d.reasons and not f.records.load().attempts
    assert not run_document(f).get("operations")
    assert valid_operation_id(OPERATION)


def test_planner_cannot_add_or_change_the_operation_id_after_approval(tmp_path):
    p, r, f, c = setup_flow(tmp_path)
    cfg = enable(r, f, c)
    r.contexts[PROFILE]["runtime_authority"]["operation_id"] = "op-someone-elses"  # no re-approval
    d = f.decide(p, now=NOW)
    assert d.result == "hold" and "runtime_authority_approval_mismatch" in d.reasons


# ---------------------------------------------------------------- one join record per attempt, joined by id
def test_attempt_joins_operation_check_and_attempt_by_id(tmp_path):
    p, r, f, c = setup_flow(tmp_path)
    enable(r, f, c)
    d = f.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    attempt, observation = f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    record = f.records.load()
    (join,) = record.attempt_joins
    effect_open = [e for e in record.check_events if e.phase == "opened" and e.stage == "effect"]
    effect_check = [x for x in record.resolution_checks if x.stage == "effect"]
    assert len(effect_open) == len(effect_check) == 1
    assert join.check_id == effect_open[0].check_id == effect_check[0].check_id
    assert join.attempt_id == attempt.attempt_id and join.effect_id == d.effect_id
    assert join.operation_id == OPERATION and join.decision_id == d.decision_id
    assert (join.resolver_id, join.resolver_version, join.class_max_age) == ("synthetic-resolver", "1", 60)
    assert join.merged_into is None and join.expected_effective_grant_digest is None
    assert [row["operation_id"] for row in run_document(f)["operations"]] == [OPERATION]
    # decision-stage check also shares its id across journal and ResolutionCheck
    decision_open = next(e for e in record.check_events if e.phase == "opened" and e.stage == "decision")
    assert decision_open.check_id in {x.check_id for x in record.resolution_checks if x.stage == "decision"}
    assert f.destination.snapshot()["operations"] == {OPERATION: d.effect_id}


def test_join_row_is_written_before_the_attempt_and_once_per_attempt(tmp_path, monkeypatch):
    p, r, f, c = setup_flow(tmp_path)
    enable(r, f, c)
    d = f.decide(p, now=NOW)
    seen = []
    original = f.records.append_attempt

    def spy(value):
        seen.append((value.status, [j.attempt_id for j in f.records.load().attempt_joins]))
        return original(value)
    monkeypatch.setattr(f.records, "append_attempt", spy)
    attempt, _ = f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert seen and all(attempt.attempt_id in joined for _, joined in seen)  # join precedes every attempt row
    assert [j.attempt_id for j in f.records.load().attempt_joins] == [attempt.attempt_id]


def test_dispatch_is_refused_when_the_destination_cannot_dedupe_on_operation_id(tmp_path):
    p, r, f, c = setup_flow(tmp_path)
    enable(r, f, c)
    d = f.decide(p, now=NOW)

    class Legacy:
        def observe(self, *a, **k): return f.destination.observe(*a, **k)
    f.destination = Legacy()
    with pytest.raises(PermissionError, match="operation_identity_capability_unavailable"):
        f.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert not f.records.load().attempts and not run_document(f).get("attempt_joins")


# ---------------------------------------------------------------- renewal rules
def renewal_rows(f):
    return [x.model_dump() for x in f.records.load().operation_renewals]


def test_only_the_grant_issuer_writes_a_renewal_and_a_worker_attempt_is_refused_and_recorded(tmp_path):
    p, r, f, c = setup_flow(tmp_path)
    cfg = enable(r, f, c)
    d1 = f.decide(p, now=NOW)
    assert d1.result == "authorized"
    with pytest.raises(PermissionError, match="renewal_not_written_by_grant_issuer"):
        f.record_renewal(OPERATION, to_revision="2", written_by=p.actor, now=NOW)
    (refused,) = renewal_rows(f)
    assert (refused["outcome"], refused["refusal_code"], refused["written_by"]) == (
        "refused", "renewal_not_written_by_grant_issuer", p.actor)
    # the grant moved to revision 2 but no accepted renewal names the operation: held, not licensed
    renew(r, cfg, "2")
    d2 = f.decide(p, now=NOW)
    assert d2.result == "hold" and "operation_renewal_unrecorded" in d2.reasons
    assert f.destination.snapshot()["effects"] == {}
    row = f.record_renewal(OPERATION, to_revision="2", written_by=ISSUER, now=NOW)
    assert (row.outcome, row.from_revision, row.to_revision, row.grant_id) == (
        "accepted", "1", "2", d1.binding.grant_id)
    d3 = f.decide(p, now=NOW)
    assert d3.result == "authorized" and d3.effect_id != d1.effect_id  # legacy effect_id still changes per revision


@pytest.mark.parametrize("operation,revision,code", [("unknown-op", "2", "operation_not_admitted"),
                                                      (OPERATION, "1", "renewal_revision_not_new")])
def test_renewal_of_unknown_operation_or_non_new_revision_is_refused_and_recorded(tmp_path, operation, revision, code):
    p, r, f, c = setup_flow(tmp_path)
    enable(r, f, c)
    f.decide(p, now=NOW)
    with pytest.raises(PermissionError, match=code):
        f.record_renewal(operation, to_revision=revision, written_by=ISSUER, now=NOW)
    assert renewal_rows(f)[-1]["refusal_code"] == code


def test_renewal_requires_the_profile(tmp_path):
    p, r, f, c = setup_flow(tmp_path)
    with pytest.raises(PermissionError, match="not enabled"):
        f.record_renewal(OPERATION, to_revision="2", written_by=ISSUER, now=NOW)


def test_operation_id_cannot_move_to_another_grant(tmp_path):
    p, r, f, c = setup_flow(tmp_path)
    cfg = enable(r, f, c)
    assert f.decide(p, now=NOW).result == "authorized"
    # same id, different grant: a collision, never a silent continuation
    document = run_document(f)
    document["operations"][0]["grant_id"] = "urn:cognous:grant:other"
    f.records._write(document)
    d = f.decide(p, now=NOW)
    assert d.result == "hold" and "operation_grant_mismatch" in d.reasons


# ---------------------------------------------------------------- destination dedupe on the operation id
class DelayedCommit(LocalRefundDestination):
    """MINIMAL IN-TEST delayed-commit destination (stand-in for the later CI delayed-commit mode)."""

    def __init__(self, path):
        super().__init__(path)
        self.entered, self.release = threading.Event(), threading.Event()
        self.hold_first = True

    def apply(self, **kwargs):
        if self.hold_first:
            self.hold_first = False
            self.entered.set()
            assert self.release.wait(10)
        return super().apply(**kwargs)


def delayed_renewal_flow(tmp_path, *, identity, wide=True, monkeypatch=None):
    if wide:
        two_effects_manifest(monkeypatch)
    p, r, f, c = setup_flow(tmp_path)
    if wide:
        two_effects(r)
    cfg = enable(r, f, c) if identity else c
    f.destination = DelayedCommit(tmp_path / "delayed.json")
    d1 = f.decide(p, now=NOW)
    assert d1.result == "authorized", d1.reasons
    outcome = {}

    def first():
        try:
            outcome["r1"] = f.execute(p, d1, adapter_id=p.adapter_id, now=NOW)
        except Exception as exc:  # recorded for the assertions
            outcome["r1_error"] = exc
    thread = threading.Thread(target=first)
    thread.start()
    assert f.destination.entered.wait(10)  # r1 passed its check and is now inside the destination
    renew(r, cfg, "2")
    if identity:
        f.record_renewal(OPERATION, to_revision="2", written_by=ISSUER, now=NOW)
    d2 = f.decide(p, now=NOW)
    assert d2.result == "authorized", d2.reasons
    outcome["r2"] = f.execute(p, d2, adapter_id=p.adapter_id, now=NOW)
    f.destination.release.set()
    thread.join(10)
    assert not thread.is_alive()
    return f, d1, d2, outcome


def test_legacy_cap_of_one_masks_the_duplicate_today(tmp_path):
    # Expected today (ran on main 5f5ae03f): the per-grant cap of 1 is the only thing that stops r1.
    f, d1, d2, outcome = delayed_renewal_flow(tmp_path, identity=False, wide=False)
    assert d1.effect_id != d2.effect_id
    assert set(f.destination.snapshot()["effects"]) == {d2.effect_id}
    assert isinstance(outcome.get("r1_error"), Exception) or outcome["r1"][0].error == "cumulative_grant_max_effects_exhausted"


def test_legacy_delayed_r1_after_renewal_commits_a_second_effect_when_the_cap_allows_it(tmp_path, monkeypatch):
    # Expected today (ran on main 5f5ae03f): two effect ids, two effects.
    f, d1, d2, outcome = delayed_renewal_flow(tmp_path, identity=False, monkeypatch=monkeypatch)
    assert d1.effect_id != d2.effect_id
    assert set(f.destination.snapshot()["effects"]) == {d1.effect_id, d2.effect_id}


def test_delayed_r1_after_renewal_commits_a_single_effect_under_the_profile(tmp_path, monkeypatch):
    f, d1, d2, outcome = delayed_renewal_flow(tmp_path, identity=True, monkeypatch=monkeypatch)
    state = f.destination.snapshot()
    assert set(state["effects"]) == {d2.effect_id}, "second effect for the same operation"
    assert state["operations"] == {OPERATION: d2.effect_id}
    record = f.records.load()
    attempts = {}
    for item in record.attempts:
        attempts[item.attempt_id] = item
    by_effect = {a.effect_id: a for a in attempts.values()}
    assert by_effect[d2.effect_id].status == "acknowledged"
    assert by_effect[d1.effect_id].status == "failed" and by_effect[d1.effect_id].error == "operation_already_committed"
    joins = {j.attempt_id: j for j in record.attempt_joins}
    assert set(joins) == set(attempts) and len(joins) == 2
    assert {j.operation_id for j in joins.values()} == {OPERATION}
    assert {j.effect_id for j in joins.values()} == {d1.effect_id, d2.effect_id}
    # each join's check is the journal check that licensed that attempt, matched by id
    opened = {e.check_id: e for e in record.check_events if e.phase == "opened" and e.stage == "effect"}
    for join in joins.values():
        assert opened[join.check_id].effect_id == join.effect_id
        assert any(x.check_id == join.check_id and x.stage == "effect" for x in record.resolution_checks)
    assert len({j.check_id for j in joins.values()}) == 2
    assert {j.grant_revision for j in joins.values()} == {"1", "2"}


def test_local_destination_operation_dedupe_is_keyed_on_operation_id_only_when_supplied(tmp_path):
    dest = LocalRefundDestination(tmp_path / "d.json")
    args = dict(grant_id="g", max_effects=5, target="t", amount=1.0, unit="USD", payload={})
    dest.apply(effect_id="e1", **args)
    dest.apply(effect_id="e2", **args)  # legacy: no operation id, two effects
    dest.apply(effect_id="e3", operation_id="op", **args)
    with pytest.raises(DefinitiveDestinationRejection, match="operation_already_committed"):
        dest.apply(effect_id="e4", operation_id="op", **args)
    assert dest.apply(effect_id="e3", operation_id="op", **args)["duplicate"] is True  # same effect id: legacy duplicate
    assert set(dest.snapshot()["effects"]) == {"e1", "e2", "e3"}
