"""freshness/0.1: opt-in three clocks, deadline at opening, overdue state, reaper, nonce-bound age basis, authorised age extension.

Synthetic fixtures only. The composed cross-component scenarios live in the qualification suite (suites/operation-identity,
test_freshness_profile.py); these tests cover the control plane's own rules.

Provenance of "expected today" values (default path, profile unset): the `*_today` rows were RUN on main 83b49b5 before this
change and are re-run on every test run. Nothing here is taken from code reading alone.
"""
import json
import os
import threading
from datetime import timedelta

import pytest

import agent_control_plane.bounded as bounded
from agent_control_plane.bounded import BoundedRunRecord, CheckEvent, _process_owner, commitment
from agent_control_plane.freshness import (
    AgeBoundExtension, AgeExtensionRefused, CheckLeaseUnavailable, FreshnessProfile, NONCE_CAPABILITY, Reaper, freshness_counts,
)
from agent_control_plane.reason_vocabulary import refusal_trends
from agent_control_plane.rule_revision import RuleRevision, RuleRevisionProfile, append_rule_revision
from tests.test_bounded_authorization import NOW, POLICY_REF, PROFILE
from tests.test_runtime_authority import bind_approval, setup_flow

REGISTRY = json.loads((__import__("pathlib").Path(__file__).resolve().parents[1] / "schemas"
                       / "runtime_authority_reasons_0_1.json").read_text(encoding="utf-8"))
SIGNER, OTHER = "urn:cognous:principal:rule-signer", "urn:cognous:principal:requester"
POLICY_SIGNER = "urn:cognous:principal:policy-signer"
POLICY_DIGEST = commitment({"policy": "v1"})


class Clock:
    def __init__(self):
        self.now = NOW

    def __call__(self):
        return self.now

    def tick(self, seconds):
        self.now = self.now + timedelta(seconds=seconds)


@pytest.fixture
def clock(monkeypatch):
    c = Clock()
    monkeypatch.setattr(bounded, "_now", c)
    return c


def enable(r, f, cfg, **options):
    """Switch a setup_flow workflow to freshness/0.1 (host config; the approval commitment covers it)."""
    cfg2 = cfg.model_copy(update={"freshness": FreshnessProfile(**options)})
    bind_approval(r, cfg2)
    f.runtime_authority_profile = cfg2.snapshot()
    return cfg2


def authority(f, r, signers=(SIGNER, POLICY_SIGNER)):
    """Configure the N2 rule-revision signer set (reused by age extensions) and adopt the fixture policy so decisions pass."""
    r.policies[POLICY_REF].digest = POLICY_DIGEST
    f.rule_revision_profile = RuleRevisionProfile(signers=list(signers))
    append_rule_revision(f.records, f.rule_revision_profile, RuleRevision(
        revision_id="adopt-1", rule_kind="policy", rule_ref=POLICY_REF, from_digest=None, to_digest=POLICY_DIGEST,
        reviser=OTHER, signer=POLICY_SIGNER, authority_ref="synthetic-authority:1", reason="synthetic",
        recorded_at=NOW.isoformat()))


def document(f):
    return json.loads(f.records.path.read_text(encoding="utf-8"))


def execute(f, p, d, now=NOW):
    return f.execute(p, d, adapter_id=p.adapter_id, now=now)


# ------------------------------------------------------------------------------------------------ default path
def test_default_path_adds_no_clock_or_freshness_keys(tmp_path, clock):
    p, r, f, c = setup_flow(tmp_path)
    assert "freshness" not in c.model_dump(mode="json")
    d = f.decide(p, now=NOW)
    execute(f, p, d)
    doc = document(f)
    assert not {"age_extensions", "age_extension_refusals", "recovery_runs"} & set(doc)
    new_keys = {"evaluated_at", "deadline", "age_bound_seconds", "extension_id", "nonce"}
    assert all(not new_keys & set(e) for e in doc["check_events"])
    assert all("age_basis" not in i for ch in doc["resolution_checks"] for i in ch["inputs"])
    assert all("recorded_at" not in ch for ch in doc["resolution_checks"])
    assert all("evaluated_at" not in x and "recorded_at" not in x for x in doc["decisions"] + doc["attempts"])
    assert len({e["recorded_at"] for e in doc["check_events"]}) == 1, "today (ran): every journal event reuses the evaluation time"


def test_default_path_stalled_check_is_dispatched_today(tmp_path, clock):
    """Expected today (ran): a check stalled 61 s past its 60 s class bound before dispatch still reaches the destination,
    when the destination observation is stamped by the checked party and does not follow the service clock."""
    p, r, f, c = setup_flow(tmp_path)
    d = f.decide(p, now=NOW)
    stall_before_dispatch(f, clock, 61, pin_observation=True)
    attempt, _ = execute(f, p, d)
    assert attempt.status == "acknowledged" and list(f.destination.snapshot()["effects"]) == [d.effect_id]
    assert not f.records.load().refusals


# ------------------------------------------------------------------------------------------------ three clocks
def test_each_journal_event_is_stamped_at_write_not_at_evaluation(tmp_path, clock):
    p, r, f, c = setup_flow(tmp_path)
    enable(r, f, c)
    original = r.identity_status

    def slow_identity(*a):
        clock.tick(7)  # the read takes wall time
        return original(*a)
    r.identity_status = slow_identity
    d = f.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    events = [e for e in f.records.load().check_events if e.stage == "decision"]
    stamps = [e.recorded_at for e in events]
    assert stamps == sorted(stamps) and len(set(stamps)) > 1, "recorded_at follows the service clock, write by write"
    assert {e.evaluated_at for e in events} == {NOW.isoformat()}, "evaluated_at is the one evaluation pass"
    assert events[-1].phase == "completed" and events[-1].recorded_at == (NOW + timedelta(seconds=7)).isoformat()
    assert d.decided_at == NOW.isoformat() and d.evaluated_at == NOW.isoformat() and d.recorded_at >= events[-1].recorded_at
    checks = f.records.load().resolution_checks
    assert checks[0].evaluated_at == NOW.isoformat() and checks[0].recorded_at == (NOW + timedelta(seconds=7)).isoformat()


def test_attempt_refusal_and_join_rows_carry_the_three_clocks(tmp_path, clock):
    p, r, f, c = setup_flow(tmp_path)
    enable(r, f, c)
    d = f.decide(p, now=NOW)
    clock.tick(3)
    execute(f, p, d)
    rows = f.records.load().attempts
    assert len(rows) == 2 and all(x.evaluated_at == NOW.isoformat() and x.started_at == NOW.isoformat() for x in rows)
    assert all(x.recorded_at == (NOW + timedelta(seconds=3)).isoformat() for x in rows)
    next(iter(r.statuses.values())).status = "revoked"
    clock.tick(5)
    d2 = f.decide(p, now=NOW)
    assert d2.result == "hold"


# ------------------------------------------------------------------------------------------------ deadline at opening
def test_check_carries_deadline_opened_at_plus_class_bound(tmp_path, clock):
    p, r, f, c = setup_flow(tmp_path)
    enable(r, f, c)
    clock.tick(2)
    f.decide(p, now=NOW)
    opened = next(e for e in f.records.load().check_events if e.phase == "opened")
    assert opened.recorded_at == (NOW + timedelta(seconds=2)).isoformat()
    assert opened.age_bound_seconds == 60 and opened.deadline == (NOW + timedelta(seconds=62)).isoformat()
    assert opened.nonce and opened.extension_id is None


def stall_before_dispatch(f, clock, seconds, *, pin_observation=False):
    """r1 passes its effect check, then stalls (here: inside the destination observation) before dispatch.

    ``pin_observation`` stamps the observation at the evaluation time (the checked party's own clock, not the service clock),
    isolating the deadline from the observation-time rules; otherwise the destination stamps it with the live service clock."""
    original = f.destination.observe
    pinned = clock.now

    def stalled(effect_id):
        clock.tick(seconds)
        observation = original(effect_id)
        return observation.model_copy(update={"observed_at": pinned.isoformat()}) if pin_observation else observation
    f.destination.observe = stalled
    return original


def test_stalled_check_past_class_bound_is_refused_before_dispatch(tmp_path, clock):
    p, r, f, c = setup_flow(tmp_path)
    enable(r, f, c)
    d = f.decide(p, now=NOW)
    stall_before_dispatch(f, clock, 61, pin_observation=True)
    with pytest.raises(PermissionError, match="check_expired_before_dispatch"):
        execute(f, p, d)
    rec = f.records.load()
    assert f.destination.snapshot()["effects"] == {}, "nothing reached the destination"
    (row,) = [x for x in rec.refusals if "check_expired_before_dispatch" in x.reasons]
    assert row.effect_id == d.effect_id and row.check_id and row.deadline
    assert row.recorded_at > row.deadline and row.evaluated_at == NOW.isoformat()
    events = [e for e in rec.check_events if e.check_id == row.check_id]
    assert [e.phase for e in events][-2:] == ["completed", "expired"] and events[-1].reasons == ["check_expired_before_dispatch"]
    last = [a for a in rec.attempts][-1]
    assert (last.status, last.error) == ("failed", "check_expired_before_dispatch")


def test_refused_before_dispatch_does_not_poison_a_later_retry(tmp_path, clock):
    p, r, f, c = setup_flow(tmp_path)
    enable(r, f, c)
    d = f.decide(p, now=NOW)
    original = stall_before_dispatch(f, clock, 61, pin_observation=True)
    with pytest.raises(PermissionError):
        execute(f, p, d)
    f.destination.observe = original
    for collection in (r.statuses, r.identities, r.mandates, r.approvals, r.policies, r.conflicts, r.evidence):
        for item in collection.values():
            item.observed_at = clock.now.isoformat()
    from tests.test_runtime_authority import sign_evidence
    for status in r.evidence.values():
        sign_evidence(status)
    later = clock.now
    attempt, _ = execute(f, p, d, now=later)  # a fresh check, a fresh deadline
    assert attempt.status == "acknowledged" and list(f.destination.snapshot()["effects"]) == [d.effect_id]


def test_within_the_bound_dispatches(tmp_path, clock):
    p, r, f, c = setup_flow(tmp_path)
    enable(r, f, c)
    d = f.decide(p, now=NOW)
    stall_before_dispatch(f, clock, 59, pin_observation=True)
    attempt, _ = execute(f, p, d)
    assert attempt.status == "acknowledged" and not f.records.load().refusals


def test_observation_clock_is_decoupled_from_the_evaluation_pass(tmp_path, clock):
    """A live observation clock stamps the observation after the single evaluation time. Legacy: observation_time_future (ran).
    freshness/0.1: that is not a future timestamp; the stalled check is refused as check_expired_before_dispatch."""
    for fresh in (False, True):
        sub = tmp_path / ("fresh" if fresh else "legacy")
        sub.mkdir()
        clock.now = NOW
        p, r, f, c = setup_flow(sub)
        if fresh:
            enable(r, f, c)
        d = f.decide(p, now=NOW)
        stall_before_dispatch(f, clock, 61)
        with pytest.raises(PermissionError) as caught:
            execute(f, p, d)
        rec = f.records.load()
        assert f.destination.snapshot()["effects"] == {}
        if fresh:
            assert "check_expired_before_dispatch" in str(caught.value) and not any(
                "observation_time_future" in x.reasons for x in rec.reconciliations)
        else:
            assert any("observation_time_future" in x.reasons for x in rec.reconciliations)
            assert not any("check_expired_before_dispatch" in x.reasons for x in rec.refusals)


def test_extension_recorded_before_stall_lengthens_the_deadline(tmp_path, clock):
    p, r, f, c = setup_flow(tmp_path)
    enable(r, f, c, max_age_extension_seconds=300)
    authority(f, r)
    ext = f.record_age_extension(class_id="synthetic-irreversible", to_max_age_seconds=200, not_before=NOW.isoformat(),
                                 expires_at=(NOW + timedelta(hours=1)).isoformat(), outage_ref="outage-1",
                                 requested_by=OTHER, signer=SIGNER, authority_ref="urn:cognous:authority:outage-1", now=NOW)
    d = f.decide(p, now=NOW)
    opened = [e for e in f.records.load().check_events if e.phase == "opened"][0]
    assert (opened.age_bound_seconds, opened.extension_id) == (200, ext.extension_id)
    stall_before_dispatch(f, clock, 61, pin_observation=True)
    attempt, _ = execute(f, p, d)
    assert attempt.status == "acknowledged", "61 s is inside the extended bound"


# ------------------------------------------------------------------------------------------------ overdue and recovery
def _hold_check_open(f, p, r, release, started):
    original = r.grant_status

    def blocked(ref):
        started.set()
        release.wait(20)
        return original(ref)
    r.grant_status = blocked
    return threading.Thread(target=lambda: f.decide(p, now=NOW))


def test_live_check_past_deadline_is_reported_overdue_and_not_closed(tmp_path, clock):
    p, r, f, c = setup_flow(tmp_path)
    enable(r, f, c)
    release, started = threading.Event(), threading.Event()
    thread = _hold_check_open(f, p, r, release, started)
    thread.start()
    assert started.wait(10)
    clock.tick(61)
    legacy = f.records.recover_interrupted_checks()
    assert legacy == 0 and "overdue" not in {e.phase for e in f.records.load().check_events}, "today (ran): a stalled live check is skipped silently"
    report = f.records.recovery_pass(trigger="manual")
    assert [x["check_id"] for x in report.overdue] == [next(e.check_id for e in f.records.load().check_events if e.phase == "opened")]
    assert report.overdue[0]["reasons"] == ["check_overdue"] and report.overdue[0]["overdue_seconds"] == pytest.approx(1)
    assert not report.interrupted
    phases = [e.phase for e in f.records.load().check_events]
    assert "overdue" in phases and "interrupted" not in phases and "completed" not in phases, "alive: reported, not closed"
    again = f.records.recovery_pass()
    assert len(again.overdue) == 1 and [e.phase for e in f.records.load().check_events].count("overdue") == 1, "reported once in the journal"
    release.set()
    thread.join(20)
    assert [e.phase for e in f.records.load().check_events][-1] == "completed", "the live owner can still finish its own check"


def test_dead_owner_is_closed_not_reported_overdue(tmp_path, clock):
    p, r, f, c = setup_flow(tmp_path)
    enable(r, f, c)
    f.records.append_check_event(CheckEvent(check_id="gone", phase="opened", stage="effect", recorded_at=NOW.isoformat(),
                                            owner=_process_owner(), proposal_commitment=commitment({}),
                                            deadline=(NOW + timedelta(seconds=60)).isoformat()))
    clock.tick(500)
    report = f.records.recovery_pass(trigger="manual")
    assert report.interrupted == ["gone"] and not report.overdue
    assert f.records.load().check_events[-1].phase == "interrupted"


def test_live_check_within_deadline_and_legacy_check_are_open_not_overdue(tmp_path, clock):
    p, r, f, c = setup_flow(tmp_path)
    enable(r, f, c)
    for cid, deadline in (("fresh", NOW + timedelta(seconds=60)), ("legacy", None)):
        f.records.append_check_event(CheckEvent(check_id=cid, phase="opened", stage="effect", recorded_at=NOW.isoformat(),
                                                owner=_process_owner(), proposal_commitment=commitment({}),
                                                **({"deadline": deadline.isoformat()} if deadline else {})))
    with f.records.check_lease("fresh"), f.records.check_lease("legacy"):
        clock.tick(10)
        report = f.records.recovery_pass()
        assert sorted(report.open_within_deadline) == ["fresh", "legacy"] and not report.overdue
        clock.tick(1000)
        report = f.records.recovery_pass()
        assert [x["check_id"] for x in report.overdue] == ["fresh"] and report.open_within_deadline == ["legacy"]


def test_superseded_owner_cannot_write_to_a_closed_check(tmp_path, clock):
    """Regression guard (expected today, ran: refused): after recovery closed a check, the original owner's late write is refused."""
    p, r, f, c = setup_flow(tmp_path)
    owner = _process_owner()
    opening = CheckEvent(check_id="c1", phase="opened", stage="effect", recorded_at=NOW.isoformat(), owner=owner,
                         proposal_commitment=commitment({}))
    f.records.append_check_event(opening)
    assert f.records.recover_interrupted_checks() == 1
    before = document(f)["check_events"]
    with pytest.raises(ValueError, match="check already closed"):
        f.records.append_check_event(opening.model_copy(update={"phase": "completed"}))
    with pytest.raises(ValueError, match="check already closed"):
        f.records.append_check_event(opening.model_copy(update={"phase": "expired"}))
    assert document(f)["check_events"] == before
    f.records.append_check_event(CheckEvent(check_id="c2", phase="opened", stage="effect", recorded_at=NOW.isoformat(),
                                            owner=owner, proposal_commitment=commitment({})))
    with pytest.raises(ValueError, match="owner mismatch"):
        f.records.append_check_event(CheckEvent(check_id="c2", phase="completed", stage="effect", recorded_at=NOW.isoformat(),
                                                owner=_process_owner(), proposal_commitment=commitment({})))


def test_lease_acquisition_has_a_deadline_only_under_the_profile(tmp_path, clock):
    p, r, f, c = setup_flow(tmp_path)
    with f.records.check_lease("held"):
        other = os.open(f.records._check_lease_path("held"), os.O_RDWR | os.O_CLOEXEC)
        try:
            with pytest.raises(CheckLeaseUnavailable):
                with f.records.check_lease("held", acquire_timeout=0.05):
                    pass
        finally:
            os.close(other)
    with f.records.check_lease("held", acquire_timeout=0.05):  # free again: acquired
        pass


def test_lease_unavailable_holds_with_a_typed_reason(tmp_path, clock, monkeypatch):
    p, r, f, c = setup_flow(tmp_path)
    enable(r, f, c, lease_acquire_timeout_seconds=0.05)
    from contextlib import contextmanager

    @contextmanager
    def unavailable(check_id, *, acquire_timeout=None):
        raise CheckLeaseUnavailable("check_lease_unavailable")
        yield
    monkeypatch.setattr(f.records, "check_lease", unavailable)
    d = f.decide(p, now=NOW)
    assert d.result == "hold" and d.reasons == ["check_lease_unavailable"]
    assert not f.records.load().attempts and f.destination.snapshot()["effects"] == {}


# ------------------------------------------------------------------------------------------------ reaper and report
def test_reaper_runs_at_startup_then_on_the_declared_interval(tmp_path, clock):
    p, r, f, c = setup_flow(tmp_path)
    enable(r, f, c, reaper_interval_seconds=30)
    f.records.append_check_event(CheckEvent(check_id="orphan", phase="opened", stage="decision", recorded_at=NOW.isoformat(),
                                            owner=_process_owner(), proposal_commitment=commitment({})))
    reaper = f.reaper(clock=clock)
    first = reaper.run_due()
    assert first is not None and first.interrupted == ["orphan"]
    clock.tick(10)
    assert reaper.run_due() is None, "not due before the declared interval"
    clock.tick(25)
    assert reaper.run_due() is not None
    runs = f.records.load().recovery_runs
    assert [x.trigger for x in runs] == ["startup", "interval"] and runs[0].interrupted == ["orphan"]


def test_reaper_thread_runs_startup_pass_synchronously_and_stops(tmp_path, clock):
    p, r, f, c = setup_flow(tmp_path)
    enable(r, f, c, reaper_interval_seconds=1)
    reaper = f.reaper()
    report = reaper.start()
    try:
        assert report.as_of and [x.trigger for x in f.records.load().recovery_runs][:1] == ["startup"]
    finally:
        reaper.stop()


def test_reaper_requires_the_profile(tmp_path, clock):
    p, r, f, c = setup_flow(tmp_path)
    with pytest.raises(PermissionError):
        f.reaper()


def test_report_counts_sit_next_to_refusal_counts(tmp_path, clock):
    p, r, f, c = setup_flow(tmp_path)
    enable(r, f, c)
    d = f.decide(p, now=NOW)
    stall_before_dispatch(f, clock, 61, pin_observation=True)
    with pytest.raises(PermissionError):
        execute(f, p, d)
    f.records.append_check_event(CheckEvent(check_id="orphan", phase="opened", stage="effect", recorded_at=NOW.isoformat(),
                                            owner=_process_owner(), proposal_commitment=commitment({})))
    f.records.recover_interrupted_checks()
    f.records.append_check_event(CheckEvent(check_id="stuck", phase="opened", stage="effect",
                                            recorded_at=(clock.now - timedelta(seconds=90)).isoformat(),
                                            owner=_process_owner(), proposal_commitment=commitment({}),
                                            deadline=(clock.now - timedelta(seconds=30)).isoformat()))
    rec = f.records.load()
    refusals = [x.model_dump(mode="json") for x in rec.refusals]
    report = refusal_trends([], refusals, previous_exposure=0, current_exposure=1,
                            check_events=[e.model_dump(mode="json") for e in rec.check_events], as_of=clock.now.isoformat())
    assert report["total_refusals"] == len(refusals) >= 1
    assert report["freshness"] == {"as_of": clock.now.isoformat(), "open_count": 1, "abandoned_open_count": 1, "overdue_count": 1,
                                   "expired_before_dispatch_count": 1, "oldest_open_age_seconds": 90.0}
    assert "freshness" not in refusal_trends([], refusals, previous_exposure=0, current_exposure=1)
    with pytest.raises(ValueError):
        refusal_trends([], [], previous_exposure=0, current_exposure=0, check_events=[])
    assert freshness_counts([], as_of=NOW)["oldest_open_age_seconds"] is None


# ------------------------------------------------------------------------------------------------ age basis
def basis_of(f):
    return {(i.input_type): i.age_basis for ch in f.records.load().resolution_checks for i in ch.inputs}


def test_age_basis_nonce_bound_when_the_resolver_echoes_else_source_asserted(tmp_path, clock):
    p, r, f, c = setup_flow(tmp_path / "a")
    enable(r, f, c)
    assert f.decide(p, now=NOW).result == "authorized"
    assert set(basis_of(f).values()) == {"source_asserted"} | {None}, basis_of(f)
    assert basis_of(f)["grant"] == "source_asserted" and basis_of(f)["manifest"] is None

    (tmp_path / "b").mkdir()
    p, r, f, c = setup_flow(tmp_path / "b")
    r.echo_nonce = True
    assert r.nonce_capability == NONCE_CAPABILITY
    enable(r, f, c)
    d = f.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    bases = basis_of(f)
    assert bases["grant"] == bases["identity"] == bases["policy"] == "nonce_bound"
    opened = next(e for e in f.records.load().check_events if e.phase == "opened")
    assert opened.nonce and len(opened.nonce) == 32


def test_replayed_nonce_is_rejected_and_recorded(tmp_path, clock):
    p, r, f, c = setup_flow(tmp_path)
    r.echo_nonce = True
    enable(r, f, c)
    d = f.decide(p, now=NOW)
    assert d.result == "authorized"
    recorded = {}
    original = r.nonce_read

    def recording(nonce, method, *args):
        recorded[method] = original(nonce, method, *args)
        return recorded[method]
    r.nonce_read = recording
    f.decide(p, now=NOW)  # an earlier good response is on tape

    def replaying(nonce, method, *args):
        if method == "grant_status":
            return recorded["grant_status"][0], recorded["grant_status"][1]  # the old record AND its old echoed nonce
        return original(nonce, method, *args)
    r.nonce_read = replaying
    with pytest.raises(PermissionError):
        execute(f, p, d)
    rec = f.records.load()
    assert f.destination.snapshot()["effects"] == {} and not rec.attempts
    (row,) = rec.refusals
    assert "status_nonce_mismatch" in row.reasons
    grant = next(x for x in row.resolution_inputs if x.input_type == "grant")
    assert grant.read_state == "nonce_mismatch" and grant.expected["nonce"] != grant.observed["nonce"]
    assert grant.age_basis == "source_asserted", "a mismatched echo is never nonce bound"
    (changed,) = [x for x in row.changed_inputs if x.input_type == "grant"]
    assert changed.expected_version.startswith("nonce=") and changed.expected_version != changed.observed_version


def test_a_resolver_that_cannot_echo_is_labelled_source_asserted_and_still_works(tmp_path, clock):
    p, r, f, c = setup_flow(tmp_path)
    enable(r, f, c)  # r.echo_nonce stays False: no capability
    assert r.nonce_capability is None
    assert f.decide(p, now=NOW).result == "authorized"


# ------------------------------------------------------------------------------------------------ outage extension
def stale_grant(r, seconds):
    next(iter(r.statuses.values())).observed_at = (NOW - timedelta(seconds=seconds)).isoformat()


def request(f, **override):
    base = dict(class_id="synthetic-irreversible", to_max_age_seconds=200, not_before=NOW.isoformat(),
                expires_at=(NOW + timedelta(hours=1)).isoformat(), outage_ref="outage-1", requested_by=OTHER,
                signer=SIGNER, authority_ref="urn:cognous:authority:outage-1", now=NOW)
    base.update(override)
    return f.record_age_extension(**base)


def test_extension_is_a_recorded_decision_with_its_authority(tmp_path, clock):
    p, r, f, c = setup_flow(tmp_path)
    enable(r, f, c, max_age_extension_seconds=300)
    authority(f, r)
    stale_grant(r, 70)
    held = f.decide(p, now=NOW)
    assert held.result == "hold" and "grant_status_stale_or_future" in held.reasons
    row = request(f)
    assert row.signer == SIGNER and row.requested_by == OTHER and row.authority_ref and row.outage_ref == "outage-1"
    assert row.from_max_age_seconds == 60 and row.to_max_age_seconds == 200
    assert f.records.load().age_extensions[0].extension_id == row.extension_id
    ok = f.decide(p, now=NOW)
    assert ok.result == "authorized", ok.reasons
    opened = [e for e in f.records.load().check_events if e.phase == "opened"]
    assert (opened[0].extension_id, opened[0].age_bound_seconds) == (None, 60), "before the extension: base bound"
    assert (opened[-1].extension_id, opened[-1].age_bound_seconds) == (row.extension_id, 200), "after: the recorded extension"


@pytest.mark.parametrize("override,code", [
    ({"signer": None}, "age_extension_unsigned"),
    ({"signer": OTHER}, "age_extension_self_signed"),
    ({"signer": "urn:cognous:principal:nobody"}, "age_extension_signer_not_configured"),
    ({"to_max_age_seconds": 1000}, "age_extension_exceeds_limit"),
    ({"to_max_age_seconds": 60}, "age_extension_invalid"),
    ({"outage_ref": "x", "expires_at": NOW.isoformat()}, "age_extension_invalid"),
])
def test_unauthorised_or_malformed_extension_is_refused_and_recorded(tmp_path, clock, override, code):
    p, r, f, c = setup_flow(tmp_path)
    enable(r, f, c, max_age_extension_seconds=300)
    authority(f, r)
    with pytest.raises(AgeExtensionRefused) as caught:
        request(f, **override)
    assert code in caught.value.reasons
    doc = document(f)
    assert not doc.get("age_extensions") and code in doc["age_extension_refusals"][0]["reasons"]
    stale_grant(r, 70)
    assert f.decide(p, now=NOW).result == "hold"


def test_extension_needs_the_rule_revision_signer_set_and_a_limit(tmp_path, clock):
    p, r, f, c = setup_flow(tmp_path)
    enable(r, f, c)  # max_age_extension_seconds 0: every extension exceeds the declared limit
    with pytest.raises(AgeExtensionRefused) as caught:
        request(f)
    assert {"age_extension_authority_unconfigured", "age_extension_exceeds_limit"} <= set(caught.value.reasons)
    with pytest.raises(PermissionError):
        setup = setup_flow(tmp_path / "plain")
        setup[2].record_age_extension(class_id="synthetic-irreversible", to_max_age_seconds=1, not_before="x", expires_at="y",
                                      outage_ref="o", requested_by="a", signer="b")


def test_extension_authority_is_re_checked_at_every_use(tmp_path, clock):
    p, r, f, c = setup_flow(tmp_path)
    enable(r, f, c, max_age_extension_seconds=300)
    authority(f, r)
    request(f)
    stale_grant(r, 70)
    assert f.decide(p, now=NOW).result == "authorized"
    f.rule_revision_profile = RuleRevisionProfile(signers=[POLICY_SIGNER])  # the extension's signer is withdrawn
    d = f.decide(p, now=NOW)
    assert d.result == "hold" and {"grant_status_stale_or_future", "age_extension_signer_not_configured"} <= set(d.reasons)


def test_extension_window_bounds_its_use(tmp_path, clock):
    p, r, f, c = setup_flow(tmp_path)
    enable(r, f, c, max_age_extension_seconds=300)
    authority(f, r)
    request(f, not_before=(NOW + timedelta(minutes=5)).isoformat(), expires_at=(NOW + timedelta(minutes=10)).isoformat())
    stale_grant(r, 70)
    d = f.decide(p, now=NOW)
    assert d.result == "hold" and not any(x.startswith("age_extension_") for x in d.reasons), "outside its window: not applied"


# ------------------------------------------------------------------------------------------------ registry
def test_every_freshness_code_is_registered():
    from agent_control_plane import freshness
    codes = {v for k, v in vars(freshness).items() if k.startswith("CODE_")}
    assert len(codes) == 10 and codes <= set(REGISTRY["codes"])
    assert all(REGISTRY["codes"][x]["reason_kind"] == "typed_only" for x in codes)


def test_profile_is_part_of_the_approval_commitment(tmp_path, clock):
    from agent_control_plane.runtime_authority import approval_commitment
    p, r, f, c = setup_flow(tmp_path)
    plain = approval_commitment(c, r.contexts[PROFILE])
    with_profile = approval_commitment(c.model_copy(update={"freshness": FreshnessProfile()}), r.contexts[PROFILE])
    assert plain != with_profile
    without_changes = BoundedRunRecord.model_validate(document(f)).model_dump(mode="json")
    assert "age_extensions" not in without_changes and "recovery_runs" not in without_changes
