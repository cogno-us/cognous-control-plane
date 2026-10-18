"""dedupe-ttl/0.1: opt-in key TTL, provider horizon, escalation deadline inside the key TTL, in-progress never mints a key.

Synthetic fixtures only. The composed cross-component scenarios live in the qualification suite (suites/operation-identity,
test_dedupe_profile.py), against the runtime's `dedupe-ttl/0.1` destination capability.

Provenance of "expected today" values (default path, profile unset): the `*_today` rows were RUN on main 3f6a766 before this change
and are re-run on every test run. Nothing here is taken from code reading alone.
"""
import ast
import json
import pathlib
from datetime import timedelta

import pytest

import agent_control_plane.bounded as bounded
from agent_control_plane import dedupe as dd
from agent_control_plane.bounded import LocalRefundDestination
from agent_control_plane.dedupe import DedupeProfile, DestinationInProgress
from tests.test_bounded_authorization import ISSUER, NOW
from tests.test_operation_identity import IDENTITY, OPERATION, enable, renew, run_document, two_effects, two_effects_manifest
from tests.test_runtime_authority import setup_flow

REGISTRY = json.loads((pathlib.Path(__file__).resolve().parents[1] / "schemas" / "runtime_authority_reasons_0_2.json").read_text())
PROFILE = DedupeProfile(dedupe_ttl_seconds=600, provider_horizon_seconds=120, escalation_deadline_seconds=300)


@pytest.fixture(autouse=True)
def _clock(monkeypatch):
    monkeypatch.setattr(bounded, "_now", lambda: NOW)


class SilentDestination(LocalRefundDestination):
    """Accepts the request and never answers: the effect is not durable (yet) and the acknowledgement is lost."""

    def __init__(self, path, *, capability=False, ttl=600, mode="lost"):
        super().__init__(path)
        self.mode = mode
        if capability:
            self.dedupe_capability, self.dedupe_ttl_seconds = dd.DESTINATION_CAPABILITY, ttl

    def apply(self, **kwargs):
        if self.mode == "ok":
            return super().apply(**kwargs)
        if self.mode == "in_progress":
            raise DestinationInProgress()
        raise TimeoutError("acknowledgement lost")


def flow(tmp_path, monkeypatch, *, destination=None, profile=PROFILE):
    two_effects_manifest(monkeypatch)
    p, r, f, c = setup_flow(tmp_path)
    two_effects(r)
    cfg = enable(r, f, c)
    cfg = cfg.model_copy(update={"dedupe": profile})
    from tests.test_runtime_authority import bind_approval
    bind_approval(r, cfg)
    f.runtime_authority_profile = cfg.snapshot()
    if destination is not None:
        f.destination = destination(tmp_path / "silent.json")
    return p, r, f, cfg


def go(f, p, d, at=NOW):
    return f.execute(p, d, adapter_id=p.adapter_id, now=at)


def at(seconds):
    return NOW + timedelta(seconds=seconds)


# ---------------------------------------------------------------- profile
def test_escalation_must_fire_inside_the_key_ttl_and_after_the_horizon():
    DedupeProfile(dedupe_ttl_seconds=10, provider_horizon_seconds=5, escalation_deadline_seconds=5)  # equal to the horizon is allowed
    for ttl, horizon, deadline in ((10, 5, 10), (10, 5, 11), (10, 6, 5), (10, 11, 11)):
        with pytest.raises(ValueError, match="escalation_deadline_not_inside_key_ttl"):
            DedupeProfile(dedupe_ttl_seconds=ttl, provider_horizon_seconds=horizon, escalation_deadline_seconds=deadline)


def test_profile_needs_operation_identity_and_is_off_by_default(tmp_path):
    from agent_control_plane.runtime_authority import ActionClass, RuntimeAuthorityProfile
    with pytest.raises(ValueError, match="operation-identity"):
        RuntimeAuthorityProfile(catalogue_version="x", actions={"a": ActionClass(class_id="c")}, dedupe=PROFILE)
    p, r, f, c = setup_flow(tmp_path)
    assert "dedupe" not in c.model_dump(mode="json")
    with pytest.raises(PermissionError):
        f.escalation_pass(now=NOW)
    with pytest.raises(PermissionError):
        f.dedupe_report(now=NOW)


def test_capability_is_declared_never_inferred():
    class Declared:
        dedupe_capability, dedupe_ttl_seconds = dd.DESTINATION_CAPABILITY, 600

    class ShortLived(Declared):
        dedupe_ttl_seconds = 599

    class Wrong(Declared):
        dedupe_capability = "something-else/1"

    class StringTtl(Declared):
        dedupe_ttl_seconds = "600"
    assert dd.dedupe_mode(Declared(), PROFILE) == "destination_ttl"
    assert [dd.dedupe_mode(x(), PROFILE) for x in (ShortLived, Wrong, StringTtl, object)] == ["none"] * 4
    assert dd.dedupe_mode(LocalRefundDestination.__new__(LocalRefundDestination), PROFILE) == "none"


# ---------------------------------------------------------------- unknown attempt: horizon, escalation inside the key TTL
@pytest.mark.parametrize("capability,mode", [(False, "none"), (True, "destination_ttl")])
def test_unknown_attempt_waits_for_the_horizon_then_escalates_inside_the_key_ttl(tmp_path, monkeypatch, capability, mode):
    p, r, f, c = flow(tmp_path, monkeypatch, destination=lambda path: SilentDestination(path, capability=capability))
    d = f.decide(p, now=NOW)
    attempt, observation = go(f, p, d)
    assert attempt.status == "unknown" and observation.state == "absent"
    states = {s: [x["state"] for x in f.dedupe_report(now=at(s))] for s in (60, 119, 120, 299, 300)}
    assert states == {60: ["unknown_until_horizon"], 119: ["unknown_until_horizon"], 120: ["horizon_passed_awaiting_escalation"],
                      299: ["horizon_passed_awaiting_escalation"], 300: ["escalation_due"]}
    assert f.escalation_pass(now=at(299)) == [] and "dedupe_escalations" not in run_document(f)
    (row,) = f.escalation_pass(now=at(300))
    assert row.fired_inside_key_ttl and row.reasons == ["attempt_unresolved_past_horizon"] and row.mode == mode
    assert row.effect_id == d.effect_id and row.operation_id == OPERATION and row.in_progress is False
    assert row.key_expires_at == at(600).isoformat() and row.escalation_deadline_at == at(300).isoformat()
    assert row.same_key_safe_until == (at(600).isoformat() if capability else None)
    assert f.escalation_pass(now=at(301)) == [], "once per effect"
    assert [x["state"] for x in f.dedupe_report(now=at(301))] == ["escalated"]
    # the attempt stays unknown: nothing flipped it, nothing retried it
    latest = {a.attempt_id: a for a in f.records.load().attempts}
    assert [a.status for a in latest.values()] == ["unknown"] and f.destination.snapshot()["effects"] == {}
    with pytest.raises(PermissionError, match="observed absence does not establish retry eligibility"):
        go(f, p, d, at(5))


def test_mode_follows_the_destination_that_dispatches_not_the_workflows_own(tmp_path, monkeypatch):
    """A runtime executor route dispatches through another object than ``workflow.destination``; the host names it."""
    p, r, f, c = flow(tmp_path, monkeypatch, destination=SilentDestination)  # the workflow's own destination: no capability
    d = f.decide(p, now=NOW)
    go(f, p, d)
    other = SilentDestination(tmp_path / "other.json", capability=True)
    assert [x["mode"] for x in f.dedupe_report(now=at(1))] == ["none"]
    assert [x["mode"] for x in f.dedupe_report(now=at(1), destination=other)] == ["destination_ttl"]
    (row,) = f.escalation_pass(now=at(300), destination=other)
    assert row.mode == "destination_ttl" and row.same_key_safe_until == at(600).isoformat()


def test_escalation_after_the_key_ttl_is_flagged(tmp_path, monkeypatch):
    p, r, f, c = flow(tmp_path, monkeypatch, destination=SilentDestination)
    d = f.decide(p, now=NOW)
    go(f, p, d)
    (row,) = f.escalation_pass(now=at(700))
    assert not row.fired_inside_key_ttl and row.reasons == ["attempt_unresolved_past_horizon", "escalation_after_key_ttl"]


def test_an_attempt_that_resolved_is_not_escalated(tmp_path, monkeypatch):
    p, r, f, c = flow(tmp_path, monkeypatch)  # the local destination acknowledges
    d = f.decide(p, now=NOW)
    attempt, _ = go(f, p, d)
    assert attempt.status == "acknowledged" and f.dedupe_report(now=at(10_000)) == [] and f.escalation_pass(now=at(10_000)) == []


def test_a_definitive_failure_is_not_unknown_and_is_not_escalated(tmp_path, monkeypatch):
    from agent_control_plane.bounded import DefinitiveDestinationRejection

    class Rejecting(LocalRefundDestination):
        def apply(self, **kw):
            raise DefinitiveDestinationRejection("synthetic_rejection")
    p, r, f, c = flow(tmp_path, monkeypatch, destination=Rejecting)
    d = f.decide(p, now=NOW)
    attempt, _ = go(f, p, d)
    assert attempt.status == "failed" and f.dedupe_report(now=at(10_000)) == []


# ---------------------------------------------------------------- in_progress never mints a new key
def test_in_progress_response_never_mints_a_new_key(tmp_path, monkeypatch):
    p, r, f, c = flow(tmp_path, monkeypatch, destination=lambda path: SilentDestination(path, capability=True, mode="in_progress"))
    d1 = f.decide(p, now=NOW)
    attempt, _ = go(f, p, d1)
    assert attempt.status == "unknown" and attempt.error == "destination_in_progress" and attempt.acknowledgement == {"in_progress": True}
    renew(r, f.runtime_authority_profile, "2")  # the grant is renewed: a new revision would mint a new effect id (a new key)
    f.record_renewal(OPERATION, to_revision="2", written_by=ISSUER, now=NOW)
    d2 = f.decide(p, now=NOW)
    assert d2.result == "authorized" and d2.effect_id != d1.effect_id
    with pytest.raises(PermissionError):
        go(f, p, d2)
    refusal = f.records.load().refusals[-1]
    assert refusal.reasons == ["dedupe_unresolved_attempt_blocks_new_key"] and refusal.effect_id == d2.effect_id
    record = f.records.load()
    assert {a.effect_id for a in record.attempts} == {d1.effect_id}, "no attempt was made under a second key"
    assert {j.effect_id for j in record.attempt_joins} == {d1.effect_id}
    assert [x["in_progress"] for x in f.dedupe_report(now=at(10))] == [True]


def test_without_the_profile_a_renewal_dispatches_a_second_key_today(tmp_path, monkeypatch):
    """Expected today (ran, profile unset, same destination): the unresolved first attempt does not stop the renewed one."""
    p, r, f, c = flow(tmp_path, monkeypatch, destination=lambda path: SilentDestination(path, mode="in_progress"), profile=None)
    d1 = f.decide(p, now=NOW)
    go(f, p, d1)
    renew(r, f.runtime_authority_profile, "2")
    f.record_renewal(OPERATION, to_revision="2", written_by=ISSUER, now=NOW)
    d2 = f.decide(p, now=NOW)
    attempt, _ = go(f, p, d2)
    assert attempt.error == "destination_outcome_unknown:DestinationInProgress"
    assert {a.effect_id for a in f.records.load().attempts} == {d1.effect_id, d2.effect_id}


def test_in_progress_is_unknown_not_failed_and_resolves_when_the_destination_lands_it(tmp_path, monkeypatch):
    p, r, f, c = flow(tmp_path, monkeypatch, destination=lambda path: SilentDestination(path, capability=True, mode="in_progress"))
    d = f.decide(p, now=NOW)
    go(f, p, d)
    assert [x["state"] for x in f.dedupe_report(now=at(10))] == ["unknown_until_horizon"]
    f.destination.mode = "ok"  # the provider finishes the request it was processing
    f.destination.apply(effect_id=d.effect_id, grant_id=d.binding.grant_id, max_effects=2, target="t", amount=1, unit="USD", payload={})
    assert f.reconcile(d.effect_id, now=NOW).result == "applied"
    assert f.dedupe_report(now=at(10)) == [] and f.escalation_pass(now=at(10_000)) == [], "a closed-out attempt is not escalated"


def test_escalation_inside_flag_flips_exactly_at_the_key_expiry(tmp_path, monkeypatch):
    """The destination's key is valid while age < TTL (runtime destination), so at exactly the TTL it is already gone."""
    for seconds, inside in ((599, True), (600, False)):
        p, r, f, c = flow(tmp_path / str(seconds), monkeypatch, destination=SilentDestination)
        d = f.decide(p, now=NOW)
        go(f, p, d)
        (row,) = f.escalation_pass(now=at(seconds))
        assert row.fired_inside_key_ttl is inside and (row.reasons == ["attempt_unresolved_past_horizon"]) is inside


def test_a_second_pass_cannot_append_a_second_escalation_for_the_same_effect(tmp_path, monkeypatch):
    p, r, f, c = flow(tmp_path, monkeypatch, destination=SilentDestination)
    d = f.decide(p, now=NOW)
    go(f, p, d)
    (row,) = f.escalation_pass(now=at(300))
    assert f.records.append_escalations(lambda document: [row]) == [], "the store itself keeps one row per effect"
    assert len(run_document(f)["dedupe_escalations"]) == 1


def test_an_effect_settled_by_a_closeout_is_applied_for_the_key_gate(tmp_path, monkeypatch):
    p, r, f, c = flow(tmp_path, monkeypatch, destination=lambda path: SilentDestination(path, capability=True, mode="in_progress"))
    d1 = f.decide(p, now=NOW)
    go(f, p, d1)
    f.destination.mode = "ok"
    f.destination.apply(effect_id=d1.effect_id, grant_id=d1.binding.grant_id, max_effects=2, target="t", amount=1, unit="USD", payload={})
    assert f.reconcile(d1.effect_id, now=NOW).result == "applied"
    renew(r, f.runtime_authority_profile, "2")
    f.record_renewal(OPERATION, to_revision="2", written_by=ISSUER, now=NOW)
    d2 = f.decide(p, now=NOW)
    with pytest.raises(PermissionError):
        go(f, p, d2)
    assert f.records.load().refusals[-1].reasons == ["dedupe_operation_effect_applied"]


# ---------------------------------------------------------------- key expiry never makes a duplicate fresh
class ForgetfulDestination(LocalRefundDestination):
    """Declares the capability and forgets the operation key at its TTL (what a real provider does). Effect-id dedupe is kept."""

    def __init__(self, path, *, capability=True, ttl=600):
        super().__init__(path)
        if capability:
            self.dedupe_capability, self.dedupe_ttl_seconds = dd.DESTINATION_CAPABILITY, ttl

    def expire_keys(self):
        with self._transaction():
            state = self._load()
            state["operations"] = {}
            self._write(state)


def _applied_then_expired_then_renewed(tmp_path, monkeypatch, profile):
    p, r, f, c = flow(tmp_path, monkeypatch, destination=lambda path: ForgetfulDestination(path), profile=profile)
    d1 = f.decide(p, now=NOW)
    attempt, _ = go(f, p, d1)
    assert attempt.status == "acknowledged"
    f.destination.expire_keys()  # the destination's key TTL passed: it no longer remembers the operation
    renew(r, f.runtime_authority_profile, "2")
    f.record_renewal(OPERATION, to_revision="2", written_by=ISSUER, now=NOW)
    d2 = f.decide(p, now=NOW)
    assert d2.result == "authorized" and d2.effect_id != d1.effect_id
    return f, p, d1, d2


def test_an_expired_destination_key_does_not_turn_a_duplicate_into_a_fresh_effect(tmp_path, monkeypatch):
    f, p, d1, d2 = _applied_then_expired_then_renewed(tmp_path, monkeypatch, PROFILE)
    with pytest.raises(PermissionError):
        go(f, p, d2)
    assert f.records.load().refusals[-1].reasons == ["dedupe_operation_effect_applied"]
    assert set(f.destination.snapshot()["effects"]) == {d1.effect_id}, "no second effect landed"
    assert {a.effect_id for a in f.records.load().attempts} == {d1.effect_id}, "no attempt was made under a second key"


def test_same_effect_resubmission_after_the_ttl_is_still_deduped_by_effect_id(tmp_path, monkeypatch):
    p, r, f, c = flow(tmp_path, monkeypatch, destination=lambda path: ForgetfulDestination(path))
    d1 = f.decide(p, now=NOW)
    go(f, p, d1)
    f.destination.expire_keys()
    again, _ = go(f, p, d1)
    assert again.status == "acknowledged" and set(f.destination.snapshot()["effects"]) == {d1.effect_id}, "effect-id dedupe never expires"


def test_without_the_profile_an_expired_key_lets_the_second_effect_land_today(tmp_path, monkeypatch):
    """Expected today (ran, profile unset, destination forgets the key): the renewed effect is accepted as new."""
    f, p, d1, d2 = _applied_then_expired_then_renewed(tmp_path, monkeypatch, None)
    attempt, _ = go(f, p, d2)
    assert attempt.status == "acknowledged" and set(f.destination.snapshot()["effects"]) == {d1.effect_id, d2.effect_id}


# ---------------------------------------------------------------- registry
def test_every_dedupe_code_is_registered():
    codes = {getattr(dd, n) for n in dir(dd) if n.startswith("CODE_")}
    assert len(codes) == 4 and codes <= set(REGISTRY["codes"])
    source = pathlib.Path(dd.__file__).read_text()
    literals = {n.value for n in ast.walk(ast.parse(source)) if isinstance(n, ast.Constant) and isinstance(n.value, str)
                and n.value.startswith(("dedupe_unresolved", "dedupe_operation", "attempt_unresolved", "escalation_after"))}
    assert literals <= set(REGISTRY["codes"])
