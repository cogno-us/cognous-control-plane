"""Time parsing conformance (ODES time semantics, sections 1 and 3).

One strict parser (``time_instant.parse_instant``) behind every comparison parser of the control plane. Valid instants parse to
exactly what the earlier ``fromisoformat`` parsers returned; naive, over-precise and out-of-range forms are refused through each
site's existing refusal path. The dedupe escalation deadline is inclusive.
"""
from __future__ import annotations

import io
import json
import random
import shutil
from contextlib import redirect_stderr, redirect_stdout
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agent_control_plane import bounded, cli_run, dedupe, freshness, reversibility, rule_revision
from agent_control_plane import decision_input_profile as dip
from agent_control_plane.cli import main
from agent_control_plane.policy_gate import PolicyGate
from agent_control_plane.runtime_authority import ActionClass
from agent_control_plane.time_instant import (TIME_INSTANT_INVALID, TIME_INSTANT_NAIVE, InstantError, aware_utc,
                                              parse_instant)


def _legacy(value: str) -> datetime:
    """The parser every comparison site used before (bounded._parse and its copies)."""
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


# ---------------------------------------------------------------- the parser
def _valid_corpus() -> list[str]:
    fixed = [
        "2026-10-18T12:00:00Z", "2026-10-18T12:00:00+00:00", "2026-10-18T14:00:00+02:00", "2026-10-18T12:00:00.000000+00:00",
        "2026-10-18T12:00:00.1Z", "2026-10-18T12:00:00.123456Z", "2026-10-18T12:00:00.000001-05:30", "2026-10-18T12:00:00-00:00",
        "2026-10-18T23:59:59.999999+23:59", "2026-10-18T00:00:00-23:59", "2024-02-29T00:00:00Z", "0001-01-01T00:00:00Z",
        "0001-01-01T00:00:00-01:00", "9999-12-31T23:59:59.999999Z", "9999-12-31T23:59:59+01:00",
    ]
    rng = random.Random(20261018)
    for _ in range(2000):
        dt = datetime(rng.randint(2, 9998), rng.randint(1, 12), rng.randint(1, 28), rng.randint(0, 23), rng.randint(0, 59),
                      rng.randint(0, 59), rng.choice([0, rng.randint(0, 999_999)]))
        frac = "" if dt.microsecond == 0 and rng.random() < 0.5 else "." + f"{dt.microsecond:06d}"[: rng.randint(1, 6)]
        off = rng.choice(["Z", "+00:00", "-00:00", f"+{rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}",
                          f"-{rng.randint(0, 23):02d}:{rng.randint(0, 59):02d}"])
        fixed.append(dt.strftime("%Y-%m-%dT%H:%M:%S").zfill(19) + frac + off)
    return fixed


def test_valid_instants_parse_exactly_as_before():
    """Default-path identity: every valid instant (aware, at most six fraction digits) gives the legacy datetime, UTC tzinfo
    and isoformat."""
    for value in _valid_corpus():
        new, old = parse_instant(value), _legacy(value)
        assert new == old and new.tzinfo is timezone.utc and new.isoformat() == old.isoformat(), value


def test_offsets_never_change_the_instant():
    same = {parse_instant(v) for v in ("2026-10-18T14:00:00+02:00", "2026-10-18T12:00:00Z", "2026-10-18T12:00:00.000000+00:00",
                                       "2026-10-18T12:00:00-00:00", "2026-10-18T07:30:00-04:30")}
    assert len(same) == 1


NAIVE = ["2026-10-18T12:00:00", "2026-10-18T12:00:00.5", "2026-10-18T12:00:00.123456"]
INVALID = [
    "2026-10-18T12:00:00.0000001Z",        # seventh fraction digit: refused, never truncated
    "2026-10-18T12:00:00.1234567+00:00",
    "2026-10-18T12:00:00+00:60",           # offset minute 60
    "2026-10-18T12:00:00+24:00",           # offset hour 24
    "2026-12-31T23:59:60Z",                # leap second
    "2026-10-18T24:00:00Z", "2026-10-18T12:60:00Z", "2026-02-30T12:00:00Z", "2026-13-01T00:00:00Z", "0000-01-01T00:00:00Z",
    "0001-01-01T00:00:00+01:00",           # leaves year 0001 in UTC
    "9999-12-31T23:59:59-01:00",           # leaves year 9999 in UTC
    "2026-10-18", "2026-10-18T12:00Z", "2026-10-18T12Z", "2026-10-18 12:00:00Z", "20261018T120000Z", "2026-W42-7T12:00:00Z",
    "2026-10-18T12:00:00,5Z", "2026-10-18T12:00:00+05", "2026-10-18T12:00:00+0500", "2026-10-18t12:00:00Z",
    "2026-10-18T12:00:00z", "2026-10-18T12:00:00.Z", " 2026-10-18T12:00:00Z", "2026-10-18T12:00:00Z ",
    "2026-10-18T12:00:00Z\n", "2026-10-18T12:00:00+00:00Z", "٢026-10-18T12:00:00Z", "２026-10-18T12:00:00Z", "", "soon",
]


@pytest.mark.parametrize("value", NAIVE)
def test_naive_instants_are_refused_not_read_as_utc(value):
    with pytest.raises(InstantError) as caught:
        parse_instant(value)
    assert caught.value.code == TIME_INSTANT_NAIVE and str(caught.value).startswith(f"[{TIME_INSTANT_NAIVE}]")
    assert isinstance(caught.value, ValueError)


@pytest.mark.parametrize("value", INVALID)
def test_malformed_instants_are_refused(value):
    with pytest.raises(InstantError) as caught:
        parse_instant(value)
    assert caught.value.code == TIME_INSTANT_INVALID and str(caught.value).startswith(f"[{TIME_INSTANT_INVALID}]")


def test_seven_digits_never_equal_the_truncated_instant():
    """The legacy parser read .0000001 as .000000 (two different instants compared equal); the strict one refuses it."""
    assert _legacy("2026-10-18T12:00:00.0000001Z") == _legacy("2026-10-18T12:00:00Z")
    with pytest.raises(InstantError):
        parse_instant("2026-10-18T12:00:00.0000001Z")


def test_non_strings_raise_type_error_and_naive_datetimes_are_refused():
    for value in (None, 1760000000, datetime(2026, 10, 18, tzinfo=timezone.utc)):
        with pytest.raises(TypeError):
            parse_instant(value)
    with pytest.raises(InstantError, match=TIME_INSTANT_NAIVE):
        aware_utc(datetime(2026, 10, 18, 12))
    assert aware_utc(datetime(2026, 10, 18, 14, tzinfo=timezone(timedelta(hours=2)))) == datetime(2026, 10, 18, 12, tzinfo=timezone.utc)


# ---------------------------------------------------------------- every comparison parser uses it
PARSERS = {
    "bounded._parse": bounded._parse,
    "freshness.parse_time": freshness.parse_time,
    "policy_gate._parse_time": PolicyGate()._parse_time,
    "dedupe._t": dedupe._t,
    "reversibility._utc": reversibility._utc,
    "rule_revision._t": rule_revision._t,
}


@pytest.mark.parametrize("name", sorted(PARSERS))
@pytest.mark.parametrize("value", ["2026-10-05T19:00:00", "2026-10-05T19:00:00.0000001+00:00", "2026-10-05T19:00:00+00:60"])
def test_comparison_parsers_refuse_naive_overprecise_and_bad_offsets(name, value):
    with pytest.raises(ValueError):
        PARSERS[name](value)


@pytest.mark.parametrize("name", sorted(PARSERS))
def test_comparison_parsers_return_aware_utc(name):
    """rule_revision._t used to keep a naive time naive (and the offset as written); it now returns aware UTC like the rest."""
    value = PARSERS[name]("2026-10-05T21:00:00.5+02:00")
    assert value == datetime(2026, 10, 5, 19, 0, 0, 500000, tzinfo=timezone.utc) and value.tzinfo is timezone.utc


@pytest.mark.parametrize(("value", "message"), [
    ("2026-10-05T19:00:00", "timestamp must include a timezone"),
    ("2026-10-05T19:00:00.0000001Z", "timestamp is malformed"),
    ("2026-10-05T19:00:00+00:60", "timestamp is malformed"),
    ("2026-10-05", "timestamp is malformed"),
])
def test_decision_input_profile_keeps_its_codes(value, message):
    with pytest.raises(dip.ProfileValidationError) as caught:
        dip._parse_time(value, code="EVIDENCE_TIME_INVALID")
    assert caught.value.code == "EVIDENCE_TIME_INVALID" and message in str(caught.value)
    assert dip._parse_time("2026-10-05T21:00:00+02:00", code="X") == datetime(2026, 10, 5, 19, tzinfo=timezone.utc)


def test_decision_input_profile_still_loads_standalone_by_path():
    """tools/verify_decision_input_commitment.py loads the module by file path, outside the package."""
    import importlib.util
    path = Path(dip.__file__)
    spec = importlib.util.spec_from_file_location("decision_input_profile_standalone", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    with pytest.raises(module.ProfileValidationError, match="timezone"):
        module._parse_time("2026-10-05T19:00:00", code="X")


@pytest.mark.parametrize(("value", "message"), [
    ("2026-10-05T19:00:00", "must be timezone-aware"),
    ("2026-10-05T19:00:00.0000001Z", "not an ISO-8601 time"),
    ("2026-10-05T19:00:00+00:60", "not an ISO-8601 time"),
])
def test_acp_run_now_is_strict(value, message):
    with pytest.raises(cli_run.InvalidInput, match=message):
        cli_run._parse_now(value)


@pytest.mark.parametrize(("until", "message"), [
    ("2026-10-05T19:00:00", "needs a UTC offset"),
    ("2026-10-05T19:00:00.0000001Z", "timestamp_invalid: reversible_until"),
    ("2026-10-05T19:00:00+00:60", "timestamp_invalid: reversible_until"),
    ("2026-12-31T23:59:60Z", "timestamp_invalid: reversible_until"),
])
def test_reversible_until_declaration_is_strict(until, message):
    with pytest.raises(ValueError, match=message):
        ActionClass(class_id="x", reversibility="reversible_until", reversible_until=until)


# ---------------------------------------------------------------- end to end through the existing refusal paths
from tests.test_bounded_authorization import NOW, PROFILE, observation_workflow  # noqa: E402
from tests.test_runtime_authority import bind_approval, held, setup_flow  # noqa: E402

BAD = ["{}", "{}.0000001+00:00", "{}+00:60"]


@pytest.mark.parametrize("pattern", BAD)
@pytest.mark.parametrize("member", ["not_before", "expires_at"])
def test_grant_window_with_a_bad_instant_holds_as_invalid_resolution_record(tmp_path, pattern, member):
    p, r, f, c = setup_flow(tmp_path)
    grant = r.contexts[PROFILE]["grant"]
    grant[member] = pattern.format(datetime.fromisoformat(grant[member]).astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S"))
    bind_approval(r, c)
    assert held(f, p, "resolution_record_invalid").reasons == ["resolution_record_invalid"]


def test_grant_window_end_is_exclusive_and_start_inclusive(tmp_path):
    p, r, f, c = setup_flow(tmp_path / "end")
    r.contexts[PROFILE]["grant"]["expires_at"] = NOW.isoformat()
    bind_approval(r, c)
    held(f, p, "grant_outside_validity")


@pytest.mark.parametrize(("observed_at", "reason"), [
    ("2026-10-05T19:00:00.0000001+00:00", "observation_time_malformed"),
    ("2026-10-05T19:00:00+00:60", "observation_time_malformed"),
    ("2026-10-05T19:00", "observation_time_malformed"),
    ("2026-10-05T19:00:00.5", "observation_time_timezone_missing"),
])
def test_destination_observation_time_is_strict(tmp_path, observed_at, reason):
    from agent_control_plane.bounded import EffectObservation
    observation = EffectObservation(effect_id="effect-1", observed_at=observed_at, state="absent", destination_state={})
    base, records, flow = observation_workflow(tmp_path, observation)
    result = flow.reconcile("effect-1", now=NOW)
    assert result.result == "hold" and reason in result.reasons and records.load().observations == []


EXAMPLES = Path(__file__).resolve().parent.parent / "examples" / "acp_run"


def _acp_run(tmp_path, grant_member=None, value=None):
    base = tmp_path / "in"
    base.mkdir()
    shutil.copy(EXAMPLES / "manifest.json", base / "manifest.json")
    for name in ("proposal", "authority-context", "resolver-state"):
        shutil.copy(EXAMPLES / "authorized" / f"{name}.json", base / f"{name}.json")
    if grant_member:
        doc = json.loads((base / "authority-context.json").read_text())
        doc["grant"][grant_member] = value
        (base / "authority-context.json").write_text(json.dumps(doc))
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        code = main(["run", "--manifest", str(base / "manifest.json"), "--proposal", str(base / "proposal.json"),
                     "--authority-context", str(base / "authority-context.json"),
                     "--resolver-state", str(base / "resolver-state.json"), "--store-dir", str(tmp_path / "store"),
                     "--out-dir", str(tmp_path / "out"), "--now", "2026-10-05T19:00:00Z", "--format", "json"])
    return code, json.loads((tmp_path / "out" / "result.json").read_text())


@pytest.mark.parametrize("value", ["2026-10-05T20:00:00", "2026-10-05T20:00:00.0000001+00:00", "2026-10-05T20:00:00+00:60",
                                   "2026-10-05T20:00Z"])
def test_acp_run_refuses_a_bad_grant_instant_without_an_effect(tmp_path, value):
    """Legacy path (no runtime-authority profile): a malformed grant time already ended the run with exit 4 before any decision
    or effect; naive, over-precise and bad-offset times now take that same path (they used to authorize)."""
    code, result = _acp_run(tmp_path, "expires_at", value)
    assert code == 4 and result["reason_codes"] == ["internal_error"]
    assert not (tmp_path / "out" / "bounded-run-record.json").exists()
    destination = tmp_path / "store" / "destination.json"
    assert not destination.exists() or json.loads(destination.read_text()).get("effects", {}) == {}


def test_acp_run_valid_offset_form_still_authorizes(tmp_path):
    code, result = _acp_run(tmp_path, "expires_at", "2026-10-05T22:00:00.000000+02:00")
    assert code == 0 and result["reason_codes"] == []


# ---------------------------------------------------------------- policy gate
def _gate_inputs():
    from tests.test_policy_gate import _make_action, _make_frame
    return _make_action("email_send", "external_send"), _make_frame(allowed_tools=["email_send"])


@pytest.mark.parametrize("now", ["2026-01-01T00:00:00", "2026-01-01T00:00:00.0000001Z", datetime(2026, 1, 1)])
def test_policy_gate_refuses_a_naive_or_overprecise_evaluation_time(now):
    action, frame = _gate_inputs()
    with pytest.raises(ValueError):
        PolicyGate().evaluate(action, frame, [], now=now)


def test_policy_gate_authority_expiry_is_strict_and_exclusive():
    action, frame = _gate_inputs()
    gate = PolicyGate()
    def record(expires_at):
        from tests.test_policy_gate import _make_authority
        return _make_authority(["external_send"], expires_at=expires_at)
    now = "2026-01-01T00:00:00+00:00"
    at_end = gate._active_authority_scopes(action, frame, [record("2026-01-01T00:00:00Z")], gate._parse_time(now))
    inside = gate._active_authority_scopes(action, frame, [record("2026-01-01T00:00:00.000001Z")], gate._parse_time(now))
    assert "external_send" not in at_end and "external_send" in inside
    with pytest.raises(ValueError):
        gate._active_authority_scopes(action, frame, [record("2026-01-01T01:00:00")], gate._parse_time(now))


# ---------------------------------------------------------------- dedupe: the escalation deadline is inclusive
PROFILE_DD = dedupe.DedupeProfile(dedupe_ttl_seconds=600, provider_horizon_seconds=120, escalation_deadline_seconds=300)
FIRST = datetime(2026, 10, 5, 19, 0, tzinfo=timezone.utc)
DOC = {"attempts": [{"attempt_id": "a-1", "effect_id": "e-1", "status": "unknown", "recorded_at": FIRST.isoformat()}]}


@pytest.mark.parametrize(("offset", "state"), [
    (timedelta(seconds=300) - timedelta(microseconds=1), "horizon_passed_awaiting_escalation"),
    (timedelta(seconds=300), "horizon_passed_awaiting_escalation"),
    (timedelta(seconds=300, microseconds=1), "escalation_due"),
])
def test_escalation_is_due_only_strictly_after_the_deadline(offset, state):
    (item,) = dedupe.classify(DOC, PROFILE_DD, "none", FIRST + offset)
    assert item["state"] == state and item["escalation_deadline_at"] == (FIRST + timedelta(seconds=300)).isoformat()
    rows = dedupe.due_escalations(DOC, PROFILE_DD, "none", FIRST + offset, recorded_at=(FIRST + offset).isoformat())
    assert len(rows) == (state == "escalation_due")


def test_horizon_and_key_window_boundaries_are_unchanged():
    """The provider horizon is a window start (inclusive) and the key lifetime [first, first + ttl) a window: unchanged."""
    at = lambda s: FIRST + timedelta(seconds=s)  # noqa: E731
    assert [x["state"] for x in dedupe.classify(DOC, PROFILE_DD, "none", at(120))] == ["horizon_passed_awaiting_escalation"]
    assert [x["key_expired"] for x in dedupe.classify(DOC, PROFILE_DD, "none", at(600))] == [True]
    assert [x["key_expired"] for x in dedupe.classify(DOC, PROFILE_DD, "none", at(599))] == [False]


def test_dedupe_refuses_a_naive_attempt_time():
    doc = {"attempts": [dict(DOC["attempts"][0], recorded_at="2026-10-05T19:00:00")]}
    with pytest.raises(ValueError):
        dedupe.unresolved_effects(doc)
