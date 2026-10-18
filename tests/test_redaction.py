"""Tests for redacted exports."""

from __future__ import annotations

from agent_control_plane.models import RedactionConfig
from agent_control_plane.records import RunRecorder
from agent_control_plane.redaction import redact_replay_bundle, redact_run_record


def _build_record_and_bundle():
    recorder = RunRecorder()
    recorder.start_run(
        task="redaction test",
        actor="redaction-agent",
        environment="test",
        allowed_tools=["crm_read", "email_send"],
        blocked_tools=["email_send"],
        policy_version="v1.0",
    )
    action = recorder.propose_action(
        tool_name="email_send",
        action_type="external_send",
        target="customer@example.com",
        payload={"subject": "Status update"},
        reason="Send the update to the customer.",
    )
    recorder.evaluate_action(action)
    recorder.complete_run("Final reply body.")
    return recorder.to_run_record(), recorder.generate_replay_bundle()


def test_payloads_are_redacted_by_default() -> None:
    record, _ = _build_record_and_bundle()

    redacted = redact_run_record(record)

    assert redacted.actions[0].payload == {"redacted": True}


def test_targets_are_redacted_when_requested() -> None:
    record, _ = _build_record_and_bundle()

    redacted = redact_run_record(record, RedactionConfig(redact_targets=True))

    assert redacted.actions[0].target == "[REDACTED]"


def test_final_output_is_redacted_when_requested() -> None:
    record, _ = _build_record_and_bundle()

    redacted = redact_run_record(record, RedactionConfig(redact_final_output=True))

    assert redacted.final_output == "[REDACTED]"


def test_reasons_are_redacted_when_requested() -> None:
    record, _ = _build_record_and_bundle()

    redacted = redact_run_record(record, RedactionConfig(redact_reasons=True))

    assert redacted.actions[0].reason == "[REDACTED]"
    assert redacted.decisions[0].reason == "[REDACTED]"
    assert redacted.blocked_actions[0].reason == "[REDACTED]"
    assert redacted.policy_traces[0].rules_evaluated[-1].reason == "[REDACTED]"


def test_original_object_is_unchanged() -> None:
    record, _ = _build_record_and_bundle()
    original_payload = dict(record.actions[0].payload)

    redact_run_record(record, RedactionConfig(redact_targets=True, redact_reasons=True))

    assert record.actions[0].payload == original_payload
    assert record.actions[0].target == "customer@example.com"
    assert record.actions[0].reason == "Send the update to the customer."


def test_redacted_replay_bundle_preserves_ids_and_decision_fingerprints_when_kept() -> None:
    record, bundle = _build_record_and_bundle()

    redacted = redact_replay_bundle(
        bundle,
        RedactionConfig(
            redact_targets=True, redact_final_output=True, redact_reasons=True, keep_fingerprints=True
        ),
    )

    assert redacted.run_id == bundle.run_id
    assert redacted.replay_bundle_id == bundle.replay_bundle_id
    assert redacted.actions[0].action_id == bundle.actions[0].action_id
    assert (
        redacted.decisions[0].deterministic_fingerprint
        == record.decisions[0].deterministic_fingerprint
    )


def test_fingerprints_are_blanked_by_default_when_payloads_or_targets_are_redacted() -> None:
    record, bundle = _build_record_and_bundle()
    assert record.decisions[0].deterministic_fingerprint  # recorded
    for config in (RedactionConfig(), RedactionConfig(redact_payloads=False, redact_targets=True)):
        redacted_run = redact_run_record(record, config)
        redacted_bundle = redact_replay_bundle(bundle, config)
        for item in (redacted_run, redacted_bundle):
            assert all(d.deterministic_fingerprint == "" for d in item.decisions)
            assert all(t.deterministic_fingerprint == "" for t in item.policy_traces)
            assert item.decisions[0].decision_id == record.decisions[0].decision_id
    # the original is not changed
    assert record.decisions[0].deterministic_fingerprint


def test_fingerprints_are_kept_when_nothing_sensitive_is_redacted_or_when_asked() -> None:
    record, _ = _build_record_and_bundle()
    only_reasons = redact_run_record(record, RedactionConfig(redact_payloads=False, redact_reasons=True))
    assert only_reasons.decisions[0].deterministic_fingerprint == record.decisions[0].deterministic_fingerprint
    kept = redact_run_record(record, RedactionConfig(keep_fingerprints=True))
    assert kept.decisions[0].deterministic_fingerprint == record.decisions[0].deterministic_fingerprint


def test_a_low_entropy_target_is_not_recoverable_from_a_default_redacted_export() -> None:
    import hashlib  # noqa: F401  (the guess below would need the fingerprint; there is none)

    record, _ = _build_record_and_bundle()
    redacted = redact_run_record(record, RedactionConfig(redact_targets=True))
    assert redacted.decisions[0].deterministic_fingerprint == ""
    assert redacted.policy_traces[0].deterministic_fingerprint == ""
    assert "customer@example.com" not in redacted.model_dump_json()
