"""The control plane accepts exactly the governance Authority Context generations 0.1.0 and 0.2.0.

delay_limit (0.2.0) is a declaration only: the control plane reads no value from it and applies no default delay.
"""
from __future__ import annotations

import pytest

from agent_control_plane import bounded
from tests.test_bounded_authorization import NOW, PROFILE, proposal, resolver_for, workflow

DECLARED = {"max_pending_seconds": 3600, "on_miss": "defer_with_reason"}


def _decide(tmp_path, version, delay_limit):
    p = proposal()
    resolver = resolver_for(p)
    context = resolver.contexts[PROFILE]
    context["schema_version"] = version
    consequence = context["requirement"]["consequence"]
    consequence.pop("delay_limit", None)
    if delay_limit is not None:
        consequence["delay_limit"] = delay_limit
    return workflow(tmp_path, p, resolver=resolver).decide(p, now=NOW)


def test_supported_versions_are_listed_explicitly():
    assert tuple(bounded.AUTHORITY_CONTEXT_VERSIONS) == ("0.1.0", "0.2.0")


@pytest.mark.parametrize("version,delay_limit", [("0.1.0", None), ("0.2.0", DECLARED)])
def test_each_supported_generation_is_accepted_and_recorded_as_declared(tmp_path, version, delay_limit):
    decision = _decide(tmp_path, version, delay_limit)
    assert decision.result == "authorized", decision.reasons
    assert "authority_context_version_mismatch" not in decision.reasons


@pytest.mark.parametrize("version", ["0.3.0", "0.1", "", None, 1, ["0.2.0"]])
def test_other_versions_are_refused(tmp_path, version):
    decision = _decide(tmp_path, version, DECLARED)
    assert decision.result != "authorized"
    assert "authority_context_version_mismatch" in decision.reasons


@pytest.mark.parametrize("delay_limit", [
    {"max_pending_seconds": 1, "on_miss": "defer_with_reason"},
    {"max_pending_seconds": 10**9, "on_miss": "escalate_to_alternate_reviewer"},
])
def test_delay_limit_is_declaration_only(tmp_path, delay_limit):
    """A later change that enforces delay_limit must be deliberate and replace this test."""
    baseline = _decide(tmp_path / "a", "0.2.0", DECLARED)
    other = _decide(tmp_path / "b", "0.2.0", delay_limit)
    assert (other.result, other.reasons) == (baseline.result, baseline.reasons)


def test_no_default_delay_is_applied_to_a_0_1_0_context(tmp_path):
    decision = _decide(tmp_path, "0.1.0", None)
    assert decision.result == "authorized"
    assert not any("delay" in reason for reason in decision.reasons)
