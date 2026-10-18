"""The rule-revision trend helpers read times with the one strict instant parser."""

from __future__ import annotations

import pytest

from agent_control_plane.reason_vocabulary import (
    VocabularyChange,
    _annotate_adoption,
    adoption_times,
    measured_arity,
)
from agent_control_plane.time_instant import InstantError

BAD_FORMS = [
    "2026-10-05 19:00:00+00:00",   # space separator
    "2026-10-05T19:00:00",         # no offset
    "2026-10-05T19:00:00.1234567Z",  # seventh fraction digit
    "2026-10-05T24:00:00Z",        # hour 24
    "2026-10-05",                  # date only
]


def _change(version: str, at: str) -> dict:
    return {"version": version, "acknowledged_at": at}


def _revision(label: str, at: str) -> dict:
    return {"rule_kind": "reason_registry", "rule_ref": label, "recorded_at": at}


def test_valid_instants_give_the_same_results_as_before() -> None:
    changes = [_change("v2", "2026-10-05T19:00:00Z"), _change("v2", "2026-10-05T18:00:00+00:00")]
    revisions = [_revision("v3", "2026-10-06T10:00:00.5-02:00")]
    assert adoption_times(changes, revisions) == {"v2": "2026-10-05T18:00:00+00:00", "v3": "2026-10-06T10:00:00.5-02:00"}
    rows = [{"reasons": ["a"], "decided_at": "2026-10-05T19:30:00Z", "resolution_inputs": []},
            {"reasons": ["a"], "decided_at": "2026-10-05T10:00:00Z", "resolution_inputs": []}]
    out = measured_arity(rows, as_of="2026-10-05T20:00:00Z", period_seconds=3600)
    assert out["codes"]["a"]["measured"] == 1


@pytest.mark.parametrize("bad", BAD_FORMS)
def test_adoption_times_refuses_loose_forms(bad: str) -> None:
    with pytest.raises(ValueError):
        adoption_times([_change("v2", "2026-10-05T19:00:00Z"), _change("v2", bad)], [])


@pytest.mark.parametrize("bad", BAD_FORMS)
def test_measured_arity_refuses_loose_forms(bad: str) -> None:
    rows = [{"reasons": ["a"], "decided_at": bad, "resolution_inputs": []}]
    with pytest.raises(ValueError):
        measured_arity(rows, as_of="2026-10-05T20:00:00Z", period_seconds=3600)
    with pytest.raises(ValueError):
        measured_arity([], as_of=bad, period_seconds=3600)


def test_annotate_adoption_refuses_loose_row_time() -> None:
    report = {"series": []}
    changes = [_change("v2", "2026-10-05T19:00:00Z")]
    rows = [{"reason_vocabulary_version": "v2", "decided_at": "2026-10-05 18:00:00+00:00", "reasons": []}]
    with pytest.raises(ValueError):
        _annotate_adoption(report, rows, [], changes, [])


def test_refusal_is_an_instant_error() -> None:
    with pytest.raises(InstantError):
        adoption_times([_change("v2", "2026-10-05T19:00:00Z"), _change("v2", "2026-10-05 19:00:00+00:00")], [])
