"""The reason registry is two labels: 0.1 (the original 121 codes, a pinned file) and 0.2 (the full set, 0.1 plus the opt-in profile codes).

Background (review R1 finding 4): the registry grew from 121 to 139 codes (N1, N3, N5) and then further (N4) under the single label
`runtime-authority-reasons/0.1`, while docs and a test said it was unchanged. Now:

* `schemas/runtime_authority_reasons_0_1.json` is the original 121 codes, byte-identical to its form at commit 2936e3f (the last
  commit before any profile code was added; sha256 below). Nothing may edit it.
* `schemas/runtime_authority_reasons_0_2.json` is the full set. It is a superset (not only the additions) because one row can mix codes of
  both and carries exactly one label, which must resolve all of its codes.
* A row carries 0.1 unless one of its reasons is a code only 0.2 registers, so every default-path row is byte-identical to before.
"""
import hashlib
import json
import pathlib

import pytest

import agent_control_plane.bounded as bounded
from agent_control_plane.runtime_authority import (CODES_ADDED_IN_0_2, VOCABULARY_VERSION, VOCABULARY_VERSION_0_2, vocabulary_for)

SCHEMAS = pathlib.Path(__file__).resolve().parents[1] / "schemas"
RAW_0_1 = (SCHEMAS / "runtime_authority_reasons_0_1.json").read_bytes()
RAW_0_2 = (SCHEMAS / "runtime_authority_reasons_0_2.json").read_bytes()
R01, R02 = json.loads(RAW_0_1), json.loads(RAW_0_2)
#: sha256 of the 121-code file as committed at 2936e3f ("Register every emitted runtime-authority reason code"), before N1 added a code.
#: Default-path manifest-gate and authority-limit codes added after 0.1 was pinned; they belong to no opt-in profile, so a refusal row that
#: carries one gets label 0.2 (the only file that can register them).
SCAN3_DEFAULT_PATH_CODES = frozenset({"action_blocked", "missing_effect_limits", "missing_amount_limit",
                                      "effect_limit_malformed", "authority_limit_malformed",
                                      "invalid_manifest"})
PINNED_0_1_SHA256 = "fbc4df2e02457e294ca1f819d0e507c4452e46691e4f139a66be48967c2096c0"


def test_the_0_1_file_is_the_original_121_codes_byte_identical_to_its_pinned_form():
    assert hashlib.sha256(RAW_0_1).hexdigest() == PINNED_0_1_SHA256
    kinds = [v["reason_kind"] for v in R01["codes"].values()]
    assert R01["version"] == VOCABULARY_VERSION == "runtime-authority-reasons/0.1"
    assert (len(kinds), kinds.count("typed_only"), kinds.count("recomputable")) == (121, 120, 1)


def test_the_0_2_file_is_the_full_superset_of_0_1():
    kinds = [v["reason_kind"] for v in R02["codes"].values()]
    assert R02["version"] == VOCABULARY_VERSION_0_2 == "runtime-authority-reasons/0.2"
    assert (len(kinds), kinds.count("typed_only"), kinds.count("recomputable")) == (164, 163, 1)
    assert all(R02["codes"][code] == spec for code, spec in R01["codes"].items()), "every 0.1 entry is unchanged in 0.2"
    assert list(R02["codes"])[:len(R01["codes"])] == list(R01["codes"]), "and keeps its position"
    assert set(R02["codes"]) - set(R01["codes"]) == CODES_ADDED_IN_0_2 and len(CODES_ADDED_IN_0_2) == 43
    assert set(R01["codes"]) <= set(R02["codes"])


def test_every_added_code_belongs_to_an_opt_in_profile():
    """The 0.2 additions are only ever emitted by opt-in profiles, which is why the default path never carries label 0.2."""
    for code in CODES_ADDED_IN_0_2 - SCAN3_DEFAULT_PATH_CODES:
        assert "/0.1" in R02["codes"][code]["description"], code  # each names its profile, for example freshness/0.1


@pytest.mark.parametrize("reasons,label", [
    ([], VOCABULARY_VERSION),
    (["grant_revoked"], VOCABULARY_VERSION),
    (["grant_revoked", "status_unreadable", "check_interrupted"], VOCABULARY_VERSION),
    (["check_overdue"], VOCABULARY_VERSION_0_2),
    (["grant_revoked", "operation_not_admitted"], VOCABULARY_VERSION_0_2),  # mixed: the superset label resolves both
])
def test_a_row_carries_0_2_only_when_it_has_a_code_only_0_2_registers(reasons, label):
    assert vocabulary_for(reasons) == label


def test_every_code_resolves_under_the_label_the_row_gets():
    for code in R02["codes"]:
        label = vocabulary_for([code])
        assert code in (R01["codes"] if label == VOCABULARY_VERSION else R02["codes"])
        assert (label == VOCABULARY_VERSION_0_2) == (code in CODES_ADDED_IN_0_2)
    for code in R01["codes"]:
        assert vocabulary_for([code]) == VOCABULARY_VERSION, "an original code never moves a row to 0.2"


def test_default_path_rows_keep_label_0_1(tmp_path, monkeypatch):
    from tests.test_bounded_authorization import NOW
    from tests.test_runtime_authority import setup_flow
    monkeypatch.setattr(bounded, "_now", lambda: NOW)
    p, r, f, c = setup_flow(tmp_path)
    next(iter(r.statuses.values())).status = "revoked"
    held = f.decide(p, now=NOW)
    assert held.result == "hold" and "grant_revoked" in held.reasons
    assert held.reason_vocabulary_version == VOCABULARY_VERSION
    completed = [e for e in f.records.load().check_events if e.phase == "completed"]
    assert completed and {e.reason_vocabulary_version for e in completed} == {VOCABULARY_VERSION}


def test_profile_rows_with_a_0_2_code_carry_0_2_on_the_decision_the_refusal_and_the_journal_event(tmp_path, monkeypatch):
    """A decision held by an opt-in profile code, an effect-time refusal by one, and the journal events that name one."""
    from tests.test_bounded_authorization import NOW
    from tests.test_dedupe import PROFILE, flow as dedupe_flow, go, ForgetfulDestination
    from tests.test_operation_identity import ISSUER, OPERATION, renew
    monkeypatch.setattr(bounded, "_now", lambda: NOW)
    p, r, f, c = dedupe_flow(tmp_path, monkeypatch, destination=lambda path: ForgetfulDestination(path), profile=PROFILE)
    d1 = f.decide(p, now=NOW)
    go(f, p, d1)
    f.destination.expire_keys()
    renew(r, f.runtime_authority_profile, "2")
    f.record_renewal(OPERATION, to_revision="2", written_by=ISSUER, now=NOW)
    d2 = f.decide(p, now=NOW)
    with pytest.raises(PermissionError):
        go(f, p, d2)
    record = f.records.load()
    assert record.refusals[-1].reasons == ["dedupe_operation_effect_applied"]
    assert record.refusals[-1].reason_vocabulary_version == VOCABULARY_VERSION_0_2
    assert d1.reason_vocabulary_version == VOCABULARY_VERSION and d2.reason_vocabulary_version == VOCABULARY_VERSION
    assert all(e.reason_vocabulary_version == vocabulary_for(e.reasons) for e in record.check_events if e.phase == "completed")


def test_a_held_decision_with_a_0_2_code_and_its_completed_event_carry_0_2(tmp_path, monkeypatch):
    from tests.test_bounded_authorization import NOW
    from tests.test_operation_identity import enable
    from tests.test_runtime_authority import setup_flow
    monkeypatch.setattr(bounded, "_now", lambda: NOW)
    p, r, f, c = setup_flow(tmp_path)
    enable(r, f, c, operation_id=None)  # operation-identity/0.1 with no operation id in the approved extension
    d = f.decide(p, now=NOW)
    assert d.result == "hold" and "operation_id_missing" in d.reasons
    assert d.reason_vocabulary_version == VOCABULARY_VERSION_0_2
    (event,) = [e for e in f.records.load().check_events if e.phase == "completed"]
    assert "operation_id_missing" in event.reasons and event.reason_vocabulary_version == VOCABULARY_VERSION_0_2
