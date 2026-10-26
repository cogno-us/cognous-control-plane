"""runtime-authority-reasons/0.3: an immutable successor of the frozen 164-code 0.2 registry, adding the eight policy-binding codes.

* 0.1 (121 codes) and 0.2 (164 codes) are frozen byte-for-byte; the 164-code assertions elsewhere are unchanged.
* 0.3 holds the 164 entries of 0.2 unchanged and in order plus eight typed-only codes (172). A row carries 0.3 only when it carries one
  of the eight, so no existing row is relabelled and no historical code is reinterpreted.
* The eight names are PROPOSED and NOT RATIFIED by the owning component (docs/runtime-authority-reasons-0-3-code-ownership.md).
* A label identifies a file by its pinned sha256 (``registry_identity``). That is an integrity check against this build's own pin; it is
  NOT an authenticated production evidence chain (no signed mapping or trust-root contract exists; none was invented).
"""
import hashlib
import json
import pathlib

import pytest

from agent_control_plane.policy_binding import NEW_CODES
from agent_control_plane.runtime_authority import (
    CODES_ADDED_IN_0_2, CODES_ADDED_IN_0_3, REGISTRY_SHA256, VOCABULARY_VERSION, VOCABULARY_VERSION_0_2, VOCABULARY_VERSION_0_3,
    registry_admits, registry_identity, vocabulary_for,
)
from tests.test_bounded_authorization import NOW, PROFILE
from tests.test_policy_binding_approval_generation import adopt, binding, decide
from tests.test_runtime_authority import setup_flow

SCHEMAS = pathlib.Path(__file__).resolve().parents[1] / "schemas"
RAW = {label: (SCHEMAS / name).read_bytes() for label, name in (
    (VOCABULARY_VERSION, "runtime_authority_reasons_0_1.json"), (VOCABULARY_VERSION_0_2, "runtime_authority_reasons_0_2.json"),
    (VOCABULARY_VERSION_0_3, "runtime_authority_reasons_0_3.json"))}
R01, R02, R03 = (json.loads(RAW[x]) for x in (VOCABULARY_VERSION, VOCABULARY_VERSION_0_2, VOCABULARY_VERSION_0_3))
BLOB_0_2 = "a46ef35e7ece5c3a16e50d174000c49e3632eb12"      # the historical 164-code blob; also the git blob at base 7a4bcd40


def git_blob(raw: bytes) -> str:
    return hashlib.sha1(b"blob %d\0" % len(raw) + raw).hexdigest()


def test_each_label_is_pinned_to_its_file_and_0_2_is_the_historical_blob():
    for label, raw in RAW.items():
        assert hashlib.sha256(raw).hexdigest() == REGISTRY_SHA256[label] == registry_identity(label)
    assert git_blob(RAW[VOCABULARY_VERSION_0_2]) == BLOB_0_2
    assert len({REGISTRY_SHA256[x] for x in RAW}) == 3
    assert set(REGISTRY_SHA256) == set(RAW)


def test_0_2_is_still_the_164_code_registry():
    kinds = [v["reason_kind"] for v in R02["codes"].values()]
    assert R02["version"] == VOCABULARY_VERSION_0_2 and (len(kinds), kinds.count("typed_only"), kinds.count("recomputable")) == (164, 163, 1)
    assert not set(NEW_CODES) & set(R02["codes"])


def test_0_3_is_the_172_code_immutable_successor():
    kinds = [v["reason_kind"] for v in R03["codes"].values()]
    assert R03["version"] == VOCABULARY_VERSION_0_3 == "runtime-authority-reasons/0.3"
    assert (len(kinds), kinds.count("typed_only"), kinds.count("recomputable")) == (172, 171, 1)
    assert all(R03["codes"][c] == spec for c, spec in R02["codes"].items()), "every 0.2 entry is unchanged in 0.3"
    assert list(R03["codes"])[:len(R02["codes"])] == list(R02["codes"]), "and keeps its position"
    assert list(R03["codes"])[len(R02["codes"]):] == list(NEW_CODES)
    assert set(R03["codes"]) - set(R02["codes"]) == CODES_ADDED_IN_0_3 == set(NEW_CODES) and len(CODES_ADDED_IN_0_3) == 8
    assert not CODES_ADDED_IN_0_3 & CODES_ADDED_IN_0_2
    for code in NEW_CODES:
        assert R03["codes"][code]["reason_kind"] == "typed_only" and "policy-binding/0.1 only" in R03["codes"][code]["description"], code


@pytest.mark.parametrize("reasons,label", [
    ([], VOCABULARY_VERSION),
    (["grant_revoked"], VOCABULARY_VERSION),
    (["check_overdue"], VOCABULARY_VERSION_0_2),                                   # an existing 0.2 row keeps 0.2
    (["policy_binding_invalid"], VOCABULARY_VERSION_0_3),
    (["grant_revoked", "freshness_ceiling_exceeded"], VOCABULARY_VERSION_0_3),     # mixed: the superset label resolves both
    (["check_overdue", "approval_policy_generation_mismatch"], VOCABULARY_VERSION_0_3),
])
def test_a_row_carries_0_3_only_when_it_has_one_of_the_eight_codes(reasons, label):
    assert vocabulary_for(reasons) == label


def test_every_code_resolves_under_the_label_it_gets_and_no_old_code_moves():
    for code in R03["codes"]:
        label = vocabulary_for([code])
        assert code in {VOCABULARY_VERSION: R01, VOCABULARY_VERSION_0_2: R02, VOCABULARY_VERSION_0_3: R03}[label]["codes"]
        assert (label == VOCABULARY_VERSION_0_3) == (code in CODES_ADDED_IN_0_3)
    for code in R02["codes"]:
        assert vocabulary_for([code]) != VOCABULARY_VERSION_0_3, "a 0.2 code never moves a row to 0.3"


@pytest.mark.parametrize("label", ["", "runtime-authority-reasons/0.4", "runtime-authority-reasons/0", "RUNTIME-AUTHORITY-REASONS/0.3", None, 3, b"x",
                                   ["runtime-authority-reasons/0.3"]])
def test_an_unsupported_label_fails_closed_with_no_fallback(label):
    with pytest.raises(ValueError):
        registry_identity(label)
    assert registry_admits(label, [], R03["codes"]) is False


def test_registry_admits_refuses_a_code_the_label_does_not_register_and_an_unlisted_code():
    both = {**R03["codes"]}
    assert registry_admits(VOCABULARY_VERSION_0_3, ["policy_binding_invalid", "grant_revoked", "check_overdue"], both) is True
    assert registry_admits(VOCABULARY_VERSION_0_2, ["policy_binding_invalid"], both) is False
    assert registry_admits(VOCABULARY_VERSION, ["policy_binding_invalid"], both) is False
    assert registry_admits(VOCABULARY_VERSION, ["check_overdue"], both) is False
    assert registry_admits(VOCABULARY_VERSION_0_2, ["check_overdue"], R02["codes"]) is True
    assert registry_admits(VOCABULARY_VERSION_0_3, ["not_a_registered_code"], R03["codes"]) is False   # existence needs the loaded registry
    assert registry_admits(VOCABULARY_VERSION_0_3, ["policy_binding_invalid"], R03["codes"]) is True
    assert registry_admits(VOCABULARY_VERSION_0_3, ["policy_binding_invalid"], R02["codes"]) is False
    for bad in ("policy_binding_invalid", None, [None], [b"x"], 5):
        assert registry_admits(VOCABULARY_VERSION_0_3, bad, R03["codes"]) is False
    with pytest.raises(TypeError):
        registry_admits(VOCABULARY_VERSION_0_3, ["policy_binding_invalid"])   # the loaded registry is required, never defaulted


def test_the_rows_of_a_policy_binding_hold_carry_0_3_and_default_rows_keep_0_1(tmp_path):
    p, r, f, c = setup_flow(tmp_path)
    d0 = decide(f, p)
    assert d0.result == "authorized" and d0.reason_vocabulary_version == VOCABULARY_VERSION
    adopt(r, f, c, binding(), issue=False)                                # legacy approval under a binding profile: held
    d1 = decide(f, p)
    assert d1.result == "hold" and "approval_policy_generation_missing" in d1.reasons
    assert d1.reason_vocabulary_version == VOCABULARY_VERSION_0_3
    assert registry_admits(d1.reason_vocabulary_version, d1.reasons, R03["codes"])
    completed = [e for e in f.records.load().check_events if e.phase == "completed"]
    assert completed[0].reason_vocabulary_version == VOCABULARY_VERSION and completed[-1].reason_vocabulary_version == VOCABULARY_VERSION_0_3
