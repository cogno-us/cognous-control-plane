"""V02 / EXT-S4-4 AR-20 LEGACY COMPATIBILITY: byte-identical no-binding claims.

The frozen vectors in tests/fixtures/v02_legacy_claim_vectors.json were generated on the UNMODIFIED base fff27ebf (R6) BEFORE any V02 source
change and committed with the test inventory. These tests must PASS on the base and keep passing after the change.

  L-01 issuance reproduces each frozen claim byte-for-byte (JSON text, claim_commitment, canonical-bytes digest) under deterministic uuids
  L-02 the frozen claims verify, as model instances and as dictionaries; their commitments recompute
  L-03 model round trip is byte-stable and emits no policy_binding key
  L-04 legacy profile constant unchanged; legacy claims carry exactly the pre-V02 member set
  L-05 protected files are byte-identical to the base: bounded.py (commitment, no semantic edit), policy_binding.py, runtime_authority.py
  L-06 legacy refusals are unchanged (tampered claim, stale commitment)

Synthetic fixtures only. Builder-authored; not independent qualification.
"""
from __future__ import annotations

import copy
import hashlib
import json
import subprocess
from pathlib import Path

import pytest

from agent_control_plane.bounded import _canonical_bytes, commitment
from agent_control_plane.local_authority_effect import (
    LOCAL_AUTHORITY_EFFECT_PROFILE,
    LocalExecutionClaim,
    TenantLocalExecutionClaim,
    verify_local_execution_claim,
)
from tests.v02_support import VECTORS, build_legacy_vectors

ROOT = Path(__file__).resolve().parent.parent
FROZEN = json.loads(VECTORS.read_text(encoding="utf-8"))
PROTECTED_BLOBS = {  # git blob ids at the base fff27ebf356007e1eb3bb24198efc7e3e3f0c5eb
    "src/agent_control_plane/bounded.py": "2cc8d998ff0a8fec3112a8b0634111fcf8fbef17",
    "src/agent_control_plane/policy_binding.py": "426d47797e92f19690a21b4e8b5dc1c35d1b579c",
    "src/agent_control_plane/runtime_authority.py": "0b2c5e49c0cd3e0738e5c4c9e9d4fc8590563fa2",
}
CLASSES = {"LocalExecutionClaim": LocalExecutionClaim, "TenantLocalExecutionClaim": TenantLocalExecutionClaim}


@pytest.fixture(scope="module")
def regenerated():
    return build_legacy_vectors()


def test_frozen_inventory():
    assert sorted(FROZEN) == ["decision_input", "plain", "tenant"]
    assert LOCAL_AUTHORITY_EFFECT_PROFILE == "urn:cognous:profiles:local-authority-effect:0.1.0-proposed"


@pytest.mark.parametrize("name", ["plain", "decision_input", "tenant"])
def test_l01_issuance_reproduces_the_frozen_claim_byte_for_byte(regenerated, name):
    assert regenerated[name] == FROZEN[name]
    assert regenerated[name]["claim_json"].encode("utf-8") == FROZEN[name]["claim_json"].encode("utf-8")


@pytest.mark.parametrize("name", ["plain", "decision_input", "tenant"])
def test_l02_frozen_claims_verify_and_commitments_recompute(name):
    entry = FROZEN[name]
    raw = json.loads(entry["claim_json"])
    assert verify_local_execution_claim(raw) is True
    model = CLASSES[entry["claim_class"]].model_validate(raw)
    assert verify_local_execution_claim(model) is True
    body = {k: v for k, v in raw.items() if k != "claim_commitment"}
    assert commitment(body) == raw["claim_commitment"] == entry["claim_commitment"]
    assert hashlib.sha256(_canonical_bytes(raw)).hexdigest() == entry["canonical_bytes_sha256"]


@pytest.mark.parametrize("name", ["plain", "decision_input", "tenant"])
def test_l03_round_trip_is_byte_stable_and_emits_no_binding_key(name):
    entry = FROZEN[name]
    model = CLASSES[entry["claim_class"]].model_validate_json(entry["claim_json"])
    assert model.model_dump_json() == entry["claim_json"]
    dumped = model.model_dump(mode="json", exclude_none=False)
    assert sorted(dumped) == entry["keys"] and "policy_binding" not in dumped
    assert getattr(model, "policy_binding", None) is None


@pytest.mark.parametrize("name", ["plain", "decision_input", "tenant"])
def test_l04_legacy_claims_carry_the_legacy_profile(name):
    raw = json.loads(FROZEN[name]["claim_json"])
    assert raw["profile"] == LOCAL_AUTHORITY_EFFECT_PROFILE
    assert raw["authorizing_by_possession"] is False and raw["source"] == "trusted_control_plane_workflow"


@pytest.mark.parametrize("path,blob", sorted(PROTECTED_BLOBS.items()))
def test_l05_protected_sources_are_byte_identical_to_the_base(path, blob):
    got = subprocess.run(["git", "hash-object", path], cwd=ROOT, capture_output=True, text=True, check=True).stdout.strip()
    assert got == blob, f"{path} changed: V02 must not edit it"


def test_l06_legacy_refusals_are_unchanged():
    raw = json.loads(FROZEN["plain"]["claim_json"])
    tampered = copy.deepcopy(raw)
    tampered["target"] = "acct:other"
    assert verify_local_execution_claim(tampered) is False
    stale = copy.deepcopy(raw)
    stale["claim_commitment"] = "sha256:" + "0" * 64
    assert verify_local_execution_claim(stale) is False
    other_profile = copy.deepcopy(raw)
    other_profile["profile"] = "urn:cognous:profiles:local-authority-effect:9.9.9"
    assert verify_local_execution_claim(other_profile) is False
