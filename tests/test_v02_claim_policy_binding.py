"""V02 / EXT-S4-4 acceptance oracles: claim-carried canonical policy binding (ocs-policy-binding/1) under a successor claim profile.

PREDECLARED INVENTORY. This file was committed BEFORE any V02 source change; expected outcomes are the assertions below.
BUILDER_TESTED developer demonstration. NOT independently qualified. NOT operational authorization: a claim-carried binding authorizes
nothing; Runtime must compare it with durable active authority under the destination transaction lock (V04/V05, not implemented here).

  A   canonical binding validator and Registry golden vectors (15 valid / 128 invalid / integer-boundary / identifier matrix)
  AR-01 BINDING INTEGRITY    B-01..B-17, C-xx   altered member, stale commitment, edited JSON, substitution, wrong profile, malformed structure
  AR-06 AUTHORITY SEPARATION D-01..D-10         grant/approval separation, identity consistency, activation identity, no independent authority
  AR-20 LEGACY COMPATIBILITY tests/test_v02_legacy_claim_vector.py (frozen byte vectors, generated on the unmodified base)

The Registry vectors are read from a checkout named by OCS_REGISTRY_PIN_DIR (exact pin verified below); without it the vector tests are NOT RUN
(skipped with a reason). No Registry code is imported or copied into the Control Plane.
"""
from __future__ import annotations

import copy
import json
import os
import subprocess
from pathlib import Path

import pytest
from pydantic import ValidationError

from agent_control_plane.bounded import _canonical_bytes, commitment
from agent_control_plane.canonical_policy_binding import BINDING_PROFILE, binding_defect, binding_digest
from agent_control_plane.local_authority_effect import (
    LOCAL_AUTHORITY_EFFECT_PROFILE,
    LOCAL_AUTHORITY_EFFECT_PROFILE_V2,
    LocalExecutionClaim,
    TenantLocalExecutionClaim,
    materialize_local_execution_claim,
    provision_local_execution_claim,
    verify_local_execution_claim,
)
from agent_control_plane.policy_binding import PolicyBinding
from agent_control_plane.strict_json import strict_loads
from tests.test_bounded_authorization import TENANT
from tests.test_bounded_authorization import NOW as TENANT_NOW
from tests.v02_support import (
    CONSUMER, LEGACY_NOW, OPERATION, canonical_binding, deterministic_uuids, legacy_flow, reference_binding_digest, sha, tenant_flow,
)

PIN = "943ab1831e39fadac1eb2a414ae322ccfa09bc6a"
VECTOR_BLOB = "00e1cdd428ab9943570fd5a319549832b6178e20"
VECTOR_REL = "docs/ext-implementation/data/ext-s1-5-policy-identity-vectors.json"
TOP = ["binding_profile", "record_id", "record_version", "record_digest", "selection_id", "selection_epoch", "selection_digest", "family",
       "consumer_id", "scope", "operation", "effective_policy_digest", "activation_ref", "trust_snapshot_version", "trust_snapshot_fingerprint"]
SCOPE = ["tenant", "institution", "authority_domain"]
PATHS = [m for m in TOP] + [f"scope.{s}" for s in SCOPE]


# ---------------------------------------------------------------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------------------------------------------------------------
def vectors():
    pin = os.environ.get("OCS_REGISTRY_PIN_DIR")
    if not pin or not (Path(pin) / VECTOR_REL).is_file():
        pytest.skip("NOT RUN: OCS_REGISTRY_PIN_DIR is not set to a Registry checkout containing the binding vectors")
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=pin, capture_output=True, text=True, check=True).stdout.strip()
    assert head == PIN, f"Registry checkout is {head}, expected the pin {PIN}"
    return json.loads((Path(pin) / VECTOR_REL).read_text(encoding="ascii")), Path(pin)


def load(text_or_bytes):
    return strict_loads(text_or_bytes)


def refused(obj_or_loader) -> bool:
    """True when the Control Plane text boundary or the binding validator refuses."""
    try:
        obj = obj_or_loader() if callable(obj_or_loader) else obj_or_loader
    except Exception:
        return True
    return binding_defect(obj) is not None


def get(b, path):
    for part in path.split("."):
        b = b[part]
    return b


def put(b, path, value):
    b = copy.deepcopy(b)
    cur = b
    parts = path.split(".")
    for part in parts[:-1]:
        cur = cur[part]
    cur[parts[-1]] = value
    return b


def mutated_value(value):
    if type(value) is int:
        return value + 1
    if isinstance(value, str) and value.startswith("sha256:"):
        return sha("f") if value != sha("f") else sha("9")
    if value == BINDING_PROFILE:
        return "ocs-policy-binding/2"
    return value + "x"


def resign(raw, **updates):
    """A self-consistent forgery: apply updates then recompute the claim commitment (the commitment is not a signature)."""
    raw = copy.deepcopy(raw)
    for k, v in updates.items():
        if v is _DROP:
            raw.pop(k, None)
        else:
            raw[k] = v
    raw.pop("claim_commitment", None)
    raw["claim_commitment"] = commitment(raw)
    return raw


_DROP = object()


def issue(tmp_path, b=None, *, consumer=CONSUMER, operation=OPERATION, claim_id="claim-v02-1", provision=None, **flow_kw):
    b = canonical_binding() if b is None else b
    p, r, f, d, cfg = tenant_flow(tmp_path, b, **flow_kw)
    kw = dict(now=TENANT_NOW, claim_id=claim_id, policy_binding=b, expected_consumer_id=consumer, expected_operation=operation)
    if provision is not None:
        claim = provision_local_execution_claim(f, p, d, provision=provision, **kw)
    else:
        claim = materialize_local_execution_claim(f, p, d, **kw)
    return claim, (p, r, f, d, cfg)


@pytest.fixture
def uuids():
    with deterministic_uuids():
        yield


def last_claim_reasons(flow):
    checks = flow.records.load().resolution_checks
    assert checks and checks[-1].stage == "claim"
    return list(checks[-1].reasons)


# ---------------------------------------------------------------------------------------------------------------------------------
# A. canonical binding validator and Registry golden vectors
# ---------------------------------------------------------------------------------------------------------------------------------
def test_a00_profile_constant_and_reference_digest_agree():
    assert BINDING_PROFILE == "ocs-policy-binding/1"
    b = canonical_binding()
    assert binding_defect(b) is None
    assert binding_digest(b) == reference_binding_digest(b)
    assert binding_digest(b).startswith("sha256:") and binding_digest(b) == binding_digest(copy.deepcopy(b))


def test_a01_registry_pin_and_inventory_are_exact():
    v, pin = vectors()
    blob = subprocess.run(["git", "hash-object", str(pin / VECTOR_REL)], capture_output=True, text=True, check=True).stdout.strip()
    assert blob == VECTOR_BLOB
    assert len(v["valid"]) == 15 and len(v["invalid"]) == 128 and len(v["integer_boundary"]) == 31


def test_a02_valid_vectors_validate_and_are_byte_identical_to_the_registry():
    v, _ = vectors()
    for vec in v["valid"]:
        obj = load(vec["input_json"])
        assert binding_defect(obj) is None, vec["id"]
        exp = vec["expected"]
        assert _canonical_bytes(obj).hex() == exp["canonical_bytes_hex"], vec["id"]  # the existing Control Plane serializer
        assert _canonical_bytes(obj).decode("ascii") == exp["canonical_ascii"], vec["id"]
        assert binding_digest(obj) == exp["binding_digest"], vec["id"]
        assert binding_digest(obj) != exp["digest_without_prefix_control"], vec["id"]


def test_a03_equivalence_and_difference_relations_hold():
    v, _ = vectors()
    by_id = {vec["id"]: vec for vec in v["valid"]}
    for vec in v["valid"]:
        mine = _canonical_bytes(load(vec["input_json"]))
        for other in ([vec["equivalent_to"]] if vec.get("equivalent_to") else []):
            assert mine == _canonical_bytes(load(by_id[other]["input_json"])), (vec["id"], other)
        for other in vec.get("must_differ_from") or []:
            assert mine != _canonical_bytes(load(by_id[other]["input_json"])), (vec["id"], other)


def test_a04_every_invalid_vector_is_refused():
    v, _ = vectors()
    escaped = []
    for vec in v["invalid"]:
        data = bytes.fromhex(vec["input_hex"]) if "input_hex" in vec else vec["input_json"]
        if not refused(lambda: load(data)):
            escaped.append(vec["id"])
    assert escaped == []


def test_a05_integer_boundary_vectors():
    v, _ = vectors()
    for vec in v["integer_boundary"]:
        exp = vec["expected"]
        if exp["result"] == "valid":
            obj = load(vec["input_json"])
            assert binding_defect(obj) is None and _canonical_bytes(obj).hex() == exp["canonical_bytes_hex"] and binding_digest(obj) == exp["binding_digest"], vec["id"]
        else:
            assert refused(lambda: load(vec["input_json"])), vec["id"]


def test_a06_identifier_matrix_every_bad_value_in_every_identifier_member():
    v, _ = vectors()
    matrix = v["identifier_matrix"]
    for member in matrix["members"]:
        for bad in matrix["bad_values"]:
            assert binding_defect(put(canonical_binding(), member, bad["value"])) is not None, (member, bad["id"])


def test_a07_missing_extra_and_wrongly_typed_members():
    b = canonical_binding()
    for path in PATHS:
        missing = copy.deepcopy(b)
        parent = missing if "." not in path else missing[path.split(".")[0]]
        del parent[path.split(".")[-1]]
        assert binding_defect(missing) is not None, path
    assert binding_defect({**b, "extra": 1}) is not None
    assert binding_defect({**b, "scope": {**b["scope"], "extra": "x"}}) is not None
    assert binding_defect({**b, "scope.tenant": "x"}) is not None  # a literal dotted key never fills the nested member
    for path in PATHS:
        for wrong in (None, 1.5, [], {}, True, b"x"):
            if path == "scope" and wrong == {}:
                continue
            assert binding_defect(put(b, path, wrong)) is not None, (path, wrong)
    for bad in (None, [], "x", 1, (), {}):
        assert binding_defect(bad) is not None


def test_a08_strict_integers_digests_and_identifiers():
    b = canonical_binding()
    for path, low, high in (("record_version", 1, 2**31 - 1), ("selection_epoch", 1, 2**31 - 1), ("trust_snapshot_version", 1, 2**53 - 1)):
        assert binding_defect(put(b, path, low)) is None and binding_defect(put(b, path, high)) is None
        for bad in (0, -1, high + 1, True, False, 1.0, "1", None):
            assert binding_defect(put(b, path, bad)) is not None, (path, bad)
    good = "sha256:" + "ab" * 32
    for path in ("record_digest", "selection_digest", "effective_policy_digest", "activation_ref", "trust_snapshot_fingerprint"):
        assert binding_defect(put(b, path, good)) is None
        for bad in ("sha256:" + "AB" * 32, "sha256:" + "a" * 63, "sha256:" + "a" * 65, "a" * 64, good + "\n", " " + good, "sha256:" + "g" * 64, "SHA256:" + "a" * 64, None):
            assert binding_defect(put(b, path, bad)) is not None, (path, bad)
    for path in ("record_id", "selection_id", "family", "consumer_id", "operation", "scope.tenant", "scope.institution", "scope.authority_domain"):
        assert binding_defect(put(b, path, "A" + "z" * 127)) is None
        for bad in ("", "a" * 129, ".a", "_a", "-a", ":a", "a b", "a/b", "a*", "a\n", "café", "Ａ", "á", "a\x00", "\U0001f600"):
            assert binding_defect(put(b, path, bad)) is not None, (path, bad)
    assert binding_defect(put(b, "binding_profile", "ocs-policy-binding/2")) is not None


def test_a09_subclasses_and_non_dict_containers_are_refused():
    class S(str):
        pass

    class I(int):
        pass

    class D(dict):
        pass
    b = canonical_binding()
    assert binding_defect(put(b, "record_id", S("rec-1"))) is not None
    assert binding_defect(put(b, "record_version", I(2))) is not None
    assert binding_defect(D(b)) is not None
    assert binding_defect(put(b, "scope", D(b["scope"]))) is not None


def test_a10_digest_refuses_a_defective_binding_and_does_not_mutate_input():
    b = canonical_binding()
    snapshot = copy.deepcopy(b)
    binding_digest(b)
    assert b == snapshot
    with pytest.raises(ValueError):
        binding_digest(put(b, "record_id", "bad id"))
    reordered = dict(reversed(list(b.items())))
    assert binding_digest(reordered) == binding_digest(b)


# ---------------------------------------------------------------------------------------------------------------------------------
# B. AR-01 binding integrity (claim model, commitment, verification)
# ---------------------------------------------------------------------------------------------------------------------------------
def test_b01_successor_claim_carries_the_binding_under_the_existing_commitment(tmp_path, uuids):
    b = canonical_binding()
    claim, _ = issue(tmp_path, b)
    assert type(claim) is TenantLocalExecutionClaim
    assert claim.profile == LOCAL_AUTHORITY_EFFECT_PROFILE_V2 != LOCAL_AUTHORITY_EFFECT_PROFILE
    assert claim.policy_binding == b and claim.authorizing_by_possession is False
    raw = claim.model_dump(mode="json", exclude_none=False)
    assert raw["policy_binding"] == b and _canonical_bytes(raw["policy_binding"]) == _canonical_bytes(b)
    body = {k: v for k, v in raw.items() if k != "claim_commitment"}
    assert commitment(body) == claim.claim_commitment  # the existing implementation, over a body that includes the complete binding
    assert verify_local_execution_claim(claim) is True and verify_local_execution_claim(raw) is True
    assert "policy_binding_digest" not in raw and "binding_digest" not in raw  # no sibling digest field


@pytest.mark.parametrize("path", PATHS)
def test_b02_any_altered_binding_member_invalidates_the_commitment(tmp_path, uuids, path):
    claim, _ = issue(tmp_path)
    raw = claim.model_dump(mode="json", exclude_none=False)
    raw["policy_binding"] = put(raw["policy_binding"], path, mutated_value(get(raw["policy_binding"], path)))
    assert verify_local_execution_claim(raw) is False


def test_b03_a_recomputed_binding_digest_cannot_stand_in_for_the_claim_commitment(tmp_path, uuids):
    claim, _ = issue(tmp_path)
    raw = claim.model_dump(mode="json", exclude_none=False)
    forged = put(raw["policy_binding"], "record_id", "rec-forged")
    raw["policy_binding"] = forged
    assert binding_digest(forged) != binding_digest(claim.policy_binding)  # recomputing the binding digest is possible ...
    assert verify_local_execution_claim(raw) is False                       # ... and changes nothing: the claim commitment still refuses


def test_b03b_known_limit_a_fully_recomputed_claim_is_self_consistent_but_not_authority(tmp_path, uuids):
    """Pinned limit (same as every legacy claim): the commitment is not a signature. Authority is the provisioned store (V04/V05)."""
    claim, _ = issue(tmp_path)
    raw = claim.model_dump(mode="json", exclude_none=False)
    forged = resign(raw, policy_binding=put(raw["policy_binding"], "record_id", "rec-forged"))
    assert verify_local_execution_claim(forged) is True
    assert forged["authorizing_by_possession"] is False
    assert resign(raw, authorizing_by_possession=True) and verify_local_execution_claim(resign(raw, authorizing_by_possession=True)) is False


def test_b04_edited_stored_claim_json_is_refused(tmp_path, uuids):
    claim, _ = issue(tmp_path)
    text = claim.model_dump_json()
    for key, value in (("target", "acct:other"), ("tenant_id", "tenant-beta"), ("grant_id", "urn:cognous:grant:x"), ("amount", 1.0), ("expires_at", "2030-01-01T00:00:00Z")):
        edited = json.loads(text)
        edited[key] = value
        assert verify_local_execution_claim(edited) is False, key
    edited = json.loads(text)
    edited["policy_binding"]["scope"]["tenant"] = "tenant-beta"
    assert verify_local_execution_claim(edited) is False
    assert verify_local_execution_claim(json.loads(text)) is True


def test_b05_claim_commitment_mismatch_is_refused(tmp_path, uuids):
    claim, _ = issue(tmp_path)
    raw = claim.model_dump(mode="json", exclude_none=False)
    for bad in (sha("0"), commitment({"other": 1}), "", None, claim.claim_commitment.upper()):
        assert verify_local_execution_claim({**raw, "claim_commitment": bad}) is False


def test_b06_a_binding_substituted_between_claims_is_refused(tmp_path, uuids):
    first, _ = issue(tmp_path / "one", canonical_binding(), claim_id="claim-1")
    second, _ = issue(tmp_path / "two", canonical_binding(record_id="rec-other", selection_epoch=3), claim_id="claim-2")
    a, b = (c.model_dump(mode="json", exclude_none=False) for c in (first, second))
    swapped = {**a, "policy_binding": b["policy_binding"]}
    assert verify_local_execution_claim(swapped) is False
    assert verify_local_execution_claim(a) is True and verify_local_execution_claim(b) is True


def test_b07_legacy_profile_carrying_a_binding_is_refused(tmp_path, uuids):
    claim, _ = issue(tmp_path)
    raw = claim.model_dump(mode="json", exclude_none=False)
    legacy_with_binding = resign(raw, profile=LOCAL_AUTHORITY_EFFECT_PROFILE)  # self-consistent commitment, undeclared binding
    assert verify_local_execution_claim(legacy_with_binding) is False
    with pytest.raises(ValidationError):
        TenantLocalExecutionClaim.model_validate(legacy_with_binding)
    with pytest.raises(ValidationError):
        LocalExecutionClaim.model_validate(legacy_with_binding)


def test_b08_successor_profile_missing_its_binding_is_refused(tmp_path, uuids):
    claim, _ = issue(tmp_path)
    raw = claim.model_dump(mode="json", exclude_none=False)
    missing = resign(raw, policy_binding=_DROP)
    assert verify_local_execution_claim(missing) is False
    with pytest.raises(ValidationError):
        TenantLocalExecutionClaim.model_validate(missing)
    explicit_null = resign(raw, policy_binding=None)
    assert verify_local_execution_claim(explicit_null) is False


@pytest.mark.parametrize("shape", ["none", "list", "string", "int", "empty", "profile_only", "extra", "wrong_profile", "scope_string"])
def test_b09_malformed_binding_structure_is_refused(tmp_path, uuids, shape):
    claim, _ = issue(tmp_path)
    raw = claim.model_dump(mode="json", exclude_none=False)
    b = raw["policy_binding"]
    bad = {"none": None, "list": [], "string": "x", "int": 1, "empty": {}, "profile_only": {"binding_profile": "ocs-policy-binding/1"},
           "extra": {**b, "extra": 1}, "wrong_profile": {**b, "binding_profile": "ocs-policy-binding/2"}, "scope_string": {**b, "scope": "tenant"}}[shape]
    forged = resign(raw, policy_binding=bad)
    assert verify_local_execution_claim(forged) is False
    with pytest.raises(ValidationError):
        TenantLocalExecutionClaim.model_validate(forged)


def test_b10_binding_added_or_removed_after_commitment_is_refused(tmp_path, uuids):
    successor, _ = issue(tmp_path / "s")
    raw = successor.model_dump(mode="json", exclude_none=False)
    removed = {k: v for k, v in raw.items() if k != "policy_binding"}
    assert verify_local_execution_claim(removed) is False
    removed_legacy_profile = {**removed, "profile": LOCAL_AUTHORITY_EFFECT_PROFILE}
    assert verify_local_execution_claim(removed_legacy_profile) is False
    with deterministic_uuids():
        p, r, f, d, cfg = tenant_flow(tmp_path / "l", None, profile_binding=None)
        legacy = materialize_local_execution_claim(f, p, d, now=TENANT_NOW, claim_id="claim-legacy").model_dump(mode="json", exclude_none=False)
    assert verify_local_execution_claim(legacy) is True
    added = {**legacy, "policy_binding": canonical_binding()}
    assert verify_local_execution_claim(added) is False
    added_and_successor = {**added, "profile": LOCAL_AUTHORITY_EFFECT_PROFILE_V2}
    assert verify_local_execution_claim(added_and_successor) is False


def test_b11_model_reconstruction_does_not_drop_the_binding(tmp_path, uuids):
    claim, _ = issue(tmp_path)
    raw = claim.model_dump(mode="json", exclude_none=False)
    rebuilt = TenantLocalExecutionClaim.model_validate(raw)
    assert rebuilt.policy_binding == claim.policy_binding
    assert rebuilt.model_dump(mode="json", exclude_none=False) == raw
    assert TenantLocalExecutionClaim.model_validate_json(claim.model_dump_json()).policy_binding == claim.policy_binding
    assert verify_local_execution_claim(rebuilt) is True and verify_local_execution_claim(rebuilt.model_copy(deep=True)) is True
    assert verify_local_execution_claim(rebuilt.model_copy(update={"policy_binding": None})) is False  # a bypassed copy that drops it
    assert LocalExecutionClaim.model_validate(json.loads(legacy_claim_text(tmp_path))).policy_binding is None  # legacy: declared field, absent


def legacy_claim_text(tmp_path):
    with deterministic_uuids():
        p, r, f, d = legacy_flow(tmp_path / "legacy-model")
        return materialize_local_execution_claim(f, p, d, now=LEGACY_NOW, claim_id="c").model_dump_json()


def test_b12_unknown_fields_are_refused_on_legacy_and_successor_dictionary_claims(tmp_path, uuids):
    legacy = json.loads(legacy_claim_text(tmp_path))
    assert verify_local_execution_claim(legacy) is True
    for extra in ({"unknown": 1}, {"policy_binding": canonical_binding()}, {"policy_binding_digest": sha("a")}):
        assert verify_local_execution_claim(resign(legacy, **extra)) is False, extra  # even with a recomputed commitment
    claim, _ = issue(tmp_path / "s")
    raw = claim.model_dump(mode="json", exclude_none=False)
    assert verify_local_execution_claim(resign(raw, unknown=1)) is False
    assert verify_local_execution_claim(resign(raw, policy_binding_digest=binding_digest(raw["policy_binding"]))) is False


def test_b13_unrecognized_claim_profiles_are_refused(tmp_path, uuids):
    claim, _ = issue(tmp_path)
    raw = claim.model_dump(mode="json", exclude_none=False)
    for profile in ("urn:cognous:profiles:local-authority-effect:9.9.9", "", None, 1, LOCAL_AUTHORITY_EFFECT_PROFILE_V2 + "x"):
        assert verify_local_execution_claim(resign(raw, profile=profile)) is False, profile


def test_b14_non_tenant_claim_with_a_binding_is_refused(tmp_path, uuids):
    raw = json.loads(legacy_claim_text(tmp_path))
    forged = resign(raw, profile=LOCAL_AUTHORITY_EFFECT_PROFILE_V2, policy_binding=canonical_binding())
    assert verify_local_execution_claim(forged) is False
    with pytest.raises(ValidationError):
        LocalExecutionClaim.model_validate(forged)
    p, r, f, d = legacy_flow(tmp_path / "plain")
    with pytest.raises(PermissionError):
        materialize_local_execution_claim(f, p, d, now=LEGACY_NOW, policy_binding=canonical_binding(),
                                          expected_consumer_id=CONSUMER, expected_operation=OPERATION)


@pytest.mark.parametrize("path,value", [("scope.tenant", "tenant-beta"), ("scope.institution", "urn:cognous:institution:other"),
                                         ("scope.authority_domain", "other-domain")])
def test_b15_binding_scope_must_match_the_claims_own_scope(tmp_path, uuids, path, value):
    claim, _ = issue(tmp_path)
    raw = claim.model_dump(mode="json", exclude_none=False)
    forged = resign(raw, policy_binding=put(raw["policy_binding"], path, value))  # self-consistent commitment, inconsistent scope
    assert verify_local_execution_claim(forged) is False
    with pytest.raises(ValidationError):
        TenantLocalExecutionClaim.model_validate(forged)


def test_b16_binding_is_invisible_to_policy_state_and_authority_state(tmp_path, uuids):
    with_binding, _ = issue(tmp_path / "with", claim_id="claim-same")
    with deterministic_uuids():
        p, r, f, d, cfg = tenant_flow(tmp_path / "without", canonical_binding())
        without = materialize_local_execution_claim(f, p, d, now=TENANT_NOW, claim_id="claim-same")
    a, b = (c.model_dump(mode="json", exclude_none=False) for c in (with_binding, without))
    for key in ("policy_state", "policy_state_commitment", "approval_state", "approval_state_commitment", "evidence_state", "evidence_state_commitment",
                "authority_state_commitment", "operation_commitment", "requirement_commitment"):
        assert a[key] == b[key], key
    assert {k for k in a if a.get(k) != b.get(k)} == {"profile", "policy_binding", "claim_commitment"}
    assert without.profile == LOCAL_AUTHORITY_EFFECT_PROFILE and "policy_binding" not in b


def test_b17_omitting_the_binding_keeps_the_legacy_profile_even_when_the_profile_has_one(tmp_path, uuids):
    p, r, f, d, cfg = tenant_flow(tmp_path, canonical_binding())
    claim = materialize_local_execution_claim(f, p, d, now=TENANT_NOW, claim_id="c")
    assert claim.profile == LOCAL_AUTHORITY_EFFECT_PROFILE and "policy_binding" not in claim.model_dump(mode="json", exclude_none=False)
    assert verify_local_execution_claim(claim) is True


# ---------------------------------------------------------------------------------------------------------------------------------
# C. issuance refusals (PermissionError; existing claim-stage journal diagnostics; no new reason codes)
# ---------------------------------------------------------------------------------------------------------------------------------
def test_c01_wrong_consumer_or_operation_is_refused(tmp_path, uuids):
    for kw in (dict(consumer="runtime-other"), dict(operation="op-other")):
        with pytest.raises(PermissionError, match="policy binding"):
            issue(tmp_path / ("c" + next(iter(kw))), **kw)


@pytest.mark.parametrize("kw", [dict(expected_consumer_id=None), dict(expected_operation=None), dict(expected_consumer_id=None, expected_operation=None),
                                dict(expected_consumer_id=1), dict(expected_operation="op transfer")])
def test_c02_expected_consumer_and_operation_are_mandatory_host_inputs(tmp_path, uuids, kw):
    b = canonical_binding()
    p, r, f, d, cfg = tenant_flow(tmp_path, b)
    base = dict(now=TENANT_NOW, policy_binding=b, expected_consumer_id=CONSUMER, expected_operation=OPERATION)
    base.update(kw)
    with pytest.raises(PermissionError):
        materialize_local_execution_claim(f, p, d, **base)


def test_c03_expected_values_without_a_binding_are_refused(tmp_path, uuids):
    p, r, f, d, cfg = tenant_flow(tmp_path, canonical_binding())
    with pytest.raises(PermissionError):
        materialize_local_execution_claim(f, p, d, now=TENANT_NOW, expected_consumer_id=CONSUMER)


@pytest.mark.parametrize("path,value", [("scope.tenant", "tenant-beta"), ("scope.institution", "urn:cognous:institution:other"),
                                         ("scope.authority_domain", "other-domain")])
def test_c04_incorrect_tenant_institution_or_domain_is_refused(tmp_path, uuids, path, value):
    b = put(canonical_binding(), path, value)
    with pytest.raises(PermissionError):
        issue(tmp_path, b)


def test_c05_malformed_binding_is_refused_and_recorded_with_an_existing_reason_code(tmp_path, uuids):
    b = canonical_binding()
    p, r, f, d, cfg = tenant_flow(tmp_path, b)
    bad = {**b, "extra": 1}
    with pytest.raises(PermissionError):
        materialize_local_execution_claim(f, p, d, now=TENANT_NOW, policy_binding=bad, expected_consumer_id=CONSUMER, expected_operation=OPERATION)
    assert "policy_binding_invalid" in last_claim_reasons(f)


def test_c06_refusal_never_provisions_and_success_provisions_exactly_once(tmp_path, uuids):
    seen = []
    with pytest.raises(PermissionError):
        issue(tmp_path / "bad", canonical_binding(), consumer="runtime-other", provision=seen.append)
    assert seen == []
    claim, _ = issue(tmp_path / "ok", provision=seen.append)
    assert len(seen) == 1 and seen[0] is claim and claim.profile == LOCAL_AUTHORITY_EFFECT_PROFILE_V2


def test_c07_binding_object_is_copied_not_aliased(tmp_path, uuids):
    b = canonical_binding()
    claim, _ = issue(tmp_path, b)
    b["scope"]["tenant"] = "tenant-mutated-after-issuance"
    assert claim.policy_binding["scope"]["tenant"] == TENANT and verify_local_execution_claim(claim) is True


# ---------------------------------------------------------------------------------------------------------------------------------
# D. AR-06 authority separation (the binding never replaces a grant or an approval and creates no independent authority)
# ---------------------------------------------------------------------------------------------------------------------------------
def test_d01_grant_without_approval_issues_no_claim(tmp_path, uuids):
    b = canonical_binding()
    p, r, f, d, cfg = tenant_flow(tmp_path, b)
    r.approvals.clear()
    with pytest.raises(PermissionError, match="authorization-critical inputs changed"):
        materialize_local_execution_claim(f, p, d, now=TENANT_NOW, policy_binding=b, expected_consumer_id=CONSUMER, expected_operation=OPERATION)


def test_d02_approval_without_grant_issues_no_claim(tmp_path, uuids):
    b = canonical_binding()
    p, r, f, d, cfg = tenant_flow(tmp_path, b)
    for status in r.statuses.values():
        status.status = "revoked"
    with pytest.raises(PermissionError, match="authorization-critical inputs changed"):
        materialize_local_execution_claim(f, p, d, now=TENANT_NOW, policy_binding=b, expected_consumer_id=CONSUMER, expected_operation=OPERATION)


@pytest.mark.parametrize("what", ["approval", "grant"])
def test_d03_a_binding_cannot_substitute_for_a_missing_grant_or_approval(tmp_path, uuids, what):
    b = canonical_binding()
    p, r, f, d, cfg = tenant_flow(tmp_path, b)
    if what == "approval":
        r.approvals.clear()
    else:
        for status in r.statuses.values():
            status.status = "revoked"
    held = f.decide(p, now=TENANT_NOW)
    assert held.result != "authorized"
    with pytest.raises(PermissionError, match="not authorized"):
        materialize_local_execution_claim(f, p, held, now=TENANT_NOW, policy_binding=b, expected_consumer_id=CONSUMER, expected_operation=OPERATION)


@pytest.mark.parametrize("profile_over,code", [
    (dict(activation_ref=sha("1")), "approval_policy_activation_mismatch"),
    (dict(selection_epoch=4), "policy_binding_invalid"),
    (dict(binding_digest=sha("2")), "policy_binding_invalid"),
])
def test_d04_inconsistent_approval_and_binding_identities_are_refused(tmp_path, uuids, profile_over, code):
    b = canonical_binding()
    pb = PolicyBinding(binding_digest=reference_binding_digest(b), selection_epoch=b["selection_epoch"], activation_ref=b["activation_ref"],
                       policy_generation=1, disposition="selected").model_copy(update=profile_over)
    p, r, f, d, cfg = tenant_flow(tmp_path, b, profile_binding=pb)
    with pytest.raises(PermissionError):
        materialize_local_execution_claim(f, p, d, now=TENANT_NOW, policy_binding=b, expected_consumer_id=CONSUMER, expected_operation=OPERATION)


def test_d04b_identity_mismatch_is_recorded_with_existing_reason_codes(tmp_path, uuids):
    b = canonical_binding()
    other = canonical_binding(activation_ref=sha("1"))
    p, r, f, d, cfg = tenant_flow(tmp_path, b)
    with pytest.raises(PermissionError):
        materialize_local_execution_claim(f, p, d, now=TENANT_NOW, policy_binding=other, expected_consumer_id=CONSUMER, expected_operation=OPERATION)
    assert "approval_policy_activation_mismatch" in last_claim_reasons(f)


def test_d05_profile_without_an_approval_side_binding_refuses_a_claim_binding(tmp_path, uuids):
    b = canonical_binding()
    p, r, f, d, cfg = tenant_flow(tmp_path, b, profile_binding=None)
    with pytest.raises(PermissionError):
        materialize_local_execution_claim(f, p, d, now=TENANT_NOW, policy_binding=b, expected_consumer_id=CONSUMER, expected_operation=OPERATION)
    assert "policy_binding_invalid" in last_claim_reasons(f)


def test_d06_withdrawn_approval_side_disposition_cannot_carry_a_canonical_binding(tmp_path, uuids):
    b = canonical_binding()
    withdrawn = PolicyBinding(selection_epoch=b["selection_epoch"], activation_ref=b["activation_ref"], policy_generation=1, disposition="withdrawn")
    p, r, f, d, cfg = tenant_flow(tmp_path, b, profile_binding=withdrawn)
    with pytest.raises(PermissionError):
        materialize_local_execution_claim(f, p, d, now=TENANT_NOW, policy_binding=b, expected_consumer_id=CONSUMER, expected_operation=OPERATION)


def test_d07_unsupported_approval_generation_issues_no_claim(tmp_path, uuids):
    b = canonical_binding()
    p, r, f, d, cfg = tenant_flow(tmp_path, b)
    broken = cfg.policy_binding.model_copy(update={"policy_generation": 0})  # bypasses validators; re-run at every evaluation
    f.runtime_authority_profile = cfg.model_copy(update={"policy_binding": broken}).snapshot()
    with pytest.raises(PermissionError):
        materialize_local_execution_claim(f, p, d, now=TENANT_NOW, policy_binding=b, expected_consumer_id=CONSUMER, expected_operation=OPERATION)


@pytest.mark.parametrize("bad", [None, "", sha("c").upper(), "sha256:" + "c" * 63, 7])
def test_d08_invalid_activation_identity_is_refused(tmp_path, uuids, bad):
    b = canonical_binding()
    p, r, f, d, cfg = tenant_flow(tmp_path, b)
    with pytest.raises(PermissionError):
        materialize_local_execution_claim(f, p, d, now=TENANT_NOW, policy_binding={**b, "activation_ref": bad},
                                          expected_consumer_id=CONSUMER, expected_operation=OPERATION)


def test_d09_a_valid_binding_creates_no_independent_authority(tmp_path, uuids):
    b = canonical_binding()
    claim, (p, r, f, d, cfg) = issue(tmp_path, b)
    assert claim.authorizing_by_possession is False and claim.source == "trusted_control_plane_workflow"
    assert f.destination.snapshot()["effects"] == {}  # issuing a claim effects nothing
    raw = claim.model_dump(mode="json", exclude_none=False)
    for key in ("grant_id", "grant_revision", "approval_state", "authority_state_commitment", "approval_state_commitment"):
        assert raw[key]  # the grant and approval evidence the binding rides on is still present and still required
    forged = resign(raw, approval_state=[], approval_state_commitment=commitment([]))
    assert verify_local_execution_claim(forged) is False  # authority_state_commitment still covers the original approvals


def test_d10_policy_generation_and_selection_epoch_are_not_conflated(tmp_path, uuids):
    b = canonical_binding(selection_epoch=3)
    claim, _ = issue(tmp_path, b, generation=7)
    assert "policy_generation" not in claim.policy_binding and claim.policy_binding["selection_epoch"] == 3
    assert verify_local_execution_claim(claim) is True
