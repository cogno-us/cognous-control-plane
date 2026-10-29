"""Unit oracles of the persisted effective-configuration binding `effective-configuration-binding/0.1` (D-06 Option B, carriage C2): pure functions only.

BUILDER_TESTED developer evidence. NOT independently qualified (F3-A independent qualification is PENDING). Needs no Registry checkout: nothing here builds a workflow.
The expected digest is recomputed here with `hashlib` over independently serialized canonical JSON, not by calling the module under test.
"""
from __future__ import annotations

import ast
import copy
import hashlib
import json
from pathlib import Path

import pytest

from agent_control_plane import effective_configuration_binding as ecb

SRC = Path(ecb.__file__)
H = lambda c: "sha256:" + c * 64  # noqa: E731
MAXV = 2147483647


def members(**over):
    base = {
        "scope": {"consumer_id": "consumer-test", "tenant_id": "tenant-alpha", "action_id": "urn:cognous:action:refund-issue-routine-v1", "institution_id": "inst-1",
                  "authority_domain": "customer-refunds"},
        "host_profile_digest": H("a"), "effective_profile_digest": H("b"),
        "f4_scalars": {"status_max_age_seconds": 60, "approval_max_age_seconds": 60},
        "other_scalars": {"clock_tolerance_seconds": 5, "identity_max_age_seconds": 60, "mandate_max_age_seconds": 60},
        "observation_policy": {"max_age_seconds": 300, "clock_tolerance_seconds": 5},
        "families": [{"slot": "class_age", "family_id": "f5-action-class-age-bounds", "contract_version": "r08-v2", "family_schema_revision": None, "effective_policy_digest": H("c")},
                     {"slot": "class_unreadable", "family_id": "f5-action-class-unreadable-policy", "contract_version": "r08-v5", "family_schema_revision": 1,
                      "effective_policy_digest": H("d")}],
    }
    base.update(over)
    return base


def independent_digest(m, version=ecb.VERSION):
    body = {"domain": "cognous.control-plane.effective-configuration-binding", "version": version, **m}
    return "sha256:" + hashlib.sha256(json.dumps(body, sort_keys=True, separators=(",", ":"), ensure_ascii=False, allow_nan=False).encode("utf-8")).hexdigest()


def leaves(obj, path=()):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield from leaves(v, path + (k,))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            yield from leaves(v, path + (i,))
    else:
        yield path, obj


def set_at(obj, path, value):
    for k in path[:-1]:
        obj = obj[k]
    obj[path[-1]] = value


def perturb(path, value):
    """A DIFFERENT value inside the same structural domain (so only the equality, not the shape, can flag it)."""
    if value is None:
        return {"host_profile_digest": H("1"), "effective_profile_digest": H("1"), "observation_policy": {"max_age_seconds": 1, "clock_tolerance_seconds": 0}}.get(path[0], 7)
    if isinstance(value, str) and value.startswith("sha256:"):
        return H("2") if value != H("2") else H("3")
    if isinstance(value, str):
        return value + "-x"
    return value + 1 if value < MAXV else value - 1


def record(m=None, **over):
    m = m if m is not None else members()
    rec = {"version": ecb.VERSION, "digest": independent_digest(m), "members": m}
    rec.update(over)
    return rec


def persisted(rec, **extra):
    return {"profile": "runtime-authority/0.1", "catalogue_digest": H("e"), **extra, **({ecb.KEY: rec} if rec is not None else {})}


LIVE = ecb.mint(members())
CLS = dict(index=0, cutoff=0, decision_count=1)


# --------------------------------------------------------------------------------------------------------------------------------------------- the preimage
def test_frozen_constants():
    assert (ecb.KEY, ecb.VERSION, ecb.DOMAIN) == ("effective_configuration", "effective-configuration-binding/0.1", "cognous.control-plane.effective-configuration-binding")
    assert ecb.SCALAR_MAX == MAXV and ecb.ACCEPTED == (ecb.BOUND, ecb.LEGACY)
    assert set(ecb.STATUSES) == {"bound", "mismatch", "invalid", "version-unsupported", "legacy", "unbound-after-cutoff"}


def test_digest_is_the_existing_canonical_commitment_over_domain_version_and_members():
    m = members()
    assert ecb.digest_of(ecb.VERSION, m) == independent_digest(m)
    assert ecb.mint(m) == {"version": ecb.VERSION, "digest": independent_digest(m), "members": m}
    from agent_control_plane.bounded import commitment
    assert commitment({"domain": ecb.DOMAIN, "version": ecb.VERSION, **m}) == ecb.mint(m)["digest"]


def test_the_preimage_names_exactly_the_frozen_members():
    assert ecb.MEMBER_FIELDS == ("scope", "host_profile_digest", "effective_profile_digest", "f4_scalars", "other_scalars", "observation_policy", "families")
    assert ecb.SCOPE_FIELDS == ("consumer_id", "tenant_id", "action_id", "institution_id", "authority_domain")
    assert ecb.F4_FIELDS == ("status_max_age_seconds", "approval_max_age_seconds")
    assert ecb.OTHER_FIELDS == ("clock_tolerance_seconds", "identity_max_age_seconds", "mandate_max_age_seconds")
    assert ecb.FAMILY_FIELDS == ("slot", "family_id", "contract_version", "family_schema_revision", "effective_policy_digest")
    for excluded in ("evaluated_at", "selection_id", "selection_epoch"):
        assert excluded not in json.dumps(members())


def test_member_key_order_does_not_change_the_digest_but_family_order_does():
    m = members()
    shuffled = {k: m[k] for k in reversed(list(m))}
    shuffled["scope"] = {k: m["scope"][k] for k in reversed(list(m["scope"]))}
    assert ecb.digest_of(ecb.VERSION, shuffled) == ecb.digest_of(ecb.VERSION, m)
    swapped = members(families=list(reversed(m["families"])))
    assert ecb.digest_of(ecb.VERSION, swapped) != ecb.digest_of(ecb.VERSION, m)


def test_every_leaf_perturbed_changes_the_digest_and_flips_the_verdict_to_mismatch():
    """Table-driven: EVERY leaf of the members (each scope field, each profile digest, each scalar, each ObservationPolicy value, each family field, the null-able ones too)."""
    m = members()
    paths = list(leaves(m))
    assert len(paths) == 24  # 5 scope + 2 profile digests + 2 + 3 scalars + 2 observation + 2 x 5 family fields
    for path, value in paths:
        variant = copy.deepcopy(m)
        set_at(variant, path, perturb(path, value))
        assert ecb.members_defect(variant) is None, path
        assert ecb.digest_of(ecb.VERSION, variant) != ecb.digest_of(ecb.VERSION, m), path
        assert ecb.classify(persisted(record(variant)), LIVE, **CLS) == ecb.MISMATCH, path
    assert ecb.classify(persisted(record(m)), LIVE, **CLS) == ecb.BOUND  # the unperturbed control


def test_present_versus_explicitly_absent_observation_policy_flips_the_verdict_both_ways():
    with_obs, without = members(), members(observation_policy=None)
    assert ecb.classify(persisted(record(with_obs)), ecb.mint(without), **CLS) == ecb.MISMATCH
    assert ecb.classify(persisted(record(without)), ecb.mint(with_obs), **CLS) == ecb.MISMATCH
    assert ecb.classify(persisted(record(without)), ecb.mint(without), **CLS) == ecb.BOUND


def test_a_removed_added_duplicated_or_reordered_family_row_flips_the_verdict():
    m = members()
    rows = m["families"]
    for fams in (rows[:1], rows[1:], rows + [dict(rows[0], slot="class_extra")], list(reversed(rows)), []):
        v = members(families=copy.deepcopy(fams))
        assert ecb.classify(persisted(record(v)), LIVE, **CLS) == ecb.MISMATCH
    assert ecb.members_defect(members(families=rows + [rows[0]])) == "families"  # a duplicate slot is not a valid member


# --------------------------------------------------------------------------------------------------------------------------------- invalid / unsupported member
BAD_VALUES = {"bool": True, "float": 1.0, "str": "60", "negative": -1, "huge": MAXV + 1, "none": None}


@pytest.mark.parametrize("kind", sorted(BAD_VALUES))
def test_a_wrong_typed_or_out_of_range_value_in_any_integer_leaf_is_invalid_even_with_a_consistent_digest(kind):
    m = members()
    count = 0
    for path, value in leaves(m):
        if type(value) is not int or path[0] == "families" and path[-1] != "family_schema_revision":
            continue
        if kind == "none" and path[-1] == "family_schema_revision":
            continue  # null IS the valid value of a schema revision that the adapter does not record
        count += 1
        variant = copy.deepcopy(m)
        set_at(variant, path, BAD_VALUES[kind])
        rec = {"version": ecb.VERSION, "digest": "sha256:" + "0" * 64, "members": variant}  # digest of a non-canonical value cannot even be recomputed by the writer
        assert ecb.classify(persisted(rec), LIVE, **CLS) == ecb.INVALID, (path, kind)
        if kind not in ("float",):  # canonical JSON accepts these, so the digest CAN be consistent: the type/range rule alone must refuse
            rec["digest"] = independent_digest(variant)
            assert ecb.classify(persisted(rec), LIVE, **CLS) == ecb.INVALID, (path, kind)
    assert count >= 7  # 2 f4 + 3 other + 2 observation (+ the recorded family schema revision)


def test_a_digest_that_is_not_the_recomputation_of_its_own_members_is_invalid():
    m = members()
    for digest in (H("9"), "sha256:" + "0" * 64, independent_digest(members(f4_scalars={"status_max_age_seconds": 1, "approval_max_age_seconds": 1})), "sha256:" + "A" * 64, "x", 7, None):
        assert ecb.classify(persisted(record(m, digest=digest)), LIVE, **CLS) == ecb.INVALID, digest


def test_digest_is_compared_in_addition_to_members_never_alone():
    other = members(f4_scalars={"status_max_age_seconds": 59, "approval_max_age_seconds": 60})
    forged = record(other, digest=LIVE["digest"])  # the live digest pasted over different members
    assert ecb.classify(persisted(forged), LIVE, **CLS) == ecb.INVALID
    assert ecb.classify(persisted(record(other)), LIVE, **CLS) == ecb.MISMATCH


@pytest.mark.parametrize("version", ["effective-configuration-binding/0.2", "effective-configuration-binding/0.0", "", "EFFECTIVE-CONFIGURATION-BINDING/0.1", "effective-configuration-binding/0.1 "])
def test_an_unknown_version_is_unsupported_even_when_everything_else_is_consistent(version):
    m = members()
    assert ecb.classify(persisted({"version": version, "digest": independent_digest(m, version), "members": m}), LIVE, **CLS) == ecb.VERSION_UNSUPPORTED


@pytest.mark.parametrize("rec", [None, [], "x", 1, True, {}, {"version": 1}, {"version": None}, {"digest": H("a"), "members": members()}])
def test_a_malformed_member_is_invalid(rec):
    status = ecb.classify(persisted(rec) if rec is not None else {"profile": "x", ecb.KEY: None}, LIVE, **CLS)
    assert status == ecb.INVALID


def test_extra_missing_or_renamed_record_and_member_keys_are_invalid():
    m = members()
    good = record(m)
    for bad in (dict(good, extra=1), {k: v for k, v in good.items() if k != "digest"}, {k: v for k, v in good.items() if k != "members"},
                dict(good, members=dict(m, extra_member=1)), dict(good, members={k: v for k, v in m.items() if k != "families"}),
                dict(good, members=dict(m, scope=dict(m["scope"], extra="x"))), dict(good, members=dict(m, f4_scalars={"status_max_age_seconds": 1}))):
        assert ecb.classify(persisted(bad), LIVE, **CLS) == ecb.INVALID


def test_a_replayed_member_from_another_scope_is_a_mismatch():
    other_scope = members(scope=dict(members()["scope"], tenant_id="tenant-other"))
    assert ecb.classify(persisted(record(other_scope)), LIVE, **CLS) == ecb.MISMATCH


# ----------------------------------------------------------------------------------------------------------------------------------------- the legacy rule
def test_a_missing_member_is_legacy_only_below_an_explicit_valid_cutoff():
    ra = persisted(None)
    assert ecb.classify(ra, LIVE, index=0, cutoff=1, decision_count=1) == ecb.LEGACY
    assert ecb.classify(ra, LIVE, index=4, cutoff=5, decision_count=9) == ecb.LEGACY
    assert ecb.classify(ra, LIVE, index=0, cutoff=0, decision_count=1) == ecb.UNBOUND_AFTER_CUTOFF  # default cutoff 0: nothing is legacy
    assert ecb.classify(ra, LIVE, index=5, cutoff=5, decision_count=9) == ecb.UNBOUND_AFTER_CUTOFF  # at the cutoff (off-by-one boundary)
    assert ecb.classify(ra, LIVE, index=6, cutoff=5, decision_count=9) == ecb.UNBOUND_AFTER_CUTOFF
    assert ecb.classify(ra, LIVE, index=None, cutoff=5, decision_count=9) == ecb.UNBOUND_AFTER_CUTOFF  # an unknown position is never legacy


@pytest.mark.parametrize("cutoff", [True, False, -1, 1.0, "1", None, MAXV + 1, 10 ** 30, float("inf"), [1], 1.5])
def test_an_invalid_cutoff_never_makes_anything_legacy(cutoff):
    assert ecb.legacy_cutoff_defect(cutoff) is not None
    assert ecb.classify(persisted(None), LIVE, index=0, cutoff=cutoff, decision_count=10 ** 9) == ecb.UNBOUND_AFTER_CUTOFF


def test_a_cutoff_larger_than_the_decisions_in_the_store_disables_the_legacy_rule():
    """The decisions list only grows, so a cutoff above its length cannot be 'the decisions at activation'; it must not accept a later legacy-writer append."""
    assert ecb.classify(persisted(None), LIVE, index=2, cutoff=9, decision_count=3) == ecb.UNBOUND_AFTER_CUTOFF
    assert ecb.classify(persisted(None), LIVE, index=2, cutoff=3, decision_count=3) == ecb.LEGACY


def test_the_cutoff_is_an_exact_finite_int_with_no_wildcard():
    for ok in (0, 1, MAXV):
        assert ecb.legacy_cutoff_defect(ok) is None
    assert ecb.legacy_cutoff_defect(MAXV + 1) == "legacy_cutoff_invalid"


def test_a_present_member_is_never_treated_as_legacy_whatever_the_cutoff():
    bad = persisted(record(members(), digest=H("9")))
    assert ecb.classify(bad, LIVE, index=0, cutoff=1, decision_count=1) == ecb.INVALID
    assert ecb.classify(persisted(record(members(f4_scalars={"status_max_age_seconds": 1, "approval_max_age_seconds": 1}))), LIVE, index=0, cutoff=1, decision_count=1) == ecb.MISMATCH


def test_a_non_dict_runtime_authority_is_unbound():
    for ra in (None, [], "x"):
        assert ecb.classify(ra, LIVE, index=0, cutoff=0, decision_count=1) == ecb.UNBOUND_AFTER_CUTOFF
        assert ecb.classify(ra, LIVE, index=0, cutoff=1, decision_count=1) == ecb.LEGACY  # a legacy F4-only decision persists runtime_authority as null


# ------------------------------------------------------------------------------------------------------------------------------ builders and validation
def test_build_members_refuses_every_wrong_typed_value():
    ok = dict(scope=members()["scope"], host_profile_digest=H("a"), effective_profile_digest=None, f4_scalars={"status_max_age_seconds": 1, "approval_max_age_seconds": 2},
              other_scalars={"clock_tolerance_seconds": 0, "identity_max_age_seconds": 3, "mandate_max_age_seconds": MAXV}, observation_policy=None, families=[])
    assert ecb.build_members(**ok)["other_scalars"]["mandate_max_age_seconds"] == MAXV
    for bad in (True, 1.0, "1", -1, MAXV + 1, None):
        for group, key in (("f4_scalars", "status_max_age_seconds"), ("other_scalars", "identity_max_age_seconds")):
            with pytest.raises(ecb.BindingInvalid):
                ecb.build_members(**dict(ok, **{group: dict(ok[group], **{key: bad})}))
        with pytest.raises(ecb.BindingInvalid):
            ecb.build_members(**dict(ok, observation_policy={"max_age_seconds": bad, "clock_tolerance_seconds": 0}))
    for bad_digest in ("sha256:" + "0" * 64, "sha256:" + "A" * 64, "sha256:abc", "md5:" + "a" * 32, 5):
        with pytest.raises(ecb.BindingInvalid):
            ecb.build_members(**dict(ok, host_profile_digest=bad_digest))
    with pytest.raises(ecb.BindingInvalid):
        ecb.build_members(**dict(ok, scope=dict(ok["scope"], tenant_id="")))
    with pytest.raises(ecb.BindingInvalid):
        ecb.mint(dict(members(), extra=1))


def test_mint_returns_a_detached_copy():
    m = members()
    rec = ecb.mint(m)
    rec["members"]["scope"]["tenant_id"] = "changed"
    assert m["scope"]["tenant_id"] == "tenant-alpha" and ecb.mint(m)["members"]["scope"]["tenant_id"] == "tenant-alpha"


def test_scope_identity_has_the_five_shared_keys():
    assert tuple(ecb.scope_identity("c", "t", "a", "i", "d")) == ("consumer_id", "tenant_id", "action_id", "institution_id", "authority_domain")


# ------------------------------------------------------------------------------------------------------------------------------------ family generality
TABLE = {"s1": ("fam-1", "r08-v2"), "s2": ("fam-2", "r08-v5"), "s3": ("fam-3", "r08-v8")}


def test_family_rows_come_from_the_table_and_the_bound_identity_in_composition_order():
    bound = {"s1": ({"x": 1}, H("1")), "s2": None, "s3": ({"y": 2}, H("3")), "effective_profile_digest": None}
    rows = ecb.family_rows(bound, ("s1", "s2", "s3"), TABLE, {"s3": 1})
    assert [r["slot"] for r in rows] == ["s1", "s3"]  # s2 is not declared: ABSENT, so the declared set is part of the identity
    assert rows[1] == {"slot": "s3", "family_id": "fam-3", "contract_version": "r08-v8", "family_schema_revision": 1, "effective_policy_digest": H("3")}
    assert rows[0]["family_schema_revision"] is None


def test_a_newly_added_family_appears_without_a_change_to_the_binding_code():
    table, order = dict(TABLE), ("s1", "s2", "s3")
    bound = {"s1": ({}, H("1")), "s2": None, "s3": None}
    before = ecb.family_rows(bound, order, table, {})
    table["s4"] = ("fam-4", "r08-v9")
    after = ecb.family_rows(dict(bound, s4=({}, H("4"))), order + ("s4",), table, {})
    assert [r["slot"] for r in before] == ["s1"] and [r["slot"] for r in after] == ["s1", "s4"]
    assert ecb.mint(members(families=before))["digest"] != ecb.mint(members(families=after))["digest"]


def test_a_governed_slot_unknown_to_the_table_is_refused_never_silently_left_out():
    with pytest.raises(ecb.BindingInvalid):
        ecb.family_rows({"s1": ({}, H("1")), "s9": ({}, H("9"))}, ("s1", "s2", "s3"), TABLE, {})
    with pytest.raises(ecb.BindingInvalid):
        ecb.family_rows({"s1": ({}, H("1"))}, ("s1",), {}, {})
    with pytest.raises(ecb.BindingInvalid):
        ecb.family_rows({"s1": "not-a-tuple"}, ("s1",), TABLE, {})
    assert ecb.family_rows({"s9": None, "effective_profile_digest": None}, ("s1",), TABLE, {}) == []  # an UNDECLARED unknown slot is not governed


# ----------------------------------------------------------------------------------------------------------------------------------------------- structure
def test_the_module_is_pure_and_imports_only_the_existing_commitment():
    tree = ast.parse(SRC.read_text())
    imported = sorted({(n.module or "") + ":" + a.name for n in ast.walk(tree) if isinstance(n, ast.ImportFrom) for a in n.names}
                      | {a.name for n in ast.walk(tree) if isinstance(n, ast.Import) for a in n.names})
    assert imported == ["__future__:annotations", "agent_control_plane.bounded:commitment", "re", "typing:Any", "typing:Mapping", "typing:Optional"], imported
    code = SRC.read_text()
    assert "hashlib" not in code and "json" not in code  # no second hash / canonicalization is invented
