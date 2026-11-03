"""CAP H1: schema + non-secret examples for `ocs-authority-profile/0.1`. BUILDER_TESTED developer evidence; NOT independently qualified.

CLAIM SCOPE: shape documentation only. The loader (`load_authority_profile`) is the SOLE authority; the schema is NON-AUTHORITATIVE. Nothing here establishes operational trust,
authenticates anything, or admits a selection. There is no structural/keyless mode: these tests call the production loader, which validates shape before any Registry import.

Registry/PyNaCl-dependent checks need a Registry checkout at `PIN` in `OCS_CAP_REGISTRY_DIR`. With `OCS_REQUIRE_REGISTRY_PIN=1` (CI) their absence is a FAILURE, never a skip.
"""
from __future__ import annotations

import copy
import json
import os
import re
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

import pytest

from agent_control_plane import registry_authority_profile as cap

PIN = "7de0ec9f8471c7a2ff630eb4035fa24d60b5e2eb"
ROOT = Path(__file__).resolve().parents[1]
SCHEMA_PATH = ROOT / "schemas" / "ocs_authority_profile_0_1.schema.json"
EX = ROOT / "examples" / "authority-profile"
SYNTH = EX / "synthetic.profile.json"
SNAP = EX / "synthetic.snapshot.json"
TEMPLATE = EX / "operational.profile.template.json"
PUBLIC_SEED = bytes(range(32))  # the public, widely shared synthetic test seed: anyone can sign with it
_REQUIRED = os.environ.get("OCS_REQUIRE_REGISTRY_PIN") == "1"

SCHEMA = json.loads(SCHEMA_PATH.read_text(encoding="utf-8"))
PROFILE = json.loads(SYNTH.read_text(encoding="utf-8"))


def _unavailable(reason: str):
    if _REQUIRED:
        pytest.fail("OCS_REQUIRE_REGISTRY_PIN=1 but " + reason, pytrace=False)
    pytest.skip("NOT RUN: " + reason)


@pytest.fixture
def registry():
    d = os.environ.get("OCS_CAP_REGISTRY_DIR")
    if not d or not (Path(d) / "registry_successor").is_dir():
        _unavailable("OCS_CAP_REGISTRY_DIR is not set to a Registry checkout")
    d = str(Path(d).resolve())
    head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=d, capture_output=True, text=True).stdout.strip()
    if head != PIN:
        pytest.fail(f"Registry checkout is {head!r}, expected the pin {PIN}", pytrace=False)
    if d not in sys.path:
        sys.path.insert(0, d)
    try:
        import nacl.bindings as nb
    except ImportError:
        _unavailable("PyNaCl is not installed")
    from registry_successor import v2_policy_identity as v2i
    return nb, v2i


# ---------------------------------------------------------------------------------------------------------------------- helpers
def _branch(node: dict, inst: dict) -> dict:
    """Pick the oneOf branch whose `kind` const matches the instance (the only oneOf is `clock`)."""
    for b in node.get("oneOf", [node]):
        if b.get("properties", {}).get("kind", {}).get("const") == inst.get("kind") or "oneOf" not in node:
            return b
    raise AssertionError("no matching schema branch")


def _object_nodes(node: dict, inst, path: tuple = ()):
    """Yield (path, schema_object_node, instance_dict) for every object level of the instance."""
    if isinstance(inst, dict):
        n = _branch(node, inst)
        yield path, n, inst
        for k, v in inst.items():
            sub = n["properties"].get(k)
            if sub is not None:
                yield from _object_nodes(sub, v, path + (k,))
    elif isinstance(inst, list):
        for i, v in enumerate(inst):
            yield from _object_nodes(node["items"], v, path + (i,))


def _write(tmp_path: Path, doc: dict, name: str = "profile.json") -> Path:
    p = tmp_path / name
    p.write_text(json.dumps(doc), encoding="utf-8")
    return p


def _get(doc, path):
    for k in path:
        doc = doc[k]
    return doc


def _code(excinfo) -> str:
    return excinfo.value.code


# ---------------------------------------------------------------------------------------------------------------------- schema
def test_schema_is_closed_non_authoritative_and_keyless():
    assert "NON-AUTHORITATIVE" in SCHEMA["$comment"] and "sole authority" in SCHEMA["$comment"]
    assert SCHEMA["additionalProperties"] is False and SCHEMA["properties"]["version"]["const"] == cap.PROFILE_VERSION
    assert set(SCHEMA["properties"]["mode"]["enum"]) == set(cap.MODES)
    text = SCHEMA_PATH.read_text(encoding="utf-8").lower()
    assert "authentication_enabled" not in text and "structural" not in text and "keyless" not in text

    def closed(n):
        if isinstance(n, dict):
            if n.get("type") == "object":
                assert n["additionalProperties"] is False and set(n["required"]) == set(n["properties"])
            for v in n.values():
                closed(v)
        elif isinstance(n, list):
            for v in n:
                closed(v)

    closed(SCHEMA)


def test_example_member_sets_equal_schema_properties_at_every_level():
    for path, node, inst in _object_nodes(SCHEMA, PROFILE):
        assert set(inst) == set(node["properties"]), path
    t = json.loads(TEMPLATE.read_text(encoding="utf-8"))
    for path, node, inst in _object_nodes(SCHEMA, t):
        assert set(inst) == set(node["properties"]), path


def test_schema_covers_the_fixed_instant_clock_branch():
    fixed = [b for b in SCHEMA["properties"]["clock"]["oneOf"] if "as_of" in b["properties"]]
    assert len(fixed) == 1 and set(fixed[0]["properties"]) == {"kind", "as_of"}


# ---------------------------------------------------------------------------------------------------------------------- loader-driven drift (the loader is the authority)
def test_synthetic_example_loads_under_synthetic_and_only_synthetic(tmp_path):
    p = cap.load_authority_profile(SYNTH, expected_mode="synthetic")
    assert p.mode == "synthetic" and p.state_backend == "none-g1" and p.clock_kind == "system_utc"
    with pytest.raises(cap.AuthorityProfileRefusal) as e:
        cap.load_authority_profile(SYNTH, expected_mode="operational")
    assert _code(e) == "authority_config_mode_mismatch"
    with pytest.raises(cap.AuthorityProfileRefusal) as e:
        cap.load_authority_profile(SYNTH)
    assert _code(e) == "authority_config_mode_mismatch"


def _drift_cases():
    cases = []
    for path, node, inst in _object_nodes(SCHEMA, PROFILE):
        for prop in node["properties"]:
            cases.append(("delete", path, prop))
        cases.append(("add", path, "extra_member"))
    return cases


@pytest.mark.parametrize("op,path,prop", _drift_cases(), ids=lambda v: "/".join(map(str, v)) if isinstance(v, tuple) else str(v))
def test_loader_refuses_every_schema_member_deleted_and_every_unknown_member_added(tmp_path, op, path, prop):
    doc = copy.deepcopy(PROFILE)
    target = _get(doc, path)
    if op == "delete":
        del target[prop]
    else:
        target[prop] = "x"
    with pytest.raises(cap.AuthorityProfileRefusal) as e:
        cap.load_authority_profile(_write(tmp_path, doc), expected_mode="synthetic")
    assert _code(e) == "authority_config_malformed"


def test_loader_refuses_the_fixed_instant_clock_members_both_ways(tmp_path):
    ok = copy.deepcopy(PROFILE)
    ok["clock"] = {"kind": "fixed_instant", "as_of": "2026-10-05T19:00:00Z"}
    assert cap.load_authority_profile(_write(tmp_path, ok), expected_mode="synthetic").clock_kind == "fixed_instant"
    for bad in ({"kind": "fixed_instant"}, {"kind": "fixed_instant", "as_of": "2026-10-05T19:00:00Z", "x": 1}, {"kind": "system_utc", "as_of": "2026-10-05T19:00:00Z"}):
        d = copy.deepcopy(PROFILE)
        d["clock"] = bad
        with pytest.raises(cap.AuthorityProfileRefusal) as e:
            cap.load_authority_profile(_write(tmp_path, d), expected_mode="synthetic")
        assert _code(e) == "authority_config_malformed"


# ---------------------------------------------------------------------------------------------------------------------- operational template
def test_operational_template_never_loads_tripwire_only(tmp_path):
    """TRIPWIRE ONLY. Operational mode refuses unconditionally in the G1/G2 loader (`authority_config_unprovisioned`), and a missing owner digest raises the same code
    earlier, so this assertion passes with or without placeholders. It proves that no operational file (this template included) can load; it does NOT prove input-dependent
    behaviour. The plan's 'refuse when inputs are unavailable' is satisfied only by that unconditional refusal until H3."""
    data = TEMPLATE.read_bytes()
    assert b"UNSELECTED" in data
    digest = cap._digest(data)  # noqa: SLF001
    for kw in ({}, {"expected_config_digest": digest}):
        with pytest.raises(cap.AuthorityProfileRefusal) as e:
            cap.load_authority_profile(TEMPLATE, expected_mode="operational", **kw)
        assert _code(e) == "authority_config_unprovisioned"
    with pytest.raises(cap.AuthorityProfileRefusal) as e:
        cap.load_authority_profile(TEMPLATE, expected_mode="synthetic")
    assert _code(e) == "authority_config_mode_mismatch"


def test_synthetic_example_cannot_be_reused_as_an_operational_config(tmp_path):
    for mutate in (lambda d: d.update(mode="operational"),):
        d = copy.deepcopy(PROFILE)
        mutate(d)
        p = _write(tmp_path, d)
        with pytest.raises(cap.AuthorityProfileRefusal) as e:
            cap.load_authority_profile(p, expected_mode="synthetic")
        assert _code(e) == "authority_config_mode_mismatch"
        with pytest.raises(cap.AuthorityProfileRefusal) as e:
            cap.load_authority_profile(p, expected_mode="operational", expected_config_digest=cap._digest(p.read_bytes()))  # noqa: SLF001
        assert _code(e) == "authority_config_unprovisioned"


def test_limit_fixed_instant_edit_of_the_example_loads_and_is_caught_only_by_the_owner_digest(tmp_path):
    """DOCUMENTED LIMIT (pinned): expiry protects only under a system_utc clock. Editing the copied example to a fixed_instant before the snapshot expiry loads in synthetic mode;
    only the owner-supplied expected_config_digest refuses it."""
    d = copy.deepcopy(PROFILE)
    d["clock"] = {"kind": "fixed_instant", "as_of": "2019-06-01T00:00:00Z"}
    p = _write(tmp_path, d)
    assert cap.load_authority_profile(p, expected_mode="synthetic").clock_kind == "fixed_instant"
    with pytest.raises(cap.AuthorityProfileRefusal) as e:
        cap.load_authority_profile(p, expected_mode="synthetic", expected_config_digest=cap._digest(SYNTH.read_bytes()))  # noqa: SLF001
    assert _code(e) == "authority_config_digest_mismatch"


# ---------------------------------------------------------------------------------------------------------------------- non-secret and not-a-trust-anchor
_PEM = re.compile(r"-----BEGIN")
_HEX64 = re.compile(r"(?<![0-9a-fA-F])[0-9a-fA-F]{64}(?![0-9a-fA-F])")


def _names(x):
    if isinstance(x, dict):
        for k, v in x.items():
            yield k
            yield from _names(v)
    elif isinstance(x, list):
        for v in x:
            yield from _names(v)


def test_no_example_carries_secret_member_names_or_pem(tmp_path):
    for f in (SYNTH, SNAP, TEMPLATE):
        text = f.read_text(encoding="utf-8")
        assert not _PEM.search(text), f
        for name in _names(json.loads(text)):
            assert not cap._SECRET_KEY.search(name), (f, name)  # noqa: SLF001
    # profile/template pass the loader's own secret denial (checked before mode); the snapshot is not secret-scanned by the loader, so its shape is pinned instead
    assert set(json.loads(SNAP.read_text())) == {"snapshot_id", "version", "valid_until", "issuers", "revoked_key_ids", "revoked_selections", "min_epochs"}
    issuer = json.loads(SNAP.read_text())["issuers"][0]
    assert set(issuer) == {"key_id", "issuer_id", "alg", "public_key", "authority"}
    assert len(_HEX64.findall(SNAP.read_text())) == 1 and issuer["public_key"] in _HEX64.findall(SNAP.read_text())
    unlabelled = lambda t: _HEX64.findall(re.sub(r"sha256:[0-9a-f]{64}", "", t))  # noqa: E731  (a labelled digest is public data, as in the loader)
    assert not unlabelled(SYNTH.read_text()) and not unlabelled(TEMPLATE.read_text())


def test_example_snapshot_is_labelled_synthetic_and_already_expired():
    snap = json.loads(SNAP.read_text())
    assert snap["snapshot_id"] == "SYNTHETIC-NOT-A-TRUST-ANCHOR" and PROFILE["id"].startswith("SYNTHETIC-NOT-A-TRUST-ANCHOR")
    assert PROFILE["clock"] == {"kind": "system_utc"}
    expiry = datetime.strptime(snap["valid_until"], "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    assert expiry < datetime(2021, 1, 1, tzinfo=timezone.utc) and expiry < datetime.now(timezone.utc)
    readme = (EX / "README.md").read_text(encoding="utf-8")
    assert "public" in readme and "forged" in readme and "NON-PRODUCTION" in readme and "expected_config_digest" in readme


def test_example_public_key_is_the_public_seed_key_and_the_pin_is_consistent(registry):
    nb, v2i = registry
    pk, _sk = nb.crypto_sign_seed_keypair(PUBLIC_SEED)
    snap = json.loads(SNAP.read_text())
    assert snap["issuers"][0]["public_key"] == pk.hex()
    import hashlib
    assert PROFILE["trust_anchor"]["keys"][0]["public_key_sha256"] == "sha256:" + hashlib.sha256(pk).hexdigest()
    assert PROFILE["snapshot"]["expected"]["fingerprint"] == v2i.trust_snapshot_fingerprint(snap)
    profile = cap.load_authority_profile(SYNTH, expected_mode="synthetic")
    trust, fingerprint = cap.load_pinned_trust(profile)  # the example is internally consistent with the loader's pin controls ...
    assert fingerprint == profile.pin_fingerprint
    assert datetime.strptime(trust.valid_until, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc) < datetime.now(timezone.utc)  # ... and expired (refused under a system_utc clock; see the pinned limit below)
