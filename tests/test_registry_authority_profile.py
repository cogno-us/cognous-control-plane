"""CAP v0.1 gate G1: configurable Registry authority profile `ocs-authority-profile/0.1` for the F4 selection source. BUILDER_TESTED developer evidence. NOT independently qualified.

CLAIM SCOPE: claim A only (synthetic keys, real Ed25519 through the Registry adapter). NO durable anti-rollback (G2): no state exists in this gate. Operational mode only FAILS CLOSED.

Needs a Registry checkout at the exact `PIN` in `OCS_CAP_REGISTRY_DIR` and PyNaCl. With `OCS_REQUIRE_REGISTRY_PIN=1` (CI) a missing/wrong pin or PyNaCl is a FAILURE, never a skip.
"""
from __future__ import annotations

import base64
import copy
import dataclasses
import hashlib
import json
import os
import subprocess
import sys
from pathlib import Path

import pytest

PIN = "7de0ec9f8471c7a2ff630eb4035fa24d60b5e2eb"
_REQUIRED = os.environ.get("OCS_REQUIRE_REGISTRY_PIN") == "1"


def _unavailable(reason: str):
    if _REQUIRED:
        pytest.fail("OCS_REQUIRE_REGISTRY_PIN=1 but " + reason, pytrace=False)
    pytest.skip("NOT RUN: " + reason, allow_module_level=True)


PIN_DIR = os.environ.get("OCS_CAP_REGISTRY_DIR")
if not PIN_DIR or not (Path(PIN_DIR) / "registry_successor").is_dir():
    _unavailable("OCS_CAP_REGISTRY_DIR is not set to a Registry checkout")
PIN_DIR = str(Path(PIN_DIR).resolve())
_head = subprocess.run(["git", "rev-parse", "HEAD"], cwd=PIN_DIR, capture_output=True, text=True).stdout.strip()
if _head != PIN:
    pytest.fail(f"Registry checkout is {_head!r}, expected the pin {PIN}", pytrace=False)
sys.path.insert(0, PIN_DIR)
sys.path.insert(0, str(Path(PIN_DIR) / "tests"))
try:
    import nacl.bindings as nb
except ImportError:
    _unavailable("PyNaCl is not installed")

import r08_support as r  # noqa: E402
import s01_support as s  # noqa: E402
from registry_adapters import ed25519_verifier as ev  # noqa: E402
from registry_successor import common as c  # noqa: E402
from registry_successor import v2_age_bounds as f4  # noqa: E402
from registry_successor import v2_policy_identity as v2i  # noqa: E402
from registry_successor import v2_verified_selection as vsel  # noqa: E402
from registry_successor import verify as v  # noqa: E402

from agent_control_plane import registry_authority_profile as cap  # noqa: E402
from agent_control_plane.bounded import BoundedRecordStore, LocalRefundDestination, ObservationPolicy  # noqa: E402
from agent_control_plane.registry_governed_lifecycle import GovernedScope, RegistrySelectionRefused, SelectionMaterial  # noqa: E402
from tests.test_bounded_authorization import NOW, manifest, tenant_proposal, tenant_resolver_for, TENANT  # noqa: E402

PK, SK = nb.crypto_sign_seed_keypair(bytes(range(32)))
OTHER_PK, OTHER_SK = nb.crypto_sign_seed_keypair(bytes(range(1, 33)))
OPERATION = "refund-issue-routine"
SEL_ID = "sel-test-1"
AS_OF = "2026-10-05T19:00:00Z"


def _scope_for_manifest():
    action = [a for a in manifest()["actions"]][0]
    auth = action["authority_context"]
    return action["action_id"], auth["institution_id"], auth["authority_domain"]


ACTION_ID, INSTITUTION, DOMAIN = _scope_for_manifest()
SCOPE = GovernedScope("consumer-test", TENANT.lower(), ACTION_ID, OPERATION)
CONTEXT = {"consumer_id": "consumer-test", "tenant": TENANT.lower(), "institution": INSTITUTION, "authority_domain": DOMAIN, "operation": OPERATION}
GRANT = [CONTEXT[k] for k in ("consumer_id", "tenant", "institution", "authority_domain", "operation")]
STMT_SCOPE = {"tenant": TENANT.lower(), "institution": INSTITUTION, "authority_domain": DOMAIN}
EFFECTIVE = {"valid_from": "2026-10-01T00:00:00Z", "valid_until": "2026-10-06T00:00:00Z"}


# ---------------------------------------------------------------------------------------------------------------------------- builders
def snapshot_doc(*, pub=PK, grants=None, min_epochs=((SEL_ID, 1),), version=1, extra_issuers=()):
    issuers = [{"key_id": s.KEY_ID, "issuer_id": "issuer-test-1", "alg": "ed25519", "public_key": pub.hex(), "authority": [list(g) for g in (grants or [GRANT])]}]
    issuers.extend(extra_issuers)
    return {"snapshot_id": "snap-test-1", "version": version, "valid_until": "2026-10-07T00:00:00Z", "issuers": issuers, "revoked_key_ids": [],
            "revoked_selections": [], "min_epochs": [list(p) for p in min_epochs]}


def trust_object(doc):
    return v.TrustSnapshot(doc["snapshot_id"], doc["version"], doc["valid_until"],
                           tuple(v.IssuerEntry(i["key_id"], i["issuer_id"], i["alg"], bytes.fromhex(i["public_key"]), tuple(v.AuthorityGrant(*g) for g in i["authority"]))
                                 for i in doc["issuers"]),
                           frozenset(doc["revoked_key_ids"]), frozenset(tuple(p) for p in doc["revoked_selections"]), tuple(tuple(p) for p in doc["min_epochs"]))


def config_doc(doc, *, mode="synthetic"):
    issuers = [{"issuer_id": i["issuer_id"], "key_id": i["key_id"], "grants": [dict(zip(("consumer_id", "tenant", "institution", "authority_domain", "operation"), g))
                                                                                 for g in i["authority"]]} for i in doc["issuers"]]
    keys = [{"key_id": i["key_id"], "public_key_sha256": "sha256:" + hashlib.sha256(bytes.fromhex(i["public_key"])).hexdigest()} for i in doc["issuers"]]
    synth = "UNSELECTED-SYNTHETIC"
    return {"version": cap.PROFILE_VERSION, "id": "cap-synthetic-f4-test", "mode": mode, "verifier": {"contract": "r08-v2", "family": "f4"},
            "trust_anchor": {"algorithm": "ed25519", "keys": keys}, "issuers": issuers, "expected_context": dict(CONTEXT),
            "snapshot": {"source": {"kind": "file", "reference": "snapshot.json"},
                         "expected": {"snapshot_id": doc["snapshot_id"], "version": doc["version"], "fingerprint": v2i.trust_snapshot_fingerprint(doc)}},
            "clock": {"kind": "fixed_instant", "as_of": AS_OF},
            "state": {"backend": "none-g1", "namespace": "cap-test", "reference": "none", "anchor_reference": "none"},
            "identities": {"snapshot_publisher_ref": synth, "enforcing_operator_ref": synth, "state_admin_ref": synth}}


class Env:
    """A written profile directory: `snapshot.json`, `profile.json`, and the loaded profile."""

    def __init__(self, tmp_path, *, doc=None, config_over=None, mode="synthetic", expected_mode="synthetic", **load_kw):
        self.dir = tmp_path / "profile"
        self.dir.mkdir()
        self.doc = doc or snapshot_doc()
        self.config = config_doc(self.doc, mode=mode)
        for k, val in (config_over or {}).items():
            self.config[k] = val
        (self.dir / "snapshot.json").write_text(json.dumps(self.doc))
        self.config_path = self.dir / "profile.json"
        self.config_path.write_text(json.dumps(self.config))
        self.profile = cap.load_authority_profile(self.config_path, expected_mode=expected_mode, **load_kw)
        self.trust = trust_object(self.doc)

    def rewrite_snapshot(self, doc):
        (self.dir / "snapshot.json").write_text(json.dumps(doc))


def sign(stmt, sk=SK):
    return base64.b64encode(nb.crypto_sign(s.V2_DOMAIN + c.canonical_bytes(stmt), sk)[:64]).decode("ascii")


def host_material(trust, *, sk=SK, pub=PK, stmt_over=None, status=60, approval=60):
    rec = r.seal_record(dict(r.make_record(), contract_version="r08-v2", family=f4.FAMILY_F4, record_id="f4-age-record",
                             payload={"status_max_age_seconds": status, "approval_max_age_seconds": approval}))
    over = dict(consumer_id="consumer-test", scope=STMT_SCOPE, operation=OPERATION, effective=EFFECTIVE, issued_at="2026-10-01T00:00:00Z", family=f4.FAMILY_F4)
    over.update(stmt_over or {})
    stmt = r.make_statement_v2(rec, **over)
    sel = r.dumps(s.envelope(stmt, domain=s.V2_DOMAIN, contract="r08-v2", signature=sign(stmt, sk), pub=pub))
    return SelectionMaterial(r.dumps(rec), sel, trust)


class Source:
    def __init__(self, material):
        self.material, self.calls = material, 0

    def __call__(self):
        self.calls += 1
        return self.material


@pytest.fixture(autouse=True)
def _fixed_clock(monkeypatch):
    import agent_control_plane.bounded as bounded_module
    import agent_control_plane.registry_f4_age_governance as gov
    monkeypatch.setattr(bounded_module, "_now", lambda: NOW)
    monkeypatch.setattr(gov, "_now", lambda: NOW)


@pytest.fixture
def verifier_spy(monkeypatch):
    calls = []
    real = vsel.verify_f4_selection_v2

    def spy(*a, **k):
        calls.append(1)
        return real(*a, **k)

    monkeypatch.setattr(vsel, "verify_f4_selection_v2", spy)
    return calls


def make_flow(tmp_path, env, source, **kw):
    p = tenant_proposal()
    kw.setdefault("resolver", tenant_resolver_for(p))
    return cap.governed_age_workflow(env.profile, host_source=source, scope=kw.pop("scope", SCOPE), expected_mode="synthetic", manifest=manifest(),
                                     destination=LocalRefundDestination(tmp_path / "destination.json"), records=BoundedRecordStore(tmp_path / "run.json", "run-1"),
                                     observation_policy=ObservationPolicy(max_age_seconds=300, clock_tolerance_seconds=5), **kw)


def snapshot_of_files(tmp_path):
    return sorted((x.name, x.read_bytes()) for x in tmp_path.rglob("*.json"))


def refusal_code(exc):
    return exc.value.code


# ---------------------------------------------------------------------------------------------------------------------------- P1 positive
def test_p1_factory_flow_authorizes_reads_the_source_each_boundary_and_pins_the_fingerprint(tmp_path):
    env = Env(tmp_path)
    src = Source(host_material(env.trust))
    flow = make_flow(tmp_path, env, src)
    assert flow.cap_authority_mode == "synthetic" and flow.cap_authority_id == "cap-synthetic-f4-test"
    p = tenant_proposal()
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    wrapper = flow.cap_selection_source
    assert wrapper.reads == src.calls == 4 and wrapper.last_refusal is None
    kw = cap.replay_trust_kwargs(env.profile)
    assert kw["trust_snapshot_fingerprint"] == env.profile.pin_fingerprint == v2i.trust_snapshot_fingerprint_from_verified(kw["trust_snapshot"])
    assert kw["expected_context"] == CONTEXT and kw["trust_snapshot_ref"] == ("snap-test-1", 1) and kw["time_mode"] == "as_of"
    assert cap.check_replay_markers(env.profile, [{"trust_snapshot_fingerprint": env.profile.pin_fingerprint}])
    assert not cap.check_replay_markers(env.profile, [{"trust_snapshot_fingerprint": "sha256:" + "0" * 64}]) and not cap.check_replay_markers(env.profile, [])


# ---------------------------------------------------------------------------------------------------------------------------- N1 forged authority
def test_n1_attacker_supplied_snapshot_is_refused_before_the_verifier(tmp_path, verifier_spy):
    env = Env(tmp_path)
    attacker = trust_object(snapshot_doc(pub=OTHER_PK))
    with pytest.raises(cap.AuthorityProfileRefusal) as e:
        make_flow(tmp_path, env, Source(host_material(attacker, sk=OTHER_SK, pub=OTHER_PK)))
    assert refusal_code(e) == "snapshot_pin_mismatch" and verifier_spy == []


@pytest.mark.parametrize("mutate", ["version", "extra_issuer", "extra_grant", "revocation", "floor", "key_swap"])
def test_n1_altered_pinned_file_after_construction_is_refused_without_a_state_change(tmp_path, verifier_spy, mutate):
    env = Env(tmp_path)
    src = Source(host_material(env.trust))
    flow = make_flow(tmp_path, env, src)
    n = len(verifier_spy)
    doc = copy.deepcopy(env.doc)
    if mutate == "version":
        doc["version"] = 2
    elif mutate == "extra_issuer":
        doc["issuers"].append({"key_id": "key-test-2", "issuer_id": "issuer-test-2", "alg": "ed25519", "public_key": OTHER_PK.hex(), "authority": [GRANT]})
    elif mutate == "extra_grant":
        doc["issuers"][0]["authority"].append(["consumer-test", TENANT.lower(), INSTITUTION, DOMAIN, "other-operation"])
    elif mutate == "revocation":
        doc["revoked_key_ids"] = ["key-other"]
    elif mutate == "floor":
        doc["min_epochs"] = [[SEL_ID, 1], ["sel-other", 5]]
    elif mutate == "key_swap":
        doc["issuers"][0]["public_key"] = OTHER_PK.hex()
    env.rewrite_snapshot(doc)
    before = snapshot_of_files(tmp_path)
    p = tenant_proposal()
    with pytest.raises(PermissionError):
        flow.decide(p, now=NOW)
    assert flow.cap_selection_source.last_refusal.code == "snapshot_pin_mismatch" and len(verifier_spy) == n
    assert snapshot_of_files(tmp_path) == before


def test_n1_missing_pinned_file_is_refused(tmp_path, verifier_spy):
    env = Env(tmp_path)
    flow = make_flow(tmp_path, env, Source(host_material(env.trust)))
    (env.dir / "snapshot.json").unlink()
    with pytest.raises(PermissionError):
        flow.decide(tenant_proposal(), now=NOW)
    assert flow.cap_selection_source.last_refusal.code == "authority_config_missing"


# ---------------------------------------------------------------------------------------------------------------------------- N2 wrong scope / authority
def test_n2_scope_that_differs_from_expected_context_is_refused_at_build(tmp_path):
    env = Env(tmp_path)
    for scope in (GovernedScope("consumer-other", TENANT.lower(), ACTION_ID, OPERATION), GovernedScope("consumer-test", "tenant-other", ACTION_ID, OPERATION),
                  GovernedScope("consumer-test", TENANT.lower(), ACTION_ID, "other-operation")):
        with pytest.raises(cap.AuthorityProfileRefusal) as e:
            make_flow(tmp_path, env, Source(host_material(env.trust)), scope=scope)
        assert refusal_code(e) == "authority_config_scope_mismatch"


@pytest.mark.parametrize("what", ["tenant", "operation", "consumer"])
def test_n2_selection_for_another_scope_reaches_the_verifier_and_is_not_applied(tmp_path, verifier_spy, what):
    env = Env(tmp_path)
    over = {"tenant": {"scope": dict(STMT_SCOPE, tenant="tenant-other")}, "operation": {"operation": "other-operation"}, "consumer": {"consumer_id": "consumer-other"}}[what]
    with pytest.raises(cap.AuthorityProfileRefusal) as e:
        make_flow(tmp_path, env, Source(host_material(env.trust, stmt_over=over)))
    assert refusal_code(e) == "registry_not_applied" and e.value.refusal.registry_code and len(verifier_spy) == 1


def test_n2_issuer_not_granted_for_the_scope_is_refused_by_the_verifier(tmp_path, verifier_spy):
    ungranted = ["consumer-test", TENANT.lower(), INSTITUTION, DOMAIN, "other-operation"]
    env = Env(tmp_path, doc=snapshot_doc(grants=[ungranted]))  # file and declaration agree, so the pin holds and the REGISTRY authority layer must refuse
    with pytest.raises(cap.AuthorityProfileRefusal) as e:
        make_flow(tmp_path, env, Source(host_material(env.trust)))
    assert refusal_code(e) == "registry_not_applied" and len(verifier_spy) == 1


def test_n2_wildcard_grant_is_refused_by_the_configuration(tmp_path):
    star = {k: "*" for k in ("consumer_id", "tenant", "institution", "authority_domain", "operation")}
    with pytest.raises(cap.AuthorityProfileRefusal) as e:
        Env(tmp_path, config_over={"issuers": [{"issuer_id": "issuer-test-1", "key_id": s.KEY_ID, "grants": [star]}]})
    assert refusal_code(e) == "authority_config_malformed"


# ---------------------------------------------------------------------------------------------------------------------------- N3 mode / configuration
def test_n3_mode_mismatch_is_refused_both_ways_and_without_a_declared_expectation(tmp_path):
    env = Env(tmp_path)
    for bad in ("operational", None, "", "SYNTHETIC", "fallback"):
        with pytest.raises(cap.AuthorityProfileRefusal) as e:
            cap.load_authority_profile(env.config_path, expected_mode=bad)
        assert refusal_code(e) == "authority_config_mode_mismatch"
    op = tmp_path / "op"
    op.mkdir()
    cfg = dict(env.config, mode="operational")
    (op / "profile.json").write_text(json.dumps(cfg))
    (op / "snapshot.json").write_text(json.dumps(env.doc))
    with pytest.raises(cap.AuthorityProfileRefusal) as e:  # an operational file never loads as synthetic: no fallback
        cap.load_authority_profile(op / "profile.json", expected_mode="synthetic")
    assert refusal_code(e) == "authority_config_mode_mismatch"


def test_n3_wrapper_refuses_when_the_profile_mode_is_not_the_owner_expected_mode(tmp_path, verifier_spy):
    env = Env(tmp_path)
    w = cap.PinnedSelectionSource(env.profile, Source(host_material(env.trust)), ev.Ed25519Verifier(), expected_mode="operational")
    with pytest.raises(cap.AuthorityProfileRefusal) as e:
        w()
    assert refusal_code(e) == "authority_config_mode_mismatch" and verifier_spy == [] and w.last_refusal.code == "authority_config_mode_mismatch"


def _operational(tmp_path, **over):
    d = tmp_path / "op"
    d.mkdir(exist_ok=True)
    env_doc = snapshot_doc()
    cfg = config_doc(env_doc, mode="operational")
    cfg["clock"] = {"kind": "system_utc"}
    real = "ops-ref-1"
    cfg["identities"] = {"snapshot_publisher_ref": real, "enforcing_operator_ref": real, "state_admin_ref": real}
    cfg["state"] = {"backend": "file", "namespace": "ns-1", "reference": "ref-1", "anchor_reference": "anchor-1"}
    cfg.update(over)
    (d / "profile.json").write_text(json.dumps(cfg))
    (d / "snapshot.json").write_text(json.dumps(env_doc))
    data = (d / "profile.json").read_bytes()
    return d / "profile.json", "sha256:" + hashlib.sha256(data).hexdigest()


def test_n3_operational_fails_closed_even_when_fully_populated_in_g1(tmp_path):
    path, digest = _operational(tmp_path)
    with pytest.raises(cap.AuthorityProfileRefusal) as e:
        cap.load_authority_profile(path, expected_mode="operational", expected_config_digest=digest)
    assert refusal_code(e) == "authority_config_unprovisioned" and "G2" in e.value.detail


def test_n3_operational_requires_the_owner_digest_and_rejects_placeholders_and_fixed_instants(tmp_path):
    path, digest = _operational(tmp_path)
    with pytest.raises(cap.AuthorityProfileRefusal) as e:
        cap.load_authority_profile(path, expected_mode="operational")
    assert refusal_code(e) == "authority_config_unprovisioned"
    ident = {"snapshot_publisher_ref": "UNSELECTED", "enforcing_operator_ref": "ops", "state_admin_ref": "ops"}
    for over in ({"identities": ident}, {"clock": {"kind": "fixed_instant", "as_of": AS_OF}},
                 {"state": {"backend": "file", "namespace": "ns", "reference": "PLACEHOLDER", "anchor_reference": "a"}}):
        p2, d2 = _operational(tmp_path, **over)
        with pytest.raises(cap.AuthorityProfileRefusal) as e:
            cap.load_authority_profile(p2, expected_mode="operational", expected_config_digest=d2)
        assert refusal_code(e) == "authority_config_unprovisioned"
    p3, _ = _operational(tmp_path)
    with pytest.raises(cap.AuthorityProfileRefusal) as e:
        cap.load_authority_profile(p3, expected_mode="operational", expected_config_digest="sha256:" + "1" * 64)
    assert refusal_code(e) == "authority_config_digest_mismatch"


def test_n3_digest_mismatch_and_version_and_unknown_members(tmp_path):
    env = Env(tmp_path)
    with pytest.raises(cap.AuthorityProfileRefusal) as e:
        cap.load_authority_profile(env.config_path, expected_mode="synthetic", expected_config_digest="sha256:" + "2" * 64)
    assert refusal_code(e) == "authority_config_digest_mismatch"
    ok = cap.load_authority_profile(env.config_path, expected_mode="synthetic", expected_config_digest=env.profile.config_digest)
    assert ok.config_digest == env.profile.config_digest
    for mutate, code in ((lambda c_: c_.update(version="ocs-authority-profile/9.9"), "authority_config_version_unsupported"),
                         (lambda c_: c_.update(extra="x"), "authority_config_malformed"),
                         (lambda c_: c_.pop("clock"), "authority_config_malformed"),
                         (lambda c_: c_["verifier"].update(family="f5"), "authority_config_malformed"),
                         (lambda c_: c_["snapshot"]["expected"].update(fingerprint="deadbeef"), "authority_config_malformed")):
        cfg = copy.deepcopy(env.config)
        mutate(cfg)
        env.config_path.write_text(json.dumps(cfg))
        with pytest.raises(cap.AuthorityProfileRefusal) as e:
            cap.load_authority_profile(env.config_path, expected_mode="synthetic")
        assert refusal_code(e) == code
    env.config_path.write_text("{not json")
    with pytest.raises(cap.AuthorityProfileRefusal) as e:
        cap.load_authority_profile(env.config_path, expected_mode="synthetic")
    assert refusal_code(e) == "authority_config_malformed"
    with pytest.raises(cap.AuthorityProfileRefusal) as e:
        cap.load_authority_profile(tmp_path / "nope.json", expected_mode="synthetic")
    assert refusal_code(e) == "authority_config_missing"


SECRETS = [("seed_hex", lambda c_: c_["trust_anchor"].update(seed="x")),
           ("private_key", lambda c_: c_["trust_anchor"]["keys"][0].update(private_key="x")),
           ("bare_hex_64", lambda c_: c_["trust_anchor"]["keys"][0].update(public_key_sha256="ab" * 32)),
           ("bare_hex_128", lambda c_: c_.update(id="ab" * 64)),
           ("base64_32", lambda c_: c_.update(id=base64.b64encode(bytes(range(32))).decode())),
           ("base64_64", lambda c_: c_.update(id=base64.b64encode(bytes(range(64))).decode())),
           ("pem", lambda c_: c_["state"].update(namespace="-----BEGIN PRIVATE KEY-----")),
           ("password_member", lambda c_: c_["state"].update(password="x")),
           ("signing_member", lambda c_: c_["state"].update(signing_ref="x"))]


@pytest.mark.parametrize("name,mutate", SECRETS, ids=[n for n, _ in SECRETS])
def test_n3_secret_material_is_refused_in_either_mode(tmp_path, name, mutate):
    env = Env(tmp_path)
    cfg = copy.deepcopy(env.config)
    mutate(cfg)
    env.config_path.write_text(json.dumps(cfg))
    with pytest.raises(cap.AuthorityProfileRefusal) as e:
        cap.load_authority_profile(env.config_path, expected_mode="synthetic")
    assert refusal_code(e) == "authority_config_secret_material"


def test_n3_innocent_words_are_not_secret_or_placeholder_false_positives(tmp_path):
    env = Env(tmp_path)
    cfg = copy.deepcopy(env.config)
    cfg["state"]["namespace"] = "latest-todos-exemplary"  # contains "todo"/"example"-like substrings inside words, not on delimiter boundaries
    env.config_path.write_text(json.dumps(cfg))
    assert cap.load_authority_profile(env.config_path, expected_mode="synthetic").mode == "synthetic"


def test_n3_factory_refuses_caller_supplied_source_verifier_and_operational_test_time(tmp_path):
    env = Env(tmp_path)
    src = Source(host_material(env.trust))
    for extra in ({"selection_source": src}, {"verifier": ev.Ed25519Verifier()}):
        with pytest.raises(cap.AuthorityProfileRefusal) as e:
            make_flow(tmp_path, env, src, **extra)
        assert refusal_code(e) == "authority_factory_argument_refused"
    operational = dataclasses.replace(env.profile, mode="operational")
    with pytest.raises(cap.AuthorityProfileRefusal) as e:
        cap.governed_age_workflow(operational, host_source=src, scope=SCOPE, expected_mode="operational", allow_test_time=True)
    assert refusal_code(e) == "authority_factory_argument_refused"


# ---------------------------------------------------------------------------------------------------------------------------- N4 verifier / epoch floor
class _Sub(ev.Ed25519Verifier):
    pass


@pytest.mark.parametrize("bad", [None, _Sub(), object(), lambda *a: True], ids=["none", "subclass", "object", "stub"])
def test_n4_verifier_that_is_not_the_exact_registry_adapter_is_refused_before_verification(tmp_path, verifier_spy, bad):
    env = Env(tmp_path)
    w = cap.PinnedSelectionSource(env.profile, Source(host_material(env.trust)), bad, expected_mode="synthetic")
    with pytest.raises(cap.AuthorityProfileRefusal) as e:
        w()
    assert refusal_code(e) == "verifier_unavailable" and verifier_spy == [] and w.last_refusal.code == "verifier_unavailable"


def test_n4_snapshot_without_a_per_selection_epoch_floor_is_refused(tmp_path, verifier_spy):
    env = Env(tmp_path, doc=snapshot_doc(min_epochs=()))
    with pytest.raises(cap.AuthorityProfileRefusal) as e:
        make_flow(tmp_path, env, Source(host_material(env.trust)))
    assert refusal_code(e) == "epoch_floor_missing" and len(verifier_spy) == 1


def test_n4_unsigned_or_wrongly_signed_selection_is_not_admitted(tmp_path, verifier_spy):
    env = Env(tmp_path)
    with pytest.raises(cap.AuthorityProfileRefusal) as e:
        make_flow(tmp_path, env, Source(host_material(env.trust, sk=OTHER_SK)))  # signed by a key the pinned snapshot does not hold
    assert refusal_code(e) == "registry_not_applied" and len(verifier_spy) == 1


def test_module_text_carries_no_forbidden_scanner_marker():
    assert "on_" + "unreadable" not in Path(cap.__file__).read_text()


def test_m1_a_hand_built_operational_profile_cannot_reach_wrapper_factory_or_replay_helper(tmp_path):
    env = Env(tmp_path)
    src = Source(host_material(env.trust))
    op = dataclasses.replace(env.profile, mode="operational")
    for call in (lambda: cap.PinnedSelectionSource(op, src, ev.Ed25519Verifier(), expected_mode="operational"),
                 lambda: cap.governed_age_workflow(op, host_source=src, scope=SCOPE, expected_mode="operational"),
                 lambda: cap.replay_trust_kwargs(op)):
        with pytest.raises(cap.AuthorityProfileRefusal) as e:
            call()
        assert refusal_code(e) == "authority_config_unprovisioned"


@pytest.mark.parametrize("value", [base64.b64encode(bytes(range(32))).decode().rstrip("="), base64.urlsafe_b64encode(bytes(range(64))).decode(),
                                   "0x" + "ab" * 32, "ed25519:" + "ab" * 32, ":".join(["ab"] * 32), "key is " + "ab" * 32, " " + "ab" * 32 + " "])
def test_m1_secret_shapes_in_free_strings_are_refused(tmp_path, value):
    env = Env(tmp_path)
    cfg = copy.deepcopy(env.config)
    cfg["state"]["reference"] = value
    env.config_path.write_text(json.dumps(cfg))
    with pytest.raises(cap.AuthorityProfileRefusal) as e:
        cap.load_authority_profile(env.config_path, expected_mode="synthetic")
    assert refusal_code(e) == "authority_config_secret_material"


def test_m2_trailing_newline_and_impossible_instant_are_malformed(tmp_path):
    env = Env(tmp_path)
    for mutate in (lambda c_: c_.update(id="cap-id\n"), lambda c_: c_["clock"].update(as_of="2026-13-45T99:99:99Z")):
        cfg = copy.deepcopy(env.config)
        mutate(cfg)
        env.config_path.write_text(json.dumps(cfg))
        with pytest.raises(cap.AuthorityProfileRefusal) as e:
            cap.load_authority_profile(env.config_path, expected_mode="synthetic")
        assert refusal_code(e) == "authority_config_malformed"


def test_m3_last_refusal_is_cleared_per_call_and_set_on_host_failure(tmp_path):
    env = Env(tmp_path)
    good = Source(host_material(env.trust))
    w = cap.PinnedSelectionSource(env.profile, good, ev.Ed25519Verifier(), expected_mode="synthetic")
    w()
    assert w.last_refusal is None

    def boom():
        raise RuntimeError("down")
    w._host = boom
    with pytest.raises(RuntimeError):
        w()
    assert w.last_refusal.code == "selection_source_failed"
