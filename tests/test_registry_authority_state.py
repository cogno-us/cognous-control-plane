"""CAP v0.1 gate G2: durable restart-safe freshness state (`ocs-cap-freshness-state/1`) for the F4 authority profile. BUILDER_TESTED developer evidence. NOT independently qualified.

CLAIM SCOPE: SYNTHETIC keys, real Ed25519, a REAL persisted file store. Operational trust NOT established. Local file integrity does NOT protect against an attacker who can replace or roll back
the whole store (pinned below by `test_limit_*`). Needs `OCS_CAP_REGISTRY_DIR` (Registry 7de0ec9f) and PyNaCl; `OCS_REQUIRE_REGISTRY_PIN=1` makes a missing pin a failure.
"""
from __future__ import annotations

import copy
import hashlib
import json
import os
import subprocess
import sys
import threading
from pathlib import Path

import pytest

from tests.test_registry_authority_profile import (  # noqa: F401  (G1 harness reused; it also puts the Registry pin on sys.path)
    AS_OF, CONTEXT, Env, GRANT, SCOPE, SEL_ID, Source, _fixed_clock, cap, config_doc, ev, host_material, make_flow, snapshot_doc, trust_object, v2i,
)
from tests.test_bounded_authorization import NOW, tenant_proposal
from agent_control_plane import registry_authority_state as st_mod

REPO = Path(__file__).resolve().parent.parent
NS = "cap-test-ns"


def env_g2(tmp_path, *, doc=None, **kw):
    env = Env(tmp_path, doc=doc, config_over={"state": {"backend": "file-g2", "namespace": NS, "reference": "state/cap-state.json", "anchor_reference": "none"}}, **kw)
    (env.dir / "state").mkdir(exist_ok=True)
    return env


def bootstrap_doc(env, **over):
    doc = {"schema": st_mod.BOOTSTRAP_SCHEMA, "bootstrap_id": "boot-test-0001", "namespace": NS, "authority_digest": st_mod.authority_digest(env.profile),
           "issued_for_mode": "synthetic", "issued_at": "2026-10-05T18:30:00Z", "not_after": "2026-10-05T19:30:00Z"}
    doc.update(over)
    return doc


def write_bootstrap(env, name="bootstrap.json", **over):
    p = env.dir / name
    p.write_text(json.dumps(bootstrap_doc(env, **over)))
    return p


def boot(env, **over):
    return st_mod.bootstrap_state(env.profile, write_bootstrap(env, **over), cap._now(env.profile))


def state_bytes(env):
    return Path(env.profile.state_path).read_bytes()


def sel(env, epoch=1, prior=None, status=60, trust=None):
    sup = None if prior is None else {"selection_id": SEL_ID, "epoch": prior[0], "statement_digest": prior[1], "decision_ref": "decision-test-1"}
    return host_material(trust or env.trust, stmt_over={"epoch": epoch, "supersedes": sup}, status=status, approval=status)


def digest_of(material):
    return json.loads(material.selection_text)["statement_digest"]


def admit(env, material):
    w = cap.PinnedSelectionSource(env.profile, Source(material), ev.Ed25519Verifier(), expected_mode="synthetic")
    out = w()
    return w, out


def refusal(env, material):
    with pytest.raises(cap.AuthorityProfileRefusal) as e:
        admit(env, material)
    return e.value


def rotate(env, doc):
    """A legitimate snapshot rotation: new pinned document and fingerprint, same trust anchor and grants."""
    env.rewrite_snapshot(doc)
    cfg = json.loads(env.config_path.read_text())
    cfg["snapshot"]["expected"] = {"snapshot_id": doc["snapshot_id"], "version": doc["version"], "fingerprint": v2i.trust_snapshot_fingerprint(doc)}
    env.config_path.write_text(json.dumps(cfg))
    env.profile = cap.load_authority_profile(env.config_path, expected_mode="synthetic")
    env.trust = trust_object(doc)


# ------------------------------------------------------------------------------------------------------------------------ P2 positive
def test_p2_bootstrapped_flow_authorizes_and_persists_one_generation_then_repeats_write_nothing(tmp_path):
    env = env_g2(tmp_path)
    first = boot(env)
    assert first["generation"] == 0 and first["state"]["rows"] == {} and first["bootstrap"]["bootstrap_id"] == "boot-test-0001"
    flow = make_flow(tmp_path, env, Source(sel(env)))
    after_build = state_bytes(env)
    assert json.loads(after_build)["generation"] == 1
    p = tenant_proposal()
    d = flow.decide(p, now=NOW)
    assert d.result == "authorized", d.reasons
    flow.execute(p, d, adapter_id=p.adapter_id, now=NOW)
    assert flow.cap_selection_source.reads == 4 and state_bytes(env) == after_build  # repeats use the kit guard and write nothing
    row = next(iter(st_mod.read_state(env.profile)["state"]["rows"].values()))
    assert row["epoch"] == 1 and row["activation_state"] == "active"


def test_p2_legitimate_renewal_advances_once_and_the_old_epoch_is_then_stale(tmp_path):
    env = env_g2(tmp_path)
    boot(env)
    m1 = sel(env, 1)
    admit(env, m1)
    m2 = sel(env, 2, prior=(1, digest_of(m1)))
    admit(env, m2)
    assert st_mod.read_state(env.profile)["generation"] == 2
    err = refusal(env, m1)
    assert err.code == "freshness_refused" and err.refusal.registry_code == "selection_epoch_stale"


def test_p2_restart_in_a_fresh_process_retains_the_floors(tmp_path):
    env = env_g2(tmp_path)
    boot(env)
    m1 = sel(env, 1)
    m2 = sel(env, 2, prior=(1, digest_of(m1)))
    admit(env, m1)
    admit(env, m2)
    before = state_bytes(env)
    out = run_child(env, "admit", epoch=1)  # a NEW interpreter loads the config and the persisted store
    assert out == "refused:freshness_refused:selection_epoch_stale", out
    assert state_bytes(env) == before
    assert run_child(env, "admit", epoch=2, prior_epoch=1, prior_digest=digest_of(m1)) == "ok"  # same selection again: guard, no write
    assert state_bytes(env) == before


# ------------------------------------------------------------------------------------------------------------------------ N5 state integrity
def test_n5_missing_store_refuses_and_is_never_created(tmp_path):
    env = env_g2(tmp_path)
    err = refusal(env, sel(env))
    assert err.code == "state_missing" and not Path(env.profile.state_path).exists()


def test_n5_deleting_the_store_after_use_does_not_reinitialize_the_floors(tmp_path):
    env = env_g2(tmp_path)
    boot(env)
    admit(env, sel(env, 1))
    Path(env.profile.state_path).unlink()
    assert refusal(env, sel(env, 1)).code == "state_missing"
    with pytest.raises(cap.AuthorityProfileRefusal) as e:  # the consumed ledger blocks replaying the same bootstrap
        boot(env)
    assert e.value.code == "bootstrap_consumed"


@pytest.mark.parametrize("damage", ["flip_byte", "truncate", "not_json", "extra_member", "wrong_digest", "empty"])
def test_n5_corrupt_store_refuses_without_writing(tmp_path, damage):
    env = env_g2(tmp_path)
    boot(env)
    admit(env, sel(env, 1))
    path = Path(env.profile.state_path)
    raw = path.read_bytes()
    if damage == "flip_byte":
        new = bytearray(raw)
        new[len(new) // 2] ^= 0x01
        new = bytes(new)
    elif damage == "truncate":
        new = raw[: len(raw) // 2]
    elif damage == "not_json":
        new = b"\x00\x01garbage"
    elif damage == "empty":
        new = b""
    elif damage == "extra_member":
        d = json.loads(raw)
        d["extra"] = 1
        new = json.dumps(d).encode()
    else:
        d = json.loads(raw)
        d["generation"] = 99
        new = json.dumps(d).encode()
    path.write_bytes(new)
    assert refusal(env, sel(env, 1)).code == "state_corrupt"
    assert path.read_bytes() == new


def test_n5_a_resealed_but_kit_invalid_state_is_refused(tmp_path):
    env = env_g2(tmp_path)
    boot(env)
    admit(env, sel(env, 1))
    path = Path(env.profile.state_path)
    d = json.loads(path.read_bytes())
    d["state"]["floors"]["high_water"] = {}  # an attacker lowers the floors and re-seals the digest
    d["state"]["rows"] = {k: dict(r, epoch=0) for k, r in d["state"]["rows"].items()}
    body = {k: v for k, v in d.items() if k != "state_digest"}
    path.write_bytes(st_mod._canon(st_mod._seal(body)))
    assert refusal(env, sel(env, 1)).code in ("state_corrupt", "freshness_refused")


def test_n5_store_of_another_namespace_or_authority_is_refused(tmp_path):
    env = env_g2(tmp_path)
    boot(env)
    other = tmp_path / "other"
    other.mkdir()
    env2 = Env(other, config_over={"state": {"backend": "file-g2", "namespace": "other-ns", "reference": str(env.profile.state_path), "anchor_reference": "none"}})
    assert refusal(env2, sel(env2)).code == "state_authority_mismatch"
    cfg = json.loads(env.config_path.read_text())
    cfg["expected_context"]["tenant"] = "tenant-other"  # a different scope/authority configuration over the same store
    cfg["issuers"][0]["grants"][0]["tenant"] = "tenant-other"
    env.config_path.write_text(json.dumps(cfg))
    doc = copy.deepcopy(env.doc)
    doc["issuers"][0]["authority"][0][1] = "tenant-other"
    rotate(env, doc)
    assert refusal(env, sel(env)).code == "state_authority_mismatch"


def test_limit_a_whole_store_rollback_to_an_older_valid_envelope_is_not_detected(tmp_path):
    """HONEST LIMIT (property G): local integrity cannot detect replacement of the entire store by an older valid copy. G3 anchoring is required."""
    env = env_g2(tmp_path)
    boot(env)
    m1 = sel(env, 1)
    admit(env, m1)
    old = state_bytes(env)
    admit(env, sel(env, 2, prior=(1, digest_of(m1))))
    Path(env.profile.state_path).write_bytes(old)  # privileged rollback
    admit(env, m1)  # accepted: documented, NOT claimed solved


# ------------------------------------------------------------------------------------------------------------------------ N6 bootstrap
@pytest.mark.parametrize("over,code", [
    ({"not_after": "2026-10-05T18:45:00Z", "issued_at": "2026-10-05T18:30:00Z"}, "bootstrap_expired"),
    ({"issued_at": "2026-10-05T19:30:00Z", "not_after": "2026-10-05T20:00:00Z"}, "bootstrap_expired"),
    ({"not_after": "2026-10-05T19:30:01Z"}, "bootstrap_invalid"),
    ({"namespace": "other-ns"}, "bootstrap_invalid"),
    ({"authority_digest": "sha256:" + "0" * 64}, "bootstrap_invalid"),
    ({"issued_for_mode": "operational"}, "bootstrap_invalid"),
    ({"bootstrap_id": "x"}, "bootstrap_invalid"),
    ({"floors": {"min_epochs": [[SEL_ID, 99]]}}, "bootstrap_invalid"),
    ({"min_epoch": 99}, "bootstrap_invalid"),
])
def test_n6_unauthorized_or_malformed_bootstrap_is_refused_and_creates_nothing(tmp_path, over, code):
    env = env_g2(tmp_path)
    with pytest.raises(cap.AuthorityProfileRefusal) as e:
        boot(env, **over)
    assert e.value.code == code and not Path(env.profile.state_path).exists()
    assert refusal(env, sel(env)).code == "state_missing"


def test_n6_bootstrap_never_resets_an_existing_store_and_is_one_shot(tmp_path):
    env = env_g2(tmp_path)
    boot(env)
    admit(env, sel(env, 1))
    before = state_bytes(env)
    for bid in ("boot-test-0001", "boot-test-0002"):
        with pytest.raises(cap.AuthorityProfileRefusal) as e:
            boot(env, bootstrap_id=bid)
        assert e.value.code in ("bootstrap_state_exists",)
    assert state_bytes(env) == before


def test_n6_bootstrap_with_key_shaped_material_is_refused(tmp_path):
    env = env_g2(tmp_path)
    with pytest.raises(cap.AuthorityProfileRefusal) as e:
        boot(env, bootstrap_id="ab" * 32)
    assert e.value.code == "bootstrap_invalid"


def test_n6_bootstrap_unavailable_for_g1_stateless_and_operational_profiles(tmp_path):
    env = Env(tmp_path)  # none-g1
    with pytest.raises(cap.AuthorityProfileRefusal) as e:
        st_mod.bootstrap_state(env.profile, write_bootstrap(env), cap._now(env.profile))
    assert e.value.code == "authority_config_unprovisioned"


# ------------------------------------------------------------------------------------------------------------------------ N7 monotonic freshness
def test_n7_equal_epoch_with_a_different_selection_is_refused(tmp_path):
    env = env_g2(tmp_path)
    boot(env)
    admit(env, sel(env, 1, status=60))
    before = state_bytes(env)
    err = refusal(env, sel(env, 1, status=59))
    assert err.code == "freshness_refused" and err.refusal.registry_code in ("selection_epoch_stale", "selection_supersession_invalid")
    assert state_bytes(env) == before


def test_n7_skipping_the_supersession_chain_is_refused(tmp_path):
    env = env_g2(tmp_path)
    boot(env)
    admit(env, sel(env, 1))
    before = state_bytes(env)
    assert refusal(env, sel(env, 2)).code == "freshness_refused"
    assert state_bytes(env) == before


def test_n7_older_snapshot_is_refused_after_a_newer_one_was_accepted(tmp_path):
    env = env_g2(tmp_path)
    boot(env)
    admit(env, sel(env, 1))
    v1_doc = copy.deepcopy(env.doc)
    rotate(env, snapshot_doc(version=2))
    admit(env, sel(env, 1))  # the same selection under the newer snapshot: allowed, advances the snapshot floor
    before = state_bytes(env)
    assert st_mod.read_state(env.profile)["state"]["floors"]["snapshot_version"] == 2
    rotate(env, v1_doc)  # owner (or attacker with config access) re-pins the older snapshot
    err = refusal(env, sel(env, 1))
    assert err.code in ("freshness_refused", "registry_not_applied")
    assert state_bytes(env) == before


def test_n7_lowered_min_epochs_in_a_newer_snapshot_is_refused(tmp_path):
    env = env_g2(tmp_path)
    boot(env)
    m1 = sel(env, 1)
    d1 = digest_of(m1)
    admit(env, m1)
    rotate(env, snapshot_doc(version=2, min_epochs=((SEL_ID, 2),)))
    admit(env, sel(env, 2, prior=(1, d1)))  # floor 2 stored with the accepted epoch 2
    rotate(env, snapshot_doc(version=3, min_epochs=((SEL_ID, 1),)))  # a newer snapshot that LOWERS the stored floor
    err = refusal(env, sel(env, 2, prior=(1, d1)))
    assert err.code == "freshness_refused" and err.refusal.registry_code == "min_epoch_floor_lowered"


def test_n7_revocation_set_cannot_shrink(tmp_path):
    env = env_g2(tmp_path)
    boot(env)
    admit(env, sel(env, 1))
    rotate(env, dict(snapshot_doc(version=2), revoked_key_ids=["key-other"]))
    admit(env, sel(env, 1))
    rotate(env, snapshot_doc(version=3))  # drops the earlier revocation
    err = refusal(env, sel(env, 1))
    assert err.code == "freshness_refused" and err.refusal.registry_code == "trust_snapshot_revocation_omitted"


def test_n7_revoked_or_expired_selection_is_refused_without_a_state_change(tmp_path):
    env = env_g2(tmp_path)
    boot(env)
    admit(env, sel(env, 1))
    before = state_bytes(env)
    rotate(env, dict(snapshot_doc(version=2), revoked_selections=[[SEL_ID, 1]]))
    assert refusal(env, sel(env, 1)).code == "registry_not_applied"
    rotate(env, snapshot_doc(version=3))
    expired = host_material(env.trust, stmt_over={"epoch": 1, "effective": {"valid_from": "2026-10-01T00:00:00Z", "valid_until": "2026-10-05T18:00:00Z"}})
    assert refusal(env, expired).code == "registry_not_applied"  # expired at the profile clock
    assert state_bytes(env) == before


def test_n7_untrusted_higher_epoch_cannot_advance_state(tmp_path):
    env = env_g2(tmp_path)
    boot(env)
    m1 = sel(env, 1)
    admit(env, m1)
    before = state_bytes(env)
    forged = host_material(env.trust, sk=cap_other_sk(), stmt_over={"epoch": 99, "supersedes": {"selection_id": SEL_ID, "epoch": 1, "statement_digest": digest_of(m1), "decision_ref": "decision-test-1"}})
    assert refusal(env, forged).code == "registry_not_applied"
    assert state_bytes(env) == before


def cap_other_sk():
    from tests.test_registry_authority_profile import OTHER_SK
    return OTHER_SK


# ------------------------------------------------------------------------------------------------------------------------ alternate paths / downgrade
def test_alternate_paths_cannot_bypass_the_store(tmp_path):
    env = env_g2(tmp_path)
    for build in (lambda: make_flow(tmp_path, env, Source(sel(env))), lambda: admit(env, sel(env))):
        with pytest.raises(cap.AuthorityProfileRefusal) as e:
            build()
        assert e.value.code == "state_missing"
    other = tmp_path / "g1"
    other.mkdir()
    with pytest.raises(cap.AuthorityProfileRefusal) as e:  # a stateless (none-g1) profile has no store; it cannot be used as a transaction
        st_mod.open_transaction(Env(other).profile, cap._now(env.profile))
    assert e.value.code == "authority_config_unprovisioned"


# ------------------------------------------------------------------------------------------------------------------------ atomicity / concurrency
def test_write_failure_leaves_the_store_untouched_and_does_not_admit(tmp_path, monkeypatch):
    env = env_g2(tmp_path)
    boot(env)
    before = state_bytes(env)

    def boom(*a, **k):
        raise OSError("disk full")
    monkeypatch.setattr(st_mod, "write_bytes_atomic", boom)
    assert refusal(env, sel(env, 1)).code == "state_write_failed"
    assert state_bytes(env) == before


def test_lock_failure_refuses_without_writing(tmp_path, monkeypatch):
    import fcntl
    env = env_g2(tmp_path)
    boot(env)
    before = state_bytes(env)
    monkeypatch.setattr(st_mod, "LOCK_TIMEOUT_SECONDS", 0.2)
    holder = os.open(st_mod._lock_path(env.profile), os.O_RDWR | os.O_CREAT, 0o600)
    fcntl.flock(holder, fcntl.LOCK_EX)
    try:
        assert refusal(env, sel(env, 1)).code == "state_lock_failed"
    finally:
        fcntl.flock(holder, fcntl.LOCK_UN)
        os.close(holder)
    assert state_bytes(env) == before


def test_crash_between_temp_write_and_replace_leaves_the_old_store_intact(tmp_path):
    env = env_g2(tmp_path)
    boot(env)
    m1 = sel(env, 1)
    admit(env, m1)
    before = state_bytes(env)
    out = run_child(env, "admit", epoch=2, prior_epoch=1, prior_digest=digest_of(m1), crash="before_replace", expect_rc=9)
    assert out == "" and state_bytes(env) == before  # a temporary file may remain; the store did not change
    assert st_mod.read_state(env.profile)["generation"] == 1
    assert run_child(env, "admit", epoch=2, prior_epoch=1, prior_digest=digest_of(m1)) == "ok"  # recovery: the lock is gone with the process and the retry succeeds
    assert st_mod.read_state(env.profile)["generation"] == 2


def test_concurrent_competing_advances_accept_exactly_one_selection(tmp_path):
    env = env_g2(tmp_path)
    boot(env)
    m1 = sel(env, 1)
    admit(env, m1)
    outs = {}

    def go(i, status):
        outs[i] = run_child(env, "admit", epoch=2, prior_epoch=1, prior_digest=digest_of(m1), status=status)

    threads = [threading.Thread(target=go, args=(i, 60 if i % 2 == 0 else 59)) for i in range(8)]
    [t.start() for t in threads]
    [t.join() for t in threads]
    ok60 = [i for i in outs if i % 2 == 0 and outs[i] == "ok"]
    ok59 = [i for i in outs if i % 2 == 1 and outs[i] == "ok"]
    assert (len(ok60) == 4 and not ok59) or (len(ok59) == 4 and not ok60), outs  # one variant won; all copies of it pass (guard); the other is stale
    final = st_mod.read_state(env.profile)
    assert final["generation"] == 2 and cap_kit().verify_state(final["state"]) is None


def cap_kit():
    return st_mod._kit()


# ------------------------------------------------------------------------------------------------------------------------ child process helper
def run_child(env, action, *, epoch, prior_epoch=None, prior_digest=None, status=60, crash=None, expect_rc=0):
    args = json.dumps({"config": str(env.config_path), "epoch": epoch, "prior": None if prior_epoch is None else [prior_epoch, prior_digest], "status": status, "crash": crash,
                       "snapshot_version": env.profile.pin_version})
    proc = subprocess.run([sys.executable, "-m", "tests.test_registry_authority_state", args], cwd=REPO, capture_output=True, text=True, timeout=60,
                          env=dict(os.environ, PYTHONPATH=str(REPO / "src") + os.pathsep + str(REPO)))
    assert proc.returncode == expect_rc, (proc.returncode, proc.stderr[-800:])
    return proc.stdout.strip()


if __name__ == "__main__":
    spec = json.loads(sys.argv[1])
    if spec["crash"] == "before_replace":
        os.replace = lambda *a, **k: os._exit(9)
    profile = cap.load_authority_profile(spec["config"], expected_mode="synthetic")
    doc = json.loads(Path(profile.snapshot_path).read_text())
    trust = trust_object(doc)
    material = host_material(trust, stmt_over={"epoch": spec["epoch"], "supersedes": None if spec["prior"] is None else
                                               {"selection_id": SEL_ID, "epoch": spec["prior"][0], "statement_digest": spec["prior"][1], "decision_ref": "decision-test-1"}},
                             status=spec["status"], approval=spec["status"])
    try:
        cap.PinnedSelectionSource(profile, Source(material), ev.Ed25519Verifier(), expected_mode="synthetic")()
        print("ok")
    except cap.AuthorityProfileRefusal as e:
        print(f"refused:{e.code}" + (f":{e.refusal.registry_code}" if e.refusal.registry_code else ""))
