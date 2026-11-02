"""Durable verification-time authority state for the F4 authority profile (CAP v0.1, gate G2).

BUILDER_TESTED developer implementation. NOT independently qualified. SYNTHETIC restart-safe only: OPERATIONAL TRUST NOT ESTABLISHED, PRODUCTION ADOPTION NOT AUTHORIZED.

What it is. A single-file store `ocs-cap-freshness-state/1` that wraps the unchanged Registry conformance kit state `ocs-conformance-state/1`
(`registry_conformance.highwater`: `advance`, `guard`, `verify_state`, `scope_key`, `empty_state`; resolved lazily from the Registry checkout, never vendored). The kit owns every
floor rule (selection epoch high-water, per-selection `min_epochs`, snapshot version floor, grow-only revocations, supersession); this module only
(1) builds kit observations from a selection the Registry verifier ALREADY admitted against the pinned snapshot,
(2) holds one exclusive `flock` across read -> verify -> advance -> fsync + `os.replace` (CP `atomic_write`), and
(3) refuses, without writing, on a missing, corrupt, foreign, locked or unwritable store.
Refusals, malformed input and failures never write. A repeat of the same admitted selection uses the kit `guard` and writes nothing (unless the pinned snapshot advanced).

Envelope members (closed): `schema, namespace, authority_digest, generation, parent_digest, bootstrap, state, state_digest`. `authority_digest` is the digest of the profile
configuration WITHOUT `snapshot.expected`, `snapshot.source` and `identities`, so a legitimate snapshot rotation (a new pin, same trust anchor and grants) is not a reset while any change to
mode, anchor, issuers, grants, context, clock, namespace or backend binds to a different store. State is scope-specific: the kit keys rows by the 7-field scope key.

Bootstrap. `ocs-cap-bootstrap/1` (`bootstrap_id, namespace, authority_digest, issued_for_mode, issued_at, not_after`, TTL <= 3600 s, NO floor-seeding member) is consumed by
`bootstrap_state`, which creates the store EXCLUSIVELY with an EMPTY kit state and records a consumed-id ledger next to it. A missing store is never created implicitly.

HONEST LIMITS (not claimed solved): (1) local file integrity (a digest) detects accidental or partial corruption, NOT an attacker who can replace or roll back the whole store directory,
or simply create a fresh EMPTY store by hand (neither a valid bootstrap nor the ledger is needed; the ledger only stops accidental reuse of one id), or edit the profile to `none-g1` when no `expected_config_digest` is supplied; protection against a privileged state-store writer needs an independently anchored monotonic
store (G3 operational responsibility, `anchor_reference`). (2) Floors advance only when a selection is ADMITTED, so a newer pinned snapshot whose only effect is to revoke the selection is not recorded and re-pinning the older snapshot afterwards re-admits it; a snapshot whose only effect would be a revocation of a refused selection does not
by itself advance the store. (3) One host, one filesystem with working `flock`/`os.replace`; no distributed state. (4) Continued/effect-time authority is out of scope.
"""
from __future__ import annotations

import copy
import fcntl
import hashlib
import importlib
import json
import os
import time
from pathlib import Path
from typing import Any, Optional

from agent_control_plane.atomic_write import write_bytes_atomic
from agent_control_plane.registry_authority_profile import AuthorityProfile, _refuse, _secret_deny, require_backend
from agent_control_plane.strict_json import strict_loads

STATE_SCHEMA = "ocs-cap-freshness-state/1"
BOOTSTRAP_SCHEMA = "ocs-cap-bootstrap/1"
ENVELOPE_MEMBERS = ("schema", "namespace", "authority_digest", "generation", "parent_digest", "bootstrap", "state", "state_digest")
BOOTSTRAP_MEMBERS = ("schema", "bootstrap_id", "namespace", "authority_digest", "issued_for_mode", "issued_at", "not_after")
MAX_TTL_SECONDS = 3600
MAX_STATE_BYTES = 8 * 1024 * 1024
LOCK_TIMEOUT_SECONDS = 5.0


def _canon(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, allow_nan=False).encode("ascii")


def _sha(value: Any) -> str:
    return "sha256:" + hashlib.sha256(_canon(value)).hexdigest()


def _kit():
    try:
        return importlib.import_module("registry_conformance.highwater")
    except Exception:
        raise _refuse("verifier_unavailable", "Registry conformance kit is not importable") from None


def authority_digest(profile: AuthorityProfile) -> str:
    """Digest of the configuration without `snapshot.expected`, `snapshot.source` and `identities` (snapshot rotation is not a reset)."""
    cfg = copy.deepcopy(dict(profile.config))
    cfg["snapshot"] = {}
    cfg.pop("identities", None)
    return _sha(cfg)


def _epoch(text: Any) -> int:
    from datetime import datetime, timezone
    return int(datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp())


def _seal(env: dict) -> dict:
    body = {k: v for k, v in env.items() if k != "state_digest"}
    return {**body, "state_digest": _sha(body)}


def _lock_path(profile: AuthorityProfile) -> str:
    return profile.state_path + ".lock"


def _acquire(profile: AuthorityProfile) -> int:
    try:
        fd = os.open(_lock_path(profile), os.O_RDWR | os.O_CREAT | os.O_CLOEXEC, 0o600)
    except OSError:
        raise _refuse("state_lock_failed", "lock file cannot be opened") from None
    deadline = time.monotonic() + LOCK_TIMEOUT_SECONDS
    while True:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            locked = True
        except OSError:
            locked = False
        if locked:
            try:  # the lock file must still be the file we locked (an unlinked lock would admit a second holder)
                same = os.fstat(fd).st_ino == os.stat(_lock_path(profile)).st_ino
            except OSError:
                same = False
            if same:
                return fd
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
            raise _refuse("state_lock_failed", "lock file was replaced while locking")
        if time.monotonic() >= deadline:
            os.close(fd)
            raise _refuse("state_lock_failed", "state lock not acquired in time")
        time.sleep(0.01)


def _read_envelope(profile: AuthorityProfile) -> dict:
    path = Path(profile.state_path)
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_STATE_BYTES + 1)
    except FileNotFoundError:
        raise _refuse("state_missing", "no state store: a missing store is never created implicitly (use an authorized bootstrap)") from None
    except OSError:
        raise _refuse("state_corrupt", "state store unreadable") from None
    if len(data) > MAX_STATE_BYTES:
        raise _refuse("state_corrupt", "state store too large")
    try:
        env = strict_loads(data)
    except Exception:
        raise _refuse("state_corrupt", "state store is not strict JSON") from None
    if type(env) is not dict or set(env) != set(ENVELOPE_MEMBERS) or env["schema"] != STATE_SCHEMA:
        raise _refuse("state_corrupt", "state envelope is not the closed schema")
    if type(env["generation"]) is not int or isinstance(env["generation"], bool) or env["generation"] < 0:
        raise _refuse("state_corrupt", "generation")
    if env["state_digest"] != _sha({k: v for k, v in env.items() if k != "state_digest"}):
        raise _refuse("state_corrupt", "state digest differs")
    if env["namespace"] != profile.state_namespace or env["authority_digest"] != authority_digest(profile):
        raise _refuse("state_authority_mismatch", "store belongs to another namespace or authority configuration")
    kit = _kit()
    if type(env["state"]) is not dict or kit.verify_state(env["state"]) is not None or env["state"].get("store") != "known":
        raise _refuse("state_corrupt", "kit state failed verification")
    return env


def _write_envelope(profile: AuthorityProfile, env: dict, *, exclusive: bool = False) -> None:
    try:
        write_bytes_atomic(Path(profile.state_path), _canon(env), overwrite=not exclusive)
    except FileExistsError:
        raise _refuse("bootstrap_state_exists", "a state store already exists") from None
    except Exception:
        raise _refuse("state_write_failed", "state store not written") from None


class Transaction:
    """Holds the exclusive lock and the state read at open. `commit` is the ONLY writer; closing without commit never writes."""

    def __init__(self, profile: AuthorityProfile, now: Any, fd: int, env: dict):
        self._profile, self._fd, self._env, self._now_src = profile, fd, env, now
        snap = env["state"].get("snapshot")
        self.last_accepted = None if snap is None else (snap["version"], snap["fingerprint"])
        self.generation = env["generation"]
        self.closed = False

    def close(self) -> None:
        if not self.closed:
            self.closed = True
            try:
                fcntl.flock(self._fd, fcntl.LOCK_UN)
            finally:
                os.close(self._fd)

    def commit(self, verdict: Any, selection_text: str, trust: Any) -> None:
        kit = _kit()
        profile, env = self._profile, self._env
        vsel = importlib.import_module("registry_successor.v2_verified_selection")
        if type(verdict) is not vsel.VerifiedSelectionV2 or verdict.admitted is not True or verdict.epoch_floor_applied is not True or type(selection_text) is not str:
            raise _refuse("freshness_refused", "only an admitted Registry verdict with an applied epoch floor can be committed", "verdict_not_admitted")
        now = int((self._now_src() if callable(self._now_src) else self._now_src).timestamp())  # read AFTER the lock was taken
        try:
            from agent_control_plane.registry_authority_profile import _registry
            parsed = importlib.import_module("registry_successor.v2_selection").parse_selection_envelope_v2(selection_text)
            stmt = parsed.statement
            if parsed.statement_digest != verdict.selection_digest or len(parsed.signatures) != 1:
                raise ValueError("selection text differs from the admitted verdict")
            key_id = parsed.signatures[0]["key_id"]
            if not any(iss == verdict.issuer_id and k == key_id for (iss, k, _g) in profile.declared_issuers):
                raise ValueError("signing key is not declared for the admitted issuer")
            scope = {"selection_id": verdict.selection_id, "consumer_id": verdict.consumer_id, "tenant": verdict.scope[0], "institution": verdict.scope[1],
                     "authority_domain": verdict.scope[2], "operation": verdict.operation, "family": verdict.family}
            norm = _registry()[1].trust_snapshot_from_verified(trust)
            snapshot = {"version": norm["version"], "fingerprint": verdict.trust_snapshot_fingerprint, "valid_until": _epoch(norm["valid_until"]),
                        "revoked_selections": [list(p) for p in norm["revoked_selections"]], "revoked_key_ids": list(norm["revoked_key_ids"]),
                        "min_epochs": [list(p) for p in norm["min_epochs"]]}
            select = {"kind": "select", "now": now, "scope": scope, "epoch": verdict.epoch, "selection_digest": verdict.selection_digest,
                      "supersedes": None if stmt.get("supersedes") is None else {k: stmt["supersedes"][k] for k in ("selection_id", "epoch", "statement_digest")}, "participation": verdict.participation, "valid_from": _epoch(verdict.valid_from),
                      "valid_until": _epoch(verdict.valid_until), "issuer_key_id": key_id, "issuer_id": verdict.issuer_id,
                      "record": {"record_id": verdict.record_id, "record_version": verdict.record_version, "record_digest": verdict.record_digest}, "verified": True}
        except Exception:
            raise _refuse("freshness_refused", "observation could not be built from the admitted verdict", "observation_malformed") from None
        st, v = kit.advance(env["state"], {"kind": "sync", "now": now, "snapshot": snapshot})
        if v["verdict"] != kit.ACCEPT:
            raise _refuse("freshness_refused", "pinned snapshot is not acceptable against the stored floors", v["code"])
        row = st["rows"].get(kit.scope_key(scope))
        repeat = row is not None and row["epoch"] == select["epoch"] and row["selection_digest"] == select["selection_digest"]
        if repeat:
            claim = {"scope": scope, "binding": {"selection_epoch": row["epoch"], "selection_digest": row["selection_digest"], "record": row["record"],
                                                 "activation_ref": row["activation_ref"], "trust_snapshot_version": snapshot["version"],
                                                 "trust_snapshot_fingerprint": snapshot["fingerprint"]}}
            _g, gv = kit.advance(st, {"kind": "guard", "now": now, "claim": claim})
            if gv["verdict"] != kit.ACCEPT:
                raise _refuse("freshness_refused", "stored activation no longer passes", gv["code"])
            changed = st != env["state"]
        else:
            st, sv = kit.advance(st, select)
            if sv["verdict"] != kit.ACCEPT:
                raise _refuse("freshness_refused", "selection is stale, revoked, expired, conflicting or not a legitimate advancement", sv["code"])
            changed = True
        if kit.verify_state(st) is not None:
            raise _refuse("state_corrupt", "post-transition state failed verification")
        if changed:
            body = {"schema": STATE_SCHEMA, "namespace": env["namespace"], "authority_digest": env["authority_digest"], "generation": env["generation"] + 1,
                    "parent_digest": env["state_digest"], "bootstrap": env["bootstrap"], "state": st}
            new = _seal(body)
            _write_envelope(profile, new)
            self._env = new
            self.generation = new["generation"]


def open_transaction(profile: AuthorityProfile, now: Any) -> Transaction:
    """Acquire the lock and read the store, or refuse (`state_missing`, `state_corrupt`, `state_authority_mismatch`, `state_lock_failed`). Never creates a store."""
    if profile.mode != "synthetic" or require_backend(profile) != "file-g2" or not profile.state_path:
        raise _refuse("authority_config_unprovisioned", "durable state is available only for a loader-validated synthetic file-g2 profile")
    fd = _acquire(profile)
    try:
        env = _read_envelope(profile)
    except BaseException:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
        raise
    return Transaction(profile, now, fd, env)


def read_state(profile: AuthorityProfile) -> dict:
    """Read-only inspection (takes the lock briefly). Returns a deep copy of the verified envelope."""
    if profile.mode != "synthetic" or require_backend(profile) != "file-g2" or not profile.state_path:
        raise _refuse("authority_config_unprovisioned", "state is available only for a loader-validated synthetic file-g2 profile")
    fd = _acquire(profile)
    try:
        return copy.deepcopy(_read_envelope(profile))
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)


def bootstrap_state(profile: AuthorityProfile, bootstrap_path: Any, now: Any) -> dict:
    """Owner-run, one-shot cold start. Creates the store EXCLUSIVELY with an empty kit state. Refuses an expired, malformed, foreign or already consumed bootstrap and any existing store."""
    if profile.mode != "synthetic" or require_backend(profile) != "file-g2" or not profile.state_path:
        raise _refuse("authority_config_unprovisioned", "bootstrap is available only for a loader-validated synthetic file-g2 profile")
    try:
        data = Path(bootstrap_path).read_bytes()[: 65537]
        doc = strict_loads(data)
    except Exception:
        raise _refuse("bootstrap_invalid", "bootstrap document unreadable or not strict JSON") from None
    if type(doc) is not dict or set(doc) != set(BOOTSTRAP_MEMBERS) or doc["schema"] != BOOTSTRAP_SCHEMA:
        raise _refuse("bootstrap_invalid", "bootstrap document is not the closed schema (no floor-seeding member is allowed)")
    try:
        _secret_deny(doc)
    except Exception:
        raise _refuse("bootstrap_invalid", "bootstrap carries key-shaped material") from None
    if doc["namespace"] != profile.state_namespace or doc["authority_digest"] != authority_digest(profile) or doc["issued_for_mode"] != profile.mode:
        raise _refuse("bootstrap_invalid", "bootstrap is bound to another namespace, authority configuration or mode")
    bid = doc["bootstrap_id"]
    import re
    if type(bid) is not str or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{7,63}", bid):
        raise _refuse("bootstrap_invalid", "bootstrap_id")
    try:
        issued, not_after = _epoch(doc["issued_at"]), _epoch(doc["not_after"])
    except Exception:
        raise _refuse("bootstrap_invalid", "bootstrap timestamps") from None
    t = int(now.timestamp())
    if not (issued < not_after <= issued + MAX_TTL_SECONDS):
        raise _refuse("bootstrap_invalid", "bootstrap lifetime must be positive and at most 3600 s")
    if not (issued <= t < not_after):
        raise _refuse("bootstrap_expired", "bootstrap is not valid at the verification time")
    ledger = Path(profile.state_path + ".consumed." + bid)
    fd = _acquire(profile)
    try:
        if Path(profile.state_path).exists():
            raise _refuse("bootstrap_state_exists", "a state store already exists; a bootstrap never resets a store")
        try:
            write_bytes_atomic(ledger, _canon({"bootstrap_id": bid, "namespace": profile.state_namespace}), overwrite=False)
        except FileExistsError:
            raise _refuse("bootstrap_consumed", "this bootstrap id was already consumed") from None
        except Exception:
            raise _refuse("state_write_failed", "consumed ledger not written") from None
        env = _seal({"schema": STATE_SCHEMA, "namespace": profile.state_namespace, "authority_digest": authority_digest(profile), "generation": 0,
                     "parent_digest": None, "bootstrap": {"bootstrap_id": bid, "bootstrap_digest": _sha(doc)}, "state": _kit().empty_state()})
        _write_envelope(profile, env, exclusive=True)
        return env
    finally:
        fcntl.flock(fd, fcntl.LOCK_UN)
        os.close(fd)
