"""Configurable Registry authority profile `ocs-authority-profile/0.1` for the F4 age-bounds selection source (CAP v0.1, gate G1).

BUILDER_TESTED developer implementation. NOT independently qualified. Durable anti-rollback exists ONLY for `state.backend = file-g2` (G2, `registry_authority_state.py`); `none-g1` keeps NO state, so a replayed OLDER pinned
snapshot/selection that still satisfies the pin is not detected across processes. Claim scope is unchanged from the F4 PoC: claim A only (the Registry selection signature
is admitted at decision time by the injected real Ed25519 verifier). Operational trust, issuer identity, key custody, adoption and a decision-authenticated claim (B)
are NOT established here.

What this module is. A wrapper around the host's `selection_source` (zero edits to any pinned Control Plane file) plus a closed, strict configuration and a factory:
  * The configuration (strict JSON, closed, versioned) declares the mode (`synthetic` | `operational`), the public trust anchor (key ids and `sha256:` of the PUBLIC key
    bytes only), the trusted issuers and their exact grants, the expected context, the pinned snapshot (source file + expected id/version/fingerprint) and the clock.
    It never carries key material: the public key bytes live in the separate snapshot document.
  * Per call the wrapper re-reads the pinned snapshot file (no cache), requires its Registry fingerprint to equal the pin and its issuers/keys/grants to EQUAL the declared
    ones, IGNORES (and requires equality of) any snapshot the host supplies, runs ALL eleven Registry layers through `verify_f4_selection_v2` with the exact
    `Ed25519Verifier`, requires that a per-selection epoch floor was applied, and returns FRESH material that carries the pinned snapshot object. The
    verification mechanism is identical in both modes; only the declared inputs differ.
  * `operational` mode fails closed: any placeholder, `UNSELECTED` identity, fixed instant, missing anchor/pin/state/owner digest refuses, and in G1 an otherwise complete
    operational profile STILL refuses `authority_config_unprovisioned` because no durable state exists yet (G2). There is no synthetic fallback in either direction.
The process owner supplies `expected_mode` and `expected_config_digest` as process arguments (never request data).

Typed refusals are kept on the wrapper (`last_refusal`) because the Control Plane collapses any `selection_source` exception to `selection_source_failed`.
Codes are Control Plane local; no Registry code table is edited.
"""
from __future__ import annotations

import hashlib
import importlib
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Mapping, Optional

from agent_control_plane.registry_governed_lifecycle import GovernedScope, Refusal, SelectionMaterial
from agent_control_plane.strict_json import strict_loads

PROFILE_VERSION = "ocs-authority-profile/0.1"
MODES = ("synthetic", "operational")
SYNTHETIC_IDENTITY = "UNSELECTED-SYNTHETIC"
STATE_BACKENDS = ("none-g1", "file-g2")
MAX_CONFIG_BYTES = 65536
MAX_SNAPSHOT_BYTES = 1048576

CODES = (
    "authority_config_missing", "authority_config_malformed", "authority_config_version_unsupported", "authority_config_secret_material",
    "authority_config_mode_mismatch", "authority_config_unprovisioned", "authority_config_digest_mismatch", "authority_config_scope_mismatch",
    "snapshot_pin_mismatch", "epoch_floor_missing", "verifier_unavailable", "authority_factory_argument_refused",
    "state_missing", "state_corrupt", "state_authority_mismatch", "state_lock_failed", "state_write_failed", "freshness_refused",
    "bootstrap_invalid", "bootstrap_expired", "bootstrap_consumed", "bootstrap_state_exists",
)

_TOKEN = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
_SHA = re.compile(r"sha256:[0-9a-f]{64}")
_SECRET_KEY = re.compile(r"(private|secret|seed|passw|credential|signing)", re.IGNORECASE)
_HEX_RUN = re.compile(r"[0-9a-fA-F]{64,}")
_B64_KEY = re.compile(r"(?:[A-Za-z0-9+/_-]{43}=?|[A-Za-z0-9+/_-]{86}(?:==?)?)")
_SHA_VALUE = re.compile(r"sha256:[0-9a-f]{64}")
_PLACEHOLDER = re.compile(r"(?<![A-Za-z0-9])(unselected|placeholder|unprovisioned|changeme|replace[-_]?me|todo|tbd|example|dummy|fixme)(?![A-Za-z0-9])", re.IGNORECASE)
_GRANT = ("consumer_id", "tenant", "institution", "authority_domain", "operation")


class AuthorityProfileRefusal(PermissionError):
    """Typed refusal. `.code` is one of `CODES` (or a reused Registry/Control Plane code); `.refusal` is the Control Plane `Refusal` value."""

    def __init__(self, code: str, detail: str = "", registry_code: Optional[str] = None):
        super().__init__(f"authority_profile_refused:{code}" + (f":{registry_code}" if registry_code else ""))
        self.code, self.detail = code, detail
        self.refusal = Refusal(code, registry_code)


def _refuse(code: str, detail: str = "", registry_code: Optional[str] = None) -> AuthorityProfileRefusal:
    return AuthorityProfileRefusal(code, detail, registry_code)


# ------------------------------------------------------------------------------------------------------------------------ schema helpers
def _closed(obj: Any, members: tuple, where: str) -> dict:
    if type(obj) is not dict or set(obj) != set(members):
        raise _refuse("authority_config_malformed", f"{where}: members must be exactly {sorted(members)}")
    return obj


def _tok(v: Any, where: str) -> str:
    if type(v) is not str or not _TOKEN.fullmatch(v):
        raise _refuse("authority_config_malformed", f"{where}: not a token")
    return v


def _nonempty_list(v: Any, where: str) -> list:
    if type(v) is not list or not v:
        raise _refuse("authority_config_malformed", f"{where}: must be a non-empty list")
    return v


def _walk(value: Any, path: str = ""):
    if type(value) is dict:
        for k, v in value.items():
            yield path + "/" + str(k), str(k), None
            yield from _walk(v, path + "/" + str(k))
    elif type(value) is list:
        for i, v in enumerate(value):
            yield from _walk(v, f"{path}[{i}]")
    elif type(value) is str:
        yield path, None, value


def _key_shaped(text: str) -> bool:
    if "-----BEGIN" in text:
        return True
    stripped = text.strip()
    rest = _SHA_VALUE.sub("", stripped)  # a labelled digest is public data
    squeezed = re.sub(r"[\s:_-]", "", rest.lower())
    for prefix in ("0x", "ed25519"):
        if squeezed.startswith(prefix):
            squeezed = squeezed[len(prefix):]
    if _HEX_RUN.search(squeezed) or _HEX_RUN.search(rest):
        return True
    return bool(_B64_KEY.fullmatch(rest.strip()))


def _secret_deny(config: Any) -> None:
    """Refuse any member name or string value that looks like private/secret key material. Applies in BOTH modes."""
    for path, key, text in _walk(config):
        if key is not None and _SECRET_KEY.search(key):
            raise _refuse("authority_config_secret_material", f"member name at {path}")
        if text is not None and _key_shaped(text):
            raise _refuse("authority_config_secret_material", f"key-shaped value at {path}")


def _placeholder_deny(config: Any) -> None:
    for path, _key, text in _walk(config):
        if text is not None and _PLACEHOLDER.search(text):
            raise _refuse("authority_config_unprovisioned", f"placeholder at {path}")


def _read_bounded(path: Path, limit: int) -> bytes:
    with open(path, "rb") as fh:
        return fh.read(limit + 1)


def _digest(data: bytes) -> str:
    return "sha256:" + hashlib.sha256(data).hexdigest()


# ------------------------------------------------------------------------------------------------------------------------ profile
@dataclass(frozen=True)
class AuthorityProfile:
    """Validated configuration. Holds no key material and no cached snapshot (the pinned snapshot is re-read on every use)."""
    profile_id: str
    mode: str
    config_digest: str
    config: Mapping[str, Any]
    snapshot_path: str
    pin_snapshot_id: str
    pin_version: int
    pin_fingerprint: str
    context: tuple
    clock_kind: str
    as_of: Optional[str]
    declared_issuers: tuple
    declared_keys: tuple
    state_backend: str = "none-g1"
    state_namespace: str = ""
    state_path: str = ""


def _parse_clock(clock: Any, mode: str) -> tuple:
    if type(clock) is not dict or clock.get("kind") not in ("system_utc", "fixed_instant"):
        raise _refuse("authority_config_malformed", "clock.kind")
    if clock["kind"] == "system_utc":
        _closed(clock, ("kind",), "clock")
        return "system_utc", None
    _closed(clock, ("kind", "as_of"), "clock")
    if mode == "operational":
        raise _refuse("authority_config_unprovisioned", "operational clock must be system_utc")
    try:
        if type(clock["as_of"]) is not str or not re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\dZ", clock["as_of"]):
            raise ValueError
        datetime.strptime(clock["as_of"], "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        raise _refuse("authority_config_malformed", "clock.as_of") from None
    return "fixed_instant", clock["as_of"]


def load_authority_profile(config_path: Any, *, expected_mode: Any = None, expected_config_digest: Any = None) -> AuthorityProfile:
    """Load and validate the closed configuration. `expected_mode` and (operational) `expected_config_digest` are owner-supplied process arguments."""
    if expected_mode not in MODES:
        raise _refuse("authority_config_mode_mismatch", "expected_mode is required and must be synthetic or operational")
    try:
        path = Path(config_path)
        data = _read_bounded(path, MAX_CONFIG_BYTES)
    except Exception:
        raise _refuse("authority_config_missing", "configuration file unreadable") from None
    if len(data) > MAX_CONFIG_BYTES:
        raise _refuse("authority_config_malformed", "configuration too large")
    try:
        config = strict_loads(data)
    except Exception:
        raise _refuse("authority_config_malformed", "not strict JSON") from None
    if type(config) is not dict:
        raise _refuse("authority_config_malformed", "top level must be an object")
    if config.get("version") != PROFILE_VERSION:
        raise _refuse("authority_config_version_unsupported" if "version" in config else "authority_config_malformed", "version")
    _secret_deny(config)
    members = ("version", "id", "mode", "verifier", "trust_anchor", "issuers", "expected_context", "snapshot", "clock", "state", "identities")
    _closed(config, members, "profile")
    mode = config["mode"]
    if mode not in MODES:
        raise _refuse("authority_config_malformed", "mode")
    if mode != expected_mode:
        raise _refuse("authority_config_mode_mismatch", "configured mode differs from the owner-supplied expected mode")
    digest = _digest(data)
    if expected_config_digest is not None and expected_config_digest != digest:
        raise _refuse("authority_config_digest_mismatch", "configuration digest differs from the owner-supplied digest")
    if mode == "operational" and expected_config_digest is None:
        raise _refuse("authority_config_unprovisioned", "operational mode requires the owner-supplied configuration digest")
    profile_id = _tok(config["id"], "id")
    if _closed(config["verifier"], ("contract", "family"), "verifier") != {"contract": "r08-v2", "family": "f4"}:
        raise _refuse("authority_config_malformed", "verifier must be exactly r08-v2 / f4")
    anchor = _closed(config["trust_anchor"], ("algorithm", "keys"), "trust_anchor")
    if anchor["algorithm"] != "ed25519":
        raise _refuse("authority_config_malformed", "trust_anchor.algorithm")
    keys = []
    for k in _nonempty_list(anchor["keys"], "trust_anchor.keys"):
        _closed(k, ("key_id", "public_key_sha256"), "trust_anchor.keys[]")
        if type(k["public_key_sha256"]) is not str or not _SHA.fullmatch(k["public_key_sha256"]):
            raise _refuse("authority_config_malformed", "public_key_sha256 must be sha256:<64 hex>")
        keys.append((_tok(k["key_id"], "key_id"), k["public_key_sha256"]))
    if len({k[0] for k in keys}) != len(keys):
        raise _refuse("authority_config_malformed", "duplicate trust-anchor key id")
    issuers = []
    for i in _nonempty_list(config["issuers"], "issuers"):
        _closed(i, ("issuer_id", "key_id", "grants"), "issuers[]")
        grants = []
        for g in _nonempty_list(i["grants"], "issuers[].grants"):
            _closed(g, _GRANT, "grant")
            row = tuple(_tok(g[m], "grant." + m) for m in _GRANT)
            if "*" in row:
                raise _refuse("authority_config_malformed", "wildcard grant")
            grants.append(row)
        if len(set(grants)) != len(grants):
            raise _refuse("authority_config_malformed", "duplicate grant")
        key_id = _tok(i["key_id"], "issuers[].key_id")
        if key_id not in {k[0] for k in keys}:
            raise _refuse("authority_config_malformed", "issuer key is not a trust-anchor key")
        issuers.append((_tok(i["issuer_id"], "issuer_id"), key_id, tuple(sorted(grants))))
    if len({i[1] for i in issuers}) != len(issuers) or {i[1] for i in issuers} != {k[0] for k in keys}:
        raise _refuse("authority_config_malformed", "each trust-anchor key must belong to exactly one issuer")
    context = tuple(_tok(_closed(config["expected_context"], _GRANT, "expected_context")[m], "expected_context." + m) for m in _GRANT)
    snap = _closed(config["snapshot"], ("source", "expected"), "snapshot")
    source = _closed(snap["source"], ("kind", "reference"), "snapshot.source")
    expected = _closed(snap["expected"], ("snapshot_id", "version", "fingerprint"), "snapshot.expected")
    if source["kind"] != "file" or type(source["reference"]) is not str or not source["reference"]:
        raise _refuse("authority_config_malformed", "snapshot.source must be a file reference")
    if type(expected["version"]) is not int or isinstance(expected["version"], bool) or expected["version"] < 1:
        raise _refuse("authority_config_malformed", "snapshot.expected.version")
    if type(expected["fingerprint"]) is not str or not _SHA.fullmatch(expected["fingerprint"]):
        raise _refuse("authority_config_malformed", "snapshot.expected.fingerprint")
    state = _closed(config["state"], ("backend", "namespace", "reference", "anchor_reference"), "state")
    ident = _closed(config["identities"], ("snapshot_publisher_ref", "enforcing_operator_ref", "state_admin_ref"), "identities")
    for section in (state, ident):
        for name, value in section.items():
            if type(value) is not str or not value:
                raise _refuse("authority_config_malformed", f"{name} must be a non-empty string")
    clock_kind, as_of = _parse_clock(config["clock"], mode)
    if mode == "synthetic":
        if state["backend"] not in STATE_BACKENDS:
            raise _refuse("authority_config_malformed", "state.backend must be none-g1 or file-g2")
        if state["backend"] == "file-g2":
            _tok(state["namespace"], "state.namespace")
            _tok(Path(state["reference"]).name or "", "state.reference")
        if any(v != SYNTHETIC_IDENTITY for v in ident.values()):
            raise _refuse("authority_config_malformed", "synthetic identities must be UNSELECTED-SYNTHETIC")
    else:
        _placeholder_deny(config)
        if any(not v.strip() for v in list(state.values()) + list(ident.values())):
            raise _refuse("authority_config_unprovisioned", "blank state or identity reference")
        raise _refuse("authority_config_unprovisioned", "durable anti-rollback state is not implemented in G1 (G2); operational mode cannot be activated")
    ref = Path(source["reference"])
    snapshot_path = str(ref if ref.is_absolute() else path.resolve().parent / ref)
    sref = Path(state["reference"])
    state_path = str(sref if sref.is_absolute() else path.resolve().parent / sref) if state["backend"] == "file-g2" else ""
    return AuthorityProfile(profile_id=profile_id, mode=mode, config_digest=digest, config=config, snapshot_path=snapshot_path,
                            pin_snapshot_id=_tok(expected["snapshot_id"], "snapshot.expected.snapshot_id"), pin_version=expected["version"],
                            pin_fingerprint=expected["fingerprint"], context=context, clock_kind=clock_kind, as_of=as_of,
                            declared_issuers=tuple(sorted(issuers)), declared_keys=tuple(sorted(keys)), state_backend=state["backend"], state_namespace=state["namespace"], state_path=state_path)


# ------------------------------------------------------------------------------------------------------------------------ registry (lazy)
def _registry() -> tuple:
    try:
        return (importlib.import_module("registry_successor.verify"), importlib.import_module("registry_successor.v2_policy_identity"),
                importlib.import_module("registry_successor.common"), importlib.import_module("registry_successor.v2_verified_selection"),
                importlib.import_module("registry_adapters.ed25519_verifier"))
    except Exception:
        raise _refuse("verifier_unavailable", "Registry is not importable") from None


def load_pinned_trust(profile: AuthorityProfile):
    """Re-read the pinned snapshot document and return `(TrustSnapshot, fingerprint)`. Refuses unless the Registry fingerprint equals the pin and the snapshot's
    issuers, keys and grants EQUAL the declared ones. Never cached; never reads host-supplied trust."""
    verify, ident, _common, _vsel, _ed = _registry()
    try:
        data = _read_bounded(Path(profile.snapshot_path), MAX_SNAPSHOT_BYTES)
    except Exception:
        raise _refuse("authority_config_missing", "pinned snapshot file unreadable") from None
    if len(data) > MAX_SNAPSHOT_BYTES:
        raise _refuse("snapshot_pin_mismatch", "snapshot too large")
    try:
        doc = strict_loads(data)
        fingerprint = ident.trust_snapshot_fingerprint(doc)
        norm = ident.normalize_snapshot(doc)
    except Exception:
        raise _refuse("snapshot_pin_mismatch", "snapshot document is not a valid Registry snapshot") from None
    if fingerprint != profile.pin_fingerprint or norm["snapshot_id"] != profile.pin_snapshot_id or norm["version"] != profile.pin_version:
        raise _refuse("snapshot_pin_mismatch", "fingerprint, id or version differs from the pin")
    issuers, keys = [], []
    try:
        for e in norm["issuers"]:
            if e["alg"] != "ed25519":
                raise ValueError
            pub = bytes.fromhex(e["public_key"])
            keys.append((e["key_id"], _digest(pub)))
            issuers.append((e["issuer_id"], e["key_id"], tuple(sorted(tuple(g) for g in e["authority"]))))
    except Exception:
        raise _refuse("snapshot_pin_mismatch", "snapshot issuer entry malformed") from None
    if tuple(sorted(issuers)) != profile.declared_issuers or tuple(sorted(keys)) != profile.declared_keys:
        raise _refuse("snapshot_pin_mismatch", "snapshot issuers, keys or grants differ from the declared ones")
    try:
        trust = verify.TrustSnapshot(
            norm["snapshot_id"], norm["version"], norm["valid_until"],
            tuple(verify.IssuerEntry(e["key_id"], e["issuer_id"], e["alg"], bytes.fromhex(e["public_key"]), tuple(verify.AuthorityGrant(*g) for g in e["authority"]))
                  for e in norm["issuers"]),
            frozenset(norm["revoked_key_ids"]), frozenset((p[0], p[1]) for p in norm["revoked_selections"]), tuple((p[0], p[1]) for p in norm["min_epochs"]))
        if ident.trust_snapshot_fingerprint_from_verified(trust) != profile.pin_fingerprint:
            raise ValueError
    except Exception:
        raise _refuse("snapshot_pin_mismatch", "snapshot object does not reproduce the pin") from None
    return trust, fingerprint


def _require_g1_mode(profile: AuthorityProfile) -> None:
    """The loader is not the only way to hold an `AuthorityProfile`; the wrapper, factory and Replay helper re-check the mode so a hand-built or `replace`d profile cannot reach
    an operational path. In G1 only `synthetic` is activatable."""
    if not isinstance(profile, AuthorityProfile) or profile.mode != "synthetic":
        raise _refuse("authority_config_unprovisioned", "only a loader-validated synthetic profile is activatable in G1 (operational needs durable state, G2)")


def require_backend(profile: AuthorityProfile) -> str:
    """The state backend must be exactly a known one AND equal the validated configuration's declaration; anything else (replaced, typo, None) refuses instead of running stateless."""
    backend = profile.state_backend
    declared = profile.config.get("state", {}).get("backend") if isinstance(profile.config, Mapping) else None
    if backend not in STATE_BACKENDS or backend != declared:
        raise _refuse("authority_config_unprovisioned", "state backend is not a loader-validated none-g1 or file-g2")
    return backend


def _now(profile: AuthorityProfile) -> datetime:
    _require_g1_mode(profile)
    if profile.clock_kind == "fixed_instant":
        return datetime.strptime(profile.as_of, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
    return datetime.now(timezone.utc)


# ------------------------------------------------------------------------------------------------------------------------ wrapper
class PinnedSelectionSource:
    """Callable `selection_source`. See the module docstring. `last_refusal` holds the typed `Refusal` of the most recent refused call (None after a success)."""

    def __init__(self, profile: AuthorityProfile, host_source: Callable[[], Any], verifier: Any, *, expected_mode: Any, expected_config_digest: Any = None):
        if not isinstance(profile, AuthorityProfile) or not callable(host_source):
            raise _refuse("authority_factory_argument_refused", "profile and a callable host source are required")
        _require_g1_mode(profile)
        require_backend(profile)
        self._profile, self._host, self._verifier = profile, host_source, verifier
        self._expected_mode, self._expected_digest = expected_mode, expected_config_digest
        self.last_refusal: Optional[Refusal] = None
        self.reads = 0

    def __call__(self) -> SelectionMaterial:
        self.reads += 1
        self.last_refusal = None
        try:
            material = self._admit()
        except AuthorityProfileRefusal as e:
            self.last_refusal = e.refusal
            raise
        except BaseException:
            self.last_refusal = Refusal("selection_source_failed")
            raise
        self.last_refusal = None
        return material

    def _admit(self) -> SelectionMaterial:
        profile = self._profile
        if profile.mode != self._expected_mode:
            raise _refuse("authority_config_mode_mismatch", "profile mode differs from the owner-supplied expected mode")
        if self._expected_digest is not None and profile.config_digest != self._expected_digest:
            raise _refuse("authority_config_digest_mismatch")
        verify, ident, common, vsel, ed = _registry()
        if type(self._verifier) is not ed.Ed25519Verifier:
            raise _refuse("verifier_unavailable", "verifier is not the exact Registry Ed25519Verifier")
        trust, fingerprint = load_pinned_trust(profile)
        txn = None
        if require_backend(profile) == "file-g2":  # one lock spans read -> verify -> advance; a missing/corrupt/mismatched store refuses here
            from agent_control_plane import registry_authority_state as state_mod
            txn = state_mod.open_transaction(profile, lambda: _now(profile))
        try:
            return self._admit_locked(profile, trust, fingerprint, txn)
        finally:
            if txn is not None:
                txn.close()

    def _admit_locked(self, profile, trust, fingerprint, txn) -> SelectionMaterial:
        verify, ident, common, vsel, ed = _registry()
        host = self._host()
        if type(host) is not SelectionMaterial or type(host.record_text) is not str or type(host.selection_text) is not str:
            raise _refuse("material_invalid")
        try:
            host_fp = ident.trust_snapshot_fingerprint_from_verified(host.trust)
        except Exception:
            raise _refuse("snapshot_pin_mismatch", "host-supplied snapshot is not a valid snapshot") from None
        if host_fp != fingerprint:
            raise _refuse("snapshot_pin_mismatch", "host-supplied snapshot differs from the pin")
        context = common.ExpectedContext(*profile.context)
        verdict = vsel.verify_f4_selection_v2(host.selection_text, host.record_text, context, trust, self._verifier, _now(profile),
                                              min_trust_snapshot_version=profile.pin_version,
                                              last_accepted_snapshot=None if txn is None else txn.last_accepted)
        if verdict.admitted is not True:
            raise _refuse("registry_not_applied", verdict.detail, verdict.code)
        if verdict.trust_snapshot_fingerprint != fingerprint:
            raise _refuse("snapshot_pin_mismatch", "verdict fingerprint differs from the pin")
        if verdict.epoch_floor_applied is not True:
            raise _refuse("epoch_floor_missing", "no per-selection epoch floor in the pinned snapshot")
        if txn is not None:
            txn.commit(verdict, host.selection_text, trust)
        return SelectionMaterial(host.record_text, host.selection_text, trust)


# ------------------------------------------------------------------------------------------------------------------------ factory
_FORBIDDEN_KW = ("selection_source", "verifier")


def governed_age_workflow(profile: AuthorityProfile, *, host_source: Callable[[], Any], scope: GovernedScope, expected_mode: Any, expected_config_digest: Any = None,
                          **workflow_kwargs):
    """Build a `GovernedAgeWorkflow` whose `selection_source` is the pinned wrapper and whose verifier is the exact Registry `Ed25519Verifier`. The caller cannot supply
    either, and in operational mode cannot enable test time. Sets advisory (NOT tamper-proof) `cap_authority_mode`, `cap_authority_id` and `cap_selection_source` attributes on the workflow."""
    from agent_control_plane.registry_f4_age_governance import GovernedAgeWorkflow
    for name in _FORBIDDEN_KW:
        if name in workflow_kwargs:
            raise _refuse("authority_factory_argument_refused", f"{name} is supplied by the profile")
    if profile.mode == "operational" and workflow_kwargs.get("allow_test_time"):
        raise _refuse("authority_factory_argument_refused", "allow_test_time is not available in operational mode")
    _require_g1_mode(profile)
    require_backend(profile)
    if (scope.consumer_id, scope.tenant_id, scope.operation_id) != (profile.context[0], profile.context[1], profile.context[4]):
        raise _refuse("authority_config_scope_mismatch", "scope differs from expected_context")
    ed = _registry()[4]
    source = PinnedSelectionSource(profile, host_source, ed.Ed25519Verifier(), expected_mode=expected_mode, expected_config_digest=expected_config_digest)
    if profile.mode == "synthetic" and profile.clock_kind == "fixed_instant":
        workflow_kwargs.setdefault("allow_test_time", True)
        workflow_kwargs.setdefault("construction_time", _now(profile))
    try:
        flow = GovernedAgeWorkflow(scope=scope, selection_source=source, verifier=ed.Ed25519Verifier(), **workflow_kwargs)
    except Exception:
        if source.last_refusal is not None:
            raise _refuse(source.last_refusal.code, "construction refused", source.last_refusal.registry_code) from None
        raise
    object.__setattr__(flow, "cap_authority_mode", profile.mode)
    object.__setattr__(flow, "cap_authority_id", profile.profile_id)
    object.__setattr__(flow, "cap_selection_source", source)
    return flow


# ------------------------------------------------------------------------------------------------------------------------ Replay helpers (pure)
def replay_trust_kwargs(profile: AuthorityProfile) -> dict:
    """Operator-side trust inputs for a stateless Replay admission, derived from the configuration and the pinned snapshot ONLY (never from decision data). Keys use
    Replay's `RegistryEvidenceTrust` field names; the operator adds the verifier, action/operation ids, host ages and revisions. Control Plane never imports Replay."""
    _require_g1_mode(profile)
    trust, fingerprint = load_pinned_trust(profile)
    consumer, tenant, institution, domain, operation = profile.context
    return {"trust_snapshot": trust, "trust_snapshot_ref": (profile.pin_snapshot_id, profile.pin_version),
            "expected_context": {"consumer_id": consumer, "tenant": tenant, "institution": institution, "authority_domain": domain, "operation": operation},
            "verification_time": _now(profile), "time_mode": "as_of" if profile.clock_kind == "fixed_instant" else "now",
            "min_trust_snapshot_version": profile.pin_version, "last_accepted_snapshot": None, "trust_snapshot_fingerprint": fingerprint}


def check_replay_markers(profile: AuthorityProfile, admissions: Any) -> bool:
    """True only if `admissions` (the marker's `registry_evidence` list, or a mapping holding it) is non-empty and EVERY row's `trust_snapshot_fingerprint` equals the pin."""
    rows = admissions.get("registry_evidence") if isinstance(admissions, Mapping) else admissions
    if type(rows) is not list or not rows:
        return False
    return all(isinstance(r, Mapping) and r.get("trust_snapshot_fingerprint") == profile.pin_fingerprint for r in rows)
