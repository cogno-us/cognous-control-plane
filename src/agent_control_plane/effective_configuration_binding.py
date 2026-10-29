"""Persisted effective-configuration binding `effective-configuration-binding/0.1` (D-06 Option B, carriage C2).

BUILDER_TESTED developer implementation. NOT independently qualified. NON-AUTHORIZING: the binding is an equality check that can only ADD a refusal. It is never an approval input, never
widens a bound and grants no authority. This module is pure: it reads no store, calls no Registry and imports only the existing canonical `commitment()`.

What it is. A governed decision that is authorized carries, inside the already-persisted opaque dict `binding.runtime_authority`, one extra member:

    "effective_configuration": {"version": "effective-configuration-binding/0.1", "digest": "sha256:<64 hex>", "members": {...}}

`digest` is `commitment()` (the existing sorted-key canonical JSON SHA-256) over `{"domain": DOMAIN, "version": VERSION, **members}`; it is a REDUNDANT commitment over `members`, and a reader
recomputes it from the persisted `members` before trusting anything. The members are scope, host and effective profile digests, the two F4 scalars, the three other constructor scalars, the
ObservationPolicy effective values (or an explicit null) and the declared mandatory family set. `evaluated_at`, `selection_id` and `selection_epoch` are deliberately NOT members.

Reader rules (`classify`, read-only):
  * member present and valid and equal to the live member -> `bound`;
  * member present, valid, unequal to the live member -> `mismatch`;
  * member present, malformed or with a digest that is not the recomputation of its own members -> `invalid`;
  * member present with an unknown `version` -> `version-unsupported`;
  * member absent and the decision index is below the host-supplied explicit `legacy_cutoff` (and the cutoff is a finite int that does not exceed the decisions in the store) -> `legacy`;
  * member absent otherwise -> `unbound-after-cutoff`.
Only `bound` and `legacy` are accepted. `legacy` means the previous comparison semantics: ONLY the new key is left out of the live side before the existing equality; no other key is ever ignored.

Limits (also in docs/effective-configuration-binding.md): the record store is unsigned local JSON, so this guards configuration DRIFT, restart and rebuild mix-ups, partial upgrades and buggy
writers; it does not defend against a party who can rewrite the store; it gives NO anti-rollback guarantee; the cutoff is host configuration without durable provenance.
"""
from __future__ import annotations

import re
from typing import Any, Mapping, Optional

from agent_control_plane.bounded import commitment

CLASSIFICATION = "BUILDER_TESTED; not independently qualified; non-authorizing"
KEY = "effective_configuration"
VERSION = "effective-configuration-binding/0.1"
DOMAIN = "cognous.control-plane.effective-configuration-binding"
SCALAR_MAX = 2147483647  # the existing Control Plane structural scalar range (registry_governed_lifecycle.SCALAR_MAX); not a new bound

BOUND, MISMATCH, INVALID, VERSION_UNSUPPORTED, LEGACY, UNBOUND_AFTER_CUTOFF = "bound", "mismatch", "invalid", "version-unsupported", "legacy", "unbound-after-cutoff"
ACCEPTED = (BOUND, LEGACY)  # every other status refuses with the registered reason `authorization_binding_changed`
STATUSES = (BOUND, MISMATCH, INVALID, VERSION_UNSUPPORTED, LEGACY, UNBOUND_AFTER_CUTOFF)

SCOPE_FIELDS = ("consumer_id", "tenant_id", "action_id", "institution_id", "authority_domain")
F4_FIELDS = ("status_max_age_seconds", "approval_max_age_seconds")
OTHER_FIELDS = ("clock_tolerance_seconds", "identity_max_age_seconds", "mandate_max_age_seconds")
OBSERVATION_FIELDS = ("max_age_seconds", "clock_tolerance_seconds")
FAMILY_FIELDS = ("slot", "family_id", "contract_version", "family_schema_revision", "effective_policy_digest")
MEMBER_FIELDS = ("scope", "host_profile_digest", "effective_profile_digest", "f4_scalars", "other_scalars", "observation_policy", "families")
RECORD_FIELDS = ("version", "digest", "members")
_DIGEST = re.compile(r"\Asha256:[0-9a-f]{64}\Z")
_ZERO = "sha256:" + "0" * 64


class BindingInvalid(ValueError):
    """The live configuration cannot be bound (a value is out of the structural domain). The workflow refuses; nothing is hashed."""


def _scalar(v: Any) -> bool:
    return type(v) is int and 0 <= v <= SCALAR_MAX


def _text(v: Any) -> bool:
    return type(v) is str and bool(v)


def _digest(v: Any) -> bool:
    return type(v) is str and _DIGEST.match(v) is not None and v != _ZERO


def _optional_digest(v: Any) -> bool:
    return v is None or _digest(v)


def _exact(d: Any, fields: tuple) -> bool:
    return type(d) is dict and set(d) == set(fields) and all(type(k) is str for k in d)


def members_defect(members: Any) -> Optional[str]:
    """None when `members` has exactly the frozen shape and every value is in its structural domain, else a short diagnostic (never a reason code)."""
    if not _exact(members, MEMBER_FIELDS):
        return "members_shape"
    if not _exact(members["scope"], SCOPE_FIELDS) or not all(_text(v) for v in members["scope"].values()):
        return "scope"
    if not _optional_digest(members["host_profile_digest"]) or not _optional_digest(members["effective_profile_digest"]):
        return "profile_digest"
    for name, fields in (("f4_scalars", F4_FIELDS), ("other_scalars", OTHER_FIELDS)):
        if not _exact(members[name], fields) or not all(_scalar(v) for v in members[name].values()):
            return name
    obs = members["observation_policy"]
    if obs is not None and (not _exact(obs, OBSERVATION_FIELDS) or not all(_scalar(v) for v in obs.values())):
        return "observation_policy"
    fams = members["families"]
    if type(fams) is not list:
        return "families"
    seen = set()
    for row in fams:
        if not _exact(row, FAMILY_FIELDS) or not all(_text(row[k]) for k in ("slot", "family_id", "contract_version")) or not _digest(row["effective_policy_digest"]):
            return "families"
        rev = row["family_schema_revision"]
        if rev is not None and not _scalar(rev):
            return "families"
        if row["slot"] in seen:
            return "families"
        seen.add(row["slot"])
    return None


def digest_of(version: str, members: Mapping[str, Any]) -> str:
    """The binding digest: the existing canonical `commitment()` over the domain, the version and the members. Callers validate `members` first."""
    return commitment({"domain": DOMAIN, "version": version, **members})


def mint(members: Mapping[str, Any]) -> dict:
    """The persisted member for already built `members` (validated here again: a value outside the structural domain is never hashed)."""
    defect = members_defect(members)
    if defect is not None:
        raise BindingInvalid(defect)
    copy = _plain(members)
    return {"version": VERSION, "digest": digest_of(VERSION, copy), "members": copy}


def _plain(value: Any) -> Any:
    if isinstance(value, Mapping):
        return {k: _plain(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_plain(v) for v in value]
    return value


def scope_identity(consumer_id: str, tenant_id: str, action_id: str, institution_id: str, authority_domain: str) -> dict:
    """The governed scope, in the one shape shared by this binding and by the activation ledger's configuration digest (same five keys, same names)."""
    return {"consumer_id": consumer_id, "tenant_id": tenant_id, "action_id": action_id, "institution_id": institution_id, "authority_domain": authority_domain}


def family_rows(bound: Mapping[str, Any], order: tuple, family_table: Mapping[str, tuple], schema_revisions: Mapping[str, int]) -> list:
    """The declared mandatory family set, from the EXISTING bound identity and family table, in the deterministic composition `order`. A slot that is not declared is absent.

    Generality: nothing here names a family. A family added to the table, to `order` and to `bound` appears automatically. A `bound` entry that is a family slot unknown to
    `order`/`family_table` is NOT silently skipped: it raises, so a newly governed family can never be left out of the binding."""
    known = set(order)
    for slot, part in bound.items():
        if slot == "effective_profile_digest" or part is None:
            continue
        if slot not in known or slot not in family_table:
            raise BindingInvalid("family_slot_unknown")
    rows = []
    for slot in order:
        part = bound.get(slot)
        if part is None:
            continue
        if slot not in family_table or type(part) is not tuple or len(part) < 2:
            raise BindingInvalid("family_part")
        family_id, contract = family_table[slot]
        rows.append({"slot": slot, "family_id": family_id, "contract_version": contract, "family_schema_revision": schema_revisions.get(slot), "effective_policy_digest": part[1]})
    return rows


def build_members(*, scope: Mapping[str, Any], host_profile_digest: Optional[str], effective_profile_digest: Optional[str], f4_scalars: Mapping[str, Any],
                  other_scalars: Mapping[str, Any], observation_policy: Optional[Mapping[str, Any]], families: list) -> dict:
    """Assemble and VALIDATE the members; raises `BindingInvalid` for any value outside its structural domain (exact int, never bool, 0..SCALAR_MAX; exact str; sha256 digests)."""
    members = {"scope": dict(scope), "host_profile_digest": host_profile_digest, "effective_profile_digest": effective_profile_digest, "f4_scalars": dict(f4_scalars),
               "other_scalars": dict(other_scalars), "observation_policy": None if observation_policy is None else dict(observation_policy), "families": list(families)}
    defect = members_defect(members)
    if defect is not None:
        raise BindingInvalid(defect)
    return members


def record_defect(record: Any) -> Optional[str]:
    """None for a well formed, internally consistent persisted member of a SUPPORTED version, else why not: `version_unsupported` or `invalid:<what>`.
    Internally consistent means `digest` equals the recomputation over the member's own `members`; it says nothing about whether the member matches the live configuration."""
    if type(record) is not dict or type(record.get("version")) is not str:
        return "invalid:record"
    if record["version"] != VERSION:
        return "version_unsupported"
    if not _exact(record, RECORD_FIELDS):
        return "invalid:record"
    if not _digest(record["digest"]):
        return "invalid:digest"
    defect = members_defect(record["members"])
    if defect is not None:
        return "invalid:" + defect
    if digest_of(record["version"], record["members"]) != record["digest"]:
        return "invalid:digest_mismatch"
    return None


def legacy_cutoff_defect(cutoff: Any) -> Optional[str]:
    """The cutoff is an explicit finite integer: exact `int` (never bool), 0..SCALAR_MAX. 0 (the default) means no legacy decision is accepted. There is no wildcard value."""
    return None if _scalar(cutoff) else "legacy_cutoff_invalid"


def classify(persisted_runtime_authority: Any, live: Mapping[str, Any], *, index: Optional[int], cutoff: Any, decision_count: int) -> str:
    """Read-only classification of ONE persisted authorized decision against the live member `live` (as produced by `mint`).

    `index` is the position of the decision in the append-only `decisions` list (None when unknown, which is never legacy). `cutoff` is the host-supplied `legacy_cutoff`;
    `decision_count` is the number of decisions in the store now. A cutoff larger than that count cannot describe "the decisions at activation" (the list only grows), so it
    disables the legacy rule instead of accepting decisions that were appended later."""
    ra = persisted_runtime_authority
    if type(ra) is not dict or KEY not in ra:
        legacy = (legacy_cutoff_defect(cutoff) is None and type(index) is int and type(decision_count) is int and 0 <= index < cutoff <= decision_count)
        return LEGACY if legacy else UNBOUND_AFTER_CUTOFF
    record = ra[KEY]
    defect = record_defect(record)
    if defect == "version_unsupported":
        return VERSION_UNSUPPORTED
    if defect is not None:
        return INVALID
    return BOUND if record == live else MISMATCH
