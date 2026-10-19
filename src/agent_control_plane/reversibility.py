"""Opt-in reversibility/0.1: ``irreversible | reversible_until | reversible_at_cost`` on the action class, and a bounded use of a cached
"open" purpose snapshot during a purpose outage.

Selected only by the host-governed ``RuntimeAuthorityProfile.reversibility`` field. With it unset nothing here runs, the action class
dumps exactly as before (every new member is omitted while unset) and a purpose outage refuses for every class.

The rules follow the draft ODES ``effect-reversibility`` contract (open-decision-evidence-standard, ``contracts/effect-reversibility``):

* The boolean ``irreversible`` stays as the derived legacy field: true if and only if ``reversibility`` is ``irreversible``.
  ``reversible_at_cost`` has it false.
* Order of strictness: ``irreversible`` over ``reversible_at_cost`` over ``reversible_until``.
* Reads of protected data are ``irreversible`` (``reads_protected_data`` is a producer assertion, not derived).
* Where the counterparty condition cannot be observed (``counterparty_observable`` false) the class is ``irreversible``.
* A ``reversible_until`` class is treated as ``irreversible`` once its window has passed.
* A cached "open" purpose snapshot is accepted only for a reversible class, within the class age bound (inclusive), and only while no
  recorded closure of that purpose exists. A recorded closure overrides the cache. The bound is the class bound, raised only by a
  recorded N3 age extension named by a configured signer (asserted, unauthenticated) (never for an irreversible class).
* Every use of a cached snapshot, accepted or refused, is appended as a ``snapshot_use`` row with the epoch and the age.

Limits (read before relying on it):
* The cache is the resolver's own ``cached_purpose_status``; this module cannot tell that it is authentic, only how old it says it is
  (``age_basis`` is always ``source_asserted`` for a cached read).
* A recorded closure is a purpose state this control plane itself read as closed. A closure that happened elsewhere and was never read
  here is invisible to it: the cache may then be wrong by exactly that much, within its age bound.
* ``reversible_until`` and ``reversal_cost`` are producer assertions. Whether a reversal would in fact succeed is not modelled.
"""
from __future__ import annotations

import uuid
from datetime import datetime

from .time_instant import TIME_INSTANT_NAIVE, InstantError, parse_instant
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field

PROFILE_ID = "reversibility/0.1"
VALUES = ("irreversible", "reversible_until", "reversible_at_cost")
#: Strictest first. Used wherever two readings of one class disagree.
STRICTNESS = {"irreversible": 3, "reversible_at_cost": 2, "reversible_until": 1}

CODE_CACHE_IRREVERSIBLE = "purpose_cache_irreversible_class"
CODE_CACHE_AFTER_WINDOW = "purpose_cache_after_reversal_window"
CODE_CACHE_STALE = "purpose_cache_stale"
CODE_CLOSURE_RECORDED = "purpose_closure_recorded"
CODE_EXTENSION_IRREVERSIBLE = "age_extension_irreversible_class"

SnapshotBasis = Literal["live_read", "cached_snapshot", "strict_default"]


class ReversibilityProfile(BaseModel):
    """Trusted host configuration. A marker today: the rules are fixed by the contract, not tunable per deployment."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["reversibility/0.1"] = PROFILE_ID


class SnapshotUse(BaseModel):
    """One use of a cached purpose snapshot during an outage, accepted or refused. Appended, never edited."""

    model_config = ConfigDict(extra="forbid")
    use_id: str
    class_id: str
    purpose_ref: str                      # commitment of the grant's purpose binding (system, record, epoch)
    check_id: str | None = Field(default=None, exclude_if=lambda v: v is None)
    basis: SnapshotBasis                  # cached_snapshot, or strict_default when nothing could be used
    effective_status: Literal["open", "closed"]
    accepted: bool
    reversibility: str                    # the value in force at use (irreversible after a passed window)
    epoch: str | None = None
    snapshot_status: str | None = None
    snapshot_observed_at: str | None = None
    age_seconds: float | None = None
    age_bound_seconds: int
    extension_id: str | None = Field(default=None, exclude_if=lambda v: v is None)
    age_basis: Literal["source_asserted"] = "source_asserted"
    reasons: list[str] = Field(default_factory=list)
    recorded_at: str
    evaluated_at: str


def _utc(value: str) -> datetime:
    return parse_instant(value)


X_MEMBER = "x-reversibility"
_FLAT = ("reversibility", "reversible_until", "reversal_cost", "reads_protected_data", "counterparty_observable")


def flatten_x_reversibility(data: dict) -> dict:
    """Accept the ODES form (one ``x-reversibility`` object, ``reversal_cost`` as ``{"description": ...}``) as input as well."""
    if X_MEMBER not in data:
        return data
    nested = data[X_MEMBER]
    if not isinstance(nested, dict) or any(k in data for k in _FLAT):
        raise ValueError("reversibility_member_mismatch: x-reversibility and the flat members are alternatives")
    rest = {k: v for k, v in data.items() if k != X_MEMBER}
    unknown = set(nested) - set(_FLAT)
    if unknown:
        raise ValueError(f"undeclared_member: x-reversibility has no member {sorted(unknown)[0]!r}")
    flat = dict(nested)
    cost = flat.get("reversal_cost")
    if isinstance(cost, dict):
        if set(cost) != {"description"} or not isinstance(cost["description"], str) or not cost["description"]:
            raise ValueError("schema_violation: reversal_cost is {description: non-empty text} or null")
        flat["reversal_cost"] = cost["description"]
    return {**rest, **{k: v for k, v in flat.items() if v is not None or k == "reversibility"}}


def nest_x_reversibility(dumped: dict) -> dict:
    """The dump of an action class: the five members as one ``x-reversibility`` object (all five present, null where not
    applicable), the legacy members unchanged. Nothing is added when no value is declared."""
    if "reversibility" not in dumped:
        return dumped
    cost = dumped.get("reversal_cost")
    nested = {"reversibility": dumped["reversibility"], "reversible_until": dumped.get("reversible_until"),
              "reversal_cost": {"description": cost} if cost is not None else None,
              "reads_protected_data": bool(dumped.get("reads_protected_data", False)),
              "counterparty_observable": dumped.get("counterparty_observable", True)}
    out = {k: v for k, v in dumped.items() if k not in _FLAT}
    out[X_MEMBER] = nested
    return out


def check_class_members(data: dict) -> dict:
    """Validate and complete the reversibility members of an ``ActionClass`` before it is built (used by its validator).

    Returns ``data`` with ``irreversible`` derived. Raises ``ValueError`` naming the ODES violation code.
    """
    optional = ("reversible_until", "reversal_cost", "reads_protected_data", "counterparty_observable")
    value = data.get("reversibility")
    strict_default = bool(data.get("reads_protected_data")) or data.get("counterparty_observable") is False
    if value is None and strict_default:
        value = "irreversible"          # a protected read or an unobservable counterparty defaults to the strictest value
    if value is None:
        if data.get("reversible_until") is not None or data.get("reversal_cost") is not None:
            raise ValueError("reversibility_member_mismatch: reversible_until/reversal_cost need a reversibility value")
        return data
    if value not in VALUES:
        raise ValueError(f"unknown_enum_value: reversibility {value!r}")
    derived = value == "irreversible"
    if "irreversible" in data and data["irreversible"] != derived:
        raise ValueError("irreversible_flag_mismatch: the legacy boolean is true if and only if reversibility is irreversible")
    until, cost = data.get("reversible_until"), data.get("reversal_cost")
    if (until is not None) != (value == "reversible_until") or (cost is not None) != (value == "reversible_at_cost"):
        raise ValueError("reversibility_member_mismatch: reversible_until is set only for reversible_until, "
                         "reversal_cost only for reversible_at_cost")
    if until is not None:
        try:
            parse_instant(until)
        except InstantError as exc:
            if exc.code == TIME_INSTANT_NAIVE:
                raise ValueError("timestamp_invalid: reversible_until needs a UTC offset") from None
            raise ValueError("timestamp_invalid: reversible_until") from None
        except TypeError:
            raise ValueError("timestamp_invalid: reversible_until") from None
    if data.get("reads_protected_data") and value != "irreversible":
        raise ValueError("protected_read_not_irreversible: a read cannot be taken back")
    if data.get("counterparty_observable") is False and value != "irreversible":
        raise ValueError("unobservable_not_strict: an unobservable counterparty defaults to the strictest value")
    return {**data, "reversibility": value, "irreversible": derived,
            **({k: data[k] for k in optional if k in data})}


def effective_reversibility(action_class, now: datetime) -> tuple[str, str]:
    """The value in force at ``now`` and why: ``(value, basis)``.

    A class that declares nothing is ``irreversible`` (the legacy default is the strict one). A ``reversible_until`` class past its
    window is ``irreversible`` with basis ``window_passed``.
    """
    value = getattr(action_class, "reversibility", None)
    if value is None:
        return "irreversible", "undeclared"
    if getattr(action_class, "reads_protected_data", False):
        return "irreversible", "protected_read"
    if getattr(action_class, "counterparty_observable", True) is False:
        return "irreversible", "counterparty_unobservable"
    if value == "reversible_until" and now >= _utc(action_class.reversible_until):
        return "irreversible", "window_passed"
    return value, "declared"


def effectively_irreversible(action_class, now: datetime | None) -> bool:
    """The boolean the legacy checks use. Without the profile's members it is the legacy field, unchanged."""
    if getattr(action_class, "reversibility", None) is None or now is None:
        return action_class.irreversible
    return effective_reversibility(action_class, now)[0] == "irreversible"


def recorded_closures(document: dict, purpose_ref: str) -> list[dict]:
    """Retained reads of this purpose that observed it closed: the control plane's own recorded closures."""
    return [{"check_id": c["check_id"], "recorded_at": c.get("recorded_at") or c["evaluated_at"]}
            for c in document.get("resolution_checks", [])
            for i in c.get("inputs", [])
            if i["input_type"] == "purpose" and i["input_id"] == purpose_ref and i.get("observed", {}).get("state") == "closed"]


def judge_cached_purpose(*, action_class, now: datetime, purpose_ref: str, cached, closures: list[dict],
                         bound_seconds: int, extension_id: str | None, check_id: str | None, recorded_at: str):
    """Decide whether a cached purpose snapshot may stand in for an unreadable one. Pure.

    ``cached`` is a validated ``PurposeStatus`` or None. Returns ``(SnapshotUse, accepted_status_or_None)``.
    Order of refusal: irreversible class (or passed window), recorded closure, no usable snapshot, not open, stale.
    """
    value, basis = effective_reversibility(action_class, now)
    reasons: list[str] = []
    age = None
    if cached is not None:
        age = (now - _utc(cached.observed_at)).total_seconds()
    if value == "irreversible":
        reasons.append(CODE_CACHE_AFTER_WINDOW if basis == "window_passed" else CODE_CACHE_IRREVERSIBLE)
    elif closures:
        reasons.append(CODE_CLOSURE_RECORDED)
    elif cached is None:
        reasons.append("purpose_unreadable")
    elif cached.state != "open":
        reasons.append("purpose_closed")
    elif age < 0 or age > bound_seconds:
        reasons.append(CODE_CACHE_STALE)
    accepted = not reasons
    use = SnapshotUse(
        use_id=str(uuid.uuid4()), class_id=action_class.class_id, purpose_ref=purpose_ref, check_id=check_id,
        basis="cached_snapshot" if accepted or cached is not None else "strict_default",
        effective_status="open" if accepted else "closed", accepted=accepted, reversibility=value,
        epoch=cached.epoch if cached is not None else None,
        snapshot_status=cached.state if cached is not None else None,
        snapshot_observed_at=cached.observed_at if cached is not None else None,
        age_seconds=age, age_bound_seconds=bound_seconds, extension_id=extension_id if accepted else None,
        reasons=reasons, recorded_at=recorded_at, evaluated_at=now.isoformat())
    return use, (cached if accepted else None)
