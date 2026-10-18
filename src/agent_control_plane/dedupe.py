"""Opt-in dedupe-ttl/0.1: a key TTL, a provider horizon and an escalation deadline that fires inside the key TTL.

Selected only by the host-governed ``RuntimeAuthorityProfile.dedupe`` field (it needs ``operation_identity`` too). With it unset nothing
here runs and no stored or hashed byte changes.

Three profile fields, in this order (the profile refuses any other order when it is built from fields):

    provider_horizon_seconds  <=  escalation_deadline_seconds  <  dedupe_ttl_seconds

* ``dedupe_ttl_seconds``: how long a destination that stores our id is asked to keep it. Declared by the destination as capability
  ``dedupe-ttl/0.1`` plus ``dedupe_ttl_seconds``; a destination that declares less than the profile asks, or nothing, has no capability
  (mode ``none``). The capability is never inferred.
* ``provider_horizon_seconds``: how long after the first dispatch the provider may still commit it. An attempt whose outcome is
  unknown stays ``unknown`` until then; an absent read before the horizon proves nothing.
* ``escalation_deadline_seconds``: when a still-unresolved attempt escalates to a person or a reconciler. Inside the key TTL, so the
  escalation is recorded while the destination still remembers the key. ``escalation_pass`` fires it (a host runs it on its reaper
  interval); an escalation recorded after the key TTL is flagged ``escalation_after_key_ttl``.

An ``in_progress`` response from the destination is not a failure and not an acknowledgement: the attempt stays ``unknown`` with
``destination_in_progress`` and **no new key is minted**. Under this profile a later attempt under a different effect id for an
operation that has an unresolved attempt is refused (``dedupe_unresolved_attempt_blocks_new_key``).

Limits (read before relying on it):
* Nothing here retries. With a capable destination a same-key resubmission is safe inside the TTL, but this profile only records
  that (``same_key_safe_until``); it does not resubmit. Absent observation never makes an unknown attempt retryable.
* The escalation row is a record. Whoever reads it must act; nothing here contacts anyone.
* Rows are visibility for an honest reader, not tamper evidence.
* No real provider is touched: the capability is implemented by the runtime's CI/local destination only.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timedelta, timezone
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, model_validator

PROFILE_ID = "dedupe-ttl/0.1"
#: A destination declares this (and ``dedupe_ttl_seconds``) when it stores our id and dedupes on it inside a TTL.
DESTINATION_CAPABILITY = "dedupe-ttl/0.1"

CODE_BLOCKS_NEW_KEY = "dedupe_unresolved_attempt_blocks_new_key"
CODE_ALREADY_APPLIED = "dedupe_operation_effect_applied"
CODE_UNRESOLVED_PAST_HORIZON = "attempt_unresolved_past_horizon"
CODE_ESCALATION_LATE = "escalation_after_key_ttl"
ERROR_IN_PROGRESS = "destination_in_progress"

DedupeMode = Literal["destination_ttl", "none"]


class DedupeProfile(BaseModel):
    """Trusted host configuration."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["dedupe-ttl/0.1"] = PROFILE_ID
    dedupe_ttl_seconds: int = Field(gt=0)
    provider_horizon_seconds: int = Field(gt=0)
    escalation_deadline_seconds: int = Field(gt=0)

    @model_validator(mode="after")
    def _escalation_inside_key_ttl(self):
        if not self.provider_horizon_seconds <= self.escalation_deadline_seconds < self.dedupe_ttl_seconds:
            raise ValueError("escalation_deadline_not_inside_key_ttl: need provider_horizon_seconds <= escalation_deadline_seconds "
                             "< dedupe_ttl_seconds")
        return self


class DestinationInProgress(Exception):
    """The destination holds our key and is still processing it. Not a failure, not an acknowledgement, never a reason for a new key."""


class DedupeEscalation(BaseModel):
    """An unresolved attempt escalated at its deadline. Appended once per effect, never edited."""

    model_config = ConfigDict(extra="forbid")
    escalation_id: str
    effect_id: str
    operation_id: str | None = None
    mode: DedupeMode
    in_progress: bool = False
    first_attempt_at: str
    provider_horizon_at: str
    escalation_deadline_at: str
    key_expires_at: str
    same_key_safe_until: str | None = None      # mode destination_ttl only: until then a same-key resubmission is deduped
    fired_at: str
    fired_inside_key_ttl: bool
    reasons: list[str]
    recorded_at: str
    evaluated_at: str | None = Field(default=None, exclude_if=lambda v: v is None)


def dedupe_mode(destination, profile: DedupeProfile) -> DedupeMode:
    """``destination_ttl`` only if the destination declares the capability and a TTL at least the profile's."""
    if getattr(destination, "dedupe_capability", None) != DESTINATION_CAPABILITY:
        return "none"
    ttl = getattr(destination, "dedupe_ttl_seconds", None)
    return "destination_ttl" if type(ttl) is int and ttl >= profile.dedupe_ttl_seconds else "none"


def _t(value: str) -> datetime:
    dt = datetime.fromisoformat(value.replace("Z", "+00:00"))
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt.astimezone(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def unresolved_effects(document: dict) -> dict[str, dict]:
    """Effects whose attempts left no outcome: ``attempted``/``unknown`` and neither acknowledged, partial nor closed out.

    Maps effect id to ``{first, in_progress, operation_id}``. A ``failed`` attempt did not apply and is not unresolved.
    """
    latest: dict[str, dict] = {}
    first: dict[str, datetime] = {}
    for row in document.get("attempts", []):
        latest[row["attempt_id"]] = row
        stamp = _t(row.get("recorded_at") or row["started_at"])
        first[row["effect_id"]] = min(first.get(row["effect_id"], stamp), stamp)
    closed = {c["attempt_id"] for c in document.get("closeouts", [])}
    by_effect: dict[str, list[dict]] = {}
    for row in latest.values():
        by_effect.setdefault(row["effect_id"], []).append(row)
    operation = {j["attempt_id"]: j["operation_id"] for j in document.get("attempt_joins", [])}
    out: dict[str, dict] = {}
    for effect, rows in by_effect.items():
        if any(r["status"] in ("acknowledged", "partial") or r["attempt_id"] in closed for r in rows):
            continue
        open_rows = [r for r in rows if r["status"] in ("attempted", "unknown")]
        if open_rows:
            out[effect] = {"first": first[effect], "operation_id": next((operation[r["attempt_id"]] for r in rows if r["attempt_id"] in operation), None),
                           "in_progress": any(r.get("error") == ERROR_IN_PROGRESS for r in open_rows)}
    return out


def blocks_new_key(document: dict, operation_ids: list[str], effect_id: str) -> bool:
    """True if an operation (or merged set) has an unresolved attempt under a different effect id: a new key must not be minted."""
    wanted = set(operation_ids)
    return any(info["operation_id"] in wanted and effect != effect_id for effect, info in unresolved_effects(document).items())


def applied_under_other_effect(document: dict, operation_ids: list[str], effect_id: str) -> bool:
    """True if an operation (or merged set) already has an applied effect under a different effect id.

    Applied: an attempt acknowledged or partial, or any attempt with a closeout. This is the control plane's own memory and it never
    expires: the destination's key TTL bounds what the *destination* remembers, not what this ledger knows. So a key that has expired
    at the destination can never turn a second effect for the same operation into a fresh one (fail closed, refused before dispatch).
    """
    joins = {j["attempt_id"]: j["operation_id"] for j in document.get("attempt_joins", []) if j["operation_id"] in set(operation_ids)}
    closed = {c["attempt_id"] for c in document.get("closeouts", []) if c["observed_state"] in ("applied", "partial")}
    latest = {row["attempt_id"]: row for row in document.get("attempts", [])}
    return any(row["effect_id"] != effect_id and attempt_id in joins and (row["status"] in ("acknowledged", "partial") or attempt_id in closed)
               for attempt_id, row in latest.items())


def classify(document: dict, profile: DedupeProfile, mode: DedupeMode, now: datetime) -> list[dict]:
    """State of every unresolved attempt at ``now``. Pure. ``state`` is one of ``unknown_until_horizon``,
    ``horizon_passed_awaiting_escalation``, ``escalation_due`` (deadline passed, no row yet) or ``escalated``."""
    escalated = {x["effect_id"] for x in document.get("dedupe_escalations", [])}
    out = []
    for effect, info in sorted(unresolved_effects(document).items()):
        first = info["first"]
        horizon = first + timedelta(seconds=profile.provider_horizon_seconds)
        deadline = first + timedelta(seconds=profile.escalation_deadline_seconds)
        expires = first + timedelta(seconds=profile.dedupe_ttl_seconds)
        state = ("escalated" if effect in escalated else "escalation_due" if now >= deadline
                 else "horizon_passed_awaiting_escalation" if now >= horizon else "unknown_until_horizon")
        out.append({"effect_id": effect, "operation_id": info["operation_id"], "state": state, "mode": mode,
                    "in_progress": info["in_progress"], "first_attempt_at": _iso(first), "provider_horizon_at": _iso(horizon),
                    "escalation_deadline_at": _iso(deadline), "key_expires_at": _iso(expires),
                    "key_expired": now >= expires})
    return out


def due_escalations(document: dict, profile: DedupeProfile, mode: DedupeMode, now: datetime, *, recorded_at: str,
                    evaluated_at: str | None = None) -> list[DedupeEscalation]:
    """Escalation rows to append now: one per unresolved effect past its deadline with no escalation yet. Pure."""
    rows = []
    for item in classify(document, profile, mode, now):
        if item["state"] != "escalation_due":
            continue
        inside = now < _t(item["key_expires_at"])
        rows.append(DedupeEscalation(
            escalation_id=str(uuid.uuid4()), effect_id=item["effect_id"], operation_id=item["operation_id"], mode=mode,
            in_progress=item["in_progress"], first_attempt_at=item["first_attempt_at"],
            provider_horizon_at=item["provider_horizon_at"], escalation_deadline_at=item["escalation_deadline_at"],
            key_expires_at=item["key_expires_at"],
            same_key_safe_until=item["key_expires_at"] if mode == "destination_ttl" else None,
            fired_at=_iso(now), fired_inside_key_ttl=inside,
            reasons=[CODE_UNRESOLVED_PAST_HORIZON] + ([] if inside else [CODE_ESCALATION_LATE]),
            recorded_at=recorded_at, **({"evaluated_at": evaluated_at} if evaluated_at else {})))
    return rows
