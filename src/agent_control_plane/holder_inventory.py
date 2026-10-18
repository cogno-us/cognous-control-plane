"""Opt-in holder inventory (holder-inventory/0.1): the enumerated holders of authority, and what a revocation probe may claim.

Selected only by the host-governed ``RuntimeAuthorityProfile.holder_inventory`` field together with the per-class flag
``ActionClass.requires_revocation_assurance``. With both unset nothing here runs and every stored and hashed byte is unchanged
(both fields are omitted from profile dumps while unset).

* An action class flagged ``requires_revocation_assurance`` holds (``holder_inventory_missing``) until the profile carries an
  inventory that enumerates at least one holder and names who recorded it. The hold is the point: the stack cannot show that a
  revocation reached holders nobody listed.
* ``classify_holders`` turns refusal rows into two lists: holders with a witnessed refusal, and holders with none. A holder with
  no refusal is ``coverage_unknown``. It is never reported as expired, revoked, lapsed or inactive: no refusal was produced, so
  nothing is known about whether its authority still stands.

Limits: an inventory is a claim by whoever wrote it. A holder nobody enumerated stays invisible to every probe, so the inventory
is the control and this module cannot check it for completeness. It never asserts that a holder it lists is the only route to an
effect.
"""
from __future__ import annotations

from typing import Iterable, Literal

from pydantic import BaseModel, ConfigDict, Field

PROFILE_ID = "holder-inventory/0.1"
CODE_MISSING = "holder_inventory_missing"

CLASSIFICATION_WITNESSED = "witnessed_refusal"
CLASSIFICATION_UNKNOWN = "coverage_unknown"


class AuthorityHolder(BaseModel):
    """One enumerated holder of authority to cause the effect, and where its authority is enforced."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    holder_id: str = Field(min_length=1, max_length=256)
    #: routed: every effect passes the control plane's effect-time check. self_credentialed: the holder holds a credential for
    #: the destination itself and can act without passing the control plane. other: neither claim is made.
    kind: Literal["routed", "self_credentialed", "other"]
    enforcement_point: str = Field(min_length=1, max_length=256)
    credential_ref: str | None = Field(default=None, max_length=256)   # a reference, never a secret


class HolderInventory(BaseModel):
    """Trusted host configuration: the holders the host claims to have enumerated. Covered by the approval commitment once set."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["holder-inventory/0.1"] = PROFILE_ID
    inventory_id: str = Field(min_length=1, max_length=256)
    recorded_by: str = Field(min_length=1, max_length=256)
    recorded_at: str = Field(min_length=1)
    holders: list[AuthorityHolder] = Field(default_factory=list, max_length=10000)

    def exists(self) -> bool:
        """An inventory counts only if it enumerates a holder (an empty list claims nothing)."""
        return bool(self.holders)


def inventory_defects(inventory: HolderInventory | None) -> list[str]:
    return [] if inventory is not None and inventory.exists() else [CODE_MISSING]


def classify_holders(holders: Iterable[dict], refusal_rows: Iterable[dict]) -> dict:
    """Two lists. A holder is witnessed only if a refusal row names it as a changed input or by one of its effect ids.

    ``holders``: dicts with ``holder_id`` and optional ``kind`` and ``effect_ids`` (an inventory's holders dumped, plus the effect
    ids the probe attributed to each). Same rule and strings as the qualification template ``classify_holders``.
    """
    rows = list(refusal_rows)
    witnessed, unenumerated = [], []
    for holder in holders:
        hid = holder["holder_id"]
        effects = set(holder.get("effect_ids") or ())
        hits = [r for r in rows if hid in {c.get("input_id") for c in (r.get("changed_inputs") or [])} or r.get("effect_id") in effects]
        if hits:
            witnessed.append({"holder_id": hid, "kind": holder.get("kind"), "classification": CLASSIFICATION_WITNESSED,
                              "refusals": [{"refusal_id": r.get("refusal_id"), "effect_id": r.get("effect_id"),
                                            "reasons": list(r.get("reasons") or [])} for r in hits]})
        else:
            unenumerated.append({"holder_id": hid, "kind": holder.get("kind"), "classification": CLASSIFICATION_UNKNOWN,
                                 "note": "no refusal produced; authority status unknown, needs containment or a probe"})
    return {"witnessed_refusals": witnessed, "unenumerated_authority_needing_containment": unenumerated}
