"""Opt-in policy-binding/0.1: a local, stateless approval-generation binding and registry freshness ceilings.

Scope and limits (read before relying on it):

* The binding is TRUSTED host configuration. It names the effective policy identity a consumer enforces (an opaque ``binding_digest``,
  the ``selection_epoch`` of the issuing selection, the ``activation_ref`` of the governing activation transition and a
  ``disposition``) and an opaque, consumer-supplied ``policy_generation``. ``policy_generation`` is NEVER derived from or compared
  with ``selection_epoch``; ``activation_sequence`` (the durable activation-log position) is RESERVED and refused as an unknown member
  until EXT-S4-0 defines it.
* This module only compares what an approval carries with what the trusted profile carries (equality, strict types, ranges, canonical
  forms, a closed commitment-version set). It has no durable memory. It therefore does NOT establish durable anti-rollback
  enforcement: an older generation presented with a profile that still carries the older binding revives the older approval, and a
  supplier that stops emitting the binding revives the legacy approval. Both are pinned as negative controls in the tests, and both
  are obligations of the enforcing consumer (a durable ``scope_required`` ratchet and atomic effect-time verification, EXT-S4),
  which this module does not implement.
* ``disposition = "withdrawn"`` is a PROVISIONAL representation (it carries the consumer-supplied ``activation_ref`` and
  ``policy_generation`` and NO ``binding_digest``) until EXT-S4-0 defines the canonical withdrawal binding.
* ``age_ceilings`` (registry-narrowed freshness ceilings per action id) are enforced from the profile alone, at construction and at
  every evaluation, because ``model_copy`` and ``snapshot`` skip validators. A ceilinged profile must carry a freshness/0.1 profile
  with ``anchor_deadline_to_inputs``, and ``class base + max_age_extension_seconds`` may not exceed any ceiling. No maximum age is
  adopted here (the Architect has not adopted one).
"""
from __future__ import annotations

import re
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, StrictInt, model_validator

BINDING_VERSION = "policy-binding/0.1"
APPROVAL_COMMITMENT_V2 = "approval-commitment/0.2"
#: Closed set. An unknown version is refused even when the commitment matches (the approval cannot select the verifier).
SUPPORTED_APPROVAL_COMMITMENT_VERSIONS = frozenset({APPROVAL_COMMITMENT_V2})
#: Interim conservative range for the opaque generation and the epoch (a subset of the 1 to 2^53-1 range EXT-S1-5 reserves for EXT-S3-4).
INT_MIN, INT_MAX = 1, 2147483647

#: The eight additive typed-only codes of registry ``runtime-authority-reasons/0.3``. PROPOSED names, NOT RATIFIED by the owning component.
NEW_CODES = (
    "approval_commitment_version_unsupported",
    "approval_policy_generation_missing",
    "approval_policy_generation_invalid",
    "approval_policy_generation_mismatch",
    "approval_policy_activation_mismatch",
    "freshness_ceiling_exceeded",
    "freshness_ceiling_unanchored",
    "policy_binding_invalid",
)

_DIGEST = re.compile(r"sha256:[0-9a-f]{64}")
ZERO_DIGEST = "sha256:" + "0" * 64


def valid_int(value) -> bool:
    """Strict: an exact ``int`` (never a bool or subclass) inside the interim range."""
    return type(value) is int and INT_MIN <= value <= INT_MAX


def valid_digest(value) -> bool:
    """Canonical ``sha256:<64 lowercase hex>``, exact ``str``, and not the all-zero digest (refused for every digest member)."""
    return type(value) is str and _DIGEST.fullmatch(value) is not None and value != ZERO_DIGEST


class PolicyBinding(BaseModel):
    """Trusted host configuration. ``activation_sequence`` is deliberately not a member: ``extra='forbid'`` refuses it."""
    model_config = ConfigDict(extra="forbid", frozen=True)
    version: Literal["policy-binding/0.1"] = BINDING_VERSION
    #: Opaque effective-policy-identity digest (EXT-S1-5). Required for ``selected``; MUST be absent for ``withdrawn``.
    binding_digest: str | None = Field(default=None, exclude_if=lambda v: v is None)
    selection_epoch: StrictInt = Field(ge=INT_MIN, le=INT_MAX)
    activation_ref: str
    #: Opaque, consumer-supplied. Never derived from ``selection_epoch``.
    policy_generation: StrictInt = Field(ge=INT_MIN, le=INT_MAX)
    disposition: Literal["selected", "withdrawn"]
    #: action_id -> ceiling in seconds (>= 1). Omitted from dumps while empty.
    age_ceilings: dict[str, StrictInt] = Field(default_factory=dict, exclude_if=lambda v: not v)

    @model_validator(mode="after")
    def _members_are_defined(self):
        if member_defects(self):
            raise ValueError("policy_binding members are invalid")
        return self


def member_defects(binding) -> bool:
    """True when the binding is malformed. Strict and independent of pydantic, so it also judges a ``model_copy``-bypassed instance."""
    if type(binding) is not PolicyBinding or binding.version != BINDING_VERSION:
        return True
    if not valid_int(binding.selection_epoch) or not valid_int(binding.policy_generation):
        return True
    if not valid_digest(binding.activation_ref) or binding.disposition not in ("selected", "withdrawn"):
        return True
    ceilings = binding.age_ceilings
    if type(ceilings) is not dict or any(type(k) is not str or not k or type(v) is not int or v < 1 for k, v in ceilings.items()):
        return True
    if binding.disposition == "selected":
        return not valid_digest(binding.binding_digest)
    # withdrawn: no digest member at all (not None, not empty, not all-zero, not a copied selected-record digest) and nothing narrowed
    return "binding_digest" in binding.model_fields_set or binding.binding_digest is not None or bool(ceilings)


def identity_members(binding) -> dict:
    """The effective policy identity as separate preimage members (attribute reads only). ``validate_extensions`` refuses a malformed binding before this is hashed."""
    out = {"activation_ref": getattr(binding, "activation_ref", None), "selection_epoch": getattr(binding, "selection_epoch", None),
           "disposition": getattr(binding, "disposition", None)}
    digest = getattr(binding, "binding_digest", None)
    if digest is not None:
        out["binding_digest"] = digest
    return out


def policy_binding_defects(profile) -> list[str]:
    """Defects of the profile's binding: any of ``invalid``, ``unanchored``, ``exceeded``. Run at construction AND at every evaluation."""
    binding = getattr(profile, "policy_binding", None)
    if binding is None:
        return []
    if member_defects(binding):
        return ["invalid"]
    ceilings = binding.age_ceilings
    if not ceilings:
        return []
    out = []
    actions = profile.actions
    if any(action_id not in actions for action_id in ceilings):
        out.append("invalid")
    freshness = profile.freshness
    if freshness is None or freshness.anchor_deadline_to_inputs is not True:
        out.append("unanchored")
    extension = freshness.max_age_extension_seconds if freshness is not None else 0
    for action_id, ceiling in ceilings.items():
        action = actions.get(action_id)
        if action is None:
            continue
        base = action.max_status_age_seconds
        # a negative (bypassed) extension can never lower a bound, so it is counted as 0; a negative base is malformed
        if type(base) is not int or type(extension) is not int or base < 0 or base + max(extension, 0) > ceiling:
            out.append("exceeded")
            break
    return out
