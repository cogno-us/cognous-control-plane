"""ocs-policy-binding/1: strict validation and digest of the Registry canonical effective-policy binding (EXT-S4-4, claim carriage only).

This module implements the PUBLISHED profile (Registry ``docs/r08-v2-contract.md`` section 4 and 4.1); it does not import or copy Registry code
and it does not interpret policy. It is distinct from the approval-side ``policy-binding/0.1`` object (``policy_binding.py``), which it neither
replaces nor extends.

* ``binding_defect`` is a strict, closed-membership check with no normalization and no coercion. It returns the path of the first defective
  member, or ``None``. The path is diagnostic text only; it is NOT a reason code.
* ``binding_digest`` is ``"sha256:" + hex(sha256(b"ocs-reg/r08-v2/policy-binding\\n" + canonical_bytes(binding)))`` over the existing Control Plane
  serializer (``bounded._canonical_bytes``). Every string member is ASCII, so those bytes equal the Registry ``canonical_bytes`` output.

A valid binding is evidence of what was selected and activated. It authorizes nothing: a claim that carries one is still only a claim, and the
enforcing component must compare it with durable active authority under the destination lock (a later sprint, not implemented here).
"""
from __future__ import annotations

import hashlib
import re

from agent_control_plane.bounded import _canonical_bytes

BINDING_PROFILE = "ocs-policy-binding/1"
DIGEST_DOMAIN = b"ocs-reg/r08-v2/policy-binding\n"

#: Closed top-level membership (the named schema of contract section 4, not any prose member count).
MEMBERS = (
    "binding_profile", "record_id", "record_version", "record_digest", "selection_id", "selection_epoch", "selection_digest", "family",
    "consumer_id", "scope", "operation", "effective_policy_digest", "activation_ref", "trust_snapshot_version", "trust_snapshot_fingerprint",
)
SCOPE_MEMBERS = ("tenant", "institution", "authority_domain")
IDENTIFIERS = ("record_id", "selection_id", "family", "consumer_id", "operation")
DIGESTS = ("record_digest", "selection_digest", "effective_policy_digest", "activation_ref", "trust_snapshot_fingerprint")
#: Per-field integer domains. Contract 4.1 fixes the minimum (1); the upper bounds are those of the EXT-S1-5 spec / Registry vectors. Independent entries, not derived from one constant.
INTEGER_RANGES = {
    "record_version": (1, 2147483647),
    "selection_epoch": (1, 2147483647),
    "trust_snapshot_version": (1, 9007199254740991),
}

# Explicit ASCII ranges only: no \w, \d, locale or re.IGNORECASE; \Z (not $) so a trailing newline is never accepted.
_IDENTIFIER = re.compile(r"\A[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_DIGEST = re.compile(r"\Asha256:[0-9a-f]{64}\Z")


def _identifier_ok(value) -> bool:
    return type(value) is str and _IDENTIFIER.match(value) is not None


def _digest_ok(value) -> bool:
    return type(value) is str and _DIGEST.match(value) is not None


def _int_ok(value, low: int, high: int) -> bool:
    return type(value) is int and low <= value <= high  # exact int: never a bool, subclass, float or string


def binding_defect(binding) -> str | None:
    """Path of the first defect in ``binding`` (membership, then types and values), or ``None`` when it is a valid completed binding."""
    if type(binding) is not dict:
        return "binding"
    if any(type(key) is not str for key in binding):
        return "binding"
    for name in MEMBERS:
        if name not in binding:
            return name
    for name in sorted(binding):
        if name not in MEMBERS:
            return name
    scope = binding["scope"]
    if type(scope) is not dict or any(type(key) is not str for key in scope):
        return "scope"
    for name in SCOPE_MEMBERS:
        if name not in scope:
            return f"scope.{name}"
    for name in sorted(scope):
        if name not in SCOPE_MEMBERS:
            return f"scope.{name}"
    if type(binding["binding_profile"]) is not str or binding["binding_profile"] != BINDING_PROFILE:
        return "binding_profile"
    for name in IDENTIFIERS:
        if not _identifier_ok(binding[name]):
            return name
    for name in SCOPE_MEMBERS:
        if not _identifier_ok(scope[name]):
            return f"scope.{name}"
    for name in DIGESTS:
        if not _digest_ok(binding[name]):
            return name
    for name, (low, high) in INTEGER_RANGES.items():
        if not _int_ok(binding[name], low, high):
            return name
    return None


def binding_digest(binding) -> str:
    """The ``binding_digest`` of a valid completed binding. A defective binding raises ``ValueError`` (it is never digested)."""
    defect = binding_defect(binding)
    if defect is not None:
        raise ValueError(f"policy binding member invalid: {defect}")
    return "sha256:" + hashlib.sha256(DIGEST_DOMAIN + _canonical_bytes(binding)).hexdigest()
