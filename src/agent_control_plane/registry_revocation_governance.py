"""Registry-governed `requires_revocation_assurance` (per action class) and terminal-revocation enablement (profile-wide): pure derivations for Registry contract `r08-v6`.

BUILDER_TESTED developer implementation. NOT independently qualified. NOT an authorization mechanism and NOT a policy language. This module adds NO workflow class: the two
derivations are called by the existing composed `GovernedPolicyWorkflow` (`registry_governed_policy`), which owns the lifecycle (construction, decision entry, execute entry and the
pre-dispatch commit gate), the original-host and final-composition checks and the one-effective-profile binding. `bounded.py`, `runtime_authority.py`, `freshness.py`,
`policy_binding.py`, `holder_inventory.py` and every other evaluator are unchanged.

What each Registry value means here (and what it does not):

* `requires_revocation_assurance` (`ActionClass`, Registry family `f5-action-class-revocation-assurance-policy`, values `required` > `not_required`). `required` is a POLICY
  REQUIREMENT, not evidence. Its only consequence in the unchanged evaluator (`runtime_authority.validate_extensions`) is a HOLD: the class holds `holder_inventory_missing`
  unless the HOST profile carries a holder inventory that enumerates at least one holder. A Registry `required` therefore can only ADD a hold; it never creates, supplies or
  verifies an inventory, never proves that a revocation reached any holder, and never issues an assurance receipt. Where the host has no inventory a Registry `required` makes
  every action of the class hold (a self-inflicted denial, which is fail-closed and is not repaired by anything here). An inventory is an unverified host claim
  (`holder_inventory.py`); `required` does not make it a verified one.
* Terminal-revocation enablement (`RuntimeAuthorityProfile.terminal_revocation`, Registry family `f5-terminal-revocation-enablement-policy`, values `on` > `off`). `on` is the host's
  own opt-in "obligation to enforce": a grant revision that a retained resolution check already observed `revoked` is refused (`grant_revocation_recorded`) even when the status read now
  says `active`. It adds a refusal and nothing else: it does not decide who may revoke, does not revoke anything, does not create a terminal state transition, does not reverse
  or supersede one (a new grant revision remains the only way back) and does not turn a Registry record into permission to revoke. The memory is the host's own retained
  checks: a revocation this control plane never observed cannot be remembered, and withdrawing or losing the Registry selection never silently turns the obligation off (the
  required selection is re-verified at every boundary and any failure refuses).

Narrowing relation (the only one asserted): `not_required` < `required` and `off` < `on`; the effective value is the stricter of the host value and the Registry value, so the
result is never looser than the host and a Registry `not_required`/`off` over a stricter host value changes nothing.

Binding. Both values live inside the `RuntimeAuthorityProfile`, which `approval_commitment` hashes (`profile.model_dump()`), and the same hash is the persisted decision binding's
`catalogue_digest`; the flag is omitted from the dump while false and the section while absent, so a forced value changes the profile digest and an approval issued against the host
profile is not valid for the effective one. NOTHING outside the profile is bound here: unlike the F4 age scalars, neither parameter has a constructor-only copy.

Registry is resolved lazily from the host environment (a pinned checkout, never vendored); if it is unavailable the result is a refusal.
"""
from __future__ import annotations

import importlib
import json
from datetime import datetime
from typing import Any, Mapping, Optional

from agent_control_plane.registry_governed_lifecycle import GovernedScope, Refusal, SelectionMaterial
from agent_control_plane.runtime_authority import RuntimeAuthorityProfile

CONTRACT_V6 = "r08-v6"
FAMILY_RA = "f5-action-class-revocation-assurance-policy"
FIELD_RA = "class_requires_revocation_assurance"
REQUIRED, NOT_REQUIRED = "required", "not_required"
_RANK_RA = {REQUIRED: 0, NOT_REQUIRED: 1}  # stricter first
FAMILY_TR = "f5-terminal-revocation-enablement-policy"
FIELD_TR = "terminal_revocation"
ON, OFF = "on", "off"
_RANK_TR = {ON: 0, OFF: 1}  # stricter first
TERMINAL_SECTION = {"version": "terminal-revocation/0.1"}  # the existing TerminalRevocationProfile, byte for byte


def _ra_value(v: Any) -> bool:
    return type(v) is str and v in _RANK_RA


def _tr_value(v: Any) -> bool:
    return type(v) is str and v in _RANK_TR


def stricter_assurance(a: str, b: str) -> str:
    return a if _RANK_RA[a] <= _RANK_RA[b] else b


def stricter_terminal(a: str, b: str) -> str:
    return a if _RANK_TR[a] <= _RANK_TR[b] else b


def host_class_assurance(profile: RuntimeAuthorityProfile) -> tuple[Optional[dict], Optional[str]]:
    """`class_id -> required|not_required` over the host profile's actions, or `(None, code)`. Fail closed on a non-bool flag or two values for one class."""
    values: dict = {}
    for cl in profile.actions.values():
        cid, flag = cl.class_id, cl.requires_revocation_assurance
        if type(cid) is not str or not cid or type(flag) is not bool:
            return None, "host_class_assurance_invalid"
        val = REQUIRED if flag else NOT_REQUIRED
        if cid in values and values[cid] != val:
            return None, "class_assurance_ambiguous"
        values[cid] = val
    return values, None


def host_terminal_value(profile: RuntimeAuthorityProfile) -> str:
    """`on` when the host profile carries the terminal-revocation section, else `off`."""
    return ON if profile.terminal_revocation is not None else OFF


def _strict_pairs(pairs):
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate key")
    return dict(pairs)


def _reject_number(_):
    raise ValueError("non-string number")


def _record_payload(record_text: str, field: str) -> Optional[Any]:
    """The `field` member of an ALREADY Registry-verified record text (a second strict parse: duplicate keys, floats and constants are refused), or None."""
    try:
        doc = json.loads(record_text, object_pairs_hook=_strict_pairs, parse_float=_reject_number, parse_constant=_reject_number)
        payload = doc["payload"]
        return payload[field] if type(payload) is dict and set(payload) == {field} else None
    except Exception:
        return None


def registry_assurance_map(record_text: str) -> Optional[dict]:
    m = _record_payload(record_text, FIELD_RA)
    if type(m) is not dict or not m or not all(type(k) is str and _ra_value(v) for k, v in m.items()):
        return None
    return m


def registry_terminal_value(record_text: str) -> Optional[str]:
    v = _record_payload(record_text, FIELD_TR)
    return v if _tr_value(v) else None


def compose_assurance(base: RuntimeAuthorityProfile, effective: Mapping[str, str]) -> RuntimeAuthorityProfile:
    """The profile with `requires_revocation_assurance` ADDED for every action whose class is `required` in `effective`. Pure; it only ever adds (a host flag is never cleared, whatever
    `effective` says), and nothing else in the profile changes."""
    doc = base.model_dump(mode="json")
    for action in doc["actions"].values():
        if effective[action["class_id"]] == REQUIRED:
            action["requires_revocation_assurance"] = True
    return RuntimeAuthorityProfile.model_validate(doc)


def compose_terminal(base: RuntimeAuthorityProfile, effective: str) -> RuntimeAuthorityProfile:
    """The profile with the terminal-revocation section ADDED when `effective == on`. Pure; it only ever adds (a host section is never removed, whatever `effective` says), and nothing
    else changes."""
    doc = base.model_dump(mode="json")
    if effective == ON:
        doc["terminal_revocation"] = dict(TERMINAL_SECTION)
    return RuntimeAuthorityProfile.model_validate(doc)


def _registry_modules():
    base = importlib.import_module("registry_successor.decision")
    common = importlib.import_module("registry_successor.common")
    decision6 = importlib.import_module("registry_successor.v6_decision")
    identity = importlib.import_module("registry_successor.v6_policy_identity")
    verifier_cls = importlib.import_module("registry_adapters.ed25519_verifier").Ed25519Verifier
    return base, common, decision6, identity, verifier_cls


def _verified(scope: GovernedScope, institution_id: str, authority_domain: str, caller: dict, material: Any, verifier: Any, now: datetime):
    """One Registry `r08-v6` verification. Returns `((base, decision), None)` or `(None, Refusal)`; applies the shared decision-shape checks."""
    if type(material) is not SelectionMaterial or type(material.record_text) is not str or type(material.selection_text) is not str:
        return None, Refusal("material_invalid")
    try:
        base, common, decision6, identity, verifier_cls = _registry_modules()
    except Exception:
        return None, Refusal("registry_unavailable")
    if type(verifier) is not verifier_cls:
        return None, Refusal("verifier_not_admitted")
    try:
        context = common.ExpectedContext(scope.consumer_id, scope.tenant_id, institution_id, authority_domain, scope.operation_id)
        decision = decision6.verify_and_decide_v6("required", caller, material.record_text, material.selection_text, context, material.trust, verifier, now)
    except Exception:
        return None, Refusal("registry_call_failed")
    if not isinstance(decision, base.PolicyDecision) or type(decision.kind) is not str or decision.operationally_authorized is not False:
        return None, Refusal("registry_decision_invalid")
    kind = decision.kind
    if kind in ("required_policy_unavailable", "overlay_not_applied"):
        return None, Refusal("registry_not_applied", decision.code, kind)
    if kind != "applied" or decision.deny_all is not False:
        return None, Refusal("registry_decision_invalid", None, kind)
    return (identity, decision), None


def derive_assurance(*, scope: GovernedScope, institution_id: str, authority_domain: str, host: RuntimeAuthorityProfile, host_values: Mapping[str, str], material: Any,
                     verifier: Any, now: datetime):
    """Pure single verification of the revocation-assurance selection. Returns `((effective class map, Registry policy digest), None)` or `(None, Refusal)`.
    Builds no workflow and writes nothing."""
    got, refusal = _verified(scope, institution_id, authority_domain, {FIELD_RA: dict(host_values)}, material, verifier, now)
    if refusal is not None:
        return None, refusal
    identity, decision = got
    kind, eff = decision.kind, decision.effective
    if not isinstance(eff, Mapping) or set(eff) != {FIELD_RA} or type(eff[FIELD_RA]) is not dict:
        return None, Refusal("effective_policy_invalid", None, kind)
    effective = eff[FIELD_RA]
    if set(effective) != set(host_values) or not all(_ra_value(v) for v in effective.values()):
        return None, Refusal("effective_policy_invalid", None, kind)
    if any(_RANK_RA[effective[k]] > _RANK_RA[host_values[k]] for k in host_values):
        return None, Refusal("effective_policy_widens_host", None, kind)
    registry = registry_assurance_map(material.record_text)
    if registry is None or not set(registry) <= set(host_values) or any(effective[k] != stricter_assurance(host_values[k], registry[k]) for k in registry):
        return None, Refusal("effective_policy_invalid", None, kind)
    if any(k not in registry and effective[k] != host_values[k] for k in host_values):
        return None, Refusal("effective_policy_invalid", None, kind)
    scoped = host.actions.get(scope.action_id)
    if scoped is None:
        return None, Refusal("action_class_unknown", None, kind)
    if scoped.class_id not in registry:
        return None, Refusal("scoped_class_not_governed", None, kind)
    try:
        digest = identity.effective_policy_digest(FAMILY_RA, {FIELD_RA: dict(effective)})
    except Exception:
        return None, Refusal("effective_policy_digest_unavailable", None, kind)
    return (dict(effective), digest), None


def derive_terminal(*, scope: GovernedScope, institution_id: str, authority_domain: str, host_value: str, material: Any, verifier: Any, now: datetime):
    """Pure single verification of the terminal-revocation selection. Returns `((effective value, Registry policy digest), None)` or `(None, Refusal)`.
    Builds no workflow and writes nothing."""
    if not _tr_value(host_value):
        return None, Refusal("host_terminal_invalid")
    got, refusal = _verified(scope, institution_id, authority_domain, {FIELD_TR: host_value}, material, verifier, now)
    if refusal is not None:
        return None, refusal
    identity, decision = got
    kind, eff = decision.kind, decision.effective
    if not isinstance(eff, Mapping) or set(eff) != {FIELD_TR} or not _tr_value(eff[FIELD_TR]):
        return None, Refusal("effective_policy_invalid", None, kind)
    effective = eff[FIELD_TR]
    if _RANK_TR[effective] > _RANK_TR[host_value]:
        return None, Refusal("effective_policy_widens_host", None, kind)
    registry = registry_terminal_value(material.record_text)
    if registry is None or effective != stricter_terminal(host_value, registry):
        return None, Refusal("effective_policy_invalid", None, kind)
    try:
        digest = identity.effective_policy_digest(FAMILY_TR, {FIELD_TR: effective})
    except Exception:
        return None, Refusal("effective_policy_digest_unavailable", None, kind)
    return (effective, digest), None
