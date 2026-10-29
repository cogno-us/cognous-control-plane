"""Registry-governed `ActionClass.irreversible` (per action class, strengthen-only): pure derivation for Registry contract `r08-v7`.

BUILDER_TESTED developer implementation. NOT independently qualified. NOT an authorization mechanism and NOT a policy language. This module adds NO workflow class: the derivation is
called by the existing composed `GovernedPolicyWorkflow` (`registry_governed_policy`), which owns the lifecycle (construction, decision entry, execute entry and the pre-dispatch
commit gate), the original-host and final-composition checks and the one-effective-profile binding. `bounded.py`, `runtime_authority.py`, `freshness.py`, `policy_binding.py`,
`rule_revision.py`, `reversibility.py`, `holder_inventory.py` and every other evaluator are unchanged.

What the Registry value means here (and what it does not):

* Registry family `f5-action-class-irreversibility-policy` (contract `r08-v7`, family schema revision 1), member `class_irreversible`: a `class -> irreversible | no_change` map.
  `irreversible` is a STRENGTHEN-ONLY declaration: for EVERY action of that class `ActionClass.irreversible` becomes true. `no_change` leaves the host value exactly as it is. The family
  can NEVER assert reversibility: a Registry `no_change` over a host `irreversible` class keeps `irreversible`; no Registry value can turn a true flag false.
* Source-backed consequences of a true flag in the unchanged evaluator (Control Plane `a62ca8d`): `bounded.py` refuses every action of an irreversible class whose `on_unreadable` is not
  `refuse` (`action_class_invalid`), and `reversibility.effectively_irreversible` (cached-grant tolerance) reads the flag when the class declares no `reversibility`. Nothing else in
  the evaluator reads the flag. A flip therefore can only ADD refusals (it also changes the profile digest, see Binding).
* A flip is NEVER a repair. `irreversible` is the derived legacy field of the opt-in reversibility members. The flip is accepted only for a HOST class that declares none of them:
  `reversibility`, `reversible_until` and `reversal_cost` all None, `reads_protected_data` false, `counterparty_observable` true, AND the HOST `on_unreadable` is `refuse` (the host
  value, never the value another Registry family composed: a flip must not hide a host defect by relying on a narrowing). Any other host class is refused
  `irreversible_flip_conflict:<cause>` (one named cause per condition), before anything is composed. A host class that is already `irreversible` stays unchanged (no-op).
* Two host actions that share a class id must carry the same flag (`class_irreversible_ambiguous`), so a flip is never applied to half of a class.

Narrowing relation (the only one asserted): `no_change` < `irreversible`; operator `intersection`; the effective value is the stricter of the host (caller) value and the Registry value
per class, so the result is never looser than the host. A Registry class the host does not define is refused, as in r08-v6.

Binding. `irreversible` has no `exclude_if`, so it is in the profile dump that `approval_commitment` hashes and that is the persisted decision binding's `catalogue_digest`: a flipped
profile has another commitment, an approval issued for the host profile does not authorize it (`runtime_authority_approval_mismatch`) and a decision persisted under another effective
profile is refused. No preimage, persisted field or reason code is added or changed.

Registry is resolved lazily from the host environment (a pinned checkout, never vendored); if it is unavailable the result is a refusal.
"""
from __future__ import annotations

import importlib
from datetime import datetime
from typing import Any, Mapping, Optional

from agent_control_plane.registry_governed_lifecycle import GovernedScope, Refusal, SelectionMaterial
from agent_control_plane.registry_revocation_governance import _record_payload
from agent_control_plane.runtime_authority import RuntimeAuthorityProfile

CONTRACT_V7 = "r08-v7"
FAMILY_IR = "f5-action-class-irreversibility-policy"
FIELD_IR = "class_irreversible"
FAMILY_SCHEMA_REVISION = 1
IRREVERSIBLE, NO_CHANGE = "irreversible", "no_change"
_RANK_IR = {IRREVERSIBLE: 0, NO_CHANGE: 1}  # stricter first
FLIP_CONFLICT = "irreversible_flip_conflict"
FLIP_CAUSES = ("reversibility_declared", "reversible_until_declared", "reversal_cost_declared", "on_unreadable_not_refuse", "reads_protected_data",
               "counterparty_observable_not_default")  # the order in which a cause is reported


def _ir_value(v: Any) -> bool:
    return type(v) is str and v in _RANK_IR


def stricter_irreversible(a: str, b: str) -> str:
    return a if _RANK_IR[a] <= _RANK_IR[b] else b


def host_class_irreversible(profile: RuntimeAuthorityProfile) -> tuple[Optional[dict], Optional[str]]:
    """`class_id -> irreversible|no_change` over the host profile's actions, or `(None, code)`. Fail closed on a non-bool flag or two values for one class."""
    values: dict = {}
    for cl in profile.actions.values():
        cid, flag = cl.class_id, cl.irreversible
        if type(cid) is not str or not cid or type(flag) is not bool:
            return None, "host_class_irreversible_invalid"
        val = IRREVERSIBLE if flag else NO_CHANGE
        if cid in values and values[cid] != val:
            return None, "class_irreversible_ambiguous"
        values[cid] = val
    return values, None


def registry_irreversible_map(record_text: str) -> Optional[dict]:
    """The `class -> value` map of an ALREADY Registry-verified record text, or None (a second strict parse: duplicate keys, floats and constants refused)."""
    m = _record_payload(record_text, FIELD_IR)
    if type(m) is not dict or not m or not all(type(k) is str and _ir_value(v) for k, v in m.items()):
        return None
    return m


def flip_causes(cl: Any) -> list:
    """The named reasons the HOST class `cl` may not be flipped to irreversible. Empty means the flip is a pure strengthening of an undeclared-reversibility class. Reads the HOST
    object only."""
    causes = []
    if getattr(cl, "reversibility", None) is not None:
        causes.append(FLIP_CAUSES[0])
    if getattr(cl, "reversible_until", None) is not None:
        causes.append(FLIP_CAUSES[1])
    if getattr(cl, "reversal_cost", None) is not None:
        causes.append(FLIP_CAUSES[2])
    if getattr(cl, "on_unreadable", None) != "refuse":
        causes.append(FLIP_CAUSES[3])
    if getattr(cl, "reads_protected_data", False) is not False:
        causes.append(FLIP_CAUSES[4])
    if getattr(cl, "counterparty_observable", True) is not True:
        causes.append(FLIP_CAUSES[5])
    return causes


def flip_conflict(host: RuntimeAuthorityProfile, host_values: Mapping[str, str], effective: Mapping[str, str]) -> Optional[str]:
    """`irreversible_flip_conflict:<cause>` for the first HOST class that the effective map would flip (host `no_change`, effective `irreversible`) and that may not be flipped, else
    None. Deterministic: actions in sorted id order, causes in `FLIP_CAUSES` order."""
    for aid in sorted(host.actions):
        cl = host.actions[aid]
        if host_values.get(cl.class_id) == NO_CHANGE and effective.get(cl.class_id) == IRREVERSIBLE:
            causes = flip_causes(cl)
            if causes:
                return FLIP_CONFLICT + ":" + causes[0]
    return None


def compose_irreversible(base: RuntimeAuthorityProfile, effective: Mapping[str, str]) -> RuntimeAuthorityProfile:
    """The profile with `irreversible` set true for EVERY action whose class is `irreversible` in `effective`. Pure; it only ever sets true (a host true is never cleared, whatever
    `effective` says), and nothing else in the profile changes."""
    doc = base.model_dump(mode="json")
    for action in doc["actions"].values():
        if effective[action["class_id"]] == IRREVERSIBLE:
            action["irreversible"] = True
    return RuntimeAuthorityProfile.model_validate(doc)


def _registry_modules():
    base = importlib.import_module("registry_successor.decision")
    common = importlib.import_module("registry_successor.common")
    decision7 = importlib.import_module("registry_successor.v7_decision")
    identity = importlib.import_module("registry_successor.v7_policy_identity")
    verifier_cls = importlib.import_module("registry_adapters.ed25519_verifier").Ed25519Verifier
    return base, common, decision7, identity, verifier_cls


def _verified(scope: GovernedScope, institution_id: str, authority_domain: str, caller: dict, material: Any, verifier: Any, now: datetime):
    """One Registry `r08-v7` verification. Returns `((identity, decision), None)` or `(None, Refusal)`; applies the shared decision-shape checks."""
    if type(material) is not SelectionMaterial or type(material.record_text) is not str or type(material.selection_text) is not str:
        return None, Refusal("material_invalid")
    try:
        base, common, decision7, identity, verifier_cls = _registry_modules()
    except Exception:
        return None, Refusal("registry_unavailable")
    if type(verifier) is not verifier_cls:
        return None, Refusal("verifier_not_admitted")
    try:
        context = common.ExpectedContext(scope.consumer_id, scope.tenant_id, institution_id, authority_domain, scope.operation_id)
        decision = decision7.verify_and_decide_v7("required", caller, material.record_text, material.selection_text, context, material.trust, verifier, now)
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


def derive_irreversible(*, scope: GovernedScope, institution_id: str, authority_domain: str, host: RuntimeAuthorityProfile, host_values: Mapping[str, str], material: Any,
                        verifier: Any, now: datetime):
    """Pure single verification of the irreversibility selection. Returns `((effective class map, Registry policy digest), None)` or `(None, Refusal)`. Builds no workflow and
    writes nothing. The flip pre-check reads the ORIGINAL HOST profile only."""
    got, refusal = _verified(scope, institution_id, authority_domain, {FIELD_IR: dict(host_values)}, material, verifier, now)
    if refusal is not None:
        return None, refusal
    identity, decision = got
    kind, eff = decision.kind, decision.effective
    if not isinstance(eff, Mapping) or set(eff) != {FIELD_IR} or type(eff[FIELD_IR]) is not dict:
        return None, Refusal("effective_policy_invalid", None, kind)
    effective = eff[FIELD_IR]
    if set(effective) != set(host_values) or not all(_ir_value(v) for v in effective.values()):
        return None, Refusal("effective_policy_invalid", None, kind)
    if any(_RANK_IR[effective[k]] > _RANK_IR[host_values[k]] for k in host_values):
        return None, Refusal("effective_policy_widens_host", None, kind)
    registry = registry_irreversible_map(material.record_text)
    if registry is None or not set(registry) <= set(host_values) or any(effective[k] != stricter_irreversible(host_values[k], registry[k]) for k in registry):
        return None, Refusal("effective_policy_invalid", None, kind)
    if any(k not in registry and effective[k] != host_values[k] for k in host_values):
        return None, Refusal("effective_policy_invalid", None, kind)
    scoped = host.actions.get(scope.action_id)
    if scoped is None:
        return None, Refusal("action_class_unknown", None, kind)
    if scoped.class_id not in registry:
        return None, Refusal("scoped_class_not_governed", None, kind)
    conflict = flip_conflict(host, host_values, effective)
    if conflict is not None:
        return None, Refusal(conflict, None, kind)
    try:
        digest = identity.effective_policy_digest(FAMILY_IR, {FIELD_IR: dict(effective)}, CONTRACT_V7)
    except Exception:
        return None, Refusal("effective_policy_digest_unavailable", None, kind)
    return (dict(effective), digest), None
