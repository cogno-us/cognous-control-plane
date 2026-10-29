"""Registry-governed anchor deadline and observation policy: pure derivations for Registry contract `r08-v8` (the three "final" families).

BUILDER_TESTED developer implementation. NOT independently qualified. NOT an authorization mechanism and NOT a policy language. This module adds NO workflow class: the derivations are
called by the existing composed `GovernedPolicyWorkflow` (`registry_governed_policy`), which owns the lifecycle (construction, decision entry, execute entry and the pre-dispatch commit
gate), the original-host and final-composition checks and the one-effective-configuration binding. `bounded.py`, `runtime_authority.py`, `freshness.py`, `policy_binding.py`,
`rule_revision.py`, `reversibility.py`, `holder_inventory.py` and every other evaluator are unchanged. The Registry contract is `docs/r08-v8-contract.md` of the pinned Registry checkout
(never vendored); this module reads its public surface (`verify_and_decide_v8`, `effective_policy_digest`, `registered_family_version`) and re-implements none of it.

Three independent families (one contract version does NOT imply atomic selection or activation; each is optional, each is mandatory when declared):

* `f5-anchor-deadline-to-inputs-policy` (member `anchor_deadline_to_inputs`, `anchor` | `no_change`). PROFILE-BEARING: it sets `FreshnessProfile.anchor_deadline_to_inputs` False -> True
  and nothing else. It is strengthen-only: a Registry `no_change` never lowers a host True (the Registry value can never assert false), a host True is a no-op. It never invents a
  `FreshnessProfile` or a profile: a host that has none is refused `host_freshness_profile_missing` (the Registry does not enforce this; the consumer does). The existing
  `policy_binding_unsupported` refusal for profile-bearing families is NOT lifted (D-07 removed the dependence of purpose-observation anchoring on a binding). The flag is part of the
  profile dump, so the FINAL profile has another `approval_commitment` and `catalogue_digest`: approvals are issued against the final profile. The flag only makes the unchanged evaluator
  join every judged input to the dispatch deadline; the guarantee for the purpose observation depends on the D-07 correction being present in `runtime_authority.py`.
* `f5-observation-max-age-policy` (member `observation_max_age_seconds`) and `f5-observation-clock-tolerance-policy` (member `observation_clock_tolerance_seconds`). NON-PROFILE values:
  the host passes an `ObservationPolicy`, the composed workflow computes the EFFECTIVE policy (`min(host, Registry)` per declared field, the undeclared field stays the host value)
  BEFORE the underlying bounded workflow is constructed, so the effective values are what `bounded._reconcile_observation` reads, what the held-state guard watches and what the
  D-06 binding records. The family touches ONLY `ObservationPolicy.clock_tolerance_seconds`; the CONSTRUCTOR `clock_tolerance_seconds` (a different, held, NOT AUTHORIZED, non-narrowable
  value) is never read or changed here and the Registry refuses its member name. A declared observation family with no host `ObservationPolicy` is refused at construction: a policy is
  never synthesized (the hold `observation_policy_missing` still applies to workflows that declare no such family). The ORIGINAL host policy is validated first and is never repaired.

What none of this is: the Registry bounds nothing in the host. The token range 0 / 1 .. 2147483647 is a structural canonical-encoding range of the Registry families (an existing
constant), not a host bound; a host value outside it refuses the whole caller. Lowering a value can only ADD `observation_stale` / `observation_time_future` holds on reconcile.
The pre-existing extreme-tolerance OverflowError in protected `bounded.py` is a separate defect (DEF-OBS-TOL-OVERFLOW-1) and is neither introduced nor fixed here.
"""
from __future__ import annotations

import importlib
from datetime import datetime
from typing import Any, Mapping, Optional

from agent_control_plane.bounded import ObservationPolicy
from agent_control_plane.registry_governed_lifecycle import GovernedScope, Refusal, SelectionMaterial
from agent_control_plane.registry_revocation_governance import _record_payload
from agent_control_plane.runtime_authority import RuntimeAuthorityProfile

CONTRACT_V8 = "r08-v8"
FAMILY_ANCHOR = "f5-anchor-deadline-to-inputs-policy"
FIELD_ANCHOR = "anchor_deadline_to_inputs"
FAMILY_OBS_AGE = "f5-observation-max-age-policy"
FIELD_OBS_AGE = "observation_max_age_seconds"
FAMILY_OBS_TOL = "f5-observation-clock-tolerance-policy"
FIELD_OBS_TOL = "observation_clock_tolerance_seconds"
FAMILY_SCHEMA_REVISION = 1
ANCHOR, NO_CHANGE = "anchor", "no_change"
_RANK_ANCHOR = {ANCHOR: 0, NO_CHANGE: 1}  # stricter first
TOKEN_MAX = 2147483647  # the Registry structural token range (common.MAX_INT), NOT a host bound
OBS_ATTRS = ("max_age_seconds", "clock_tolerance_seconds")  # the two ObservationPolicy fields, in the D-06 member order
_OBS_ROWS = {  # family -> (ObservationPolicy attribute, lowest admitted value). The constructor `clock_tolerance_seconds` is deliberately NOT here.
    FAMILY_OBS_AGE: ("max_age_seconds", 1),
    FAMILY_OBS_TOL: ("clock_tolerance_seconds", 0),
}
_MEMBER = {FAMILY_ANCHOR: FIELD_ANCHOR, FAMILY_OBS_AGE: FIELD_OBS_AGE, FAMILY_OBS_TOL: FIELD_OBS_TOL}
HOST_FRESHNESS_MISSING = "host_freshness_profile_missing"
HOST_OBS_MISSING = "host_observation_policy_missing"
HOST_OBS_INVALID = "host_observation_policy_invalid"


def _anchor_value(v: Any) -> bool:
    return type(v) is str and v in _RANK_ANCHOR


def stricter_anchor(a: str, b: str) -> str:
    return a if _RANK_ANCHOR[a] <= _RANK_ANCHOR[b] else b


def _int_in(v: Any, lo: int) -> bool:
    return type(v) is int and lo <= v <= TOKEN_MAX


# ------------------------------------------------------------------------------------------------------------------------------------- host preconditions
def host_anchor_value(profile: Any) -> tuple[Optional[str], Optional[str]]:
    """`(anchor|no_change, None)` from the HOST profile, or `(None, code)`. The host profile must already EXIST and already carry a `FreshnessProfile`; neither is ever created."""
    if type(profile) is not RuntimeAuthorityProfile:
        return None, "runtime_authority_profile_required"
    freshness = profile.freshness
    if freshness is None:
        return None, HOST_FRESHNESS_MISSING
    flag = freshness.anchor_deadline_to_inputs
    if type(flag) is not bool:
        return None, "host_anchor_invalid"
    return (ANCHOR if flag else NO_CHANGE), None


def host_observation_values(policy: Any) -> tuple[Optional[dict], Optional[str]]:
    """`({max_age_seconds, clock_tolerance_seconds}, None)` from the ORIGINAL host `ObservationPolicy`, or `(None, code)`. A missing policy is never synthesized; a policy that is not an
    exact `ObservationPolicy`, has a non-`int` (bool, float, str, subclass) value, `max_age < 1`, `tolerance < 0` or a value above the Registry token range is refused and never repaired
    (this reads the live attributes, so a `model_construct` object or an assigned 0 is caught)."""
    if policy is None:
        return None, HOST_OBS_MISSING
    if type(policy) is not ObservationPolicy:
        return None, HOST_OBS_INVALID
    try:
        values = {"max_age_seconds": policy.max_age_seconds, "clock_tolerance_seconds": policy.clock_tolerance_seconds}
    except Exception:
        return None, HOST_OBS_INVALID
    if not _int_in(values["max_age_seconds"], 1) or not _int_in(values["clock_tolerance_seconds"], 0):
        return None, HOST_OBS_INVALID
    return values, None


# ------------------------------------------------------------------------------------------------------------------------------------- composition and final validation
def compose_anchor(base: RuntimeAuthorityProfile, effective: Mapping[str, str]) -> RuntimeAuthorityProfile:
    """The profile with `FreshnessProfile.anchor_deadline_to_inputs` set True when `effective` is `anchor`. Pure; it only ever sets True (a host True is never cleared, whatever `effective`
    says), it requires the `FreshnessProfile` to exist (never invents one) and nothing else in the profile changes."""
    doc = base.model_dump(mode="json")
    if effective[FIELD_ANCHOR] == ANCHOR:
        freshness = doc.get("freshness")
        if freshness is None:
            raise ValueError(HOST_FRESHNESS_MISSING)
        freshness["anchor_deadline_to_inputs"] = True
    return RuntimeAuthorityProfile.model_validate(doc)


def effective_observation_values(host_values: Mapping[str, int], bound: Mapping[str, Any]) -> dict:
    """The effective `{max_age_seconds, clock_tolerance_seconds}`: the bound Registry-narrowed value of each DECLARED family, the host value of the other."""
    out = dict(host_values)
    for family, (attr, _) in _OBS_ROWS.items():
        slot = bound.get(_SLOT[family])
        if slot is not None:
            out[attr] = slot[0][_MEMBER[family]]
    return out


def observation_defect(host: Mapping[str, Any], final: Mapping[str, Any], *, age_declared: bool, tolerance_declared: bool) -> Optional[str]:
    """Final-composition check of the effective observation values against the ORIGINAL host values: exact ints inside the structural range, no value above the host value, and only
    the DECLARED fields may differ (anything else is a foreign change)."""
    if set(final) != set(OBS_ATTRS) or set(host) != set(OBS_ATTRS):
        return "composed_observation_invalid"
    if not _int_in(final["max_age_seconds"], 1) or not _int_in(final["clock_tolerance_seconds"], 0):
        return "composed_observation_invalid"
    declared = {"max_age_seconds": age_declared, "clock_tolerance_seconds": tolerance_declared}
    for attr in OBS_ATTRS:
        if final[attr] > host[attr]:
            return "composed_widens_host"
        if not declared[attr] and final[attr] != host[attr]:
            return "composed_observation_invalid"
    return None


# slot names live in registry_effective_policy.FAMILY_TABLE; the pairing is fixed here so this module needs no import of the composed workflow
SLOT_ANCHOR, SLOT_OBS_AGE, SLOT_OBS_TOL = "anchor_deadline", "observation_max_age", "observation_clock_tolerance"
_SLOT = {FAMILY_ANCHOR: SLOT_ANCHOR, FAMILY_OBS_AGE: SLOT_OBS_AGE, FAMILY_OBS_TOL: SLOT_OBS_TOL}


# ------------------------------------------------------------------------------------------------------------------------------------- Registry verification
def _registry_modules():
    base = importlib.import_module("registry_successor.decision")
    common = importlib.import_module("registry_successor.common")
    decision8 = importlib.import_module("registry_successor.v8_decision")
    identity = importlib.import_module("registry_successor.v8_policy_identity")
    verifier_cls = importlib.import_module("registry_adapters.ed25519_verifier").Ed25519Verifier
    return base, common, decision8, identity, verifier_cls


def _verified(scope: GovernedScope, institution_id: str, authority_domain: str, caller: dict, material: Any, verifier: Any, now: datetime):
    """One Registry `r08-v8` verification. Returns `((identity, decision), None)` or `(None, Refusal)`; applies the shared decision-shape checks."""
    if type(material) is not SelectionMaterial or type(material.record_text) is not str or type(material.selection_text) is not str:
        return None, Refusal("material_invalid")
    try:
        base, common, decision8, identity, verifier_cls = _registry_modules()
    except Exception:
        return None, Refusal("registry_unavailable")
    if type(verifier) is not verifier_cls:
        return None, Refusal("verifier_not_admitted")
    try:
        context = common.ExpectedContext(scope.consumer_id, scope.tenant_id, institution_id, authority_domain, scope.operation_id)
        decision = decision8.verify_and_decide_v8("required", caller, material.record_text, material.selection_text, context, material.trust, verifier, now)
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


def _digest(identity: Any, family: str, effective: Mapping[str, Any], kind: str):
    """`(digest, None)` of the EFFECTIVE payload under `r08-v8`, family schema revision 1 (the revision is the Registry's own table value, never a local constant), or `(None, Refusal)`."""
    try:
        if identity.registered_family_version(family, CONTRACT_V8) != FAMILY_SCHEMA_REVISION:
            return None, Refusal("effective_policy_digest_unavailable", None, kind)
        return identity.effective_policy_digest(family, dict(effective), CONTRACT_V8), None
    except Exception:
        return None, Refusal("effective_policy_digest_unavailable", None, kind)


def derive_anchor(*, scope: GovernedScope, institution_id: str, authority_domain: str, host: Any, material: Any, verifier: Any, now: datetime):
    """Pure single verification of the anchor-deadline selection. Returns `(({member: anchor|no_change}, Registry policy digest), None)` or `(None, Refusal)`. Builds no workflow and
    writes nothing. The host precondition (a profile with a `FreshnessProfile`) is re-checked here, on the ORIGINAL host profile."""
    host_value, code = host_anchor_value(host)
    if host_value is None:
        return None, Refusal(code)
    got, refusal = _verified(scope, institution_id, authority_domain, {FIELD_ANCHOR: host_value}, material, verifier, now)
    if refusal is not None:
        return None, refusal
    identity, decision = got
    kind, eff = decision.kind, decision.effective
    if not isinstance(eff, Mapping) or set(eff) != {FIELD_ANCHOR} or not _anchor_value(eff[FIELD_ANCHOR]):
        return None, Refusal("effective_policy_invalid", None, kind)
    effective = eff[FIELD_ANCHOR]
    if _RANK_ANCHOR[effective] > _RANK_ANCHOR[host_value]:
        return None, Refusal("effective_policy_widens_host", None, kind)
    registry = _record_payload(material.record_text, FIELD_ANCHOR)
    if not _anchor_value(registry) or effective != stricter_anchor(host_value, registry):
        return None, Refusal("effective_policy_invalid", None, kind)
    digest, refusal = _digest(identity, FAMILY_ANCHOR, {FIELD_ANCHOR: effective}, kind)
    if refusal is not None:
        return None, refusal
    return ({FIELD_ANCHOR: effective}, digest), None


def derive_observation(*, family: str, scope: GovernedScope, institution_id: str, authority_domain: str, host_value: Any, material: Any, verifier: Any, now: datetime):
    """Pure single verification of ONE observation selection (`family` is `FAMILY_OBS_AGE` or `FAMILY_OBS_TOL`). `host_value` is the ORIGINAL host value of exactly that field. Returns
    `(({member: int}, Registry policy digest), None)` or `(None, Refusal)`. Builds no workflow and writes nothing."""
    row = _OBS_ROWS.get(family)
    if row is None:
        return None, Refusal("family_unknown")
    member, lowest = _MEMBER[family], row[1]
    if not _int_in(host_value, lowest):
        return None, Refusal(HOST_OBS_INVALID)
    got, refusal = _verified(scope, institution_id, authority_domain, {member: host_value}, material, verifier, now)
    if refusal is not None:
        return None, refusal
    identity, decision = got
    kind, eff = decision.kind, decision.effective
    if not isinstance(eff, Mapping) or set(eff) != {member} or not _int_in(eff[member], lowest):
        return None, Refusal("effective_policy_invalid", None, kind)
    effective = eff[member]
    if effective > host_value:
        return None, Refusal("effective_policy_widens_host", None, kind)
    registry = _record_payload(material.record_text, member)
    if not _int_in(registry, lowest) or effective != min(host_value, registry):
        return None, Refusal("effective_policy_invalid", None, kind)
    digest, refusal = _digest(identity, family, {member: effective}, kind)
    if refusal is not None:
        return None, refusal
    return ({member: effective}, digest), None
