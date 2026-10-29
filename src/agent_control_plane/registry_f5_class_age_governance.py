"""F5 per-class status age: Registry-governed `ActionClass.max_status_age_seconds` (Registry `class_status_max_age_seconds`) for one bounded-authorization scope.

BUILDER_TESTED developer implementation. NOT independently qualified. NOT an authorization mechanism: a Registry selection only NARROWS host-configured class
status-age bounds and grants nothing. `bounded.py`, `runtime_authority.py`, `freshness.py`, `policy_binding.py` and every evaluator are unchanged; this module
builds an EFFECTIVE `RuntimeAuthorityProfile` once, hands it to the existing workflow constructor, and re-validates the selection at the decision and effect
boundaries by subclassing the existing workflow (the same pattern as `registry_f4_age_governance`, which is unchanged).

Commitment binding (source-backed, Control Plane `673ef09`):
  * `approval_commitment(profile, context)` hashes `profile.model_dump()` (runtime_authority.py:236-247), and the profile contains every `ActionClass`. The
    narrowed class age therefore enters the commitment by living in the profile that is committed, BEFORE approval issuance: the issuer computes
    `approval_commitment(workflow.runtime_authority_profile, context)` on the EFFECTIVE profile. No commitment code is touched.
  * The same profile hash is `catalogue_digest` in the persisted decision binding, so a decision made under one effective profile cannot be executed under another
    (the existing `authorization-critical inputs changed before effect` refusal).
  * If the Registry value does not narrow anything (equal or higher than the host value) and no outage extension is configured, the effective profile is
    byte-identical to the host profile: every existing approval and decision remains valid. If it narrows, an approval issued against the host profile no longer
    matches (`runtime_authority_approval_mismatch`, existing code): a new approval is required. Nothing is rewritten.
  * Outage extensions (freshness/0.1) are measured from the (narrowed) class base and capped by `max_age_extension_seconds`. Left alone, a narrowed base of 30 with
    a limit of 300 can still be extended to 330, above the Registry value. DR-CP-AGE-1 decision 5 therefore composes
    `max_age_extension_seconds := min(host limit, min over Registry-governed classes of max(0, registry value - narrowed base))`, so base + extension never exceeds
    the Registry value. Extension rows recorded against the old base fail closed (`age_extension_invalid`, existing behaviour).

Scope: a workflow is bound to ONE (consumer, tenant, action) scope, exactly as the F4 consumer: tenant is the proposal's `tenant_id`, institution and authority
domain are the host MANIFEST's declared authority context for the action, the Registry `operation` is a host-fixed identifier. The scoped action's class MUST be
named by the Registry record (a record that is silent about it governs nothing here and is refused `scoped_class_not_governed`). A Registry class the host
profile does not define is refused by Registry itself (never created). Two actions sharing a class id must carry the same host age (`class_age_ambiguous`).

Lifecycle: the selection is verified (record, signature, scope, expiry, withdrawal, revocation and epoch, exactly as Registry decides) at construction, at the
start of every `decide` and `execute`, AND at the effect-commitment boundary (the destination is wrapped so that `destination.apply`, the single place `execute`
commits an effect, first re-verifies and refuses with the existing `DefinitiveDestinationRejection`). Each verification must reproduce the effective class map,
the Registry effective-policy digest and the effective-profile digest bound at construction; the profile held by the workflow is compared to that digest at each
boundary, so a later attribute edit or `model_copy` cannot widen a class bound. A withdrawn, revoked, expired, superseded or otherwise changed selection raises
`RegistryClassAgeRefused` BEFORE the existing code runs at decision/effect entry, and leaves the destination untouched at the commit gate. The host rebuilds the
workflow to adopt a different selection.

Residual limitations (not hidden): (1) the commit gate runs immediately before `destination.apply` is entered, not inside the destination's transaction (accepted
for bounded engineering only; stronger production atomicity is unqualified); (2) freshness, revocation visibility, epoch floors and rollback protection of
`selection_source` output are host custody duties (docs/registry-f4-selection-source-custody.md applies unchanged); the Control Plane has no durable ratchet;
(3) a profile that already carries `policy_binding` (approval-generation/age_ceilings) is REFUSED here: how a Registry class age feeds the generation is not
decided; (4) the F4 scalars, clock tolerance, identity and mandate ages and every other class field are NOT governed here; this workflow does not compose with
`GovernedAgeWorkflow`.
Registry is resolved lazily from the host environment (a pinned checkout, never vendored); if it is unavailable the result is a refusal.
Consolidation (shared lifecycle): the decide/execute/commit-gate lifecycle, scope check, source invocation and destination wrapping now live in
`registry_governed_lifecycle`; this module keeps its derivation, composition and refusal vocabulary unchanged. The held profile is also checked once more AFTER the selection
source and Registry have run.
"""
from __future__ import annotations

import importlib
import json
from datetime import datetime
from typing import Any, Callable, Mapping, Optional

from agent_control_plane.bounded import _now, commitment
from agent_control_plane.registry_f4_age_governance import CONTRACT
from agent_control_plane.registry_governed_lifecycle import (
    GovernedLifecycle, GovernedScope, Refusal, RegistrySelectionRefused, SelectionMaterial, SCALAR_MAX, _GatedDestination, _declared_authority, _scalar, _text,
    check_scope, check_source, construction_now, read_source, require_authority, take_destination,
)
from agent_control_plane.runtime_authority import RuntimeAuthorityProfile

FAMILY = "f5-action-class-age-bounds"
FIELD = "class_status_max_age_seconds"
REJECTION_CODE = "registry_f5_selection_invalid"


class RegistryClassAgeRefused(RegistrySelectionRefused):
    """Raised before any existing decision/effect code or state write. `.refusal` carries the closed adapter vocabulary and Registry's typed code."""

    def __init__(self, refusal: Refusal, boundary: str):
        PermissionError.__init__(self, f"registry_f5_selection_refused:{boundary}:{refusal.code}" + (f":{refusal.registry_code}" if refusal.registry_code else ""))
        self.refusal, self.boundary = refusal, boundary


def _refuse(code: str, boundary: str) -> RegistryClassAgeRefused:
    return RegistryClassAgeRefused(Refusal(code), boundary)


def host_class_ages(profile: RuntimeAuthorityProfile) -> tuple[Optional[dict], Optional[str]]:
    """`class_id -> host max_status_age_seconds` over the profile's actions, or `(None, code)`. Fail closed on a non-exact value or two ages for one class."""
    ages: dict = {}
    for cl in profile.actions.values():
        cid, age = cl.class_id, cl.max_status_age_seconds
        if type(cid) is not str or not cid or not _scalar(age):
            return None, "host_class_age_invalid"
        if cid in ages and ages[cid] != age:
            return None, "class_age_ambiguous"
        ages[cid] = age
    return ages, None


def _strict_pairs(pairs):
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate key")
    return dict(pairs)


def _reject_number(_):
    raise ValueError("non-integer number")


def registry_class_map(record_text: str) -> Optional[dict]:
    """The `class -> seconds` map of an ALREADY Registry-verified record text, or None. Used only to learn which classes the record names (the Registry
    decision exposes the composed minimum, not coverage). A second strict parse: duplicate keys, floats and constants are refused."""
    try:
        doc = json.loads(record_text, object_pairs_hook=_strict_pairs, parse_float=_reject_number, parse_constant=_reject_number)
        payload = doc["payload"]
        m = payload[FIELD] if type(payload) is dict and set(payload) == {FIELD} else None
    except Exception:
        return None
    if type(m) is not dict or not m or not all(type(k) is str and type(v) is int and 1 <= v <= SCALAR_MAX for k, v in m.items()):
        return None
    return m


def compose_profile(host: RuntimeAuthorityProfile, effective: Mapping[str, int], registry: Mapping[str, int]) -> RuntimeAuthorityProfile:
    """The effective profile: every action's class age replaced by `effective[class_id]`, and (freshness/0.1 with an outage extension only) the extension limit
    composed so that narrowed base + extension never exceeds a Registry-governed class value (DR-CP-AGE-1 decision 5). Pure; nothing else changes."""
    doc = host.model_dump(mode="json")
    for action in doc["actions"].values():
        action["max_status_age_seconds"] = effective[action["class_id"]]
    freshness = doc.get("freshness")
    if freshness and freshness.get("max_age_extension_seconds", 0) > 0:
        room = min(max(0, registry[cid] - effective[cid]) for cid in registry)
        freshness["max_age_extension_seconds"] = min(freshness["max_age_extension_seconds"], room)
    return RuntimeAuthorityProfile.model_validate(doc)


def profile_digest(profile: RuntimeAuthorityProfile) -> str:
    """The digest the existing code already records as `catalogue_digest` in the decision binding."""
    return commitment(profile.model_dump(mode="json"))


def derive_effective(*, scope: GovernedScope, institution_id: str, authority_domain: str, host: RuntimeAuthorityProfile, host_ages: Mapping[str, int],
                     material: Any, verifier: Any, now: datetime):
    """Pure single verification. Returns `((effective profile, effective class map, policy digest, profile digest), None)` or `(None, Refusal)`. Builds no workflow
    and writes nothing."""
    if type(material) is not SelectionMaterial or type(material.record_text) is not str or type(material.selection_text) is not str:
        return None, Refusal("material_invalid")
    try:
        base = importlib.import_module("registry_successor.decision")
        common = importlib.import_module("registry_successor.common")
        identity = importlib.import_module("registry_successor.v2_policy_identity")
        verifier_cls = importlib.import_module("registry_adapters.ed25519_verifier").Ed25519Verifier
    except Exception:
        return None, Refusal("registry_unavailable")
    if type(verifier) is not verifier_cls:
        return None, Refusal("verifier_not_admitted")
    try:
        context = common.ExpectedContext(scope.consumer_id, scope.tenant_id, institution_id, authority_domain, scope.operation_id)
        decision = base.verify_and_decide_v2("required", {FIELD: dict(host_ages)}, material.record_text, material.selection_text, context, material.trust,
                                             verifier, now)
    except Exception:
        return None, Refusal("registry_call_failed")
    if not isinstance(decision, base.PolicyDecision) or type(decision.kind) is not str or decision.operationally_authorized is not False:
        return None, Refusal("registry_decision_invalid")
    kind = decision.kind
    if kind in ("required_policy_unavailable", "overlay_not_applied"):
        return None, Refusal("registry_not_applied", decision.code, kind)
    if kind != "applied" or decision.deny_all is not False:
        return None, Refusal("registry_decision_invalid", None, kind)
    eff = decision.effective
    if not isinstance(eff, Mapping) or set(eff) != {FIELD} or type(eff[FIELD]) is not dict:
        return None, Refusal("effective_policy_invalid", None, kind)
    effective = eff[FIELD]
    if set(effective) != set(host_ages) or not all(_scalar(v) for v in effective.values()):
        return None, Refusal("effective_policy_invalid", None, kind)
    if any(effective[k] > host_ages[k] for k in host_ages):
        return None, Refusal("effective_policy_widens_host", None, kind)
    registry = registry_class_map(material.record_text)
    if registry is None or not set(registry) <= set(host_ages) or any(effective[k] != min(host_ages[k], registry[k]) for k in registry):
        return None, Refusal("effective_policy_invalid", None, kind)
    scoped = host.actions.get(scope.action_id)
    if scoped is None:
        return None, Refusal("action_class_unknown", None, kind)
    if scoped.class_id not in registry:
        return None, Refusal("scoped_class_not_governed", None, kind)
    try:
        digest = identity.effective_policy_digest(FAMILY, {FIELD: dict(effective)})
        profile = compose_profile(host, effective, registry)
        return (profile, dict(effective), digest, profile_digest(profile)), None
    except Exception:
        return None, Refusal("effective_policy_digest_unavailable", None, kind)



class GovernedClassAgeWorkflow(GovernedLifecycle):
    """`BoundedAuthorizationWorkflow` whose class status-age bounds come from an authenticated Registry F5 selection, re-validated at every decision and effect.

    `runtime_authority_profile` is the HOST profile (required). `self.runtime_authority_profile` is the EFFECTIVE profile: issue approvals against it."""

    _gl_rejection_code = REJECTION_CODE

    def __init__(self, *, scope: GovernedScope, selection_source: Callable[[], Any], verifier: Any, runtime_authority_profile: Any,
                 construction_time: Optional[datetime] = None, **workflow_kwargs: Any):
        check_scope(scope, _refuse)
        check_source(selection_source, _refuse)
        if runtime_authority_profile is None:
            raise _refuse("runtime_authority_profile_required", "construction")
        try:
            host = RuntimeAuthorityProfile.model_validate(runtime_authority_profile).snapshot()
        except Exception:
            raise _refuse("host_profile_invalid", "construction") from None
        if host.policy_binding is not None:
            raise _refuse("policy_binding_unsupported", "construction")
        host_ages, code = host_class_ages(host)
        if host_ages is None:
            raise _refuse(code, "construction")
        if scope.action_id not in host.actions:
            raise _refuse("action_class_unknown", "construction")
        authority = require_authority(workflow_kwargs, scope.action_id, _refuse)
        now = construction_now(construction_time, workflow_kwargs, _now, _refuse)
        material = read_source(selection_source, _refuse, "construction")
        derived, refusal = derive_effective(scope=scope, institution_id=authority[0], authority_domain=authority[1], host=host, host_ages=host_ages,
                                            material=material, verifier=verifier, now=now)
        if refusal is not None:
            raise RegistryClassAgeRefused(refusal, "construction")
        destination = take_destination(workflow_kwargs, _refuse)
        profile, effective, digest, pdigest = derived
        super().__init__(runtime_authority_profile=profile, destination=_GatedDestination(destination, self._gl_commit_gate), **workflow_kwargs)
        self._f5_scope, self._f5_source, self._f5_verifier = scope, selection_source, verifier
        self._f5_host, self._f5_host_ages, self._f5_authority = host, host_ages, authority
        self._gl_attach(scope=scope, authority=authority, bound=(dict(effective), digest, pdigest))

    _f5_commit_gate = GovernedLifecycle._gl_commit_gate

    @property
    def f5_last_commit_refusal(self) -> Optional[Refusal]:
        return self._gl_last_commit_refusal

    @f5_last_commit_refusal.setter
    def f5_last_commit_refusal(self, value: Optional[Refusal]) -> None:
        self._gl_last_commit_refusal = value

    @property
    def registry_f5_policy_identity(self) -> dict:
        effective, digest, pdigest = self._gl_bound
        return {"contract_version": CONTRACT, "family": FAMILY, "effective_policy_digest": digest, "effective": dict(effective),
                "effective_profile_digest": pdigest, "host": dict(self._f5_host_ages),
                "scope": {"consumer_id": self._f5_scope.consumer_id, "tenant_id": self._f5_scope.tenant_id, "action_id": self._f5_scope.action_id,
                          "operation_id": self._f5_scope.operation_id}}

    def _gl_error(self, refusal: Refusal, boundary: str) -> Exception:
        return RegistryClassAgeRefused(refusal, boundary)

    def _gl_held_defect(self) -> Optional[str]:
        held = self.runtime_authority_profile
        if type(held) is not RuntimeAuthorityProfile or profile_digest(held) != self._gl_bound[2]:
            return "profile_modified"
        return None

    def _gl_read_sources(self, boundary: str) -> Any:
        return read_source(self._f5_source, _refuse, boundary)

    def _gl_derive(self, materials: Any, authority: Any, now: datetime, boundary: str) -> Any:
        derived, refusal = derive_effective(scope=self._f5_scope, institution_id=authority[0], authority_domain=authority[1], host=self._f5_host,
                                            host_ages=self._f5_host_ages, material=materials, verifier=self._f5_verifier, now=now)
        if refusal is not None:
            raise RegistryClassAgeRefused(refusal, boundary)
        _, new_effective, new_digest, new_pdigest = derived
        return (dict(new_effective), new_digest, new_pdigest)
