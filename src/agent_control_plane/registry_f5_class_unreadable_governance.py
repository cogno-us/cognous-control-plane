"""F5 per-class `on_unreadable`: Registry-governed `ActionClass.on_unreadable` (Registry `r08-v5` family `f5-action-class-unreadable-policy`, field `class_on_unreadable`) for one
bounded-authorization scope, OPTIONALLY together with the Registry-governed class status age (`registry_f5_class_age_governance`).

BUILDER_TESTED developer implementation. NOT independently qualified. NOT an authorization mechanism: a Registry selection only NARROWS a host-configured class value
(`bounded_tolerance` -> `refuse`) and grants nothing. `bounded.py`, `runtime_authority.py`, `freshness.py`, `policy_binding.py`, `rule_revision.py` and every evaluator are
unchanged, and so are `registry_f4_age_governance` and `registry_f5_class_age_governance`. This module builds ONE effective `RuntimeAuthorityProfile`, hands it to the existing
workflow constructor, and re-validates every governing selection at the decision and effect boundaries by subclassing the existing workflow (the M12 pattern).

Source-backed behaviour (Control Plane `5f11e0f`):
  * `ActionClass.on_unreadable` is `Literal["refuse", "bounded_tolerance"]` (runtime_authority.py:132). Exactly two branches read it:
      - `bounded.py:2111`: an IRREVERSIBLE class whose value is not `refuse` is `action_class_invalid` (every check of that class refuses);
      - `bounded.py:2189` (`_read_grant`): ONLY for a class that is not effectively irreversible AND is `bounded_tolerance`, an unreadable grant status may be replaced
        by a trusted cached positive. `refuse` never does. So `refuse` is never more permissive than `bounded_tolerance` on this branch, and the two-point order
        `refuse` < `bounded_tolerance` is the only relation used.
    The cached-PURPOSE-snapshot path (reversibility/0.1, `_cached_purpose`) does not read the value: a Registry `refuse` does not disable it (documented limit).
  * `approval_commitment(profile, context)` hashes `profile.model_dump()` and the profile contains every `ActionClass` (runtime_authority.py:236-247), so the narrowed value
    enters the commitment by living in the profile that is committed, BEFORE approval issuance: the issuer computes `approval_commitment(workflow.runtime_authority_profile,
    context)` on the EFFECTIVE profile. No commitment code is touched. The same profile hash is `catalogue_digest` in the persisted decision binding.
  * A value that does not narrow anything (Registry `bounded_tolerance`, or the host already `refuse`) leaves the profile byte-identical: existing approvals and decisions
    remain valid. A narrowing changes the commitment: an approval issued for the host profile holds (`runtime_authority_approval_mismatch`) and a new approval is required.

Host validity first, no healing. A host class that is irreversible AND `bounded_tolerance` is an INVALID host configuration (`bounded.py:2111`: every action of the class
refuses). The ORIGINAL host profile is validated against that invariant BEFORE any Registry call (`host_class_defect`, construction refusal `host_class_invalid`): the Registry may
only reduce permissions in an already admissible host profile; it must not repair an invalid authority declaration or conceal a host defect (the unmodified workflow still holds
such a class with `action_class_invalid`). `registry_would_heal_invalid_class` remains inside `derive_unreadable` as defence in depth for direct callers.

Composition with the class status age: the two Registry families are independent activations. They are combined ONLY by explicit configuration: pass `class_age_scope` and
`class_age_selection_source` together. Then BOTH selections are verified at every boundary, the age component is derived by the unchanged `registry_f5_class_age_governance.
derive_effective`, the on_unreadable value is composed over the age-effective profile (one field of each action class; nothing else), and the bound identity is the TUPLE
(age effective map + Registry age digest + age profile digest, on_unreadable effective map + Registry digest, FINAL effective profile digest). Any change of any member refuses
(`selection_changed`); either source failing or being withdrawn refuses; neither can be activated, replaced or revoked independently without the workflow refusing. There is no
fallback to either family alone. Without the age pair the workflow is unreadable-only and the age field is untouched.

Scope: ONE (consumer, tenant, action) scope per workflow, as the F4/F5 consumers: tenant is the proposal's `tenant_id`, institution and authority domain are the host MANIFEST's
declared authority context for the action, the Registry `operation` is a host-fixed identifier. The age scope must carry the same consumer, tenant and action (its Registry
operation id may differ). The scoped action's class MUST be named by each record (`scoped_class_not_governed`). A Registry class the host profile does not define is refused by
Registry itself (never created). Two actions sharing a class id must carry the same host value (`class_unreadable_ambiguous`). A profile with `policy_binding` is refused.

Lifecycle: every governing selection is verified (record, signature, scope, expiry, withdrawal, revocation and epoch, exactly as Registry decides) at construction, at the start of
every `decide` and `execute`, AND at the effect-commitment boundary (the destination is wrapped so that `destination.apply`, the single place `execute` commits an effect, first
re-verifies and refuses with the existing `DefinitiveDestinationRejection`). Each verification must reproduce the bound identity, and the profile held by the workflow is compared to
the bound digest at each boundary, so a later attribute edit or `model_copy` cannot widen a class value. A refusal before the commit gate raises `RegistryClassUnreadableRefused`
(a `PermissionError`) before any state write; at the gate the destination is not called and the attempt is recorded `failed`, which blocks automatic retry.
The host rebuilds the workflow to adopt a different selection.

Residual limitations (not hidden): (1) the commit gate runs immediately before `destination.apply` is entered, not inside the destination's transaction (accepted for bounded
engineering only; stronger production atomicity is unqualified); (2) freshness, revocation visibility, epoch floors and rollback protection of the selection sources are host custody
duties (docs/registry-f4-selection-source-custody.md applies unchanged); the Control Plane has no durable ratchet; (3) a profile that already carries `policy_binding` is REFUSED;
(4) the F4 scalars, clock tolerance, identity and mandate ages, `requires_revocation_assurance`, reversibility, `anchor_deadline_to_inputs`, terminal revocation and observation
policy are NOT governed here; (5) the value governs only the cached-grant branch (see above).
Registry is resolved lazily from the host environment (a pinned checkout, never vendored); if it is unavailable the result is a refusal.

Consolidation (shared lifecycle): the decide/execute/commit-gate lifecycle, scope check, source invocation and destination wrapping now live in
`registry_governed_lifecycle`; this module keeps its derivation, composition and refusal vocabulary unchanged.
"""
from __future__ import annotations

import importlib
import json
from datetime import datetime
from typing import Any, Callable, Mapping, Optional

from agent_control_plane.bounded import _now
from agent_control_plane.registry_governed_lifecycle import (
    GovernedLifecycle, GovernedScope, Refusal, RegistrySelectionRefused, SelectionMaterial, _GatedDestination, _declared_authority, _text,
    check_scope, check_source, construction_now, read_source, require_authority, take_destination, valid_scope,
)
from agent_control_plane.registry_f5_class_age_governance import derive_effective as derive_class_age, host_class_ages, profile_digest
from agent_control_plane.runtime_authority import RuntimeAuthorityProfile

CONTRACT_V5 = "r08-v5"
FAMILY = "f5-action-class-unreadable-policy"
FIELD = "class_on_unreadable"
VALUES = ("refuse", "bounded_tolerance")  # ActionClass.on_unreadable, strictest first
_RANK = {"refuse": 0, "bounded_tolerance": 1}
REJECTION_CODE = "registry_f5_unreadable_selection_invalid"


class RegistryClassUnreadableRefused(RegistrySelectionRefused):
    """Raised before any existing decision/effect code or state write. `.refusal` carries the closed adapter vocabulary and Registry's typed code."""

    def __init__(self, refusal: Refusal, boundary: str):
        PermissionError.__init__(self, f"registry_f5_unreadable_selection_refused:{boundary}:{refusal.code}" + (f":{refusal.registry_code}" if refusal.registry_code else ""))
        self.refusal, self.boundary = refusal, boundary


def _refuse(code: str, boundary: str) -> RegistryClassUnreadableRefused:
    return RegistryClassUnreadableRefused(Refusal(code), boundary)


def _value(v: Any) -> bool:
    return type(v) is str and v in _RANK


def stricter(a: str, b: str) -> str:
    return a if _RANK[a] <= _RANK[b] else b


def host_class_unreadable(profile: RuntimeAuthorityProfile) -> tuple[Optional[dict], Optional[str]]:
    """`class_id -> host on_unreadable` over the profile's actions, or `(None, code)`. Fail closed on a non-exact value or two values for one class."""
    values: dict = {}
    for cl in profile.actions.values():
        cid, val = cl.class_id, cl.on_unreadable
        if type(cid) is not str or not cid or not _value(val):
            return None, "host_class_unreadable_invalid"
        if cid in values and values[cid] != val:
            return None, "class_unreadable_ambiguous"
        values[cid] = val
    return values, None


def host_class_defect(profile: RuntimeAuthorityProfile) -> Optional[str]:
    """The ORIGINAL host profile's validity under the existing evaluator invariant (bounded.py:2111): an irreversible class whose `on_unreadable` is not `refuse` is
    `action_class_invalid` for every action of the class. Checked BEFORE any Registry call so a Registry narrowing can never repair, and so conceal, a host defect."""
    if any(cl.irreversible and cl.on_unreadable != "refuse" for cl in profile.actions.values()):
        return "host_class_invalid"
    return None


def _strict_pairs(pairs):
    keys = [k for k, _ in pairs]
    if len(set(keys)) != len(keys):
        raise ValueError("duplicate key")
    return dict(pairs)


def _reject_number(_):
    raise ValueError("non-string number")


def registry_unreadable_map(record_text: str) -> Optional[dict]:
    """The `class -> value` map of an ALREADY Registry-verified record text, or None. Used only to learn which classes the record names (the Registry decision exposes the composed
    minimum, not coverage). A second strict parse: duplicate keys, floats and constants are refused (integers elsewhere in the record are legitimate; payload values must be closed-vocabulary strings), values must be in the closed vocabulary."""
    try:
        doc = json.loads(record_text, object_pairs_hook=_strict_pairs, parse_float=_reject_number, parse_constant=_reject_number)
        payload = doc["payload"]
        m = payload[FIELD] if type(payload) is dict and set(payload) == {FIELD} else None
    except Exception:
        return None
    if type(m) is not dict or not m or not all(type(k) is str and _value(v) for k, v in m.items()):
        return None
    return m


def compose_unreadable(base: RuntimeAuthorityProfile, effective: Mapping[str, str]) -> RuntimeAuthorityProfile:
    """The profile with every action's `on_unreadable` replaced by `effective[class_id]`. Pure; no other field of any class, and nothing else in the profile, changes."""
    doc = base.model_dump(mode="json")
    for action in doc["actions"].values():
        action["on_unreadable"] = effective[action["class_id"]]
    return RuntimeAuthorityProfile.model_validate(doc)


def derive_unreadable(*, scope: GovernedScope, institution_id: str, authority_domain: str, host: RuntimeAuthorityProfile, host_values: Mapping[str, str], material: Any,
                      verifier: Any, now: datetime):
    """Pure single verification of the on_unreadable selection. Returns `((effective class map, Registry policy digest), None)` or `(None, Refusal)`. Builds no workflow and
    writes nothing."""
    if type(material) is not SelectionMaterial or type(material.record_text) is not str or type(material.selection_text) is not str:
        return None, Refusal("material_invalid")
    try:
        base = importlib.import_module("registry_successor.decision")
        common = importlib.import_module("registry_successor.common")
        v5_decision = importlib.import_module("registry_successor.v5_decision")
        identity = importlib.import_module("registry_successor.v5_policy_identity")
        verifier_cls = importlib.import_module("registry_adapters.ed25519_verifier").Ed25519Verifier
    except Exception:
        return None, Refusal("registry_unavailable")
    if type(verifier) is not verifier_cls:
        return None, Refusal("verifier_not_admitted")
    try:
        context = common.ExpectedContext(scope.consumer_id, scope.tenant_id, institution_id, authority_domain, scope.operation_id)
        decision = v5_decision.verify_and_decide_v5("required", {FIELD: dict(host_values)}, material.record_text, material.selection_text, context, material.trust, verifier, now)
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
    if set(effective) != set(host_values) or not all(_value(v) for v in effective.values()):
        return None, Refusal("effective_policy_invalid", None, kind)
    if any(_RANK[effective[k]] > _RANK[host_values[k]] for k in host_values):
        return None, Refusal("effective_policy_widens_host", None, kind)
    registry = registry_unreadable_map(material.record_text)
    if registry is None or not set(registry) <= set(host_values) or any(effective[k] != stricter(host_values[k], registry[k]) for k in registry):
        return None, Refusal("effective_policy_invalid", None, kind)
    if any(k not in registry and effective[k] != host_values[k] for k in host_values):
        return None, Refusal("effective_policy_invalid", None, kind)
    scoped = host.actions.get(scope.action_id)
    if scoped is None:
        return None, Refusal("action_class_unknown", None, kind)
    if scoped.class_id not in registry:
        return None, Refusal("scoped_class_not_governed", None, kind)
    # Defence in depth (the constructor already refuses an invalid host via host_class_defect before any Registry call): an invalid host class must never become valid through a "narrowing".
    if any(cl.irreversible and effective[cl.class_id] != cl.on_unreadable for cl in host.actions.values()):
        return None, Refusal("registry_would_heal_invalid_class", None, kind)
    try:
        digest = identity.effective_policy_digest(FAMILY, {FIELD: dict(effective)})
    except Exception:
        return None, Refusal("effective_policy_digest_unavailable", None, kind)
    return (dict(effective), digest), None


def derive_governed(*, scope: GovernedScope, age_scope: Optional[GovernedScope], institution_id: str, authority_domain: str, host: RuntimeAuthorityProfile,
                    host_values: Mapping[str, str], host_ages: Optional[Mapping[str, int]], unreadable_material: Any, age_material: Any, verifier: Any, now: datetime):
    """Pure verification of every governing selection and composition of the ONE effective profile. Returns
    `((profile, unreadable effective map, Registry unreadable digest, age part or None), None)` where the age part is `(age effective map, Registry age digest, age-profile digest)`,
    or `(None, Refusal)`. The age component (when configured) is derived by the unchanged M12 function; the unreadable value is composed over its profile."""
    base = host
    age_part = None
    if age_scope is not None:
        derived, refusal = derive_class_age(scope=age_scope, institution_id=institution_id, authority_domain=authority_domain, host=host, host_ages=host_ages,
                                            material=age_material, verifier=verifier, now=now)
        if refusal is not None:
            return None, Refusal("class_age:" + refusal.code, refusal.registry_code, refusal.registry_kind)
        base, age_effective, age_digest, age_pdigest = derived
        age_part = (age_effective, age_digest, age_pdigest)
    derived_u, refusal = derive_unreadable(scope=scope, institution_id=institution_id, authority_domain=authority_domain, host=host, host_values=host_values,
                                           material=unreadable_material, verifier=verifier, now=now)
    if refusal is not None:
        return None, refusal
    effective, digest = derived_u
    try:
        profile = compose_unreadable(base, effective)
    except Exception:
        return None, Refusal("effective_profile_invalid")
    return (profile, effective, digest, age_part), None


class GovernedClassUnreadableWorkflow(GovernedLifecycle):
    """`BoundedAuthorizationWorkflow` whose class `on_unreadable` values come from an authenticated Registry `r08-v5` selection (optionally together with the Registry class status
    age), re-validated at every decision and effect.

    `runtime_authority_profile` is the HOST profile (required). `self.runtime_authority_profile` is the EFFECTIVE profile: issue approvals against it."""

    _gl_rejection_code = REJECTION_CODE

    def __init__(self, *, scope: GovernedScope, selection_source: Callable[[], Any], verifier: Any, runtime_authority_profile: Any,
                 class_age_scope: Optional[GovernedScope] = None, class_age_selection_source: Optional[Callable[[], Any]] = None,
                 construction_time: Optional[datetime] = None, **workflow_kwargs: Any):
        check_scope(scope, _refuse)
        check_source(selection_source, _refuse)
        if (class_age_scope is None) != (class_age_selection_source is None):
            raise _refuse("class_age_configuration_invalid", "construction")
        if class_age_scope is not None:
            if not valid_scope(class_age_scope) or not callable(class_age_selection_source):
                raise _refuse("class_age_configuration_invalid", "construction")
            if (class_age_scope.consumer_id, class_age_scope.tenant_id, class_age_scope.action_id) != (scope.consumer_id, scope.tenant_id, scope.action_id):
                raise _refuse("class_age_scope_mismatch", "construction")
        if runtime_authority_profile is None:
            raise _refuse("runtime_authority_profile_required", "construction")
        try:
            host = RuntimeAuthorityProfile.model_validate(runtime_authority_profile).snapshot()
        except Exception:
            raise _refuse("host_profile_invalid", "construction") from None
        if host.policy_binding is not None:
            raise _refuse("policy_binding_unsupported", "construction")
        host_values, code = host_class_unreadable(host)
        if host_values is None:
            raise _refuse(code, "construction")
        defect = host_class_defect(host)  # host validity FIRST: before any Registry call or source read
        if defect is not None:
            raise _refuse(defect, "construction")
        host_ages = None
        if class_age_scope is not None:
            host_ages, code = host_class_ages(host)
            if host_ages is None:
                raise _refuse(code, "construction")
        if scope.action_id not in host.actions:
            raise _refuse("action_class_unknown", "construction")
        authority = require_authority(workflow_kwargs, scope.action_id, _refuse)
        now = construction_now(construction_time, workflow_kwargs, _now, _refuse)
        material = read_source(selection_source, _refuse, "construction")
        age_material = None
        if class_age_scope is not None:
            age_material = read_source(class_age_selection_source, _refuse, "construction")
        derived, refusal = derive_governed(scope=scope, age_scope=class_age_scope, institution_id=authority[0], authority_domain=authority[1], host=host, host_values=host_values,
                                           host_ages=host_ages, unreadable_material=material, age_material=age_material, verifier=verifier, now=now)
        if refusal is not None:
            raise RegistryClassUnreadableRefused(refusal, "construction")
        destination = take_destination(workflow_kwargs, _refuse)
        profile, effective, digest, age_part = derived
        super().__init__(runtime_authority_profile=profile, destination=_GatedDestination(destination, self._gl_commit_gate), **workflow_kwargs)
        self._fu_scope, self._fu_age_scope = scope, class_age_scope
        self._fu_source, self._fu_age_source, self._fu_verifier = selection_source, class_age_selection_source, verifier
        self._fu_host, self._fu_host_values, self._fu_host_ages, self._fu_authority = host, host_values, host_ages, authority
        self._gl_attach(scope=scope, authority=authority, bound=(dict(effective), digest, age_part, profile_digest(profile)))

    _fu_commit_gate = GovernedLifecycle._gl_commit_gate

    @property
    def fu_last_commit_refusal(self) -> Optional[Refusal]:
        return self._gl_last_commit_refusal

    @fu_last_commit_refusal.setter
    def fu_last_commit_refusal(self, value: Optional[Refusal]) -> None:
        self._gl_last_commit_refusal = value

    @property
    def registry_f5_unreadable_policy_identity(self) -> dict:
        effective, digest, age_part, pdigest = self._gl_bound
        scope = self._fu_scope
        identity = {"contract_version": CONTRACT_V5, "family": FAMILY, "effective_policy_digest": digest, "effective": dict(effective),
                    "effective_profile_digest": pdigest, "host": dict(self._fu_host_values),
                    "scope": {"consumer_id": scope.consumer_id, "tenant_id": scope.tenant_id, "action_id": scope.action_id, "operation_id": scope.operation_id},
                    "class_age": None}
        if age_part is not None:
            age_effective, age_digest, age_pdigest = age_part
            identity["class_age"] = {"effective": dict(age_effective), "effective_policy_digest": age_digest, "effective_profile_digest": age_pdigest,
                                     "host": dict(self._fu_host_ages), "operation_id": self._fu_age_scope.operation_id}
        return identity

    def _gl_error(self, refusal: Refusal, boundary: str) -> Exception:
        return RegistryClassUnreadableRefused(refusal, boundary)

    def _gl_held_defect(self) -> Optional[str]:
        held = self.runtime_authority_profile
        if type(held) is not RuntimeAuthorityProfile or profile_digest(held) != self._gl_bound[3]:
            return "profile_modified"
        return None

    def _gl_read_sources(self, boundary: str) -> Any:
        material = read_source(self._fu_source, _refuse, boundary)
        age_material = None
        if self._fu_age_scope is not None:
            age_material = read_source(self._fu_age_source, _refuse, boundary)
        return (material, age_material)

    def _gl_derive(self, materials: Any, authority: Any, now: datetime, boundary: str) -> Any:
        material, age_material = materials
        derived, refusal = derive_governed(scope=self._fu_scope, age_scope=self._fu_age_scope, institution_id=authority[0], authority_domain=authority[1], host=self._fu_host,
                                           host_values=self._fu_host_values, host_ages=self._fu_host_ages, unreadable_material=material, age_material=age_material,
                                           verifier=self._fu_verifier, now=now)
        if refusal is not None:
            raise RegistryClassUnreadableRefused(refusal, boundary)
        new_profile, new_effective, new_digest, new_age = derived
        return (dict(new_effective), new_digest, new_age, profile_digest(new_profile))
