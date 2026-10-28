"""F4 ages-only: Registry-governed `status_max_age_seconds` and `approval_max_age_seconds` for one bounded-authorization workflow scope.

BUILDER_TESTED developer implementation. NOT independently qualified. NOT an authorization mechanism: a Registry selection only NARROWS two host-configured
freshness bounds and grants nothing. `bounded.py` and its evaluators are unchanged (`_fresh` and every refusal reason are the existing ones); this module
chooses the two scalars and re-validates the selection at the decision and effect boundaries by subclassing the existing workflow.

Source-backed behaviour (Control Plane `bounded.py` at `d66ae07`):
  * `status_max_age_seconds` is read by the existing checks for grant status (non-profile path), conflict status and policy status;
    `approval_max_age_seconds` by the approval check. Both are instance attributes read inside `_resolve`, which only `decide` and `execute` call.
  * With a `runtime_authority_profile` the grant-status bound comes from the action class (F5, a different family and a different wave), so Registry F4
    would silently not govern it; a governed workflow therefore REFUSES a `runtime_authority_profile`.
  * Scope is not caller-supplied: tenant is the proposal's `tenant_id` (a `TenantRuntimeProposal` is required), the action is the `action_id` and the Registry
    `operation` is a host-fixed identifier mapped to it (source finding: Registry requires `operation` to match `[a-z0-9][a-z0-9._-]{2,63}`, which a URN action id does not),
    institution and authority domain are the host MANIFEST's declared authority context for that action, and the consumer id is host configuration.
    A workflow is bound to ONE (consumer, tenant, action) scope; any other proposal is refused before any Registry call.

Lifecycle: the selection is verified (record, signature, scope, expiry, withdrawal, revocation and epoch, exactly as Registry decides) at construction,
at the start of every `decide` and `execute`, AND once more at the effect-commitment boundary: the supplied destination is wrapped so that
`destination.apply` (the single place `execute` commits an effect, called after authorization re-resolution, observation/reconciliation and the
"attempted" record) first re-verifies the selection and refuses with the existing `DefinitiveDestinationRejection` (a trusted assertion that nothing was
dispatched) if it is no longer valid. Each verification must reproduce the effective values and the Registry effective-policy digest bound at
construction; a withdrawn, revoked, expired, superseded, widened or otherwise changed selection raises `RegistrySelectionRefused` BEFORE the existing
code runs at the decision and effect-entry boundaries (nothing is written), and at the commit gate leaves the destination untouched and the attempt
`failed` with error `registry_f4_selection_invalid` (the existing evidence for a definitive rejection; like any failed attempt it blocks an automatic retry
of the same effect). The host must rebuild the workflow to adopt a different selection. Participation is always `required`. The two scalars are compared to
the bound values at each boundary, so a later attribute edit cannot widen them.

Residual limitations (not hidden): (1) the commit gate runs immediately before `destination.apply` is entered, but not inside the destination's own
transaction; a revocation landing in that interval (the delegated call itself) is not seen, and the Control Plane has no hook inside a destination
transaction; (2) freshness, revocation visibility, epoch floors and rollback protection of `selection_source` output are host custody duties
(docs/registry-f4-selection-source-custody.md); the Control Plane has no durable ratchet; (3) the clock tolerance (RG-C-006), identity and mandate ages
and the F5 class bound are NOT governed here.
Registry is resolved lazily from the host environment (a pinned checkout, never vendored); if it is unavailable the result is a refusal.

Consolidation (shared lifecycle): the scope/material/refusal types, the gated destination and the decide/execute/commit-gate lifecycle now live in
`registry_governed_lifecycle` (re-exported here, so every import path and observable behaviour is unchanged). The held-state check (here: the two scalars) is also made
once more AFTER the selection source and Registry have run, immediately before the caller's next step.
"""
from __future__ import annotations

import importlib
from datetime import datetime
from typing import Any, Callable, Mapping, Optional

from agent_control_plane.bounded import BoundedAuthorizationWorkflow, _now
from agent_control_plane.registry_governed_lifecycle import (  # noqa: F401  (re-exported: existing import paths are unchanged)
    CLASSIFICATION, SCALAR_MAX, GovernedLifecycle, GovernedScope, Refusal, RegistrySelectionRefused, SelectionMaterial, _GatedDestination, _declared_authority,
    _scalar, _text, check_scope, check_source, construction_now, read_source, require_authority, take_destination,
)

AGES = ("status_max_age_seconds", "approval_max_age_seconds")
CONTRACT = "r08-v2"
REJECTION_CODE = "registry_f4_selection_invalid"


def _refuse(code: str, boundary: str) -> RegistrySelectionRefused:
    return RegistrySelectionRefused(Refusal(code), boundary)


def verify_scope_selection(*, scope: GovernedScope, institution_id: str, authority_domain: str, caller_ages: Mapping[str, int], material: Any, verifier: Any,
                           now: datetime):
    """Pure single verification. Returns `(values, digest, None)` or `(None, None, Refusal)`. Builds no workflow and writes nothing."""
    if type(material) is not SelectionMaterial or type(material.record_text) is not str or type(material.selection_text) is not str:
        return None, None, Refusal("material_invalid")
    try:
        base = importlib.import_module("registry_successor.decision")
        common = importlib.import_module("registry_successor.common")
        age_mod = importlib.import_module("registry_successor.v2_age_bounds")
        identity = importlib.import_module("registry_successor.v2_policy_identity")
        verifier_cls = importlib.import_module("registry_adapters.ed25519_verifier").Ed25519Verifier
    except Exception:
        return None, None, Refusal("registry_unavailable")
    if type(verifier) is not verifier_cls:
        return None, None, Refusal("verifier_not_admitted")
    try:
        context = common.ExpectedContext(scope.consumer_id, scope.tenant_id, institution_id, authority_domain, scope.operation_id)
        decision = base.verify_and_decide_v2("required", dict(caller_ages), material.record_text, material.selection_text, context, material.trust,
                                             verifier, now)
    except Exception:
        return None, None, Refusal("registry_call_failed")
    if not isinstance(decision, base.PolicyDecision) or type(decision.kind) is not str or decision.operationally_authorized is not False:
        return None, None, Refusal("registry_decision_invalid")
    kind = decision.kind
    if kind in ("required_policy_unavailable", "overlay_not_applied"):
        return None, None, Refusal("registry_not_applied", decision.code, kind)
    if kind != "applied" or decision.deny_all is not False:
        return None, None, Refusal("registry_decision_invalid", None, kind)
    eff = decision.effective
    if not isinstance(eff, Mapping) or set(eff) != set(AGES) or not all(_scalar(eff[k]) for k in AGES):
        return None, None, Refusal("effective_policy_invalid", None, kind)
    if any(eff[k] > caller_ages[k] for k in AGES):
        return None, None, Refusal("effective_policy_widens_host", None, kind)
    try:
        digest = identity.effective_policy_digest(age_mod.FAMILY_F4, {k: eff[k] for k in AGES})
    except Exception:
        return None, None, Refusal("effective_policy_digest_unavailable", None, kind)
    return {k: eff[k] for k in AGES}, digest, None


class GovernedAgeWorkflow(GovernedLifecycle):
    """`BoundedAuthorizationWorkflow` whose two age scalars come from an authenticated Registry F4 selection, re-validated at every decision and effect."""

    _gl_rejection_code = REJECTION_CODE

    def __init__(self, *, scope: GovernedScope, selection_source: Callable[[], Any], verifier: Any, status_max_age_seconds: int = 60,
                 approval_max_age_seconds: int = 60, construction_time: Optional[datetime] = None, **workflow_kwargs: Any):
        check_scope(scope, _refuse)
        check_source(selection_source, _refuse)
        if workflow_kwargs.get("runtime_authority_profile") is not None:
            raise _refuse("runtime_authority_profile_unsupported", "construction")
        if not (_scalar(status_max_age_seconds) and _scalar(approval_max_age_seconds)):
            raise _refuse("host_scalar_invalid", "construction")
        authority = require_authority(workflow_kwargs, scope.action_id, _refuse)
        now = construction_now(construction_time, workflow_kwargs, _now, _refuse)
        host = {AGES[0]: status_max_age_seconds, AGES[1]: approval_max_age_seconds}
        material = read_source(selection_source, _refuse, "construction")
        values, digest, refusal = verify_scope_selection(scope=scope, institution_id=authority[0], authority_domain=authority[1], caller_ages=host,
                                                         material=material, verifier=verifier, now=now)
        if refusal is not None:
            raise RegistrySelectionRefused(refusal, "construction")
        destination = take_destination(workflow_kwargs, _refuse)
        super().__init__(status_max_age_seconds=values[AGES[0]], approval_max_age_seconds=values[AGES[1]],
                         destination=_GatedDestination(destination, self._gl_commit_gate), **workflow_kwargs)
        self._f4_scope, self._f4_source, self._f4_verifier = scope, selection_source, verifier
        self._f4_host, self._f4_authority = host, authority
        self._gl_attach(scope=scope, authority=authority, bound=(dict(values), digest))

    _f4_commit_gate = GovernedLifecycle._gl_commit_gate

    @property
    def f4_last_commit_refusal(self) -> Optional[Refusal]:
        return self._gl_last_commit_refusal

    @f4_last_commit_refusal.setter
    def f4_last_commit_refusal(self, value: Optional[Refusal]) -> None:
        self._gl_last_commit_refusal = value

    @property
    def registry_f4_policy_identity(self) -> dict:
        values, digest = self._gl_bound
        return {"contract_version": CONTRACT, "family": "f4-control-plane-age-bounds", "effective_policy_digest": digest, "effective": dict(values),
                "host": dict(self._f4_host), "scope": {"consumer_id": self._f4_scope.consumer_id, "tenant_id": self._f4_scope.tenant_id,
                                                         "action_id": self._f4_scope.action_id, "operation_id": self._f4_scope.operation_id}}

    def _gl_error(self, refusal: Refusal, boundary: str) -> Exception:
        return RegistrySelectionRefused(refusal, boundary)

    def _gl_held_defect(self) -> Optional[str]:
        values, _ = self._gl_bound
        if (self.status_max_age_seconds, self.approval_max_age_seconds) != (values[AGES[0]], values[AGES[1]]):
            return "scalars_modified"
        return None

    def _gl_read_sources(self, boundary: str) -> Any:
        return read_source(self._f4_source, _refuse, boundary)

    def _gl_derive(self, materials: Any, authority: Any, now: datetime, boundary: str) -> Any:
        new_values, new_digest, refusal = verify_scope_selection(scope=self._f4_scope, institution_id=authority[0], authority_domain=authority[1],
                                                                 caller_ages=self._f4_host, material=materials, verifier=self._f4_verifier, now=now)
        if refusal is not None:
            raise RegistrySelectionRefused(refusal, boundary)
        return (dict(new_values), new_digest)
