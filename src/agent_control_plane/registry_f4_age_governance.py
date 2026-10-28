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
"""
from __future__ import annotations

import contextvars
import importlib
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Mapping, Optional

from agent_control_plane.bounded import BoundedAuthorizationWorkflow, DefinitiveDestinationRejection, TenantRuntimeProposal, _now

CLASSIFICATION = "BUILDER_TESTED; not independently qualified; non-authorizing"
AGES = ("status_max_age_seconds", "approval_max_age_seconds")
SCALAR_MAX = 2147483647
CONTRACT = "r08-v2"


@dataclass(frozen=True)
class GovernedScope:
    """Host-fixed scope of one governed workflow. Never taken from a proposal or a Registry record."""
    consumer_id: str
    tenant_id: str
    action_id: str
    operation_id: str  # the Registry `operation` identifier the host maps to `action_id` (an action URN is not a valid Registry identifier)


@dataclass(frozen=True)
class SelectionMaterial:
    """Raw material a host source returns at each boundary. Nothing here is trusted until Registry verifies it."""
    record_text: Any
    selection_text: Any
    trust: Any


@dataclass(frozen=True)
class Refusal:
    code: str
    registry_code: Optional[str] = None
    registry_kind: Optional[str] = None
    non_authorizing: bool = True
    classification: str = CLASSIFICATION


class RegistrySelectionRefused(PermissionError):
    """Raised before any existing decision/effect code or state write. `.refusal` carries the closed adapter vocabulary and Registry's typed code."""

    def __init__(self, refusal: Refusal, boundary: str):
        super().__init__(f"registry_f4_selection_refused:{boundary}:{refusal.code}" + (f":{refusal.registry_code}" if refusal.registry_code else ""))
        self.refusal, self.boundary = refusal, boundary


def _scalar(v: Any) -> bool:
    return type(v) is int and 0 <= v <= SCALAR_MAX


def _text(v: Any) -> bool:
    return type(v) is str and bool(v)


def _declared_authority(manifest: Any, action_id: str):
    """(institution_id, authority_domain) the host manifest declares for `action_id`, or None. Mirrors `_declared_action` (exactly one match)."""
    actions = manifest.get("actions", []) if isinstance(manifest, Mapping) else []
    found = [a for a in actions if isinstance(a, Mapping) and a.get("action_id") == action_id]
    if len(found) != 1:
        return None
    auth = found[0].get("authority_context") or {}
    inst, dom = auth.get("institution_id"), auth.get("authority_domain")
    return (inst, dom) if _text(inst) and _text(dom) else None


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


_EXEC_NOW: contextvars.ContextVar = contextvars.ContextVar("registry_f4_execute_now", default=None)
REJECTION_CODE = "registry_f4_selection_invalid"


class _GatedDestination:
    """Transparent wrapper of the host destination. Every attribute and method is forwarded unchanged except `apply`, which first runs the commit gate.

    The gate runs in the caller's thread immediately before the delegated `apply`; a refusal raises the existing `DefinitiveDestinationRejection`, which the
    workflow already records as a definitively rejected attempt (the wrapped destination is not called, so no dispatch happened).
    """

    def __init__(self, inner: Any, gate: Callable[[], None]):
        object.__setattr__(self, "_inner", inner)
        object.__setattr__(self, "_gate", gate)

    def __getattr__(self, name: str) -> Any:
        return getattr(object.__getattribute__(self, "_inner"), name)

    def __setattr__(self, name: str, value: Any) -> None:
        setattr(object.__getattribute__(self, "_inner"), name, value)

    def apply(self, *args: Any, **kwargs: Any) -> Any:
        object.__getattribute__(self, "_gate")()
        return object.__getattribute__(self, "_inner").apply(*args, **kwargs)


class GovernedAgeWorkflow(BoundedAuthorizationWorkflow):
    """`BoundedAuthorizationWorkflow` whose two age scalars come from an authenticated Registry F4 selection, re-validated at every decision and effect."""

    def __init__(self, *, scope: GovernedScope, selection_source: Callable[[], Any], verifier: Any, status_max_age_seconds: int = 60,
                 approval_max_age_seconds: int = 60, construction_time: Optional[datetime] = None, **workflow_kwargs: Any):
        if type(scope) is not GovernedScope or not all(_text(getattr(scope, f)) for f in ("consumer_id", "tenant_id", "action_id", "operation_id")):
            raise RegistrySelectionRefused(Refusal("scope_invalid"), "construction")
        if not callable(selection_source):
            raise RegistrySelectionRefused(Refusal("selection_source_invalid"), "construction")
        if workflow_kwargs.get("runtime_authority_profile") is not None:
            raise RegistrySelectionRefused(Refusal("runtime_authority_profile_unsupported"), "construction")
        if not (_scalar(status_max_age_seconds) and _scalar(approval_max_age_seconds)):
            raise RegistrySelectionRefused(Refusal("host_scalar_invalid"), "construction")
        authority = _declared_authority(workflow_kwargs.get("manifest"), scope.action_id)
        if authority is None:
            raise RegistrySelectionRefused(Refusal("manifest_action_undeclared"), "construction")
        allow_test_time = bool(workflow_kwargs.get("allow_test_time"))
        now = construction_time if (allow_test_time and construction_time is not None) else _now()
        if now.tzinfo is None or now.utcoffset() is None:
            raise RegistrySelectionRefused(Refusal("time_invalid"), "construction")
        host = {AGES[0]: status_max_age_seconds, AGES[1]: approval_max_age_seconds}
        try:
            material = selection_source()
        except Exception:
            raise RegistrySelectionRefused(Refusal("selection_source_failed"), "construction") from None
        values, digest, refusal = verify_scope_selection(scope=scope, institution_id=authority[0], authority_domain=authority[1], caller_ages=host,
                                                         material=material, verifier=verifier, now=now)
        if refusal is not None:
            raise RegistrySelectionRefused(refusal, "construction")
        destination = workflow_kwargs.pop("destination", None)
        if destination is None or isinstance(destination, _GatedDestination):
            raise RegistrySelectionRefused(Refusal("destination_invalid"), "construction")
        super().__init__(status_max_age_seconds=values[AGES[0]], approval_max_age_seconds=values[AGES[1]],
                         destination=_GatedDestination(destination, self._f4_commit_gate), **workflow_kwargs)
        self.f4_last_commit_refusal: Optional[Refusal] = None
        self._f4_scope, self._f4_source, self._f4_verifier = scope, selection_source, verifier
        self._f4_host, self._f4_authority = host, authority
        self._f4_bound = (dict(values), digest)

    @property
    def registry_f4_policy_identity(self) -> dict:
        values, digest = self._f4_bound
        return {"contract_version": CONTRACT, "family": "f4-control-plane-age-bounds", "effective_policy_digest": digest, "effective": dict(values),
                "host": dict(self._f4_host), "scope": {"consumer_id": self._f4_scope.consumer_id, "tenant_id": self._f4_scope.tenant_id,
                                                         "action_id": self._f4_scope.action_id, "operation_id": self._f4_scope.operation_id}}

    def _f4_revalidate(self, proposal: Any, boundary: str, now: datetime) -> None:
        scope = self._f4_scope
        if not isinstance(proposal, TenantRuntimeProposal) or proposal.tenant_id != scope.tenant_id or proposal.action_id != scope.action_id:
            raise RegistrySelectionRefused(Refusal("proposal_out_of_scope"), boundary)
        self._f4_reverify(boundary, now)

    def _f4_reverify(self, boundary: str, now: datetime) -> None:
        scope = self._f4_scope
        values, digest = self._f4_bound
        if (self.status_max_age_seconds, self.approval_max_age_seconds) != (values[AGES[0]], values[AGES[1]]):
            raise RegistrySelectionRefused(Refusal("scalars_modified"), boundary)
        authority = _declared_authority(self.manifest, scope.action_id)
        if authority != self._f4_authority:
            raise RegistrySelectionRefused(Refusal("manifest_authority_changed"), boundary)
        try:
            material = self._f4_source()
        except Exception:
            raise RegistrySelectionRefused(Refusal("selection_source_failed"), boundary) from None
        new_values, new_digest, refusal = verify_scope_selection(scope=scope, institution_id=authority[0], authority_domain=authority[1],
                                                                 caller_ages=self._f4_host, material=material, verifier=self._f4_verifier, now=now)
        if refusal is not None:
            raise RegistrySelectionRefused(refusal, boundary)
        if new_values != values or new_digest != digest:
            raise RegistrySelectionRefused(Refusal("selection_changed"), boundary)

    def _f4_commit_gate(self) -> None:
        """Last Registry check before `destination.apply` (see module docstring). Clock: the execute-entry time under a test clock, else the real clock."""
        try:
            self._f4_reverify("effect_commit", self._evaluation_time(_EXEC_NOW.get()))
        except RegistrySelectionRefused as exc:
            self.f4_last_commit_refusal = exc.refusal
            raise DefinitiveDestinationRejection(REJECTION_CODE) from None

    def decide(self, proposal, *, now=None):
        self._f4_revalidate(proposal, "decision", self._evaluation_time(now))
        return super().decide(proposal, now=now)

    def execute(self, proposal, decision, *, adapter_id, now=None, lose_ack=False, partial=False):
        entry_time = self._evaluation_time(now)
        self._f4_revalidate(proposal, "effect", entry_time)
        token = _EXEC_NOW.set(now)
        try:
            return super().execute(proposal, decision, adapter_id=adapter_id, now=now, lose_ack=lose_ack, partial=partial)
        finally:
            _EXEC_NOW.reset(token)
