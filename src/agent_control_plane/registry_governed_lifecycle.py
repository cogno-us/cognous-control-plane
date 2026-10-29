"""Shared lifecycle of the Registry-governed bounded-authorization workflows (F4 ages, F5 class status age, F5 per-class unreadable policy, and the composed workflow).

BUILDER_TESTED developer implementation. NOT independently qualified. NOT an authorization mechanism and NOT a policy language: this module holds ONLY the lifecycle that the
three governed workflows previously duplicated. It decides nothing about policy: every family keeps its own validators, composer and refusal vocabulary, and `bounded.py`,
`runtime_authority.py`, `freshness.py`, `policy_binding.py` and every evaluator are unchanged.

What is shared (and was identical, modulo names, in the three workflows):
  * the host-fixed `GovernedScope`, the raw `SelectionMaterial`, the closed `Refusal`, the base `RegistrySelectionRefused` and the transparent `_GatedDestination` (re-exported by
    `registry_f4_age_governance` so every existing import path keeps working);
  * the construction helpers: scope check, selection-source check, manifest authority, construction clock, source invocation, destination wrapping (each takes the family's own
    refusal factory, so every refusal code and exception class is unchanged);
  * `GovernedLifecycle`: decision-entry and execute-entry revalidation, the pre-dispatch commit gate (`DefinitiveDestinationRejection`, attempt recorded `failed`) and ONE
    immutable bound-state comparison. A family supplies four hooks (`_gl_error`, `_gl_held_defect`, `_gl_read_sources`, `_gl_derive`); the skeleton orders them:
        held state -> manifest authority -> source invocation -> derivation (Registry verification) -> bound-identity comparison -> held state AGAIN (last).

Ordering of the held-state check is deliberate: Registry source code runs in the middle, so the held profile/scalars are checked again after it, immediately before the caller's
next step (introduced for F4 and F5 class age by this consolidation; the F5 per-class unreadable workflow already did it).

Not shared on purpose: family derivation (Registry call, narrowing rule, composition), the family's bound-identity members, its refusal codes and exception class, and its public
identity property. Participation is never optional: a family that is configured is verified at every boundary; there is no fallback to a smaller set.
"""
from __future__ import annotations

import contextvars
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Callable, Mapping, Optional

from agent_control_plane import effective_configuration_binding as ecb
from agent_control_plane.bounded import BoundedAuthorizationWorkflow, DefinitiveDestinationRejection, TenantRuntimeProposal

CLASSIFICATION = "BUILDER_TESTED; not independently qualified; non-authorizing"
SCALAR_MAX = 2147483647
_EXEC_NOW: contextvars.ContextVar = contextvars.ContextVar("registry_governed_execute_now", default=None)
_EXEC_DECISION: contextvars.ContextVar = contextvars.ContextVar("registry_governed_execute_decision", default=None)
BINDING_CHANGED = "authorization_binding_changed"  # the REGISTERED durable reason (runtime-authority-reasons/0.3); this module introduces no reason code


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


Refuser = Callable[[str, str], Exception]  # (code, boundary) -> the family's own exception


def valid_scope(scope: Any) -> bool:
    return type(scope) is GovernedScope and all(_text(getattr(scope, f)) for f in ("consumer_id", "tenant_id", "action_id", "operation_id"))


def check_scope(scope: Any, refuse: Refuser) -> None:
    if not valid_scope(scope):
        raise refuse("scope_invalid", "construction")


def check_source(source: Any, refuse: Refuser) -> None:
    if not callable(source):
        raise refuse("selection_source_invalid", "construction")


def require_authority(workflow_kwargs: Mapping[str, Any], action_id: str, refuse: Refuser):
    authority = _declared_authority(workflow_kwargs.get("manifest"), action_id)
    if authority is None:
        raise refuse("manifest_action_undeclared", "construction")
    return authority


def construction_now(construction_time: Optional[datetime], workflow_kwargs: Mapping[str, Any], now_fn: Callable[[], datetime], refuse: Refuser) -> datetime:
    """The construction clock: the supplied time only under `allow_test_time`, else the family module's `now_fn` (looked up by the caller, so a test clock still applies)."""
    now = construction_time if (bool(workflow_kwargs.get("allow_test_time")) and construction_time is not None) else now_fn()
    if now.tzinfo is None or now.utcoffset() is None:
        raise refuse("time_invalid", "construction")
    return now


def read_source(source: Callable[[], Any], refuse: Refuser, boundary: str) -> Any:
    try:
        return source()
    except Exception:
        raise refuse("selection_source_failed", boundary) from None


def take_destination(workflow_kwargs: dict, refuse: Refuser) -> Any:
    destination = workflow_kwargs.pop("destination", None)
    if destination is None or isinstance(destination, _GatedDestination):
        raise refuse("destination_invalid", "construction")
    return destination


class GovernedLifecycle(BoundedAuthorizationWorkflow):
    """`BoundedAuthorizationWorkflow` plus the shared Registry lifecycle. A family subclass builds its effective inputs, calls `_gl_attach` after the base constructor and
    supplies the four hooks; `decide`, `execute` and the commit gate are inherited unchanged."""

    _gl_rejection_code: str = "registry_governed_selection_invalid"
    _gl_legacy_cutoff: int = 0  # explicit host-supplied finite int; 0 = no legacy decision is accepted (set by a family that binds its configuration)
    _gl_last_binding_status: Optional[str] = None  # evidence of the latest classification (not durable, not authority)

    def _gl_attach(self, *, scope: GovernedScope, authority: Any, bound: Any) -> None:
        self._gl_scope, self._gl_authority, self._gl_bound = scope, authority, bound
        self._gl_last_commit_refusal: Optional[Refusal] = None

    # -- hooks --------------------------------------------------------------------------------------------------------------------------------------------------
    def _gl_error(self, refusal: Refusal, boundary: str) -> Exception:  # pragma: no cover - abstract
        raise NotImplementedError

    def _gl_held_defect(self) -> Optional[str]:  # pragma: no cover - abstract
        """A refusal code when the state the workflow holds (effective profile and/or scalars) is no longer the bound one, else None."""
        raise NotImplementedError

    def _gl_read_sources(self, boundary: str) -> Any:  # pragma: no cover - abstract
        raise NotImplementedError

    def _gl_derive(self, materials: Any, authority: Any, now: datetime, boundary: str) -> Any:  # pragma: no cover - abstract
        """Registry-verify every governing selection and return the comparable bound identity (raise `_gl_error(...)` on any refusal)."""
        raise NotImplementedError

    def _gl_configuration_members(self) -> Optional[dict]:
        """Hook (D-06): the validated members of the live effective configuration (`effective_configuration_binding.build_members`), or None when this family workflow does not
        bind its configuration. It must read the LIVE held values and raise `ecb.BindingInvalid` for any value outside its structural domain."""
        return None

    # -- persisted effective-configuration binding (D-06 Option B, carriage C2) ----------------------------------------------------------------------------------
    def configuration_binding_status(self, decision: Any) -> Optional[str]:
        """READ-ONLY classification of one persisted authorized decision against the live configuration: `bound`, `legacy`, `unbound-after-cutoff`, `invalid`,
        `version-unsupported` or `mismatch` (None when this workflow does not bind). Writes nothing, raises nothing for a bad record, grants nothing; `execute` and the
        claim path use exactly this classification."""
        members = self._gl_configuration_members()
        if members is None:
            return None
        binding = getattr(decision, "binding", None)
        ids = [d.decision_id for d in self.records.load().decisions]
        did = getattr(decision, "decision_id", None)
        index = ids.index(did) if ids.count(did) == 1 else None
        return ecb.classify(getattr(binding, "runtime_authority", None), ecb.mint(members), index=index, cutoff=self._gl_legacy_cutoff, decision_count=len(ids))

    def _resolve(self, proposal, now, *, inputs=None, stage="decision", decision=None, check_ref=None):
        """The base resolution, then (only for an authorized result) the configuration binding. A hold or any refusal the base produced is returned unchanged: the binding can
        add a refusal through the existing `current != persisted.binding` comparison, never remove one and never turn a hold into an authorization."""
        reasons, binding = super()._resolve(proposal, now, inputs=inputs, stage=stage, decision=decision, check_ref=check_ref)
        if reasons or binding is None:
            return reasons, binding
        try:
            members = self._gl_configuration_members()
            if members is None:
                return reasons, binding
            live = ecb.mint(members)
        except ecb.BindingInvalid:
            raise self._gl_refuse("configuration_binding_invalid", "decision" if stage == "decision" else "effect") from None
        target = decision if decision is not None else _EXEC_DECISION.get()
        if stage == "decision" and target is None:  # MINT: every authorized decision of this lifecycle carries the member
            return reasons, self._gl_with_member(binding, live)
        status = self.configuration_binding_status(target) if target is not None else ecb.UNBOUND_AFTER_CUTOFF
        self._gl_last_binding_status = status
        if status == ecb.LEGACY:  # previous semantics: ONLY the new key is left out of the live side; nothing else is ignored
            return reasons, binding
        stamped = self._gl_with_member(binding, live)
        persisted_ra = getattr(getattr(target, "binding", None), "runtime_authority", None)
        if status not in ecb.ACCEPTED and stamped.runtime_authority == persisted_ra:  # unreachable by construction; fail closed if it ever happens
            return sorted(set(reasons) | {BINDING_CHANGED}), stamped
        return reasons, stamped

    @staticmethod
    def _gl_with_member(binding: Any, live: dict) -> Any:
        extension = dict(binding.runtime_authority or {})
        extension[ecb.KEY] = live
        return binding.model_copy(update={"runtime_authority": extension})

    # -- shared lifecycle ---------------------------------------------------------------------------------------------------------------------------------------
    def _gl_refuse(self, code: str, boundary: str) -> Exception:
        return self._gl_error(Refusal(code), boundary)

    def _gl_revalidate(self, proposal: Any, boundary: str, now: datetime) -> None:
        scope = self._gl_scope
        if not isinstance(proposal, TenantRuntimeProposal) or proposal.tenant_id != scope.tenant_id or proposal.action_id != scope.action_id:
            raise self._gl_refuse("proposal_out_of_scope", boundary)
        self._gl_reverify(boundary, now)

    def _gl_reverify(self, boundary: str, now: datetime) -> None:
        code = self._gl_held_defect()
        if code is not None:
            raise self._gl_refuse(code, boundary)
        authority = _declared_authority(self.manifest, self._gl_scope.action_id)
        if authority != self._gl_authority:
            raise self._gl_refuse("manifest_authority_changed", boundary)
        materials = self._gl_read_sources(boundary)
        new_bound = self._gl_derive(materials, authority, now, boundary)
        if new_bound != self._gl_bound:
            raise self._gl_refuse("selection_changed", boundary)
        code = self._gl_held_defect()  # LAST: nothing between this check and the caller's next step runs Registry source code
        if code is not None:
            raise self._gl_refuse(code, boundary)

    def _gl_commit_gate(self) -> None:
        """Last Registry check before `destination.apply`. Clock: the execute-entry time under a test clock, else the real clock."""
        try:
            self._gl_reverify("effect_commit", self._evaluation_time(_EXEC_NOW.get()))
        except RegistrySelectionRefused as exc:
            self._gl_last_commit_refusal = exc.refusal
            raise DefinitiveDestinationRejection(self._gl_rejection_code) from None

    def decide(self, proposal, *, now=None):
        self._gl_revalidate(proposal, "decision", self._evaluation_time(now))
        return super().decide(proposal, now=now)

    def execute(self, proposal, decision, *, adapter_id, now=None, lose_ack=False, partial=False):
        entry_time = self._evaluation_time(now)
        self._gl_revalidate(proposal, "effect", entry_time)
        token, dtoken = _EXEC_NOW.set(now), _EXEC_DECISION.set(decision)
        try:
            return super().execute(proposal, decision, adapter_id=adapter_id, now=now, lose_ack=lose_ack, partial=partial)
        finally:
            _EXEC_DECISION.reset(dtoken)
            _EXEC_NOW.reset(token)
