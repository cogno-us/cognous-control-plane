"""M11 PR-2: narrow the Control Plane freshness scalars with authenticated Registry configuration, then build the existing workflow.

BUILDER_TESTED developer implementation. NOT independently qualified. NOT an authorization mechanism: a result is non-authorizing and grants nothing.
It adds no capability, no network, subprocess or file effect, and does not modify `bounded.py`: enforcement stays in the existing
`BoundedAuthorizationWorkflow._fresh` and its callers; this module only chooses the three constructor scalars.

Governed values (source-confirmed in `BoundedAuthorizationWorkflow.__init__`, `_fresh`, and the local-authority-effect snapshot check):
  * `status_max_age_seconds`, `approval_max_age_seconds`  - Registry family `f4-control-plane-age-bounds` (r08-v2, entry `verify_and_decide_v2`)
  * `clock_tolerance_seconds`                             - Registry family `f4t-control-plane-clock-tolerance` (r08-v5, entry `verify_and_decide_v5`)
`identity_max_age_seconds` and `mandate_max_age_seconds` stay host-owned and are never changed here.

Fail-closed shape (same as the Runtime Registry adapters): raw inputs only; the verifier must be exactly Registry's `Ed25519Verifier`; participation
must be `required` (an optional overlay is refused, never skipped); only `kind == "applied"` proceeds; every refusal, including a malformed, stale,
withdrawn, revoked, wrong-scope or wrong-family selection, returns no workflow. A governed input that is supplied can never fall back to the caller
value. The composed value is re-checked to be `<=` the caller's value (never wider) and the Registry effective-policy digest is recomputed from
the values actually used and must match. A group left out (`None`) is simply not governed; it keeps the caller value exactly as before.

Selection is verified once, at construction. This module has no durable ratchet or lock-time recheck (the Runtime owns that for its values), so a
later revocation or expiry is seen only when the host rebuilds the workflow. Registry is resolved lazily from the host environment (a pinned
checkout, never vendored); if it cannot be imported the result is `registry_unavailable`.
"""
from __future__ import annotations

import importlib
from dataclasses import dataclass, field
from typing import Any, Mapping, Optional

CLASSIFICATION = "BUILDER_TESTED; not independently qualified; non-authorizing"
AGES = ("status_max_age_seconds", "approval_max_age_seconds")
TOLERANCE = "clock_tolerance_seconds"
SCALAR_MAX = 2147483647
_PARTICIPATION = "required"


@dataclass(frozen=True)
class GovernedInput:
    """Raw Registry inputs for one governed family. Nothing here is trusted until Registry verifies it."""
    record_text: Any
    selection_text: Any
    context: Any
    trust: Any
    now: Any


@dataclass(frozen=True)
class FreshnessNarrowingResult:
    ok: bool
    adapter_refusal: Optional[str] = None
    registry_code: Optional[str] = None
    registry_kind: Optional[str] = None
    values: Optional[Mapping[str, int]] = None            # the three scalars to use; None on refusal
    effective_policy_digests: Optional[Mapping[str, str]] = field(default=None)  # {"f4": ..., "f4t": ...} for the governed families
    non_authorizing: bool = True
    classification: str = CLASSIFICATION


def _refuse(code: str, *, registry_code: Optional[str] = None, registry_kind: Optional[str] = None) -> FreshnessNarrowingResult:
    return FreshnessNarrowingResult(False, code, registry_code, registry_kind)


def _is_scalar(v: Any) -> bool:
    return type(v) is int and 0 <= v <= SCALAR_MAX


def _decide(mod, fn, caller, gi, verifier, base_mod):
    """One Registry call. Returns (decision, None) or (None, refusal)."""
    try:
        decision = getattr(mod, fn)(_PARTICIPATION, caller, gi.record_text, gi.selection_text, gi.context, gi.trust, verifier, gi.now)
    except Exception:
        return None, _refuse("registry_call_failed")
    if not isinstance(decision, base_mod.PolicyDecision) or type(decision.kind) is not str or decision.operationally_authorized is not False:
        return None, _refuse("registry_decision_invalid")
    kind = decision.kind
    if kind in ("required_policy_unavailable", "overlay_not_applied"):
        return None, _refuse("registry_not_applied", registry_code=decision.code, registry_kind=kind)
    if kind == "applied_deny_all":
        return None, _refuse("registry_deny_all", registry_kind=kind)
    if kind != "applied" or decision.deny_all is not False:
        return None, _refuse("registry_decision_invalid", registry_kind=kind)
    return decision, None


def resolve_governed_freshness(*, status_max_age_seconds: Any, approval_max_age_seconds: Any, clock_tolerance_seconds: Any, verifier: Any,
                               ages: Optional[GovernedInput] = None, tolerance: Optional[GovernedInput] = None) -> FreshnessNarrowingResult:
    """Compose the caller's three scalars with the supplied authenticated Registry selections. Pure: no workflow, no state change."""
    caller_vals = {AGES[0]: status_max_age_seconds, AGES[1]: approval_max_age_seconds, TOLERANCE: clock_tolerance_seconds}
    if any(not _is_scalar(v) for v in caller_vals.values()):
        return _refuse("caller_scalar_invalid")  # exact int in 0..2147483647 only; a bool, float, str or out-of-range value is refused before Registry runs
    if (ages is not None and type(ages) is not GovernedInput) or (tolerance is not None and type(tolerance) is not GovernedInput):
        return _refuse("input_invalid")
    if ages is None and tolerance is None:
        return _refuse("no_governed_input")
    for gi in (ages, tolerance):
        if gi is not None and (type(gi.record_text) is not str or type(gi.selection_text) is not str):
            return _refuse("input_invalid")
    try:
        base_mod = importlib.import_module("registry_successor.decision")
        verifier_cls = importlib.import_module("registry_adapters.ed25519_verifier").Ed25519Verifier
        v5_decision = importlib.import_module("registry_successor.v5_decision")
        v2_identity = importlib.import_module("registry_successor.v2_policy_identity")
        v5_identity = importlib.import_module("registry_successor.v5_policy_identity")
        age_mod = importlib.import_module("registry_successor.v2_age_bounds")
        tol_mod = importlib.import_module("registry_successor.v5_f4t")
    except Exception:
        return _refuse("registry_unavailable")
    if type(verifier) is not verifier_cls:
        return _refuse("verifier_not_admitted")
    values = dict(caller_vals)
    digests = {}
    if ages is not None:
        decision, refusal = _decide(base_mod, "verify_and_decide_v2", {k: caller_vals[k] for k in AGES}, ages, verifier, base_mod)
        if refusal is not None:
            return refusal
        eff = decision.effective
        if not isinstance(eff, Mapping) or set(eff) != set(AGES) or not all(_is_scalar(eff[k]) for k in AGES):
            return _refuse("effective_policy_invalid", registry_kind=decision.kind)
        if any(eff[k] > caller_vals[k] for k in AGES):
            return _refuse("effective_policy_widens_caller", registry_kind=decision.kind)
        try:
            used = v2_identity.effective_policy_digest(age_mod.FAMILY_F4, {k: eff[k] for k in AGES})
        except Exception:
            return _refuse("effective_policy_digest_unavailable", registry_kind=decision.kind)
        values.update({k: eff[k] for k in AGES})
        digests["f4"] = used
    if tolerance is not None:
        decision, refusal = _decide(v5_decision, "verify_and_decide_v5", {TOLERANCE: caller_vals[TOLERANCE]}, tolerance, verifier, base_mod)
        if refusal is not None:
            return refusal
        eff = decision.effective
        if not isinstance(eff, Mapping) or set(eff) != {TOLERANCE} or not _is_scalar(eff[TOLERANCE]):
            return _refuse("effective_policy_invalid", registry_kind=decision.kind)
        if eff[TOLERANCE] > caller_vals[TOLERANCE]:
            return _refuse("effective_policy_widens_caller", registry_kind=decision.kind)
        try:
            used = v5_identity.effective_policy_digest(tol_mod.FAMILY_F4T, {TOLERANCE: eff[TOLERANCE]})
        except Exception:
            return _refuse("effective_policy_digest_unavailable", registry_kind=decision.kind)
        values[TOLERANCE] = eff[TOLERANCE]
        digests["f4t"] = used
    return FreshnessNarrowingResult(True, None, None, "applied", values, digests)


def build_governed_workflow(*, status_max_age_seconds: int = 60, approval_max_age_seconds: int = 60, clock_tolerance_seconds: int = 5, verifier: Any,
                            ages: Optional[GovernedInput] = None, tolerance: Optional[GovernedInput] = None, **workflow_kwargs: Any):
    """Return `(workflow, result)`. On any refusal `workflow` is None and nothing was constructed. The three scalars may not appear in `workflow_kwargs`."""
    from agent_control_plane.bounded import BoundedAuthorizationWorkflow

    if {"status_max_age_seconds", "approval_max_age_seconds", "clock_tolerance_seconds"} & set(workflow_kwargs):
        return None, _refuse("input_invalid")
    result = resolve_governed_freshness(status_max_age_seconds=status_max_age_seconds, approval_max_age_seconds=approval_max_age_seconds,
                                        clock_tolerance_seconds=clock_tolerance_seconds, verifier=verifier, ages=ages, tolerance=tolerance)
    if not result.ok:
        return None, result
    v = result.values
    workflow = BoundedAuthorizationWorkflow(status_max_age_seconds=v[AGES[0]], approval_max_age_seconds=v[AGES[1]], clock_tolerance_seconds=v[TOLERANCE],
                                            **workflow_kwargs)
    workflow.registry_effective_policy_digests = dict(result.effective_policy_digests)  # bound identity of what narrowed this instance
    return workflow, result
