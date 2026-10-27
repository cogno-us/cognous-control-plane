"""Trusted authorization export for the Runtime authorization pin (Registry r08-v2 Amendment 4, section 3.2; interface freeze section 3).

NON-AUTHORIZING. This module makes no authorization decision. It reads what the Control Plane already persisted (the decision, the profile
it committed to, the resolver snapshot) under the existing resolver handoff lock and returns a closed description for the trusted host
installer: either the 17 pin payload members, a terminal status the persisted authority positively shows, or "unknown".

What it does not do: it builds no claim, calls no ``provision``, reads no claim and takes no ``expected_*`` keyword as a source. Every
payload value comes from the persisted decision, the handoff snapshot, the trusted host-config profile or the installer-owned host binding body.

Isolation note: nothing in this Python function boundary provides OS isolation. The separation between the claim supplier, this export, the
installer and the Runtime comes only from the deployment's OS identities and file custody (Amendment 4 P-1 to P-5). Authenticity of the
persisted Control Plane state it reads rests on that custody; it is unsigned. See ``docs/authorization-pin-export.md``.

Bookkeeping: the existing resolution step journals a resolution check in the Control Plane record store, exactly as claim issuance does.
No decision, grant, approval or policy record is created or changed.
"""
from __future__ import annotations

import copy
from datetime import datetime
from typing import Any

from agent_control_plane import canonical_policy_binding as _cpb
from agent_control_plane.bounded import (
    BoundedAuthorizationWorkflow,
    RuntimeDecision,
    RuntimeProposal,
    TenantAuthorizationBinding,
    _iso,
    commitment,
)
from agent_control_plane.local_authority_effect import (
    _binding_issuance_reasons,
    _utc,
    _validate_issuance_snapshot,
)
from agent_control_plane.policy_binding import member_defects as _approval_binding_defects
from agent_control_plane.runtime_authority import approval_commitment as _approval_commitment

PIN_EXPORT_PROFILE = "ocs-s4/authorization-pin-export/0.1"

#: Closed payload members (Amendment 4 section 3.1, CPAA-sourced), in contract order.
PAYLOAD_MEMBERS = (
    "tenant_id", "institution_id", "authority_domain", "consumer_id", "operation",
    "decision_id", "effect_id", "action_id", "grant_id", "grant_revision",
    "approval_commitment", "binding_digest", "selection_epoch", "activation_ref", "policy_generation",
    "not_before", "expires_at",
)

# Existing resolver reason codes mapped to the closed terminal set. Anything not listed here is never mapped to a terminal status.
_REVOKED_REASONS = frozenset({"grant_revoked", "grant_revocation_recorded"})
_SUPERSEDED_REASONS = frozenset({"grant_revision_stale", "policy_superseded"})
_WITHDRAWN_REASONS = frozenset({"approval_policy_activation_mismatch"})
_APPROVAL_REASON = "approval_not_active"  # revoked vs unknown is decided from the handoff snapshot, never guessed


def _result(decision_id: str, state: str, *, reason: str, payload: dict | None = None, terminal_status: str | None = None) -> dict:
    return {"profile": PIN_EXPORT_PROFILE, "decision_id": decision_id, "state": state,
            "payload": copy.deepcopy(payload) if state == "active" else None,
            "terminal_status": terminal_status if state == "terminal" else None, "reason": reason}


def _unknown(decision_id: str, reason: str) -> dict:
    return _result(decision_id, "unknown", reason=reason)


def _terminal(decision_id: str, status: str, reason: str) -> dict:
    return _result(decision_id, "terminal", reason=reason, terminal_status=status)


def _classify(reasons: list[str], approval_revoked: bool) -> str | None:
    """Closed terminal status when EVERY reason positively maps to the same status; otherwise None (unknown). Never guesses."""
    statuses = set()
    if "policy_superseded" in reasons:
        # The resolver emits policy_stale_or_changed together with policy_superseded for the same status read; alone it is not terminal evidence.
        reasons = [x for x in reasons if x != "policy_stale_or_changed"]
    for reason in reasons:
        if reason in _REVOKED_REASONS:
            statuses.add("revoked")
        elif reason == _APPROVAL_REASON and approval_revoked:
            statuses.add("revoked")
        elif reason in _SUPERSEDED_REASONS:
            statuses.add("superseded")
        elif reason in _WITHDRAWN_REASONS:
            statuses.add("withdrawn")
        else:
            return None
    return next(iter(statuses)) if len(statuses) == 1 else None


def assess_authorization_pin(workflow: BoundedAuthorizationWorkflow, proposal: RuntimeProposal, decision: RuntimeDecision, *,
                             now: datetime, host_policy_binding: dict) -> dict:
    """Read-only assessment of one persisted decision for the trusted installer.

    ``host_policy_binding`` is the canonical 14-member body from installer-owned host configuration, never from a claim. The signature has no
    claim parameter and no ``expected_*`` parameter: consumer and operation are taken from that body.

    Returns ``{"profile", "decision_id", "state": "active"|"terminal"|"unknown", "payload", "terminal_status", "reason"}``. Raises
    ``PermissionError`` for a decision that is not the persisted authorized one, an inconsistent host binding or profile, or any validation the
    claim-issuance path would also refuse. Expiry is not a terminal transition.
    """
    if now.tzinfo is None or now.utcoffset() is None:
        raise ValueError("assessment time must be timezone-aware")
    host = copy.deepcopy(host_policy_binding)  # private copy before any other code runs
    now = workflow._evaluation_time(now)

    persisted = workflow.records.decision(decision.decision_id)
    if persisted is None or persisted != decision:
        raise PermissionError("decision is not the immutable persisted decision")
    if persisted.result != "authorized" or persisted.binding is None:
        raise PermissionError("decision is not authorized")
    current_binding = persisted.binding  # persisted object from here on; the caller's object is not read again
    decision_id = persisted.decision_id
    if not isinstance(current_binding, TenantAuthorizationBinding):
        raise PermissionError("authorization pin requires a tenant-bound persisted decision")

    profile = workflow.runtime_authority_profile
    if profile is None:
        raise PermissionError("no runtime-authority profile is configured for this workflow")
    side = getattr(profile, "policy_binding", None)
    if side is None or _approval_binding_defects(side):
        raise PermissionError("no valid approval-side policy-binding/0.1 is configured")
    if _cpb.binding_defect(host) is not None:
        raise PermissionError("host policy binding is not a valid canonical binding")
    persisted_ra = current_binding.runtime_authority
    if not isinstance(persisted_ra, dict):
        raise PermissionError("persisted decision carries no runtime-authority extension")
    persisted_catalogue = persisted_ra.get("catalogue_digest")
    persisted_approval = persisted_ra.get("approval_commitment")
    persisted_generation = persisted_ra.get("policy_generation")
    if type(persisted_catalogue) is not str or type(persisted_approval) is not str or type(persisted_generation) is not int:
        raise PermissionError("persisted runtime-authority extension is incomplete")

    withdrawn = side.disposition == "withdrawn"
    if withdrawn:
        # The provisional withdrawn representation has no binding_digest, carries the withdrawal's own activation and generation, and changes the
        # catalogue, so none of those can be compared with the persisted decision. Positive evidence is instead that the installer-owned host
        # binding body still names the activation the persisted decision committed to.
        if persisted_ra.get("policy_activation_ref") != host["activation_ref"]:
            raise PermissionError("host policy binding does not name the activation the persisted decision committed to")
    else:
        if host["activation_ref"] != side.activation_ref or host["selection_epoch"] != side.selection_epoch:
            raise PermissionError("host policy binding does not match the configured selection epoch or activation")
        if side.disposition != "selected" or side.binding_digest != _cpb.binding_digest(host):
            raise PermissionError("host policy binding digest does not match the configured profile")
        if commitment(profile.model_dump(mode="json")) != persisted_catalogue:
            raise PermissionError("configured profile differs from the profile the persisted decision committed to")
        if persisted_ra.get("policy_activation_ref") != side.activation_ref or persisted_generation != side.policy_generation:
            raise PermissionError("persisted activation or generation differs from the configured profile")

    resolver = workflow.resolver
    handoff = getattr(resolver, "authority_effect_handoff", None)
    snapshot_reader = getattr(resolver, "authority_effect_snapshot", None)
    if not callable(handoff) or not callable(snapshot_reader):
        raise PermissionError("resolver does not implement trusted authority-effect handoff")

    frozen = proposal.model_copy(deep=True)
    with handoff(frozen.authority_context_ref or ""):
        if withdrawn:
            try:
                snapshot = snapshot_reader(frozen.authority_context_ref or "")
            except Exception:  # noqa: BLE001 - an unreadable source is "unknown", never a guessed status
                return _unknown(decision_id, "authority snapshot unreadable")
            _require_approval_commitment(profile, snapshot, persisted_approval, withdrawn=True)
            return _terminal(decision_id, "withdrawn", "approval-side policy binding disposition is withdrawn")

        inputs: list = []
        check_ref: list[str] = []
        try:
            reasons, current = workflow._resolve(
                frozen, now, inputs=inputs, stage="claim", decision=persisted,
                **({"check_ref": check_ref} if (workflow._identity or workflow._freshness) else {}),
            )
            binding_reasons, _note = _binding_issuance_reasons(workflow, current, host, host["consumer_id"], host["operation"])
            reasons = workflow._record_check(inputs, now, list(reasons) + binding_reasons, "claim", check_id=check_ref[0] if check_ref else None)
        except PermissionError:
            raise
        except Exception:  # noqa: BLE001 - unreadable authority source: no pin change
            return _unknown(decision_id, "authority source unreadable")

        if reasons or current is None or current != current_binding:
            approval_revoked = False
            if _APPROVAL_REASON in reasons:
                approval_revoked = _approval_positively_revoked(snapshot_reader, frozen, current_binding)
            status = _classify(sorted(set(reasons)), approval_revoked)
            if status is None:
                shown = ",".join(sorted(set(reasons))[:8]) or "binding changed"
                return _unknown(decision_id, "authority not supported but not positively terminal: " + shown)
            return _terminal(decision_id, status, "persisted authority no longer supports the decision: " + ",".join(sorted(set(reasons))))

        try:
            snapshot = snapshot_reader(frozen.authority_context_ref or "")
        except Exception:  # noqa: BLE001
            return _unknown(decision_id, "authority snapshot unreadable")
        if not isinstance(snapshot, dict):
            return _unknown(decision_id, "authority snapshot unavailable")
        context, institution, grant, _approvals, _policies, _evidence = _validate_issuance_snapshot(workflow, frozen, persisted, snapshot, now=now)
        scope = host["scope"]
        if (scope["tenant"] != current_binding.tenant_id or scope["institution"] != institution.get("institution_id")
                or scope["authority_domain"] != institution.get("authority_domain")):
            raise PermissionError("host policy binding scope does not match the persisted decision, institution or authority domain")
        _require_approval_commitment(profile, snapshot, persisted_approval, withdrawn=False)

        start = [_utc(grant["not_before"])]
        end = [_utc(grant["expires_at"])]
        if frozen.not_before:
            start.append(_utc(frozen.not_before))
        if frozen.expires_at:
            end.append(_utc(frozen.expires_at))
        not_before, expires_at = max(start), min(end)
        if expires_at <= not_before or expires_at <= now:
            return _unknown(decision_id, "no usable validity interval (expiry is derived by the Runtime, not a terminal transition)")

        payload = {
            "tenant_id": current_binding.tenant_id,
            "institution_id": institution.get("institution_id"),
            "authority_domain": institution.get("authority_domain"),
            "consumer_id": host["consumer_id"],
            "operation": host["operation"],
            "decision_id": decision_id,
            "effect_id": persisted.effect_id,
            "action_id": current_binding.action_id,
            "grant_id": current_binding.grant_id,
            "grant_revision": current_binding.grant_revision,
            "approval_commitment": persisted_approval,
            "binding_digest": side.binding_digest,
            "selection_epoch": side.selection_epoch,
            "activation_ref": side.activation_ref,
            "policy_generation": persisted_generation,
            "not_before": _iso(not_before),
            "expires_at": _iso(expires_at),
        }
        if tuple(payload) != PAYLOAD_MEMBERS:  # structural guard: the member set and order are closed
            raise PermissionError("internal: payload members differ from the frozen set")
        return _result(decision_id, "active", reason="persisted authority supports the decision", payload=payload)


def _require_approval_commitment(profile, snapshot: Any, persisted_approval: str, *, withdrawn: bool) -> None:
    """Recompute ``approval_commitment`` from the handoff context and require equality with the persisted value."""
    context = snapshot.get("context") if isinstance(snapshot, dict) else None
    if not isinstance(context, dict):
        raise PermissionError("authority snapshot context unavailable")
    if withdrawn:
        # The withdrawn representation changes the profile and thus the commitment; it cannot be recomputed. The decision-side link was
        # checked by activation and generation instead (documented limit).
        return
    if _approval_commitment(profile, context) != persisted_approval:
        raise PermissionError("recomputed approval commitment differs from the persisted value")


def _approval_positively_revoked(snapshot_reader, proposal: RuntimeProposal, binding: TenantAuthorizationBinding) -> bool:
    """True only when the handoff snapshot shows an approval of this grant revision with status ``revoked``."""
    try:
        snapshot = snapshot_reader(proposal.authority_context_ref or "")
        grant = (snapshot.get("context") or {}).get("grant") or {}
        approvals = snapshot.get("approvals") or {}
        return any(getattr(approvals.get(ref), "status", None) == "revoked"
                   and getattr(approvals.get(ref), "grant_id", None) == binding.grant_id
                   for ref in grant.get("approval_refs", []))
    except Exception:  # noqa: BLE001
        return False
