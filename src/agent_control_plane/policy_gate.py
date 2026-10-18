"""Deterministic policy gate for Agent Control Plane.

The :class:`PolicyGate` evaluates an :class:`~agent_control_plane.models.ActionProposal`
against a :class:`~agent_control_plane.models.Frame` and a list of
:class:`~agent_control_plane.models.AuthorityRecord` objects and produces a
:class:`~agent_control_plane.models.PolicyDecision`.

Policy rules (evaluated in order)
----------------------------------
1. If ``action.tool_name`` is in ``frame.blocked_tools``  → **block**
2. If ``action.tool_name`` is not in ``frame.allowed_tools`` → **escalate**
3. If ``action.action_type == "external_send"`` and no authority scope
   includes ``"external_send"`` → **block**
4. If ``action.action_type == "read"`` and tool is allowed → **allow**
5. If ``action.action_type == "write"`` and an authority scope includes
   ``"write"`` → **allow**
6. Otherwise → **escalate**

Fingerprint
-----------
A stable SHA-256 hex digest is computed from canonical JSON containing:
``tool_name``, ``action_type``, ``target``, canonical ``payload``, sorted
``allowed_tools``, sorted ``blocked_tools``, ``policy_version``, and sorted
active authority scopes.  Identical inputs produce the same result and
``deterministic_fingerprint``.  The ``decision_id`` and ``decided_at``
fields are generated per evaluation.
"""

from __future__ import annotations

import hashlib
import json
import uuid
from datetime import datetime, timezone

from agent_control_plane.time_instant import aware_utc, parse_instant
from typing import TYPE_CHECKING

from agent_control_plane.models import (
    ActionProposal,
    AuthorityRecord,
    Frame,
    PolicyEvaluationTrace,
    PolicyDecision,
    PolicyRuleEvaluation,
)

if TYPE_CHECKING:
    pass


class PolicyGate:
    """Evaluates action proposals against a policy frame.

    The gate is stateless; all inputs required for a decision are passed
    explicitly to :meth:`evaluate`.  Identical inputs always produce the
    same result and ``deterministic_fingerprint``.  The ``decision_id`` and
    ``decided_at`` fields are generated per evaluation.
    """

    def evaluate(
        self,
        action: ActionProposal,
        frame: Frame,
        authority_records: list[AuthorityRecord],
        *,
        now: str | datetime | None = None,
    ) -> PolicyDecision:
        """Evaluate an action proposal and return a policy decision.

        Args:
            action: The proposed action to evaluate.
            frame: The execution frame active for the current run.
            authority_records: Authority records granting scoped permissions.
            now: Optional evaluation time used to filter active authority
                records. Strings must be RFC 3339 instants with an explicit
                offset; a naive string or datetime is refused (ValueError).

        Returns:
            A :class:`~agent_control_plane.models.PolicyDecision` with
            ``result`` set to ``"allow"``, ``"block"``, or ``"escalate"``.
        """
        evaluation_time = self._parse_time(now) if now is not None else self._now_utc()
        active_scopes = self._active_authority_scopes(
            action,
            frame,
            authority_records,
            evaluation_time,
        )
        fingerprint = self._fingerprint(action, frame, active_scopes)
        result, policy_name, reason, _trace_rules = self._apply_rules(
            action,
            frame,
            active_scopes,
        )

        return PolicyDecision(
            decision_id=str(uuid.uuid4()),
            action_id=action.action_id,
            run_id=action.run_id,
            result=result,
            policy_name=policy_name,
            reason=reason,
            decided_at=evaluation_time.isoformat(),
            deterministic_fingerprint=fingerprint,
        )

    def evaluate_with_trace(
        self,
        action: ActionProposal,
        frame: Frame,
        authority_records: list[AuthorityRecord],
        *,
        now: str | datetime | None = None,
    ) -> tuple[PolicyDecision, PolicyEvaluationTrace]:
        """Evaluate an action proposal and return both decision and trace."""

        evaluation_time = self._parse_time(now) if now is not None else self._now_utc()
        active_scopes = self._active_authority_scopes(
            action,
            frame,
            authority_records,
            evaluation_time,
        )
        fingerprint = self._fingerprint(action, frame, active_scopes)
        result, policy_name, reason, trace_rules = self._apply_rules(
            action,
            frame,
            active_scopes,
        )
        trace_id = str(uuid.uuid4())

        decision = PolicyDecision(
            decision_id=str(uuid.uuid4()),
            action_id=action.action_id,
            run_id=action.run_id,
            result=result,
            policy_name=policy_name,
            reason=reason,
            decided_at=evaluation_time.isoformat(),
            deterministic_fingerprint=fingerprint,
            trace_id=trace_id,
        )
        trace = PolicyEvaluationTrace(
            trace_id=trace_id,
            run_id=action.run_id,
            action_id=action.action_id,
            evaluated_at=evaluation_time.isoformat(),
            rules_evaluated=trace_rules,
            final_result=result,
            deterministic_fingerprint=fingerprint,
        )
        return decision, trace

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    def _apply_rules(
        self,
        action: ActionProposal,
        frame: Frame,
        active_scopes: set[str],
    ) -> tuple[str, str, str, list[PolicyRuleEvaluation]]:
        """Return decision details plus an ordered policy evaluation trace."""

        trace_rules: list[PolicyRuleEvaluation] = []
        for rule_name, matched, result, reason in [
            (
                "blocked_tool_policy",
                action.tool_name in frame.blocked_tools,
                "block",
                f"Tool '{action.tool_name}' is explicitly blocked in this frame.",
            ),
            (
                "unknown_tool_policy",
                action.tool_name not in frame.allowed_tools,
                "escalate",
                (
                    f"Tool '{action.tool_name}' is not in the allowed-tools list "
                    "and requires manual review."
                ),
            ),
            (
                "external_send_authority_policy",
                action.action_type == "external_send",
                "allow" if "external_send" in active_scopes else "block",
                (
                    "Authority for 'external_send' is present; action allowed."
                    if "external_send" in active_scopes
                    else "Action type 'external_send' requires an authority record "
                    "with scope 'external_send', which was not found."
                ),
            ),
            (
                "read_allowed_tool_policy",
                action.action_type == "read",
                "allow",
                f"Tool '{action.tool_name}' is allowed and action type is 'read'.",
            ),
            (
                "write_authority_policy",
                action.action_type == "write",
                "allow" if "write" in active_scopes else "escalate",
                (
                    "Authority for 'write' is present; action allowed."
                    if "write" in active_scopes
                    else "Action type 'write' requires an authority record with "
                    "scope 'write', which was not found; escalating for review."
                ),
            ),
            (
                "default_escalation_policy",
                True,
                "escalate",
                (
                    f"Action type '{action.action_type}' does not match any explicit "
                    "allow or block rule; escalating for review."
                ),
            ),
        ]:
            if matched:
                trace_rules.append(
                    PolicyRuleEvaluation(
                        rule_name=rule_name,
                        matched=True,
                        result=result,
                        reason=reason,
                    )
                )
                return result, rule_name, reason, trace_rules

            trace_rules.append(
                PolicyRuleEvaluation(
                    rule_name=rule_name,
                    matched=False,
                    result="none",
                    reason=f"Rule '{rule_name}' did not match this action.",
                )
            )

        raise RuntimeError("Policy rule evaluation did not produce a decision.")

    def _fingerprint(
        self,
        action: ActionProposal,
        frame: Frame,
        active_scopes: set[str],
    ) -> str:
        """Return a stable SHA-256 hex fingerprint of the decision inputs.

        The fingerprint is computed from a canonical JSON object whose keys
        are sorted so that serialisation is deterministic regardless of
        insertion order.
        """
        canonical: dict = {
            "tool_name": action.tool_name,
            "action_type": action.action_type,
            "target": action.target,
            "payload": action.payload,
            "allowed_tools": sorted(frame.allowed_tools),
            "blocked_tools": sorted(frame.blocked_tools),
            "policy_version": frame.policy_version,
            "authority_scopes": sorted(active_scopes),
        }

        serialised = json.dumps(canonical, sort_keys=True, ensure_ascii=True)
        return hashlib.sha256(serialised.encode()).hexdigest()

    def _active_authority_scopes(
        self,
        action: ActionProposal,
        frame: Frame,
        authority_records: list[AuthorityRecord],
        now: datetime,
    ) -> set[str]:
        """Return scopes from active authority records matching this evaluation."""

        scopes: set[str] = set()
        for record in authority_records:
            if record.run_id != action.run_id:
                continue
            if record.actor != frame.actor:
                continue
            if record.expires_at is not None and self._parse_time(record.expires_at) <= now:
                continue
            scopes.update(record.scope)
        return scopes

    def _now_utc(self) -> datetime:
        """Return the current UTC time."""

        return datetime.now(timezone.utc)

    def _parse_time(self, value: str | datetime) -> datetime:
        """Parse a time value strictly and normalise it to UTC; a naive or malformed time raises ``InstantError``."""

        if isinstance(value, datetime):
            return aware_utc(value)
        return parse_instant(value)
