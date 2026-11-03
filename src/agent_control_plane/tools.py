"""Tool adapter execution helpers."""

from __future__ import annotations

import copy
from typing import TYPE_CHECKING, Protocol

from agent_control_plane.models import PolicyDecision, ToolExecutionResult

if TYPE_CHECKING:
    from agent_control_plane.records import RunRecorder


class ToolAdapter(Protocol):
    """Minimal adapter contract for executing an allowed tool action."""

    name: str
    action_type: str

    def execute(self, target: str, payload: dict) -> dict: ...


def execute_with_control(
    recorder: "RunRecorder",
    *,
    tool_name: str,
    action_type: str,
    target: str,
    payload: dict | None = None,
    reason: str | None = None,
    adapter: ToolAdapter | None = None,
) -> tuple[PolicyDecision, ToolExecutionResult | None]:
    """Propose, evaluate, and optionally execute an action through a tool adapter."""

    # R1-A: one private deep snapshot of the caller's payload, taken before anything else runs. The recorded proposal, the policy
    # evaluation and the adapter call all derive from it; the caller's (possibly nested, mutable) dict is never read again.
    snapshot_payload = copy.deepcopy(payload) if payload else {}
    action = recorder.propose_action(
        tool_name=tool_name,
        action_type=action_type,
        target=target,
        payload=snapshot_payload,
        reason=reason,
    )
    decision, _blocked = recorder.evaluate_action(action)

    if decision.result != "allow":
        return decision, None

    if adapter is None:
        return (
            decision,
            ToolExecutionResult(
                action_id=action.action_id,
                run_id=action.run_id,
                executed=False,
                error="No adapter provided.",
            ),
        )

    if adapter.name != tool_name or adapter.action_type != action_type:
        return (
            decision,
            ToolExecutionResult(
                action_id=action.action_id,
                run_id=action.run_id,
                executed=False,
                error=(
                    "Adapter binding mismatch: approved "
                    f"{tool_name}/{action_type}, got {adapter.name}/{adapter.action_type}."
                ),
            ),
        )

    # Execute exactly the recorded/evaluated proposal (detached copy; the adapter cannot alias the recorded state either).
    frozen_payload = copy.deepcopy(action.payload)
    frozen_target = str(action.target)

    try:
        result = adapter.execute(frozen_target, frozen_payload)
    except Exception as exc:
        return (
            decision,
            ToolExecutionResult(
                action_id=action.action_id,
                run_id=action.run_id,
                executed=True,
                result={},
                error=str(exc),
            ),
        )

    recorder.record_reliance(
        source_name=tool_name,
        source_type="tool",
        scope=f"Executed {action_type} on {action.target}",
        referenced_action_id=action.action_id,
    )
    return (
        decision,
        ToolExecutionResult(
            action_id=action.action_id,
            run_id=action.run_id,
            executed=True,
            result=result,
        ),
    )
