"""Replay bundle generation and serialisation.

Provides :func:`generate_replay_bundle`, :func:`to_json`, and :func:`from_json`
so that any :class:`~agent_control_plane.models.RunRecord` can be converted
to or from a portable :class:`~agent_control_plane.models.ReplayBundle`.
"""

from __future__ import annotations

import json
import uuid

from agent_control_plane.models import ReplayBundle, RunRecord


def generate_replay_bundle(run_record: RunRecord) -> ReplayBundle:
    """Convert a :class:`~agent_control_plane.models.RunRecord` into a
    :class:`~agent_control_plane.models.ReplayBundle`.

    The bundle is a snapshot (without tool attempts or results) that includes the frame, all
    action proposals, policy decisions, authority records, reliance records,
    blocked actions, and the final output.

    Args:
        run_record: The run record to bundle.

    Returns:
        A :class:`ReplayBundle` ready for export or storage.
    """
    return ReplayBundle(
        replay_bundle_id=str(uuid.uuid4()),
        run_id=run_record.run_id,
        frame=run_record.frame,
        actions=list(run_record.actions),
        decisions=list(run_record.decisions),
        policy_traces=list(run_record.policy_traces),
        authority_records=list(run_record.authority_records),
        reliance_records=list(run_record.reliance_records),
        blocked_actions=list(run_record.blocked_actions),
        final_output=run_record.final_output,
    )


def to_json(bundle: ReplayBundle, *, indent: int = 2) -> str:
    """Serialise a :class:`~agent_control_plane.models.ReplayBundle` to a JSON string.

    Args:
        bundle: The replay bundle to serialise.
        indent: JSON indentation level (default: 2).

    Returns:
        A JSON string representation of the bundle.
    """
    return json.dumps(bundle.model_dump(), indent=indent, ensure_ascii=False)


def from_json(data: str | bytes) -> ReplayBundle:
    """Deserialise a :class:`~agent_control_plane.models.ReplayBundle` from JSON.

    Args:
        data: JSON string or bytes produced by :func:`to_json`.

    Returns:
        A :class:`ReplayBundle` instance.

    Raises:
        :class:`~agent_control_plane.exceptions.ReplayError`: If the data
            cannot be parsed or validated.
    """
    from agent_control_plane.exceptions import ReplayError

    try:
        raw = json.loads(data)
        return ReplayBundle.model_validate(raw)
    except Exception as exc:
        raise ReplayError(f"Failed to deserialise ReplayBundle: {exc}") from exc
